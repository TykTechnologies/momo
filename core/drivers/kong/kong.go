package kong

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/kevholditch/gokong"
	"github.com/mitchellh/mapstructure"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/user"

	"github.com/TykTechnologies/momo/pkg/logger"
	"github.com/TykTechnologies/momo/pkg/models"
	coreStorage "github.com/TykTechnologies/momo/pkg/storage"

	"github.com/TykTechnologies/momo/core/drivers/kong/converter"
	"github.com/TykTechnologies/momo/core/types"
	"github.com/TykTechnologies/momo/core/util"

	"github.com/TykTechnologies/momo/core/config"
)

var (
	moduleName = "momo.drivers.kong"
	log        = logger.GetAndExcludeLoggerFromTrace(moduleName)
)

type Driver struct {
	client *gokong.KongAdminClient
	cfg   *KongConfSection
	store coreStorage.MomoStore
}

func NewKongDriver() (types.GatewayDriver, error) {
	drv := &Driver{}
	err := drv.Init()
	if err != nil {
		return nil, err
	}

	return drv, nil
}

func (d *Driver) SetStore(store coreStorage.MomoStore) {
	d.store = store
}

func (d *Driver) Init() error {
	conf := &KongConfSection{}
	err := config.GetSubConf(conf, "MOMOKONG")
	if err != nil {
		return err
	}

	d.cfg = conf

	if d.cfg.Momo.Drivers.Kong.HostAddress == "" {
		log.Fatal("kong host address unset")
	}

	kConf := &gokong.Config{
		HostAddress:        d.cfg.Momo.Drivers.Kong.HostAddress,
		Username:           d.cfg.Momo.Drivers.Kong.Username,
		Password:           d.cfg.Momo.Drivers.Kong.Password,
		InsecureSkipVerify: d.cfg.Momo.Drivers.Kong.InsecureSkipVerify,
		ApiKey:             d.cfg.Momo.Drivers.Kong.ApiKey,
	}

	kongClient := gokong.NewClient(kConf)
	_, err = kongClient.Status().Get()

	if err != nil {
		return err
	}

	d.client = kongClient

	st, err := coreStorage.GetSpecificStoreType(conf.Momo.StoreType, conf.Momo.StorageTag)
	if err != nil {
		return err
	}

	momoStore, ok := st.(coreStorage.MomoStore)
	if !ok {
		return errors.New("store driver does not support MomoStore interface")
	}

	d.store = momoStore
	d.store.InitMomoStore(conf.Momo.StorageTag)

	return nil
}

func (d *Driver) Name() string {
	return driverName
}

func (d *Driver) doCreate(data map[string]*converter.Service) (map[string]*converter.Service, error) {
	for sn := range data {
		err := data[sn].Create(d.client)
		if err != nil {
			log.Error(err)
			return data, err
		}

		for i := range data[sn].Plugins {
			err := data[sn].Plugins[i].Create(d.client)
			if err != nil {
				log.Error(err)
				return data, err
			}
		}

		for rn := range data[sn].Routes {
			err := data[sn].Routes[rn].Create(d.client)
			if err != nil {
				log.Error(err)
				return data, err
			}

			for pi := range data[sn].Routes[rn].Plugins {
				err := data[sn].Routes[rn].Plugins[pi].Create(d.client)
				if err != nil {
					log.Error(err)
					return data, err
				}
			}
		}
	}

	return data, nil
}

func (d *Driver) createAPI(def *apidef.APIDefinition, mm *models.MomoMap) error {
	cv := converter.Converter{}
	data := cv.CreationOpSetFromTykDef(d.client, def)
	var err error

	data, err = d.doCreate(data)
	if err != nil {
		return err
	}

	ds := &DeploymentSet{
		ServiceMap: data,
	}

	create := false
	if mm == nil {
		create = true
		mm = &models.MomoMap{
			APIID: def.APIID,
			DriverData: map[string]interface{}{
				d.Name(): ds,
			},
		}
	}

	mm.DriverData[d.Name()] = ds

	if create {
		_, err = d.store.CreateReference(mm)
	} else {
		err = d.store.UpdateReference(def.APIID, mm)
	}

	if err != nil {
		log.Error(err)
		return err
	}

	return nil
}

func (d *Driver) updateApi(def *apidef.APIDefinition) error {
	mm, err := d.store.GetReference(def.APIID)
	if err != nil {
		return err
	}

	ids, ok := mm.DriverData[d.Name()]
	if !ok {
		return errors.New("no driver-specific data for this API ID")
	}

	depSet := &DeploymentSet{}
	err = mapstructure.Decode(ids, depSet)
	if err != nil {
		return err
	}

	if err != nil {
		return fmt.Errorf("deployment set of unexpected type: %v", reflect.TypeOf(ids))
	}

	cv := converter.Converter{Revision: depSet.ServiceMap}
	newRevision := cv.CreationOpSetFromTykDef(d.client, def)

	// Remove old routes, services and plugins
	deletions := converter.Diff(newRevision, depSet.ServiceMap)
	err = deletions.DeleteAll(d.client)
	if err != nil {
		return err
	}

	// A create will update automatically if existing IDs are present
	newRevision, err = d.doCreate(newRevision)

	depSet.ServiceMap = newRevision
	mm.DriverData[d.Name()] = depSet

	err = d.store.UpdateReference(def.APIID, mm)
	if err != nil {
		return err
	}

	return nil
}

func (d *Driver) CreateOrUpdate(def *apidef.APIDefinition) error {
	mm, err := d.store.GetReference(def.APIID)
	if err != nil {
		// Create
		return d.createAPI(def, nil)
	}

	// Is there driver data (perhaps this API has more than one driver handling it)?
	_, ok := mm.DriverData[d.Name()]
	if !ok {
		return d.createAPI(def, mm)
	}

	return d.updateApi(def)
}

func (d *Driver) Delete(apiID string) error {
	mm, err := d.store.GetReference(apiID)
	if err != nil {
		return err
	}

	ids, ok := mm.DriverData[d.Name()]
	if !ok {
		return errors.New("no driver-specific data for this API ID")
	}

	depSet := &DeploymentSet{}
	err = mapstructure.Decode(ids, depSet)
	if err != nil {
		return err
	}

	if err != nil {
		return fmt.Errorf("deployment set of unexpected type: %v", reflect.TypeOf(ids))
	}

	for _, svc := range depSet.ServiceMap {
		cv := converter.Converter{Revision: depSet.ServiceMap}
		newRevision := cv.CreationOpSetFromTykDef(d.client, &apidef.APIDefinition{})

		// Remove old routes, services and plugins
		deletions := converter.Diff(newRevision, depSet.ServiceMap)
		err = deletions.DeleteAll(d.client)
		if err != nil {
			return err
		}

		err = d.client.Services().DeleteServiceByName(svc.ID)
		if err != nil {
			log.Error(err)
			return err
		}
		log.Info("[DELETED] ", svc.GetID)
	}

	delete(mm.DriverData, d.Name())

	err = d.store.UpdateReference(apiID, mm)
	if err != nil {
		return err
	}

	return nil
}

func (d *Driver) createRateLimitPluginRequest(pr *gokong.PluginRequest, consumerID string, rate, per float64) *gokong.PluginRequest {
	if pr == nil {
		pr = &gokong.PluginRequest{
			ConsumerId: consumerID,
			Name:       "rate-limiting",
			Config:     map[string]interface{}{},
		}
	}

	set := false
	if per == 1 {
		pr.Config["second"] = rate
		set = true
	}

	if per == 60 {
		pr.Config["minute"] = rate
		set = true
	}

	if per == (60 * 60) {
		pr.Config["hour"] = rate
		set = true
	}

	if per == (60*60)*24 {
		pr.Config["day"] = rate
		set = true
	}

	if !set {
		ps := rate / per
		pr.Config["second"] = ps
	}

	return pr
}

func (d *Driver) CreateAPIKey(id string, state *user.SessionState) (string, error) {
	hsh := util.GetMD5Hash(id)
	consumer, err := d.client.Consumers().Create(&gokong.ConsumerRequest{
		Username: state.Alias,
		CustomId: hsh,
	})
	if err != nil {
		return "", err
	}

	keyCfg := map[string]interface{}{
		"consumer_id": consumer.Id,
		"key":         id,
	}

	cfg, err := json.Marshal(keyCfg)
	if err != nil {
		return "", err
	}

	cpCfg, err := d.client.Consumers().CreatePluginConfig(consumer.Id, "key-auth", string(cfg))
	if err != nil {
		return "", err
	}

	// Rate limits and quotas
	rlReq := d.createRateLimitPluginRequest(nil, consumer.Id, state.Rate, state.Per)

	if state.QuotaMax > -1 {
		rlReq = d.createRateLimitPluginRequest(rlReq, consumer.Id, float64(state.QuotaMax), float64(state.QuotaRenewalRate))
	}

	_, err = d.client.Plugins().Create(rlReq)
	if err != nil {
		log.Error(err)
		return "", err
	}

	// We need both to delete
	extID := fmt.Sprintf("%s:%s", consumer.Id, cpCfg.Id)

	if len(state.ApplyPolicies) > 0 {
		aclCfg, err := d.client.Consumers().CreatePluginConfig(consumer.Id, "acls", fmt.Sprintf(`{"group": "%s"}`, state.ApplyPolicies[0]))
		if err != nil {
			return "", err
		}

		extID += ":" + aclCfg.Id
	}

	return extID, nil
}

func (d *Driver) DeleteAPIKey(extID string) error {
	parts := strings.Split(extID, ":")
	if len(parts) > 3 {
		return errors.New("external ID must be at most three parts separated by a colon")
	}

	err := d.client.Consumers().DeletePluginConfig(parts[0], "key-auth", parts[1])
	if err != nil {
		return err
	}

	if len(parts) == 3 {
		err = d.client.Consumers().DeletePluginConfig(parts[0], "acls", parts[2])
		if err != nil {
			log.Error(err)
		}
	}

	err = d.client.Consumers().DeleteById(parts[0])
	if err != nil {
		return err
	}
	return nil
}

func (d *Driver) fetchDeploymentSet(id string) (*DeploymentSet, error) {
	mm, err := d.store.GetReference(id)
	if err != nil {
		return nil, err
	}

	ids, ok := mm.DriverData[d.Name()]
	if !ok {
		return nil, errors.New("no driver-specific data for this API ID")
	}

	depSet := &DeploymentSet{}
	err = mapstructure.Decode(ids, depSet)
	if err != nil {
		return nil, err
	}

	if err != nil {
		return nil, fmt.Errorf("deployment set of unexpected type: %v", reflect.TypeOf(ids))
	}

	return depSet, nil
}

func (d *Driver) AddPolicy(p models.Policy) (*models.DriverExtension, error) {
	dex := &models.DriverExtension{}
	ids := make([]string, 0)

	for _, entry := range p.AccessRights {
		ds, err := d.fetchDeploymentSet(entry.APIID)
		if err != nil {
			log.Error(err)
			continue
		}

		for i := range entry.Versions {
			apiName := converter.CleanName(entry.APIName + "-" + entry.Versions[i])
			svc, ok := ds.ServiceMap[apiName]
			if !ok {
				log.Error("could not find ", apiName, " in deployed service map")
				continue
			}

			// Update the ACL config with the new groups
			var acl *converter.Plugin
			for _, pl := range svc.Plugins {
				if pl.ID == "acl" {
					acl = pl
					break
				}
			}

			wlI, ok := acl.PluginRequest.Config["whitelist"]
			if !ok {
				log.Error("no whitelist present in ", acl.ID)
				continue
			}

			wl, ok := wlI.(string)
			if !ok {
				log.Error("white list is not a string, is ", reflect.TypeOf(wlI))
				continue
			}

			groups := strings.Split(wl, ",")

			// is it already there?
			skip := false
			for _, g := range groups {
				if g == p.ID {
					skip = true
					break
				}
			}

			if skip {
				continue
			}

			groups = append(groups, p.ID)
			acl.PluginRequest.Config["whitelist"] = strings.Join(groups, ",")

			_, err := d.client.Plugins().UpdateById(acl.GetID, &acl.PluginRequest)
			if err != nil {
				log.Error("acl plugin update failed: ", err)
				continue
			}

			ids = append(ids, acl.GetID)
		}

	}

	dex.ExternalID = strings.Join(ids, ":")
	dex.Meta = p.ID

	return dex, nil
}

func (d *Driver) DeletePolicy(dex models.DriverExtension) error {
	acls := strings.Split(dex.ExternalID, ":")
	pol, ok := dex.Meta.(string)
	if !ok {
		log.Error("meta data is not string, is ", reflect.TypeOf(dex.Meta))
	}

	for _, aclID := range acls {
		aclObj, err := d.client.Plugins().GetById(aclID)
		if err != nil || aclObj == nil {
			log.Error("acl not found, skipping ", aclID)
			continue
		}

		wlI, ok := aclObj.Config["whitelist"]
		if !ok {
			log.Error("no whitelist present in ", aclObj.Id)
			continue
		}

		wl, ok := wlI.(string)
		if !ok {
			log.Error("white list is not a string, is ", reflect.TypeOf(wlI))
			continue
		}

		groups := strings.Split(wl, ",")

		// is it already there?
		newWl := []string{}
		for i, g := range groups {
			if g != pol {
				newWl = append(newWl, groups[i])
			}
		}

		aclObj.Config["whitelist"] = strings.Join(newWl, ",")

		req := &gokong.PluginRequest{
			Name:      aclObj.Name,
			ServiceId: aclObj.ServiceId,
			Config:    aclObj.Config,
		}

		_, err = d.client.Plugins().UpdateById(aclObj.Id, req)
		if err != nil {
			log.Error("failed acl plugin update: ", err)
			continue
		}
	}

	return nil
}

func (d *Driver) UpdatePolicy(p models.PolicyMap) (models.DriverExtension, error) {
	meta, ok := p.Drivers[d.Name()]
	if !ok {
		log.Error("no metadata for this policy for this driver")
		return models.DriverExtension{}, nil
	}

	err := d.DeletePolicy(meta)
	if err != nil {
		return meta, err
	}

	// re-add groups
	dex, err := d.AddPolicy(p.Policy)
	if err != nil {
		return meta, err
	}

	return *dex, nil
}
