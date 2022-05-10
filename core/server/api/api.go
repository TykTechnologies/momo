package api

import (
	"errors"
	"fmt"
	"strings"

	"github.com/TykTechnologies/tyk/apidef"

	"github.com/TykTechnologies/momo/pkg/logger"
	"github.com/TykTechnologies/momo/pkg/models"
	coreStorage "github.com/TykTechnologies/momo/pkg/storage"
	tyk_api "github.com/TykTechnologies/momo/pkg/tyk-api"

	"github.com/TykTechnologies/momo/core/config"
	"github.com/TykTechnologies/momo/core/drivers"
	_ "github.com/TykTechnologies/momo/core/drivers/aws"
	"github.com/TykTechnologies/momo/core/util"
)

var (
	moduleName = "momo.server.api"
	log        = logger.GetAndExcludeLoggerFromTrace(moduleName)
)

func ProcessAPIEvent(event string, def *apidef.APIDefinition) error {
	switch event {
	case TYK_API_EVENT_ADD:
		return HandleAddOrUpdateAPI(def)
	case TYK_API_EVENT_UPDATE:
		return HandleAddOrUpdateAPI(def)
	case TYK_API_EVENT_DELETE:
		return HandleDeleteAPI(def)

	}

	if event == "" {
		event = "<no event>"
	}
	return fmt.Errorf("event not recognised: %s", event)
}

func getStore() (coreStorage.MomoStore, error) {
	conf := config.GetConf()

	st, err := coreStorage.GetSpecificStoreType(conf.Momo.StoreType, conf.Momo.StorageTag)
	if err != nil {
		return nil, err
	}

	momoStore, ok := st.(coreStorage.MomoStore)
	if !ok {
		return nil, errors.New("store driver does not support MomoStore interface")
	}

	momoStore.InitMomoStore(conf.Momo.StorageTag)
	return momoStore, nil
}

func HandleAddOrUpdateAPI(def *apidef.APIDefinition) error {
	errs := make([]string, 0)
	log.Info("tags in definition: ", def.Tags)
	for _, t := range def.Tags {
		log.Debug("checking: ", strings.ToLower(t))
		d, err := drivers.GetDriver(strings.ToLower(t))
		if err != nil {
			log.Error(err)
		}

		if err == nil {
			log.Info("detected add-or-update api event for driver: ", strings.ToLower(t))
			err = d.CreateOrUpdate(def)
			if err != nil {
				errs = append(errs, err.Error())
			}
		}

	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}

	return nil
}

func HandleDeleteAPI(def *apidef.APIDefinition) error {
	errs := make([]string, 0)
	for _, t := range def.Tags {
		d, err := drivers.GetDriver(strings.ToLower(t))
		if err == nil {
			log.Info("detected delete api event for driver: ", strings.ToLower(t))
			d.Init()
			err := d.Delete(def.APIID)
			if err != nil {
				errs = append(errs, err.Error())
			}
		}
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}

	return nil
}

func HandleAddKey(data *models.KeyData) error {
	apiCfg := tyk_api.GetConf()
	momoConf := config.GetConf()
	taggedConf, ok := apiCfg.TykAPI[momoConf.Momo.TykAPITag]
	if !ok {
		return fmt.Errorf("tag not found: %s", momoConf.Momo.TykAPITag)
	}

	tyk, err := tyk_api.NewHandler(taggedConf)
	if err != nil {
		return err
	}

	ses, err := tyk.GetKeyDetail(data.Key)
	if err != nil {
		return err
	}

	gwDrivers := make([]models.DriverMeta, 0)
	errs := make([]string, 0)
	var kid string
	for _, t := range ses.Tags {
		dName := strings.ToLower(t)
		d, err := drivers.GetDriver(dName)
		if err == nil {
			log.Info("detected add key event for driver: ", dName)
			d.Init()
			kid, err = d.CreateAPIKey(data.Key, ses)
			if err != nil {
				errs = append(errs, err.Error())
			}

			log.Info("External ID Created: ", kid)
			gwDrivers = append(gwDrivers, models.DriverMeta{Name: dName, ExternalID: kid})
		}
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}

	st, err := getStore()
	if err != nil {
		return err
	}

	hashKey := util.GetMD5Hash(data.Key)
	err = st.CreateKeyMap(hashKey, kid, gwDrivers)
	if err != nil {
		return err
	}

	return nil
}

func HandleDeleteKey(data *models.KeyData) error {
	log.Info("delete key called")
	st, err := getStore()
	if err != nil {
		return err
	}

	km, err := st.GetKeyMap(util.GetMD5Hash(data.Key))
	if err != nil {
		return err
	}

	errs := make([]string, 0)
	for _, t := range km.Drivers {
		d, err := drivers.GetDriver(strings.ToLower(t.Name))

		if err == nil {
			log.Info("detected delete key event for driver: ", strings.ToLower(t.Name))
			d.Init()

			log.Info("External ID Deleting: ", t.ExternalID)
			err := d.DeleteAPIKey(t.ExternalID)
			if err != nil {
				errs = append(errs, err.Error())
			}
		}
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}

	err = st.DeleteKeyMap(util.GetMD5Hash(data.Key))
	if err != nil {
		return err
	}

	return nil
}

func ProcessKeyEvent(event string, data *models.KeyData) error {
	switch event {
	case TYK_KEY_EVENT_ADD:
		return HandleAddKey(data)
	case TYK_KEY_EVENT_DELETE:
		return HandleDeleteKey(data)
	case TYK_KEY_EVENT_UPDATE:
		err := HandleDeleteKey(data)
		if err != nil {
			return err
		}
		err = HandleAddKey(data)
		if err != nil {
			return err
		}

	}

	if event == "" {
		event = "<no event>"
	}
	return fmt.Errorf("event not recognised: %s", event)
}
