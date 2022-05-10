package aws

import (
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/apigateway"
	"github.com/mitchellh/mapstructure"
	uuid "github.com/satori/go.uuid"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/user"

	"github.com/TykTechnologies/momo/pkg/logger"
	"github.com/TykTechnologies/momo/pkg/models"
	coreStorage "github.com/TykTechnologies/momo/pkg/storage"

	"github.com/TykTechnologies/momo/core/config"
	"github.com/TykTechnologies/momo/core/swgr"
	_ "github.com/TykTechnologies/momo/core/swgr/extension_providers/amazon_gateway"
	"github.com/TykTechnologies/momo/core/swgr/extensions"
	"github.com/TykTechnologies/momo/core/types"
	"github.com/TykTechnologies/momo/core/util"
)

const (
	driverName        = "amazon-api-gateway"
	driverStagePrefix = "amazon-api-gateway-stage."
)

var (
	moduleName = "momo.drivers.aws"
	log        = logger.GetAndExcludeLoggerFromTrace(moduleName)
)

func NewAWSDriver() (types.GatewayDriver, error) {
	drv := &Driver{}
	err := drv.Init()
	if err != nil {
		return nil, err
	}

	return drv, nil
}

func (d *Driver) Init() error {
	d.workingPackage = &DriverPackage{}

	conf := &AConf{}
	err := config.GetSubConf(conf, "MOMOAWS")
	if err != nil {
		return err
	}

	keyID := conf.Momo.Drivers.AWS.KeyID
	secret := conf.Momo.Drivers.AWS.Secret
	region := conf.Momo.Drivers.AWS.Region

	if keyID == "" || secret == "" || region == "" {
		return errors.New("no AWS credentials found")
	}

	d.SetCredentials(keyID, secret, region)

	c, err := d.createAAGClient()
	if err != nil {
		return err
	}

	d.client = c

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

func (d *Driver) GetSwaggerExtensionProvider() string {
	return d.Name()
}

func (d *Driver) SetCredentials(awsKeyID, awsSecret, awsRegion string) {
	d.awsRegion = awsRegion
	d.awsKeyID = awsKeyID
	d.awsSecret = awsSecret
}

func (d *Driver) CreateOrUpdate(def *apidef.APIDefinition) error {
	existingRef, err := d.store.GetReference(def.APIID)
	if err != nil {
		if err.Error() != "not found" {
			return err
		}
	}

	if existingRef != nil {
		asPkg := &DriverPackage{}
		dat, ok := existingRef.DriverData[d.Name()]
		if ok {
			err := mapstructure.Decode(dat, asPkg)
			if err != nil {
				return err
			}

			return d.update(*asPkg.RestAPI.Id, def, existingRef)
		}
	}

	if err := d.create(def, existingRef); err != nil {
		return err
	}

	return nil
}

func (d *Driver) getSwaggerFromDefinition(def *apidef.APIDefinition) ([]byte, error) {
	extensionProc, err := extensions.GetExtensionProcessor(d, nil)
	if err != nil {
		return nil, err
	}

	asSwgr, err := swgr.TykToSwagger(def, extensionProc)
	if err != nil {
		return nil, err
	}

	if len(asSwgr) < 1 {
		return nil, errors.New("no swagger definitions found")
	}

	// TODO: handle more versions
	js, err := asSwgr[0].MarshalJSON()
	if err != nil {
		return nil, err
	}

	return js, nil
}

func (d *Driver) update(id string, def *apidef.APIDefinition, ref *models.MomoMap) error {
	js, err := d.getSwaggerFromDefinition(def)
	if err != nil {
		return err
	}

	updateOp, err := d.client.PutRestApi(&apigateway.PutRestApiInput{
		RestApiId: aws.String(id),
		Mode:      aws.String(apigateway.PutModeOverwrite), // TODO: Potentially merge?
		Body:      js,
	})

	// There are deployment stages specified
	stages := d.extractStagesFromTags(def)
	if len(stages) > 0 {
		err := d.handleStages(stages, updateOp)
		if err != nil {
			return err
		}
	}

	if err != nil {
		return err
	}

	d.workingPackage.RestAPI = updateOp

	d.handleReference(def.APIID, ref, d.workingPackage, "api added to aws")

	return nil
}

func (d *Driver) fetchRestData(id string) (*DriverPackage, error) {
	mm, err := d.store.GetReference(id)
	if err != nil {
		return nil, err
	}

	dPkg, ok := mm.DriverData[d.Name()]
	if !ok {
		return nil, errors.New("no driver package data present in record")
	}

	pkg := &DriverPackage{}
	err = mapstructure.Decode(dPkg, pkg)
	if err != nil {
		return nil, err
	}

	return pkg, nil
}

func (d *Driver) Delete(apiID string) error {
	restData, err := d.fetchRestData(apiID)
	if err != nil {
		return err
	}

	_, err = d.client.DeleteRestApi(&apigateway.DeleteRestApiInput{
		RestApiId: restData.RestAPI.Id,
	})

	if err != nil {
		return err
	}

	err = d.store.DeleteReference(apiID)
	if err != nil {
		return err
	}

	return nil
}

func (d *Driver) handleStages(stages []string, importOp *apigateway.RestApi) error {
	log.Info("deployment stages detected")
	agwStages, err := d.client.GetStages(&apigateway.GetStagesInput{
		RestApiId: importOp.Id,
	})
	if err != nil {
		return err
	}

	existingStages := map[string]*apigateway.Stage{}
	newStages := make([]string, 0)
	for _, stName := range stages {
		foundStage := false
		for _, item := range agwStages.Item {
			if strings.ToLower(*item.StageName) == strings.ToLower(stName) {
				// found, track
				existingStages[strings.ToLower(stName)] = item
				foundStage = true
				break
			}
		}

		if !foundStage {
			newStages = append(newStages, strings.ToLower(stName))
		}
	}

	for _, eStage := range existingStages {
		log.Info("handling existing stage")
		dep, err := d.client.CreateDeployment(&apigateway.CreateDeploymentInput{
			RestApiId: importOp.Id,
			StageName: eStage.StageName,
			Variables: eStage.Variables,
		})
		if err != nil {
			log.Error("existing stage deployment error: ", err)
			return err
		}

		log.Info("deployed to existing stage: ", *eStage.StageName)
		d.workingPackage.Deployments = append(d.workingPackage.Deployments, dep)
	}

	for _, nStageName := range newStages {
		log.Info("handling new stage")
		dep, err := d.client.CreateDeployment(&apigateway.CreateDeploymentInput{
			RestApiId: importOp.Id,
			StageName: aws.String(nStageName),
		})
		if err != nil {
			log.Error("new stage deployment error: ", err)
			return err
		}

		log.Info("deployed to new stage: ", nStageName)
		d.workingPackage.Deployments = append(d.workingPackage.Deployments, dep)
	}

	return nil
}

func (d *Driver) extractStagesFromTags(def *apidef.APIDefinition) []string {
	stages := make([]string, 0)
	for _, t := range def.Tags {
		if strings.Contains(t, driverStagePrefix) {
			stageName := strings.Replace(t, driverStagePrefix, "", -1)
			stages = append(stages, stageName)
		}
	}

	return stages
}

func (d *Driver) create(def *apidef.APIDefinition, ref *models.MomoMap) error {
	js, err := d.getSwaggerFromDefinition(def)
	if err != nil {
		return err
	}

	restAPIInput := &apigateway.ImportRestApiInput{
		Body:           js,
		FailOnWarnings: aws.Bool(true),
	}

	importOp, err := d.client.ImportRestApi(restAPIInput)
	if err != nil {
		return err
	}

	d.workingPackage.RestAPI = importOp

	// There are deployment stages specified
	stages := d.extractStagesFromTags(def)
	if len(stages) > 0 {
		err := d.handleStages(stages, importOp)
		if err != nil {
			return err
		}
	}

	d.handleReference(def.APIID, ref, d.workingPackage, "api added to aws")

	return err
}

func (d *Driver) handleReference(id string, ref *models.MomoMap, pkg *DriverPackage, logMessage string) error {
	momoMap := &models.MomoMap{
		APIID: id,
		DriverData: map[string]interface{}{
			d.Name(): d.workingPackage,
		},
		Log: models.LogMap{},
	}

	updateRef := false
	if ref != nil {
		momoMap = ref
		updateRef = true
	}

	momoMap.DriverData[d.Name()] = pkg
	momoMap.Log.Add(d.Name(), logMessage, pkg)

	if updateRef {
		return d.store.UpdateReference(ref.APIID, momoMap)
	}

	_, err := d.store.CreateReference(momoMap)

	return err
}

func (d *Driver) getAWSCfgAndSession() (*aws.Config, *session.Session, error) {
	creds := credentials.NewStaticCredentials(d.awsKeyID, d.awsSecret, "")
	_, err := creds.Get()
	if err != nil {
		return nil, nil, fmt.Errorf("bad credentials: %s", err)
	}

	awsCfg := aws.NewConfig().WithRegion(d.awsRegion).WithCredentials(creds)
	sess, err := session.NewSession(awsCfg)
	if err != nil {
		return nil, nil, err
	}

	return awsCfg, sess, nil
}

func (d *Driver) createAAGClient() (*apigateway.APIGateway, error) {
	awsCfg, sess, err := d.getAWSCfgAndSession()
	if err != nil {
		return nil, err
	}

	return apigateway.New(sess, awsCfg), nil
}

func (d *Driver) CreateAPIKey(keyID string, sess *user.SessionState) (string, error) {
	n := "tyk." + util.GetMD5Hash(keyID)
	keyDat, err := d.client.CreateApiKey(&apigateway.CreateApiKeyInput{
		Name:        &n,
		Value:       &keyID,
		Description: &sess.Alias,
		Enabled:     aws.Bool(!sess.IsInactive),
	})
	if err != nil {
		return "", err
	}

	// If the API key has a policy ID associated, find the relevant Plan ID and associate
	if len(sess.PolicyIDs()) > 0 {
		for _, policyID := range sess.PolicyIDs() {
			trackedPols, err := d.store.GetSyncedPolicies()
			if err != nil {
				log.Error("couldn't find policies")
				return *keyDat.Id, nil
			}

			for _, tp := range trackedPols {
				if policyID == tp.ID {
					// We have this policy tracked
					awsData, ok := tp.Drivers[driverName]
					if ok {
						_, err := d.client.CreateUsagePlanKey(&apigateway.CreateUsagePlanKeyInput{
							KeyId:       keyDat.Id,
							KeyType:     aws.String("API_KEY"),
							UsagePlanId: aws.String(awsData.ExternalID),
						})
						if err != nil {
							log.Error("association failure: ", err)
						}

					}
				}
			}
		}
	}

	return *keyDat.Id, nil
}

func (d *Driver) DeleteAPIKey(keyID string) error {
	_, err := d.client.DeleteApiKey(&apigateway.DeleteApiKeyInput{
		ApiKey: aws.String(keyID),
	})
	if err != nil {
		return err
	}

	return nil
}

func (d *Driver) DeletePolicy(meta models.DriverExtension) error {
	_, err := d.client.DeleteUsagePlan(&apigateway.DeleteUsagePlanInput{
		UsagePlanId: aws.String(meta.ExternalID),
	})
	if err != nil {
		return err
	}

	return nil
}

func (d *Driver) AddPolicy(p models.Policy) (*models.DriverExtension, error) {
	stages := make([]string, 0)
	for _, t := range p.Tags {
		if strings.Contains(t, driverStagePrefix) {
			stageName := strings.Replace(t, driverStagePrefix, "", -1)
			stages = append(stages, stageName)
		}
	}

	log.Info("Adding policy: ", p)
	relatedAPIs := make([]*apigateway.RestApi, 0)
	for _, accessTo := range p.AccessRights {
		log.Info("Looking up: ", accessTo)

		rel, err := d.store.GetReference(accessTo.APIID)
		if err != nil {
			log.Error(err)
			return nil, err
		}

		dData, ok := rel.DriverData[driverName]
		if !ok {
			return nil, errors.New("API ID not found in driver data, please deploy API first")
		}

		asRestAPI := &DriverPackage{}
		err = mapstructure.Decode(dData, &asRestAPI)
		if err != nil {
			log.Error("mapstructure failure: ", err)
			return nil, err
		}

		relatedAPIs = append(relatedAPIs, asRestAPI.RestAPI)
	}

	apiStages := make([]*apigateway.ApiStage, 0)
	for _, stage := range stages {
		for _, api := range relatedAPIs {
			log.Debug(api)
			apiStage := &apigateway.ApiStage{
				ApiId: api.Id,
				Stage: aws.String(stage),
			}

			log.Warningf("tracking stage: %v:%v", api.Id, stage)
			apiStages = append(apiStages, apiStage)
		}
	}

	OneDay := int64(((60 * 60) * 60) * 24)
	OneWeek := OneDay * 7

	period := "DAY"
	if p.QuotaRenewalRate > OneDay {
		period = "WEEK"
	}

	if p.QuotaRenewalRate > OneWeek {
		period = "MONTH"
	}
	up, err := d.client.CreateUsagePlan(&apigateway.CreateUsagePlanInput{
		ApiStages: apiStages,
		Name:      aws.String(uuid.NewV4().String()),
		Quota: &apigateway.QuotaSettings{
			Limit:  aws.Int64(p.QuotaMax),
			Period: aws.String(period),
		},
		Throttle: &apigateway.ThrottleSettings{
			RateLimit:  aws.Float64(p.Rate),
			BurstLimit: aws.Int64(int64(p.Rate * 1.05)), // 5% burst
		},
	})
	if err != nil {
		return nil, err
	}

	return &models.DriverExtension{ExternalID: *up.Id, Meta: up}, nil
}

func (d *Driver) UpdatePolicy(p models.PolicyMap) (models.DriverExtension, error) {
	return models.DriverExtension{}, errors.New("operation not supoorted")
}
