package aws

import (
	coreStorage "github.com/TykTechnologies/momo/pkg/storage"
	"github.com/aws/aws-sdk-go/service/apigateway"

	coreTypes "github.com/TykTechnologies/momo/pkg/types"
)

type Driver struct {
	awsKeyID       string
	awsSecret      string
	awsRegion      string
	client         *apigateway.APIGateway
	store          coreStorage.MomoStore
	workingPackage *DriverPackage
}

type Conf struct {
	KeyID  string
	Secret string
	Region string
}

type AConf struct {
	Momo struct {
		StoreType  coreTypes.StorageDriver
		StorageTag string
		Drivers    struct {
			AWS struct {
				Conf
			}
		}
	}
}

type DriverPackage struct {
	RestAPI     *apigateway.RestApi
	Deployments []*apigateway.Deployment
}
