package kong

import (
	"github.com/kevholditch/gokong"

	coreTypes "github.com/TykTechnologies/momo/pkg/types"

	"github.com/TykTechnologies/momo/core/drivers/kong/converter"
)

type Conf struct {
	gokong.Config
}

type DeploymentSet struct {
	ServiceMap map[string]*converter.Service
}

type KongConfSection struct {
	Momo struct {
		StoreType  coreTypes.StorageDriver
		StorageTag string
		Drivers    struct {
			Kong struct {
				HostAddress        string
				Username           string
				Password           string
				InsecureSkipVerify bool
				ApiKey             string
			}
		}
	}
}
