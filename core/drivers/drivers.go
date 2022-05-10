package drivers

import (
	"errors"

	"github.com/TykTechnologies/momo/pkg/logger"

	"github.com/TykTechnologies/momo/core/types"
)

var (
	moduleName = "momo.drivers"
	log        = logger.GetAndExcludeLoggerFromTrace(moduleName)
)

type NewFunc func() (types.GatewayDriver, error)

var Registry = map[string]NewFunc{}

func RegisterDriver(name string, newFunc NewFunc) {
	log.Info("registering driver: ", name)
	Registry[name] = newFunc
}

func GetDriver(name string) (types.GatewayDriver, error) {
	nFunc, ok := Registry[name]
	if !ok {
		return nil, errors.New("gateway driver not found")
	}

	return nFunc()
}
