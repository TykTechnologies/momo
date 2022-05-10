package kong

import "github.com/TykTechnologies/momo/core/drivers"

const (
	driverName = "kong"
)

func init() {
	drivers.RegisterDriver(driverName, NewKongDriver)
}
