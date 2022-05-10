package aws

import "github.com/TykTechnologies/momo/core/drivers"

func init() {
	drivers.RegisterDriver(driverName, NewAWSDriver)
}
