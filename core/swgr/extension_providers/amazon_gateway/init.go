package amazon_gateway

import (
	"github.com/TykTechnologies/momo/core/swgr/extensions"
)

func init() {
	extensions.RegisterExtensionProvider("amazon-api-gateway", NewAWSExt)
}
