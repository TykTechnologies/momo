package swgr

import (
	"github.com/go-openapi/spec"

	"github.com/TykTechnologies/tyk/apidef"

	"github.com/TykTechnologies/momo/core/swgr/converter"
	"github.com/TykTechnologies/momo/core/swgr/extensions"
)

func TykToSwagger(def *apidef.APIDefinition, withExtensions extensions.ExtensionProcessor) ([]*spec.Swagger, error) {
	return converter.TykToSwagger(def, withExtensions)
}
