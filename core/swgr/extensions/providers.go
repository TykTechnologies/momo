package extensions

import (
	"errors"

	"github.com/go-openapi/spec"

	"github.com/TykTechnologies/tyk/apidef"

	"github.com/TykTechnologies/momo/pkg/models"
)

var extensionProviders = map[string]func(interface{}) ExtensionProcessor{}

func RegisterExtensionProvider(name string, initFunc func(interface{}) ExtensionProcessor) {
	extensionProviders[name] = initFunc
}

type ExtensionReader interface {
	GetSwaggerExtensionProvider() string
}

type ExtensionProcessor interface {
	Init(def *apidef.APIDefinition)
	Insert(swag *spec.Swagger, normalisedPath *models.NormalisedPathMeta, op *spec.Operation, opts map[string]interface{}) error
}

func GetExtensionProcessor(proc ExtensionReader, withConf interface{}) (ExtensionProcessor, error) {
	newFunc, ok := extensionProviders[proc.GetSwaggerExtensionProvider()]
	if !ok {
		return nil, errors.New("processor not found")
	}

	return newFunc(withConf), nil
}
