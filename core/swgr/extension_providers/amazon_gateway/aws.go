package amazon_gateway

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/go-openapi/spec"

	"github.com/TykTechnologies/tyk/apidef"

	"github.com/TykTechnologies/momo/pkg/logger"
	"github.com/TykTechnologies/momo/pkg/models"

	"github.com/TykTechnologies/momo/core/swgr/extensions"
)

var (
	moduleName = "momo.swgr.ext_provider.agw"
	log        = logger.GetAndExcludeLoggerFromTrace(moduleName)
)

const (
	awsOpentag  = "<x-aws>"
	awsCloseTag = "</x-aws>"
)

type AWSExtensions struct {
	def *apidef.APIDefinition
}

func NewAWSExt(conf interface{}) extensions.ExtensionProcessor {
	return &AWSExtensions{}
}

func (a *AWSExtensions) Init(def *apidef.APIDefinition) {
	a.def = def
}

func (a *AWSExtensions) Insert(swag *spec.Swagger, normalisedPath *models.NormalisedPathMeta, op *spec.Operation, opts map[string]interface{}) error {
	elem := AWSAPIGatewayIntegration{
		Responses: map[string]Response{
			"default": {StatusCode: "200"},
		},
		URI:                  a.def.Proxy.TargetURL,
		PassThroughBehaviour: "when_no_match",
		HttpMethod:           normalisedPath.Method,
		Type:                 "http",
	}

	if op != nil {
		if op.VendorExtensible.Extensions != nil {
			existingObj, exists := op.VendorExtensible.Extensions[AWSAPIGatewayIntegrationKey]
			if exists {
				elem = existingObj.(AWSAPIGatewayIntegration)
			}
		}
	}

	validatorElem := AWSAPIGatewayRequestValidatorsItem{
		ValidateRequestBody:       true,
		ValidateRequestParameters: false, // not directly supported
	}

	switch normalisedPath.Original.(type) {
	case apidef.HardTimeoutMeta:
		m := normalisedPath.Original.(apidef.HardTimeoutMeta)
		elem.TimeoutInMillis = m.TimeOut * 1000
	case apidef.ValidatePathMeta:
		swag.VendorExtensible.AddExtension(AWSAPIGatewayRequestValidatorsKey, map[string]AWSAPIGatewayRequestValidatorsItem{
			"basic": validatorElem,
		})

		// Only validate specific methods
		op.VendorExtensible.AddExtension(AWSAPIGatewayRequestValidatorKey, "basic")
	case apidef.TemplateMeta:
		// body transform
		m := normalisedPath.Original.(apidef.TemplateMeta)
		rawTpl, err := base64.StdEncoding.DecodeString(m.TemplateData.TemplateSource)
		if err != nil {
			return err
		}

		tpl := string(rawTpl)
		awsTpl := strings.Replace(tpl, "\n", "", -1)
		if strings.Contains(awsTpl, awsOpentag) {
			var err error
			awsTpl, err = a.extractAWSRequestTemplateMapFromTag(awsTpl)
			if err != nil {
				return err
			}
		}

		resp := Response{StatusCode: "200"}
		templateMap := map[string]string{}
		switch m.TemplateData.Input {
		case apidef.RequestXML:
			templateMap["application/xml"] = awsTpl
		case apidef.RequestJSON:
			templateMap["application/json"] = awsTpl
		default:
			return errors.New("unable to determine input mime-type")
		}

		_, ok := opts["response"]
		if ok {
			respObj, ok := elem.Responses["2\\d{2}"]
			if ok {
				// work with existing
				log.Info("Found existing response object (templater)")
				resp = respObj
			}

			resp.ResponseTemplates = templateMap
			elem.Responses["2\\d{2}"] = resp
		} else {
			elem.RequestTemplates = templateMap
		}

	case apidef.URLRewriteMeta:
		m := normalisedPath.Original.(apidef.URLRewriteMeta)
		for _, t := range m.Triggers {
			if t.On == "AWS" {
				elem.URI = t.RewriteTo
				break
			}
		}
	case apidef.HeaderInjectionMeta:
		reqRes := "integration.request.header.%s"
		_, ok := opts["response"]
		if ok {
			reqRes = "method.response.header.%s"
		}
		m := normalisedPath.Original.(apidef.HeaderInjectionMeta)
		tplMap := map[string]string{}

		for hName := range m.AddHeaders {
			n := fmt.Sprintf(reqRes, hName)
			tplMap[n] = m.AddHeaders[hName]
		}

		_, ok = opts["response"]
		if ok {
			// response header injector
			resp := Response{StatusCode: "200"}
			respObj, ok := elem.Responses["2\\d{2}"]
			if ok {
				// work with existing
				log.Info("Found existing response object (headers)")
				resp = respObj
			}
			resp.ResponseParameters = tplMap
			elem.Responses["2\\d{2}"] = resp
		} else {
			// Request param injector
			elem.RequestParameters = tplMap
		}
	}

	op.VendorExtensible.AddExtension(AWSAPIGatewayIntegrationKey, elem)
	return nil
}

func (a *AWSExtensions) extractAWSRequestTemplateMapFromTag(tpl string) (string, error) {
	start := strings.Index(tpl, awsOpentag) + len(awsOpentag)
	end := strings.Index(tpl, awsCloseTag)

	block := tpl[start:end]
	return block, nil
}
