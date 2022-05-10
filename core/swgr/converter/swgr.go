package converter

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/go-openapi/spec"
	uuid "github.com/satori/go.uuid"

	"github.com/TykTechnologies/tyk/apidef"

	"github.com/TykTechnologies/momo/pkg/logger"
	"github.com/TykTechnologies/momo/pkg/models"

	"github.com/TykTechnologies/momo/core/swgr/extensions"
)

var (
	moduleName = "momo.swgr"
	log        = logger.GetAndExcludeLoggerFromTrace(moduleName)
)

func EnsureSwaggerPath(in string) string {
	out := in
	if !strings.HasPrefix(in, "/") {
		out = fmt.Sprintf("/%s", in)
	}

	return out
}

func updateOrCreateOperation(op *spec.Operation, swag *spec.Swagger, meta *models.NormalisedPathMeta, pItem *spec.PathItem, withExtensions extensions.ExtensionProcessor, opts map[string]interface{}) *spec.Operation {
	if op == nil {
		log.Info("CREATING NEW OPERATION")
		op = &spec.Operation{}
		op.Responses = getDefaultResponse(true)
	} else {
		log.Info("USING EXISTING OPERATION")
	}

	if withExtensions != nil {
		withExtensions.Insert(swag, meta, op, opts)
	}

	if pItem.Parameters == nil {
		pItem.Parameters = generatePathParams(meta.Path)
	}

	return op
}

func createPathObjectFromTrackEndpointMeta(swag *spec.Swagger, meta *models.NormalisedPathMeta, pItem *spec.PathItem, withExtensions extensions.ExtensionProcessor, opts map[string]interface{}) (string, *spec.PathItem) {
	if pItem == nil {
		pItem = &spec.PathItem{
			PathItemProps: spec.PathItemProps{},
		}
	}

	switch strings.ToUpper(meta.Method) {
	case "GET":
		pItem.Get = updateOrCreateOperation(pItem.Get, swag, meta, pItem, withExtensions, opts)
	case "PUT":
		pItem.Put = updateOrCreateOperation(pItem.Put, swag, meta, pItem, withExtensions, opts)
	case "POST":
		pItem.Post = updateOrCreateOperation(pItem.Post, swag, meta, pItem, withExtensions, opts)
	case "DELETE":
		pItem.Delete = updateOrCreateOperation(pItem.Delete, swag, meta, pItem, withExtensions, opts)
	case "OPTIONS":
		pItem.Options = updateOrCreateOperation(pItem.Options, swag, meta, pItem, withExtensions, opts)
	case "PATCH":
		pItem.Patch = updateOrCreateOperation(pItem.Patch, swag, meta, pItem, withExtensions, opts)
	case "HEAD":
		pItem.Head = updateOrCreateOperation(pItem.Head, swag, meta, pItem, withExtensions, opts)
	}

	return EnsureSwaggerPath(meta.Path), pItem
}

func getDefaultResponse(force200 bool) *spec.Responses {
	if force200 {
		return &spec.Responses{
			ResponsesProps: spec.ResponsesProps{
				StatusCodeResponses: map[int]spec.Response{
					200: {ResponseProps: spec.ResponseProps{
						Description: "Default",
					}},
				},
			},
		}
	}

	return &spec.Responses{
		ResponsesProps: spec.ResponsesProps{
			Default: &spec.Response{ResponseProps: spec.ResponseProps{
				Description: "Default",
			}},
		},
	}
}

func generatePathParams(path string) []spec.Parameter {
	params := make([]spec.Parameter, 0)
	r, _ := regexp.Compile("{[A-Za-z0-9_-]+}")
	items := r.FindAllString(path, -1)

	for _, item := range items {
		noLBrace := strings.TrimLeft(item, "{")
		name := strings.TrimRight(noLBrace, "}")

		newParam := spec.Parameter{
			ParamProps: spec.ParamProps{
				Name:     name,
				Required: true,
				In:       "path",
			},
			SimpleSchema: spec.SimpleSchema{
				Type: "string",
			},
		}

		params = append(params, newParam)
	}

	return params
}

func newSwaggerBase() *spec.Swagger {
	newSwag := &spec.Swagger{
		SwaggerProps: spec.SwaggerProps{
			Swagger: "2.0",
			Info: &spec.Info{
				InfoProps: spec.InfoProps{},
			},
			Paths: &spec.Paths{
				Paths: map[string]spec.PathItem{},
			},
		},
	}

	return newSwag
}

func makeEndpointMeta(method, path string, original interface{}) *models.NormalisedPathMeta {
	return &models.NormalisedPathMeta{
		Method:   method,
		Path:     path,
		Original: original,
	}
}

func normaliseEndpointMeta(in interface{}) []*models.NormalisedPathMeta {
	switch in.(type) {
	case apidef.EndPointMeta:
		x := in.(apidef.EndPointMeta)
		r := make([]*models.NormalisedPathMeta, 0)
		for meth, detail := range x.MethodActions {
			if detail.Action == apidef.NoAction {
				r = append(r, makeEndpointMeta(meth, x.Path, x))
			}
		}
		return r
	case apidef.TrackEndpointMeta:
		x := in.(apidef.TrackEndpointMeta)
		return []*models.NormalisedPathMeta{makeEndpointMeta(x.Method, x.Path, x)}
	case string:
		// Cache
		x := in.(string)
		return []*models.NormalisedPathMeta{
			makeEndpointMeta("GET", x, x),
			makeEndpointMeta("HEAD", x, x),
			makeEndpointMeta("OPTIONS", x, x),
		}
	case apidef.TemplateMeta:
		x := in.(apidef.TemplateMeta)
		return []*models.NormalisedPathMeta{makeEndpointMeta(x.Method, x.Path, x)}
	case apidef.TransformJQMeta:
		x := in.(apidef.TransformJQMeta)
		return []*models.NormalisedPathMeta{makeEndpointMeta(x.Method, x.Path, x)}
	case apidef.HeaderInjectionMeta:
		x := in.(apidef.HeaderInjectionMeta)
		return []*models.NormalisedPathMeta{makeEndpointMeta(x.Method, x.Path, x)}
	case apidef.HardTimeoutMeta:
		x := in.(apidef.HardTimeoutMeta)
		return []*models.NormalisedPathMeta{makeEndpointMeta(x.Method, x.Path, x)}
	case apidef.CircuitBreakerMeta:
		x := in.(apidef.CircuitBreakerMeta)
		return []*models.NormalisedPathMeta{makeEndpointMeta(x.Method, x.Path, x)}
	case apidef.URLRewriteMeta:
		x := in.(apidef.URLRewriteMeta)
		return []*models.NormalisedPathMeta{makeEndpointMeta(x.Method, x.Path, x)}
	case apidef.RequestSizeMeta:
		x := in.(apidef.RequestSizeMeta)
		return []*models.NormalisedPathMeta{makeEndpointMeta(x.Method, x.Path, x)}
	case apidef.MethodTransformMeta:
		x := in.(apidef.MethodTransformMeta)
		return []*models.NormalisedPathMeta{makeEndpointMeta(x.Method, x.Path, x)}
	case apidef.ValidatePathMeta:
		x := in.(apidef.ValidatePathMeta)
		return []*models.NormalisedPathMeta{makeEndpointMeta(x.Method, x.Path, x)}
	default:
		log.Error("type not supported")
		return []*models.NormalisedPathMeta{}
	}
}

func processNormalisedPaths(swag *spec.Swagger, swagMap map[string]*spec.PathItem, ems []*models.NormalisedPathMeta, withExtensions extensions.ExtensionProcessor, opts map[string]interface{}) []string {
	affectedPaths := make([]string, 0)
	for _, em := range ems {
		pItem, _ := swagMap[EnsureSwaggerPath(em.Path)]
		var path string

		path, pItem = createPathObjectFromTrackEndpointMeta(swag, em, pItem, withExtensions, opts)
		swagMap[path] = pItem
		affectedPaths = append(affectedPaths, path)
	}

	return affectedPaths
}

func TykToSwagger(def *apidef.APIDefinition, withExtensions extensions.ExtensionProcessor) ([]*spec.Swagger, error) {
	swags := make([]*spec.Swagger, len(def.VersionData.Versions))

	if withExtensions != nil {
		withExtensions.Init(def)
	}

	i := 0
	for vName, version := range def.VersionData.Versions {
		swag := newSwaggerBase()
		swag.Info.Title = def.Name
		swag.Info.Version = vName

		swagMap := make(map[string]*spec.PathItem)

		for _, pth := range version.ExtendedPaths.TrackEndpoints {
			processNormalisedPaths(swag, swagMap, normaliseEndpointMeta(pth), withExtensions, nil)
		}

		// Follow up path scans should pass in found pItems
		for _, pth := range version.ExtendedPaths.WhiteList {
			processNormalisedPaths(swag, swagMap, normaliseEndpointMeta(pth), withExtensions, nil)
		}

		for _, pth := range version.ExtendedPaths.Ignored {
			processNormalisedPaths(swag, swagMap, normaliseEndpointMeta(pth), withExtensions, nil)
		}

		for _, pth := range version.ExtendedPaths.Cached {
			processNormalisedPaths(swag, swagMap, normaliseEndpointMeta(pth), withExtensions, nil)
		}

		for _, pth := range version.ExtendedPaths.Transform {
			processNormalisedPaths(swag, swagMap, normaliseEndpointMeta(pth), withExtensions, nil)
		}

		for _, pth := range version.ExtendedPaths.TransformResponse {
			err := processNormalisedPaths(swag, swagMap, normaliseEndpointMeta(pth), withExtensions, map[string]interface{}{"response": true})
			if err != nil {
				log.Error(err)
			}
		}

		for _, pth := range version.ExtendedPaths.TransformJQ {
			processNormalisedPaths(swag, swagMap, normaliseEndpointMeta(pth), withExtensions, nil)
		}

		for _, pth := range version.ExtendedPaths.TransformHeader {
			processNormalisedPaths(swag, swagMap, normaliseEndpointMeta(pth), withExtensions, nil)
		}

		for _, pth := range version.ExtendedPaths.TransformResponseHeader {
			affected := processNormalisedPaths(swag, swagMap, normaliseEndpointMeta(pth), withExtensions, map[string]interface{}{"response": true})
			for _, ap := range affected {
				swagPath := swagMap[ap]
				switch strings.ToUpper(pth.Method) {
				case "POST":
					for code, resp := range swagPath.Post.Responses.ResponsesProps.StatusCodeResponses {
						if resp.Headers == nil {
							resp.Headers = map[string]spec.Header{}
							swagPath.Post.Responses.ResponsesProps.StatusCodeResponses[code] = resp
						}
						for h := range pth.AddHeaders {
							swagPath.Post.Responses.ResponsesProps.StatusCodeResponses[code].Headers[h] = spec.Header{
								SimpleSchema: spec.SimpleSchema{
									Type: "string",
								},
							}
						}
					}
				case "PUT":
					for code, resp := range swagPath.Post.Responses.ResponsesProps.StatusCodeResponses {
						if resp.Headers == nil {
							resp.Headers = map[string]spec.Header{}
							swagPath.Post.Responses.ResponsesProps.StatusCodeResponses[code] = resp
						}
						for h := range pth.AddHeaders {
							swagPath.Post.Responses.ResponsesProps.StatusCodeResponses[code].Headers[h] = spec.Header{
								SimpleSchema: spec.SimpleSchema{
									Type: "string",
								},
							}
						}
					}
				case "PATCH":
					for code, resp := range swagPath.Post.Responses.ResponsesProps.StatusCodeResponses {
						if resp.Headers == nil {
							resp.Headers = map[string]spec.Header{}
							swagPath.Post.Responses.ResponsesProps.StatusCodeResponses[code] = resp
						}
						for h := range pth.AddHeaders {
							swagPath.Post.Responses.ResponsesProps.StatusCodeResponses[code].Headers[h] = spec.Header{
								SimpleSchema: spec.SimpleSchema{
									Type: "string",
								},
							}
						}
					}
				case "DELETE":
					for code, resp := range swagPath.Post.Responses.ResponsesProps.StatusCodeResponses {
						if resp.Headers == nil {
							resp.Headers = map[string]spec.Header{}
							swagPath.Post.Responses.ResponsesProps.StatusCodeResponses[code] = resp
						}
						for h := range pth.AddHeaders {
							swagPath.Post.Responses.ResponsesProps.StatusCodeResponses[code].Headers[h] = spec.Header{
								SimpleSchema: spec.SimpleSchema{
									Type: "string",
								},
							}
						}
					}
				}
			}
		}

		for _, pth := range version.ExtendedPaths.HardTimeouts {
			processNormalisedPaths(swag, swagMap, normaliseEndpointMeta(pth), withExtensions, nil)
		}

		for _, pth := range version.ExtendedPaths.CircuitBreaker {
			processNormalisedPaths(swag, swagMap, normaliseEndpointMeta(pth), withExtensions, nil)
		}

		for _, pth := range version.ExtendedPaths.URLRewrite {
			processNormalisedPaths(swag, swagMap, normaliseEndpointMeta(pth), withExtensions, nil)
		}

		for _, pth := range version.ExtendedPaths.Virtual {
			processNormalisedPaths(swag, swagMap, normaliseEndpointMeta(pth), withExtensions, nil)
		}

		for _, pth := range version.ExtendedPaths.SizeLimit {
			processNormalisedPaths(swag, swagMap, normaliseEndpointMeta(pth), withExtensions, nil)
		}

		for _, pth := range version.ExtendedPaths.MethodTransforms {
			processNormalisedPaths(swag, swagMap, normaliseEndpointMeta(pth), withExtensions, nil)
		}

		for _, pth := range version.ExtendedPaths.ValidateJSON {
			affected := processNormalisedPaths(swag, swagMap, normaliseEndpointMeta(pth), withExtensions, nil)
			for _, affectedPath := range affected {
				asStr, err := json.Marshal(pth.Schema)
				if err != nil {
					log.Error(err)
					continue
				}

				asSwaggerSchema := &spec.Schema{}
				err = json.Unmarshal(asStr, asSwaggerSchema)
				if err != nil {
					log.Error(err)
					continue
				}

				nVal, ok := pth.Schema["title"]
				name := strings.Replace(uuid.NewV4().String(), "-", "", -1)
				if ok {
					name = nVal.(string)
				}
				param := spec.Parameter{ParamProps: spec.ParamProps{
					Name:   name,
					In:     "body",
					Schema: asSwaggerSchema,
				}}

				switch strings.ToUpper(pth.Method) {
				case "POST":
					if len(swagMap[affectedPath].Post.Parameters) == 0 {
						swagMap[affectedPath].Post.Parameters = []spec.Parameter{param}
					} else {
						swagMap[affectedPath].Post.Parameters = append(swagMap[affectedPath].Post.Parameters, param)
					}
				case "PUT":
					if len(swagMap[affectedPath].Put.Parameters) == 0 {
						swagMap[affectedPath].Put.Parameters = []spec.Parameter{param}
					} else {
						swagMap[affectedPath].Put.Parameters = append(swagMap[affectedPath].Put.Parameters, param)
					}
				case "PATCH":
					if len(swagMap[affectedPath].Patch.Parameters) == 0 {
						swagMap[affectedPath].Patch.Parameters = []spec.Parameter{param}
					} else {
						swagMap[affectedPath].Patch.Parameters = append(swagMap[affectedPath].Patch.Parameters, param)
					}
				case "DELETE":
					if len(swagMap[affectedPath].Delete.Parameters) == 0 {
						swagMap[affectedPath].Delete.Parameters = []spec.Parameter{param}
					} else {
						swagMap[affectedPath].Delete.Parameters = append(swagMap[affectedPath].Delete.Parameters, param)
					}
				}
			}

		}

		// Flatten the map
		for pathStr, specPath := range swagMap {
			swag.Paths.Paths[pathStr] = *specPath
		}

		asURl, err := url.Parse(def.Proxy.TargetURL)
		if err != nil {
			log.Error("cannot parse host: ", err)
		} else {
			swag.Host = asURl.Host
			swag.Schemes = []string{asURl.Scheme}
			swag.BasePath = EnsureSwaggerPath(asURl.Path)
		}

		swag.SecurityDefinitions = spec.SecurityDefinitions{}
		swag.Security = []map[string][]string{}

		if def.UseStandardAuth {
			if def.Auth.AuthHeaderName != "" {
				swag.SecurityDefinitions["ApiKeyHeader"] = &spec.SecurityScheme{
					SecuritySchemeProps: spec.SecuritySchemeProps{
						Type: "apiKey",
						In:   "header",
						Name: def.Auth.AuthHeaderName,
					},
				}

				swag.Security = append(swag.Security, map[string][]string{"ApiKeyHeader": {}})
			}

			if def.Auth.UseParam {
				name := def.Auth.AuthHeaderName
				if def.Auth.ParamName != "" {
					name = def.Auth.ParamName
				}

				swag.SecurityDefinitions["ApiKeyParam"] = &spec.SecurityScheme{
					SecuritySchemeProps: spec.SecuritySchemeProps{
						Type: "apiKey",
						In:   "query",
						Name: name,
					},
				}

				swag.Security = append(swag.Security, map[string][]string{"ApiKeyParam": {}})
			}

			if def.Auth.UseCookie {
				name := def.Auth.AuthHeaderName
				if def.Auth.CookieName != "" {
					name = def.Auth.CookieName
				}

				swag.SecurityDefinitions["ApiKeyCookie"] = &spec.SecurityScheme{
					SecuritySchemeProps: spec.SecuritySchemeProps{
						Type: "apiKey",
						In:   "cookie",
						Name: name,
					},
				}

				swag.Security = append(swag.Security, map[string][]string{"ApiKeyCookie": {}})
			}

		}

		if def.UseBasicAuth {
			swag.SecurityDefinitions["basicAuth"] = &spec.SecurityScheme{
				SecuritySchemeProps: spec.SecuritySchemeProps{
					Type: "basic",
				},
			}

			swag.Security = append(swag.Security, map[string][]string{"basicAuth": {}})
		}

		swags[i] = swag
		i++
	}

	return swags, nil
}
