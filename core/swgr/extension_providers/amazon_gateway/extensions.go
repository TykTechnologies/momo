package amazon_gateway

const (
	AWSAPIGatewayIntegrationKey       = "x-amazon-apigateway-integration"
	AWSAPIGatewayRequestValidatorKey  = "x-amazon-apigateway-request-validator"
	AWSAPIGatewayRequestValidatorsKey = "x-amazon-apigateway-request-validators"
)

type Response struct {
	StatusCode         string            `json:"statusCode,omitempty"`
	ResponseTemplates  map[string]string `json:"responseTemplates,omitempty"`
	ResponseParameters map[string]string `json:"responseParameters,omitempty"`
}

const (
	PassThroughWhenNoTemplates = "when_no_templates"
	PassThroughWhenNoMatch     = "when_no_match"
	PassThroughNever           = "never"
	TypeHTTP                   = "http"
	TypeHTTPPRoxy              = "http_proxy"
	TypeAWSProxy               = "aws_proxy"
	TypeAWS                    = "aws"
	TypeMock                   = "mock"
	ContentConvertToText       = "CONVERT_TO_TEXT"
	ContentConvertToBinary     = "CONVERT_TO_BINARY"
	ConnectionTypeInternet     = "INTERNET"
	ConnectionTypeVPC          = "VPC_LINK"
)

type AWSAPIGatewayIntegration struct {
	Responses            map[string]Response `json:"responses,omitempty"`
	URI                  string              `json:"uri,omitempty"`
	PassThroughBehaviour string              `json:"passthroughBehavior,omitempty"`
	HttpMethod           string              `json:"httpMethod,omitempty"`
	Type                 string              `json:"type,omitempty"`
	CacheKeyParameters   string              `json:"cacheKeyParameters,omitempty"`
	CacheNamespace       string              `json:"cacheNamespace,omitempty"`
	ConnectionId         string              `json:"connectionId,omitempty"`
	ConnectionType       string              `json:"connectionType,omitempty"`
	Credentials          string              `json:"credentials,omitempty"`
	ContentHandling      string              `json:"contentHandling,omitempty"`
	RequestParameters    map[string]string   `json:"requestParameters,omitempty"`
	RequestTemplates     map[string]string   `json:"requestTemplates,omitempty"`
	TimeoutInMillis      int                 `json:"timeoutInMillis,omitempty"`
}

type AWSAPIGatewayRequestValidatorsItem struct {
	ValidateRequestBody       bool `json:"validateRequestBody,omitempty"`
	ValidateRequestParameters bool `json:"validateRequestParameters,omitempty"`
}
