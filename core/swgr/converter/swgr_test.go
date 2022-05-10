package converter

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/go-openapi/loads"
	"github.com/go-openapi/spec"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/validate"

	"github.com/TykTechnologies/tyk/apidef"

	_ "github.com/TykTechnologies/momo/core/swgr/extension_providers/amazon_gateway"
	"github.com/TykTechnologies/momo/core/swgr/extensions"
)

func TestTykToSwagger(t *testing.T) {
	def := &apidef.APIDefinition{}
	err := json.Unmarshal([]byte(petstoreDefWithValidation), def)
	if err != nil {
		t.Fatal(err)
	}

	s, _ := TykToSwagger(def, nil)
	rawDoc, err := s[0].MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(string(rawDoc))

	specDoc, err := loads.Analyzed(rawDoc, "2.0")
	// Attempts to report about all errors
	validate.SetContinueOnErrors(true)

	v := validate.NewSpecValidator(spec.MustLoadSwagger20Schema(), strfmt.Default)
	result, _ := v.Validate(specDoc) // returns fully detailed result with errors and warnings
	// result := validate.Spec(specDoc, strfmt.Default)		// returns single error

	if result.HasWarnings() {
		for _, desc := range result.Warnings {
			log.Printf("- WARNING: %s\n", desc.Error())
		}
	}
	if result.HasErrors() {
		str := ""
		for _, desc := range result.Errors {
			str += fmt.Sprintf("- %s\n", desc.Error())
		}
		t.Fatal(str)
	}
}

type dummyReader struct{}

func (dr *dummyReader) GetSwaggerExtensionProvider() string {
	return "amazon-api-gateway"
}

func TestTykToSwaggerWithAWSExtensions(t *testing.T) {
	def := &apidef.APIDefinition{}
	err := json.Unmarshal([]byte(petStoreWithValidationAndRequestTransform), def)
	if err != nil {
		t.Fatal(err)
	}

	extProc, err := extensions.GetExtensionProcessor(&dummyReader{}, nil)
	if err != nil {
		t.Fatal(err)
	}

	s, _ := TykToSwagger(def, extProc)
	rawDoc, err := s[0].MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(string(rawDoc))

	specDoc, err := loads.Analyzed(rawDoc, "2.0")
	// Attempts to report about all errors
	validate.SetContinueOnErrors(true)

	v := validate.NewSpecValidator(spec.MustLoadSwagger20Schema(), strfmt.Default)
	result, _ := v.Validate(specDoc) // returns fully detailed result with errors and warnings
	// result := validate.Spec(specDoc, strfmt.Default)		// returns single error

	if result.HasWarnings() {
		for _, desc := range result.Warnings {
			log.Printf("- WARNING: %s\n", desc.Error())
		}
	}
	if result.HasErrors() {
		str := ""
		for _, desc := range result.Errors {
			str += fmt.Sprintf("- %s\n", desc.Error())
		}
		t.Fatal(str)
	}
}

var petStoreWithValidationAndRequestTransform = `
{
    "id": "5b29958c1b52580001082a60",
    "name": "Swagger Petstore",
    "slug": "v1",
    "api_id": "7087d7a11f8a48fc67a22865499314de",
    "org_id": "5b298965040a68000193aed9",
    "use_keyless": false,
    "use_oauth2": false,
    "use_openid": false,
    "openid_options": {
        "providers": [],
        "segregate_by_client": false
    },
    "oauth_meta": {
        "allowed_access_types": [],
        "allowed_authorize_types": [],
        "auth_login_redirect": ""
    },
    "auth": {
        "use_param": false,
        "param_name": "",
        "use_cookie": false,
        "cookie_name": "",
        "auth_header_name": "X-Authorization",
        "use_certificate": false
    },
    "use_basic_auth": false,
    "use_mutual_tls_auth": false,
    "client_certificates": [],
    "upstream_certificates": {},
    "pinned_public_keys": {},
    "enable_jwt": false,
    "use_standard_auth": true,
    "enable_coprocess_auth": false,
    "jwt_signing_method": "",
    "jwt_source": "",
    "jwt_identity_base_field": "",
    "jwt_client_base_field": "",
    "jwt_policy_field_name": "",
    "jwt_disable_issued_at_validation": false,
    "jwt_disable_expires_at_validation": false,
    "jwt_disable_not_before_validation": false,
    "notifications": {
        "shared_secret": "",
        "oauth_on_keychange_url": ""
    },
    "enable_signature_checking": false,
    "hmac_allowed_clock_skew": -1,
    "base_identity_provided_by": "",
    "definition": {
        "location": "header",
        "key": "version"
    },
    "version_data": {
        "not_versioned": false,
        "default_version": "",
        "versions": {
            "1.0.0": {
                "name": "1.0.0",
                "expires": "",
                "paths": {
                    "ignored": [],
                    "white_list": [],
                    "black_list": []
                },
                "use_extended_paths": true,
                "extended_paths": {
                    "transform": [
                        {
                            "template_data": {
                                "input_type": "json",
                                "template_mode": "blob",
                                "enable_session": false,
                                "template_source": "e3svKgo8eC1hd3M+CiNzZXQgKCRyb290PSRpbnB1dC5wYXRoKCckJykpIAp7IAoJInN0YWdlIjogIiRyb290Lm5hbWUiLCAKCSJ1c2VyLWlkIjoiJHJvb3Qua2V5Igp9CjwveC1hd3M+CiovfX1Cb29w"
                            },
                            "path": "/pets",
                            "method": "POST"
                        }
                    ],
                    "transform_response": [
                        {
                            "template_data": {
                                "input_type": "json",
                                "template_mode": "blob",
                                "enable_session": false,
                                "template_source": "e3svKgo8eC1hd3M+CiNzZXQgKCRyb290PSRpbnB1dC5wYXRoKCckJykpIAp7IAoJInN0YWdlIjogIiRyb290Lm5hbWUiLCAKCSJ1c2VyLWlkIjoiJHJvb3Qua2V5Igp9CjwveC1hd3M+CiovfX1CZWVw"
                            },
                            "path": "/pets",
                            "method": "POST"
                        }
                    ],
                    "transform_headers": [
                        {
                            "delete_headers": [],
                            "add_headers": {
                                "X-Foo": "Bar"
                            },
                            "path": "/pets",
                            "method": "POST",
                            "act_on": false
                        }
                    ],
                    "transform_response_headers": [
                        {
                            "delete_headers": [],
                            "add_headers": {
                                "X-Baz": "Boz"
                            },
                            "path": "/pets",
                            "method": "POST",
                            "act_on": false
                        }
                    ],
                    "url_rewrites": [
                        {
                            "path": "/pets",
                            "method": "POST",
                            "match_pattern": "/pets",
                            "rewrite_to": "",
                            "triggers": [
                                {
                                    "on": "AWS",
                                    "options": {
                                        "header_matches": {},
                                        "query_val_matches": {
                                            "boo": {
                                                "match_rx": "bar"
                                            }
                                        },
                                        "path_part_matches": {},
                                        "session_meta_matches": {},
                                        "payload_matches": {
                                            "match_rx": ""
                                        }
                                    },
                                    "rewrite_to": "http://foo.com/foofana"
                                }
                            ],
                            "MatchRegexp": null
                        }
                    ],
                    "track_endpoints": [
                        {
                            "path": "/pets/{petId}",
                            "method": "GET"
                        },
                        {
                            "path": "/pets",
                            "method": "POST"
                        },
                        {
                            "path": "/pets",
                            "method": "GET"
                        }
                    ],
                    "validate_json": [
                        {
                            "path": "/pets",
                            "method": "POST",
                            "schema": {
                                "properties": {
                                    "id": {
                                        "format": "int64",
                                        "type": "integer"
                                    },
                                    "name": {
                                        "type": "string"
                                    },
                                    "tag": {
                                        "type": "string"
                                    }
                                },
                                "required": [
                                    "id",
                                    "name"
                                ],
                                "type": "object"
                            },
                            "error_response_code": 400
                        }
                    ]
                },
                "global_headers": {},
                "global_headers_remove": [],
                "global_size_limit": 0,
                "override_target": ""
            }
        }
    },
    "uptime_tests": {
        "check_list": [],
        "config": {
            "expire_utime_after": 0,
            "service_discovery": {
                "use_discovery_service": false,
                "query_endpoint": "",
                "use_nested_query": false,
                "parent_data_path": "",
                "data_path": "",
                "port_data_path": "",
                "target_path": "",
                "use_target_list": false,
                "cache_timeout": 60,
                "endpoint_returns_list": false
            },
            "recheck_wait": 0
        }
    },
    "proxy": {
        "preserve_host_header": false,
        "listen_path": "/v1",
        "target_url": "http://test.com",
        "strip_listen_path": true,
        "enable_load_balancing": false,
        "target_list": [],
        "check_host_against_uptime_tests": false,
        "service_discovery": {
            "use_discovery_service": false,
            "query_endpoint": "",
            "use_nested_query": false,
            "parent_data_path": "",
            "data_path": "",
            "port_data_path": "",
            "target_path": "",
            "use_target_list": false,
            "cache_timeout": 0,
            "endpoint_returns_list": false
        },
        "transport": {
            "ssl_ciphers": [],
            "ssl_min_version": 0,
            "proxy_url": ""
        }
    },
    "disable_rate_limit": false,
    "disable_quota": false,
    "custom_middleware": {
        "pre": [],
        "post": [],
        "post_key_auth": [],
        "auth_check": {
            "name": "",
            "path": "",
            "require_session": false
        },
        "response": [],
        "driver": "",
        "id_extractor": {
            "extract_from": "",
            "extract_with": "",
            "extractor_config": {}
        }
    },
    "custom_middleware_bundle": "",
    "cache_options": {
        "cache_timeout": 0,
        "enable_cache": false,
        "cache_all_safe_requests": false,
        "cache_response_codes": [],
        "enable_upstream_cache_control": false,
        "cache_control_ttl_header": ""
    },
    "session_lifetime": 0,
    "active": true,
    "auth_provider": {
        "name": "",
        "storage_engine": "",
        "meta": {}
    },
    "session_provider": {
        "name": "",
        "storage_engine": "",
        "meta": {}
    },
    "event_handlers": {
        "events": {}
    },
    "enable_batch_request_support": false,
    "enable_ip_whitelisting": false,
    "allowed_ips": [],
    "enable_ip_blacklisting": false,
    "blacklisted_ips": [],
    "dont_set_quota_on_create": false,
    "expire_analytics_after": 0,
    "response_processors": [
        {
            "name": "header_injector",
            "options": {}
        },
        {
            "name": "response_body_transform",
            "options": {}
        }
    ],
    "CORS": {
        "enable": false,
        "allowed_origins": [],
        "allowed_methods": [],
        "allowed_headers": [],
        "exposed_headers": [],
        "allow_credentials": false,
        "max_age": 0,
        "options_passthrough": false,
        "debug": false
    },
    "domain": "",
    "do_not_track": false,
    "tags": [],
    "enable_context_vars": false,
    "config_data": {},
    "tag_headers": [],
    "global_rate_limit": {
        "rate": 0,
        "per": 0
    },
    "strip_auth_data": false
}`

var petstoreDefWithValidation = `
{
    "id": "5b20a4bac4356c0001c03f4c",
    "name": "Swagger Petstore",
    "slug": "v1",
    "api_id": "5bad91abd16a425b5ff6ad9bb1f88d69",
    "org_id": "5588095ea8f1bf0001000007",
    "use_keyless": false,
    "use_oauth2": false,
    "use_openid": false,
    "openid_options": {
        "providers": [],
        "segregate_by_client": false
    },
    "oauth_meta": {
        "allowed_access_types": [],
        "allowed_authorize_types": [],
        "auth_login_redirect": ""
    },
    "auth": {
        "use_param": false,
        "param_name": "",
        "use_cookie": false,
        "cookie_name": "",
        "auth_header_name": "X-Authorization",
        "use_certificate": false
    },
    "use_basic_auth": false,
    "use_mutual_tls_auth": false,
    "client_certificates": [],
    "upstream_certificates": {},
    "pinned_public_keys": {},
    "enable_jwt": false,
    "use_standard_auth": true,
    "enable_coprocess_auth": false,
    "jwt_signing_method": "",
    "jwt_source": "",
    "jwt_identity_base_field": "",
    "jwt_client_base_field": "",
    "jwt_policy_field_name": "",
    "jwt_disable_issued_at_validation": false,
    "jwt_disable_expires_at_validation": false,
    "jwt_disable_not_before_validation": false,
    "notifications": {
        "shared_secret": "",
        "oauth_on_keychange_url": ""
    },
    "enable_signature_checking": false,
    "hmac_allowed_clock_skew": -1,
    "base_identity_provided_by": "",
    "definition": {
        "location": "header",
        "key": "version"
    },
    "version_data": {
        "not_versioned": false,
        "default_version": "",
        "versions": {
            "1.0.0": {
                "name": "1.0.0",
                "expires": "",
                "paths": {
                    "ignored": [],
                    "white_list": [],
                    "black_list": []
                },
                "use_extended_paths": true,
                "extended_paths": {
                    "track_endpoints": [
                        {
                            "path": "/pets/{petId}",
                            "method": "GET"
                        },
                        {
                            "path": "/pets",
                            "method": "POST"
                        },
                        {
                            "path": "/pets",
                            "method": "GET"
                        }
                    ],
                    "validate_json": [
                        {
                            "path": "/pets",
                            "method": "POST",
                            "schema": {
                                "properties": {
                                    "age": {
                                        "description": "Age in years",
                                        "minimum": 0,
                                        "type": "integer"
                                    },
                                    "firstName": {
                                        "type": "string"
                                    },
                                    "lastName": {
                                        "type": "string"
                                    }
                                },
                                "required": [
                                    "firstName",
                                    "lastName"
                                ],
                                "title": "Person",
                                "type": "object"
                            },
                            "error_response_code": 400
                        }
                    ]
                },
                "global_headers": {},
                "global_headers_remove": [],
                "global_size_limit": 0,
                "override_target": ""
            }
        }
    },
    "uptime_tests": {
        "check_list": [],
        "config": {
            "expire_utime_after": 0,
            "service_discovery": {
                "use_discovery_service": false,
                "query_endpoint": "",
                "use_nested_query": false,
                "parent_data_path": "",
                "data_path": "",
                "port_data_path": "",
                "target_path": "",
                "use_target_list": false,
                "cache_timeout": 60,
                "endpoint_returns_list": false
            },
            "recheck_wait": 0
        }
    },
    "proxy": {
        "preserve_host_header": false,
        "listen_path": "/5bad91abd16a425b5ff6ad9bb1f88d69/",
        "target_url": "http://test.com",
        "strip_listen_path": true,
        "enable_load_balancing": false,
        "target_list": [],
        "check_host_against_uptime_tests": false,
        "service_discovery": {
            "use_discovery_service": false,
            "query_endpoint": "",
            "use_nested_query": false,
            "parent_data_path": "",
            "data_path": "",
            "port_data_path": "",
            "target_path": "",
            "use_target_list": false,
            "cache_timeout": 0,
            "endpoint_returns_list": false
        },
        "transport": {
            "ssl_ciphers": [],
            "ssl_min_version": 0,
            "proxy_url": ""
        }
    },
    "disable_rate_limit": false,
    "disable_quota": false,
    "custom_middleware": {
        "pre": [],
        "post": [],
        "post_key_auth": [],
        "auth_check": {
            "name": "",
            "path": "",
            "require_session": false
        },
        "response": [],
        "driver": "",
        "id_extractor": {
            "extract_from": "",
            "extract_with": "",
            "extractor_config": {}
        }
    },
    "custom_middleware_bundle": "",
    "cache_options": {
        "cache_timeout": 0,
        "enable_cache": false,
        "cache_all_safe_requests": false,
        "cache_response_codes": [],
        "enable_upstream_cache_control": false,
        "cache_control_ttl_header": ""
    },
    "session_lifetime": 0,
    "active": true,
    "auth_provider": {
        "name": "",
        "storage_engine": "",
        "meta": {}
    },
    "session_provider": {
        "name": "",
        "storage_engine": "",
        "meta": {}
    },
    "event_handlers": {
        "events": {}
    },
    "enable_batch_request_support": false,
    "enable_ip_whitelisting": false,
    "allowed_ips": [],
    "enable_ip_blacklisting": false,
    "blacklisted_ips": [],
    "dont_set_quota_on_create": false,
    "expire_analytics_after": 0,
    "response_processors": [],
    "CORS": {
        "enable": false,
        "allowed_origins": [],
        "allowed_methods": [],
        "allowed_headers": [],
        "exposed_headers": [],
        "allow_credentials": false,
        "max_age": 0,
        "options_passthrough": false,
        "debug": false
    },
    "domain": "",
    "do_not_track": false,
    "tags": [],
    "enable_context_vars": false,
    "config_data": {},
    "tag_headers": [],
    "global_rate_limit": {
        "rate": 0,
        "per": 0
    },
    "strip_auth_data": false
}
`

var petstoreDef = `
{
    "id": "5b205e0f4c7af20001988c27",
    "name": "Swagger Petstore",
    "slug": "v2",
    "api_id": "d864148a644f46ef6e739cdd6a9103da",
    "org_id": "5af3ae87ce7a9a00013cb24c",
    "use_keyless": false,
    "use_oauth2": false,
    "use_openid": false,
    "openid_options": {
        "providers": [],
        "segregate_by_client": false
    },
    "oauth_meta": {
        "allowed_access_types": [],
        "allowed_authorize_types": [],
        "auth_login_redirect": ""
    },
    "auth": {
        "use_param": false,
        "param_name": "",
        "use_cookie": false,
        "cookie_name": "",
        "auth_header_name": "X-Authorization",
        "use_certificate": false
    },
    "use_basic_auth": false,
    "use_mutual_tls_auth": false,
    "client_certificates": [],
    "upstream_certificates": {},
    "pinned_public_keys": {},
    "enable_jwt": false,
    "use_standard_auth": true,
    "enable_coprocess_auth": false,
    "jwt_signing_method": "",
    "jwt_source": "",
    "jwt_identity_base_field": "",
    "jwt_client_base_field": "",
    "jwt_policy_field_name": "",
    "jwt_disable_issued_at_validation": false,
    "jwt_disable_expires_at_validation": false,
    "jwt_disable_not_before_validation": false,
    "notifications": {
        "shared_secret": "",
        "oauth_on_keychange_url": ""
    },
    "enable_signature_checking": false,
    "hmac_allowed_clock_skew": 0,
    "base_identity_provided_by": "",
    "definition": {
        "location": "header",
        "key": "version"
    },
    "version_data": {
        "not_versioned": false,
        "default_version": "",
        "versions": {
            "1.0.0": {
                "name": "1.0.0",
                "expires": "",
                "paths": {
                    "ignored": [],
                    "white_list": [],
                    "black_list": []
                },
                "use_extended_paths": true,
                "extended_paths": {
                    "track_endpoints": [
                        {
                            "path": "/pet/findByStatus",
                            "method": "GET"
                        },
                        {
                            "path": "/store/inventory",
                            "method": "GET"
                        },
                        {
                            "path": "/user/createWithList",
                            "method": "POST"
                        },
                        {
                            "path": "/user/login",
                            "method": "GET"
                        },
                        {
                            "path": "/user/logout",
                            "method": "GET"
                        },
                        {
                            "path": "/pet",
                            "method": "PUT"
                        },
                        {
                            "path": "/pet",
                            "method": "POST"
                        },
                        {
                            "path": "/store/order/{orderId}",
                            "method": "DELETE"
                        },
                        {
                            "path": "/store/order/{orderId}",
                            "method": "GET"
                        },
                        {
                            "path": "/user/{username}",
                            "method": "DELETE"
                        },
                        {
                            "path": "/user/{username}",
                            "method": "GET"
                        },
                        {
                            "path": "/user/{username}",
                            "method": "PUT"
                        },
                        {
                            "path": "/pet/findByTags",
                            "method": "GET"
                        },
                        {
                            "path": "/pet/{petId}/uploadImage",
                            "method": "POST"
                        },
                        {
                            "path": "/store/order",
                            "method": "POST"
                        },
                        {
                            "path": "/user",
                            "method": "POST"
                        },
                        {
                            "path": "/pet/{petId}",
                            "method": "GET"
                        },
                        {
                            "path": "/pet/{petId}",
                            "method": "POST"
                        },
                        {
                            "path": "/pet/{petId}",
                            "method": "DELETE"
                        },
                        {
                            "path": "/user/createWithArray",
                            "method": "POST"
                        }
                    ]
                },
                "global_headers": {},
                "global_headers_remove": [],
                "global_size_limit": 0,
                "override_target": ""
            }
        }
    },
    "uptime_tests": {
        "check_list": [],
        "config": {
            "expire_utime_after": 0,
            "service_discovery": {
                "use_discovery_service": false,
                "query_endpoint": "",
                "use_nested_query": false,
                "parent_data_path": "",
                "data_path": "",
                "port_data_path": "",
                "target_path": "",
                "use_target_list": false,
                "cache_timeout": 0,
                "endpoint_returns_list": false
            },
            "recheck_wait": 0
        }
    },
    "proxy": {
        "preserve_host_header": false,
        "listen_path": "/v2",
        "target_url": "http://test.com",
        "strip_listen_path": true,
        "enable_load_balancing": false,
        "target_list": [],
        "check_host_against_uptime_tests": false,
        "service_discovery": {
            "use_discovery_service": false,
            "query_endpoint": "",
            "use_nested_query": false,
            "parent_data_path": "",
            "data_path": "",
            "port_data_path": "",
            "target_path": "",
            "use_target_list": false,
            "cache_timeout": 0,
            "endpoint_returns_list": false
        },
        "transport": {
            "ssl_ciphers": [],
            "ssl_min_version": 0,
            "proxy_url": ""
        }
    },
    "disable_rate_limit": false,
    "disable_quota": false,
    "custom_middleware": {
        "pre": [],
        "post": [],
        "post_key_auth": [],
        "auth_check": {
            "name": "",
            "path": "",
            "require_session": false
        },
        "response": [],
        "driver": "",
        "id_extractor": {
            "extract_from": "",
            "extract_with": "",
            "extractor_config": {}
        }
    },
    "custom_middleware_bundle": "",
    "cache_options": {
        "cache_timeout": 0,
        "enable_cache": false,
        "cache_all_safe_requests": false,
        "cache_response_codes": [],
        "enable_upstream_cache_control": false,
        "cache_control_ttl_header": ""
    },
    "session_lifetime": 0,
    "active": true,
    "auth_provider": {
        "name": "",
        "storage_engine": "",
        "meta": {}
    },
    "session_provider": {
        "name": "",
        "storage_engine": "",
        "meta": {}
    },
    "event_handlers": {
        "events": {}
    },
    "enable_batch_request_support": false,
    "enable_ip_whitelisting": false,
    "allowed_ips": [],
    "enable_ip_blacklisting": false,
    "blacklisted_ips": [],
    "dont_set_quota_on_create": false,
    "expire_analytics_after": 0,
    "response_processors": [],
    "CORS": {
        "enable": false,
        "allowed_origins": [],
        "allowed_methods": [],
        "allowed_headers": [],
        "exposed_headers": [],
        "allow_credentials": false,
        "max_age": 0,
        "options_passthrough": false,
        "debug": false
    },
    "domain": "",
    "do_not_track": false,
    "tags": [],
    "enable_context_vars": false,
    "config_data": {},
    "tag_headers": [],
    "global_rate_limit": {
        "rate": 0,
        "per": 0
    },
    "strip_auth_data": false
}
`

var massiveDef = `
{
    "id": "570262eb87b75f0001000002",
    "name": "holidaywatchdog-api",
    "slug": "",
    "api_id": "559c7815de2c4b2660268d28ef1d01c8",
    "org_id": "5588095ea8f1bf0001000007",
    "use_keyless": true,
    "use_oauth2": false,
    "use_openid": false,
    "openid_options": {
        "providers": [],
        "segregate_by_client": false
    },
    "oauth_meta": {
        "allowed_access_types": [],
        "allowed_authorize_types": [],
        "auth_login_redirect": ""
    },
    "auth": {
        "use_param": false,
        "param_name": "",
        "use_cookie": false,
        "cookie_name": "",
        "auth_header_name": "",
        "use_certificate": false
    },
    "use_basic_auth": false,
    "use_mutual_tls_auth": false,
    "client_certificates": null,
    "upstream_certificates": {},
    "pinned_public_keys": {},
    "enable_jwt": false,
    "use_standard_auth": false,
    "enable_coprocess_auth": false,
    "jwt_signing_method": "",
    "jwt_source": "",
    "jwt_identity_base_field": "",
    "jwt_client_base_field": "",
    "jwt_policy_field_name": "",
    "jwt_disable_issued_at_validation": false,
    "jwt_disable_expires_at_validation": false,
    "jwt_disable_not_before_validation": false,
    "notifications": {
        "shared_secret": "",
        "oauth_on_keychange_url": ""
    },
    "enable_signature_checking": false,
    "hmac_allowed_clock_skew": -1,
    "base_identity_provided_by": "",
    "definition": {
        "location": "header",
        "key": "version"
    },
    "version_data": {
        "not_versioned": false,
        "default_version": "",
        "versions": {
            "v1": {
                "name": "v1",
                "expires": "",
                "paths": {
                    "ignored": [],
                    "white_list": [],
                    "black_list": []
                },
                "use_extended_paths": true,
                "extended_paths": {
                    "white_list": [
                        {
                            "path": "/user-reviews/{id}/user-review-internal-comments/count",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-reviews/{id}/user-review-internal-comments/{fk}",
                            "method_actions": {
                                "DELETE": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "PUT": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-reviews/{id}/user-review-internal-comments",
                            "method_actions": {
                                "DELETE": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/accommodations/{id}/user-photo-albums/count",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-review-internal-comments/change-stream",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/accommodations/{id}/commerce-mappings/count",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/accommodations/{id}/user-photo-albums/{fk}",
                            "method_actions": {
                                "DELETE": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "PUT": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/accommodations/{id}/commerce-mappings/{fk}",
                            "method_actions": {
                                "DELETE": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "PUT": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-review-internal-comments/{id}/exists",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/accommodations/{id}/nearby-accommodations",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-photo-albums/{id}/user-photos/count",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/external-provider-mappings/change-stream",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-photo-albums/{id}/user-photos/{fk}",
                            "method_actions": {
                                "DELETE": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "PUT": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-hwds/{id}/user-photo-albums/count",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/accommodations/{id}/user-reviews/count",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/external-provider-mappings/{id}/exists",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/accommodations/{id}/commerce-mappings",
                            "method_actions": {
                                "DELETE": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-hwds/{id}/user-photo-albums/{fk}",
                            "method_actions": {
                                "DELETE": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "PUT": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-review-internal-comments/findOne",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/accommodations/{id}/user-reviews/{fk}",
                            "method_actions": {
                                "DELETE": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "PUT": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/accommodations/{id}/user-photo-albums",
                            "method_actions": {
                                "DELETE": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/cruise-lines/{id}/cruise-ships/count",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-review-internal-comments/update",
                            "method_actions": {
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/accommodations/nearest-by-ip-address",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-review-internal-comments/count",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/cruise-lines/{id}/cruise-ships/{fk}",
                            "method_actions": {
                                "DELETE": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "PUT": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-photo-albums/{id}/user-photos",
                            "method_actions": {
                                "DELETE": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/external-provider-mappings/findOne",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-review-internal-comments/{id}",
                            "method_actions": {
                                "DELETE": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "HEAD": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "PUT": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/auth-users/{id}/accessTokens/count",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-hwds/{id}/user-reviews/count",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/auth-users/{id}/accessTokens/{fk}",
                            "method_actions": {
                                "DELETE": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "PUT": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-photos/{id}/user-photo-album",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/external-provider-mappings/update",
                            "method_actions": {
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/accommodations/{id}/user-reviews",
                            "method_actions": {
                                "DELETE": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/external-provider-mappings/count",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-hwds/{id}/user-reviews/{fk}",
                            "method_actions": {
                                "DELETE": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "PUT": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/accommodations/nearest-by-latlon",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-hwds/{id}/user-photo-albums",
                            "method_actions": {
                                "DELETE": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/country-currencies/change-stream",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-photo-albums/change-stream",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/external-provider-mappings/{id}",
                            "method_actions": {
                                "DELETE": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "HEAD": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "PUT": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/country-currencies/{id}/exists",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/cruise-lines/{id}/cruise-ships",
                            "method_actions": {
                                "DELETE": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/cruise-ships/{id}/cruise-lines",
                            "method_actions": {
                                "DELETE": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "PUT": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-photo-albums/{id}/exists",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-review-internal-comments",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "PUT": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/accommodations/{id}/detailed",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/accommodations/{id}/location",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/accommodations/change-stream",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/accommodations/reindexSearch",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/auth-users/{id}/accessTokens",
                            "method_actions": {
                                "DELETE": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/warehouse-pages/{id}/exists",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-hwds/{id}/user-reviews",
                            "method_actions": {
                                "DELETE": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/country-currencies/findOne",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/external-provider-mappings",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "PUT": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/accommodations/{id}/exists",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-reviews/change-stream",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/cruise-ships/change-stream",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/cruise-lines/change-stream",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-photo-albums/findOne",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-photos/change-stream",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/country-currencies/update",
                            "method_actions": {
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/cruise-ships/{id}/exists",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/cruise-lines/{id}/exists",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/country-currencies/count",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/seoaliases/change-stream",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-reviews/{id}/exists",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/auth-users/change-stream",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-photo-albums/update",
                            "method_actions": {
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-photo-albums/count",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-hwds/change-stream",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/warehouse-pages/findOne",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-photos/{id}/exists",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/locations/change-stream",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/country-currencies/{id}",
                            "method_actions": {
                                "DELETE": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "HEAD": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "PUT": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/accommodations/findOne",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-photo-albums/{id}",
                            "method_actions": {
                                "DELETE": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "HEAD": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "PUT": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/locations/{id}/weather",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/auth-users/{id}/exists",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-reviews/{id}/user",
                            "method_actions": {
                                "DELETE": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "PUT": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/seoaliases/{id}/exists",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/warehouse-pages/count",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-hwds/{id}/exists",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/locations/{id}/exists",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/accommodations/update",
                            "method_actions": {
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/cruise-lines/findOne",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/accommodations/count",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/cruise-ships/findOne",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/warehouse-pages/{id}",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "HEAD": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-reviews/findOne",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/accommodations/{id}",
                            "method_actions": {
                                "DELETE": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "HEAD": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "PUT": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-photos/findOne",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/cruise-ships/update",
                            "method_actions": {
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-reviews/update",
                            "method_actions": {
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/cruise-lines/update",
                            "method_actions": {
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-reviews/count",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/auth-users/confirm",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/cruise-ships/count",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/country-currencies",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "PUT": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/seoaliases/findOne",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-photos/update",
                            "method_actions": {
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/auth-users/findOne",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/cruise-lines/count",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-reviews/{id}",
                            "method_actions": {
                                "DELETE": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "HEAD": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "PUT": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/cruise-lines/{id}",
                            "method_actions": {
                                "DELETE": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "HEAD": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "PUT": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-photo-albums",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "PUT": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/cruise-ships/{id}",
                            "method_actions": {
                                "DELETE": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "HEAD": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "PUT": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/auth-users/logout",
                            "method_actions": {
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-hwds/findOne",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/locations/findOne",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/auth-users/update",
                            "method_actions": {
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-photos/count",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/seoaliases/update",
                            "method_actions": {
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/locations/update",
                            "method_actions": {
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-hwds/update",
                            "method_actions": {
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/seoaliases/count",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-photos/{id}",
                            "method_actions": {
                                "DELETE": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "HEAD": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "PUT": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/auth-users/reset",
                            "method_actions": {
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/auth-users/login",
                            "method_actions": {
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/auth-users/count",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/seoaliases/{id}",
                            "method_actions": {
                                "DELETE": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "HEAD": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "PUT": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/locations/count",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/auth-users/{id}",
                            "method_actions": {
                                "DELETE": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "HEAD": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "PUT": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/warehouse-pages",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-hwds/count",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-hwds/{id}",
                            "method_actions": {
                                "DELETE": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "HEAD": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "PUT": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/accommodations",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "PUT": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/locations/{id}",
                            "method_actions": {
                                "DELETE": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "HEAD": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "PUT": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/cruise-lines",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "PUT": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-reviews",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "PUT": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/cruise-ships",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "PUT": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-photos",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "PUT": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/seoaliases",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "PUT": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/auth-users",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "PUT": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/user-hwds",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "PUT": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        },
                        {
                            "path": "/locations",
                            "method_actions": {
                                "GET": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "PUT": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        }
                    ]
                },
                "global_headers": {},
                "global_headers_remove": [],
                "global_size_limit": 0,
                "override_target": ""
            }
        }
    },
    "uptime_tests": {
        "check_list": [],
        "config": {
            "expire_utime_after": 0,
            "service_discovery": {
                "use_discovery_service": false,
                "query_endpoint": "",
                "use_nested_query": false,
                "parent_data_path": "",
                "data_path": "",
                "port_data_path": "",
                "target_path": "",
                "use_target_list": false,
                "cache_timeout": 0,
                "endpoint_returns_list": false
            },
            "recheck_wait": 0
        }
    },
    "proxy": {
        "preserve_host_header": false,
        "listen_path": "/559c7815de2c4b2660268d28ef1d01c8/",
        "target_url": "http://test.com",
        "strip_listen_path": true,
        "enable_load_balancing": false,
        "target_list": [],
        "check_host_against_uptime_tests": false,
        "service_discovery": {
            "use_discovery_service": false,
            "query_endpoint": "",
            "use_nested_query": false,
            "parent_data_path": "",
            "data_path": "",
            "port_data_path": "",
            "target_path": "",
            "use_target_list": false,
            "cache_timeout": 0,
            "endpoint_returns_list": false
        },
        "transport": {
            "ssl_ciphers": null,
            "ssl_min_version": 0,
            "proxy_url": ""
        }
    },
    "disable_rate_limit": false,
    "disable_quota": false,
    "custom_middleware": {
        "pre": [],
        "post": [],
        "post_key_auth": null,
        "auth_check": {
            "name": "",
            "path": "",
            "require_session": false
        },
        "response": [],
        "driver": "",
        "id_extractor": {
            "extract_from": "",
            "extract_with": "",
            "extractor_config": null
        }
    },
    "custom_middleware_bundle": "",
    "cache_options": {
        "cache_timeout": 0,
        "enable_cache": false,
        "cache_all_safe_requests": false,
        "cache_response_codes": [],
        "enable_upstream_cache_control": false,
        "cache_control_ttl_header": ""
    },
    "session_lifetime": 0,
    "active": false,
    "auth_provider": {
        "name": "",
        "storage_engine": "",
        "meta": {}
    },
    "session_provider": {
        "name": "",
        "storage_engine": "",
        "meta": null
    },
    "event_handlers": {
        "events": {}
    },
    "enable_batch_request_support": false,
    "enable_ip_whitelisting": false,
    "allowed_ips": [],
    "enable_ip_blacklisting": false,
    "blacklisted_ips": null,
    "dont_set_quota_on_create": false,
    "expire_analytics_after": 0,
    "response_processors": [],
    "CORS": {
        "enable": false,
        "allowed_origins": [],
        "allowed_methods": [],
        "allowed_headers": [],
        "exposed_headers": [],
        "allow_credentials": false,
        "max_age": 0,
        "options_passthrough": false,
        "debug": false
    },
    "domain": "",
    "do_not_track": false,
    "tags": [],
    "enable_context_vars": false,
    "config_data": null,
    "tag_headers": null,
    "global_rate_limit": {
        "rate": 0,
        "per": 0
    },
    "strip_auth_data": false
}`

var fazio = `
{
    "id": "5b70d9eeeacd79000186dde8",
    "name": "ECommerce API",
    "slug": "customer",
    "api_id": "f0fd598bb8a8475b6425654e4e4d255f",
    "org_id": "5b70c3aa961d5700013356de",
    "use_keyless": false,
    "use_oauth2": true,
    "use_openid": false,
    "openid_options": {
        "providers": [],
        "segregate_by_client": false
    },
    "oauth_meta": {
        "allowed_access_types": [
            "password"
        ],
        "allowed_authorize_types": [
            "token"
        ],
        "auth_login_redirect": "https://idp-example.io"
    },
    "auth": {
        "use_param": false,
        "param_name": "",
        "use_cookie": false,
        "cookie_name": "",
        "auth_header_name": "Authorization",
        "use_certificate": false
    },
    "use_basic_auth": false,
    "use_mutual_tls_auth": false,
    "client_certificates": [],
    "upstream_certificates": {},
    "pinned_public_keys": {},
    "enable_jwt": false,
    "use_standard_auth": false,
    "enable_coprocess_auth": false,
    "jwt_signing_method": "",
    "jwt_source": "",
    "jwt_identity_base_field": "",
    "jwt_client_base_field": "",
    "jwt_policy_field_name": "",
    "jwt_disable_issued_at_validation": false,
    "jwt_disable_expires_at_validation": false,
    "jwt_disable_not_before_validation": false,
    "notifications": {
        "shared_secret": "xxx",
        "oauth_on_keychange_url": ""
    },
    "enable_signature_checking": false,
    "hmac_allowed_clock_skew": -1,
    "base_identity_provided_by": "",
    "definition": {
        "location": "header",
        "key": "x-api-version",
        "strip_path": false
    },
    "version_data": {
        "not_versioned": true,
        "default_version": "",
        "versions": {
            "Default": {
                "name": "Default",
                "expires": "",
                "paths": {
                    "ignored": [],
                    "white_list": [],
                    "black_list": []
                },
                "use_extended_paths": true,
                "extended_paths": {
                    "ignored": [
                        {
                            "path": "(.*)",
                            "method_actions": {
                                "OPTIONS": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                }
                            }
                        }
                    ],
                    "white_list": [
                        {
                            "path": "customer/{id}",
                            "method_actions": {
                                "DELETE": {
                                    "action": "reply",
                                    "code": 200,
                                    "data": "{\n\t\"id\": \"1\",\n\t\"name\": \"Tony Stark\",\n\t\"address\": \"200 Park Avenue, 10007 New York, USA\",\n\t\"phone\": \"123-456-456\"\n}",
                                    "headers": {}
                                },
                                "GET": {
                                    "action": "reply",
                                    "code": 200,
                                    "data": "{\n\t\"id\": \"1\",\n\t\"name\": \"Tony Stark\",\n\t\"address\": \"200 Park Avenue, 10007 New York, USA\"\n}",
                                    "headers": {
                                        "content-type": "application/json"
                                    }
                                },
                                "HEAD": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "OPTIONS": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {
                                        "content-type": "application/json"
                                    }
                                },
                                "PUT": {
                                    "action": "reply",
                                    "code": 200,
                                    "data": "{\n\t\"id\": \"1\",\n\t\"name\": \"Tony Stark\",\n\t\"address\": \"200 Park Avenue, 10007 New York, USA\"\n}",
                                    "headers": {
                                        "content-type": "application/json"
                                    }
                                }
                            }
                        },
                        {
                            "path": "customer/(.*)",
                            "method_actions": {
                                "GET": {
                                    "action": "reply",
                                    "code": 200,
                                    "data": "{\n\t\"id\": \"1\",\n\t\"name\": \"Tony Stark\",\n\t\"address\": \"200 Park Avenue, 10007 New York, USA\"\n}",
                                    "headers": {
                                        "content-type": "application/json"
                                    }
                                },
                                "HEAD": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "OPTIONS": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "POST": {
                                    "action": "reply",
                                    "code": 200,
                                    "data": "",
                                    "headers": {
                                        "content-type": "application/json"
                                    }
                                },
                                "PUT": {
                                    "action": "reply",
                                    "code": 200,
                                    "data": "{\n\t\"id\": \"1\",\n\t\"name\": \"Tony Stark\",\n\t\"address\": \"200 Park Avenue, 10007 New York, USA\"\n}",
                                    "headers": {
                                        "content-type": "application/json"
                                    }
                                }
                            }
                        },
                        {
                            "path": "submitOrder",
                            "method_actions": {
                                "POST": {
                                    "action": "reply",
                                    "code": 200,
                                    "data": "{\n  \"id\": \"1\",\n  \"name\": \"Tony Stark\",\n  \"address\": \"200 Park Avenue, 10007 New York, USA\",\n  \"line_items\": [\n    {\n      \"product_id\": \"abc123\",\n      \"count\": 1\n    },\n    {\n      \"product_id\": \"321bca\",\n      \"count\": 3\n    }\n  ]\n}",
                                    "headers": {
                                        "content-type": "application/json"
                                    }
                                }
                            }
                        },
                        {
                            "path": "customers",
                            "method_actions": {
                                "GET": {
                                    "action": "reply",
                                    "code": 200,
                                    "data": "[\n\t{\n\t\t\"id\": \"1\",\n\t\t\"name\": \"Tony Stark\"\n\t},\n\t{\n\t\t\"id\": \"2\",\n\t\t\"name\": \"Bruce Banner\"\n\t},\n\t{\n\t\t\"id\": \"3\",\n\t\t\"name\": \"Steven Rogers\"\n\t},\n\t{\n\t\t\"id\": \"4\",\n\t\t\"name\": \"Natasha Romanov\"\n\t},\n\t{\n\t\t\"id\": \"5\",\n\t\t\"name\": \"Carol Danvers\"\n\t}\n]",
                                    "headers": {
                                        "content-type": "application-json"
                                    }
                                }
                            }
                        },
                        {
                            "path": "(.*)",
                            "method_actions": {
                                "GET": {
                                    "action": "reply",
                                    "code": 200,
                                    "data": "{\n\t\"id\": \"1\",\n\t\"name\": \"Tony Stark\",\n\t\"address\": \"200 Park Avenue, 10007 New York, USA\"\n}",
                                    "headers": {
                                        "content-type": "application/json"
                                    }
                                },
                                "HEAD": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "OPTIONS": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {}
                                },
                                "POST": {
                                    "action": "no_action",
                                    "code": 200,
                                    "data": "",
                                    "headers": {
                                        "content-type": "application/json"
                                    }
                                },
                                "PUT": {
                                    "action": "reply",
                                    "code": 200,
                                    "data": "{\n\t\"id\": \"1\",\n\t\"name\": \"Tony Stark\",\n\t\"address\": \"200 Park Avenue, 10007 New York, USA\"\n}",
                                    "headers": {
                                        "content-type": "application/json"
                                    }
                                }
                            }
                        }
                    ],
                    "track_endpoints": [
                        {
                            "path": "customer/{id}",
                            "method": "HEAD"
                        },
                        {
                            "path": "customer/{id}",
                            "method": "PUT"
                        },
                        {
                            "path": "customer/{id}",
                            "method": "DELETE"
                        },
                        {
                            "path": "customer/{id}",
                            "method": "GET"
                        },
                        {
                            "path": "customer/(.*)",
                            "method": "POST"
                        },
                        {
                            "path": "submitOrder",
                            "method": "POST"
                        },
                        {
                            "path": "customers",
                            "method": "GET"
                        },
                        {
                            "path": "(.*)",
                            "method": "OPTIONS"
                        }
                    ],
                    "validate_json": [
                        {
                            "path": "customer/(.*)",
                            "method": "POST",
                            "schema": {
                                "$id": "http://example.com/example.json",
                                "$schema": "http://json-schema.org/draft-07/schema#",
                                "definitions": {},
                                "properties": {
                                    "address": {
                                        "$id": "/properties/address",
                                        "default": "",
                                        "examples": [
                                            "200 Park Avenue, 10007 New York, USA"
                                        ],
                                        "title": "The Address Schema ",
                                        "type": "string"
                                    },
                                    "id": {
                                        "$id": "/properties/id",
                                        "default": "",
                                        "examples": [
                                            "1"
                                        ],
                                        "title": "The Id Schema ",
                                        "type": "string"
                                    },
                                    "name": {
                                        "$id": "/properties/name",
                                        "default": "",
                                        "examples": [
                                            "Tony Stark"
                                        ],
                                        "title": "The Name Schema ",
                                        "type": "string"
                                    },
                                    "phone": {
                                        "$id": "/properties/phone",
                                        "default": "",
                                        "examples": [
                                            "123-456-456"
                                        ],
                                        "title": "The Phone Schema ",
                                        "type": "string"
                                    }
                                },
                                "type": "object"
                            },
                            "error_response_code": 422
                        },
                        {
                            "path": "submitOrder",
                            "method": "POST",
                            "schema": {
                                "$id": "http://example.com/example.json",
                                "$schema": "http://json-schema.org/draft-07/schema#",
                                "definitions": {},
                                "properties": {
                                    "address": {
                                        "$id": "/properties/address",
                                        "default": "",
                                        "examples": [
                                            "200 Park Avenue, 10007 New York, USA"
                                        ],
                                        "title": "The Address Schema ",
                                        "type": "string"
                                    },
                                    "id": {
                                        "$id": "/properties/id",
                                        "default": "",
                                        "examples": [
                                            "1"
                                        ],
                                        "title": "The Id Schema ",
                                        "type": "string"
                                    },
                                    "line_items": {
                                        "$id": "/properties/line_items",
                                        "items": {
                                            "$id": "/properties/line_items/items",
                                            "properties": {
                                                "count": {
                                                    "$id": "/properties/line_items/items/properties/count",
                                                    "default": 0,
                                                    "examples": [
                                                        1
                                                    ],
                                                    "title": "The Count Schema ",
                                                    "type": "integer"
                                                },
                                                "product_id": {
                                                    "$id": "/properties/line_items/items/properties/product_id",
                                                    "default": "",
                                                    "examples": [
                                                        "abc123"
                                                    ],
                                                    "title": "The Product_id Schema ",
                                                    "type": "string"
                                                }
                                            },
                                            "type": "object"
                                        },
                                        "type": "array"
                                    },
                                    "name": {
                                        "$id": "/properties/name",
                                        "default": "",
                                        "examples": [
                                            "Tony Stark"
                                        ],
                                        "title": "The Name Schema ",
                                        "type": "string"
                                    }
                                },
                                "type": "object"
                            },
                            "error_response_code": 422
                        }
                    ]
                },
                "global_headers": {},
                "global_headers_remove": [],
                "global_size_limit": 0,
                "override_target": ""
            }
        }
    },
    "uptime_tests": {
        "check_list": [],
        "config": {
            "expire_utime_after": 0,
            "service_discovery": {
                "use_discovery_service": false,
                "query_endpoint": "",
                "use_nested_query": false,
                "parent_data_path": "",
                "data_path": "",
                "port_data_path": "",
                "target_path": "",
                "use_target_list": false,
                "cache_timeout": 60,
                "endpoint_returns_list": false
            },
            "recheck_wait": 0
        }
    },
    "proxy": {
        "preserve_host_header": false,
        "listen_path": "/api/",
        "target_url": "http://httpbin.org/",
        "strip_listen_path": false,
        "enable_load_balancing": false,
        "target_list": [],
        "check_host_against_uptime_tests": false,
        "service_discovery": {
            "use_discovery_service": false,
            "query_endpoint": "",
            "use_nested_query": false,
            "parent_data_path": "",
            "data_path": "",
            "port_data_path": "",
            "target_path": "",
            "use_target_list": false,
            "cache_timeout": 0,
            "endpoint_returns_list": false
        },
        "transport": {
            "ssl_ciphers": [],
            "ssl_min_version": 0,
            "proxy_url": ""
        }
    },
    "disable_rate_limit": false,
    "disable_quota": false,
    "custom_middleware": {
        "pre": [],
        "post": [],
        "post_key_auth": [],
        "auth_check": {
            "name": "",
            "path": "",
            "require_session": false
        },
        "response": [],
        "driver": "",
        "id_extractor": {
            "extract_from": "",
            "extract_with": "",
            "extractor_config": {}
        }
    },
    "custom_middleware_bundle": "",
    "cache_options": {
        "cache_timeout": 60,
        "enable_cache": true,
        "cache_all_safe_requests": false,
        "cache_response_codes": [],
        "enable_upstream_cache_control": false,
        "cache_control_ttl_header": ""
    },
    "session_lifetime": 0,
    "active": true,
    "auth_provider": {
        "name": "",
        "storage_engine": "",
        "meta": {}
    },
    "session_provider": {
        "name": "",
        "storage_engine": "",
        "meta": {}
    },
    "event_handlers": {
        "events": {}
    },
    "enable_batch_request_support": false,
    "enable_ip_whitelisting": false,
    "allowed_ips": [],
    "enable_ip_blacklisting": false,
    "blacklisted_ips": [],
    "dont_set_quota_on_create": false,
    "expire_analytics_after": 0,
    "response_processors": [],
    "CORS": {
        "enable": false,
        "allowed_origins": [],
        "allowed_methods": [],
        "allowed_headers": [],
        "exposed_headers": [],
        "allow_credentials": false,
        "max_age": 24,
        "options_passthrough": false,
        "debug": false
    },
    "domain": "",
    "do_not_track": false,
    "tags": [],
    "enable_context_vars": false,
    "config_data": {},
    "tag_headers": [],
    "global_rate_limit": {
        "rate": 0,
        "per": 0
    },
    "strip_auth_data": false
}
`
