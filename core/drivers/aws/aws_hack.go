package aws

//func TestDriver_CreateOrUpdate(t *testing.T) {
//	d := Driver{}
//	d.SetCredentials(os.Getenv("AWS_ACCESS_KEY"), os.Getenv("AWS_SECRET"), "us-west-2")
//	d.Init()
//
//	def := &apidef.APIDefinition{}
//	err := json.Unmarshal([]byte(petStoreWithValidationAndRequestTransform), def)
//	if err != nil {
//		t.Fatal(err)
//	}
//
//	err = d.create(def)
//	if err != nil {
//		t.Fatal(err)
//	}
//
//	fmt.Println(d.workingPackage.RestAPI)
//}

var petStoreWithValidationAndRequestTransform = `
{
    "id": "5b29958c1b52580001082a60",
    "name": "Swagger Petstore",
    "slug": "v1",
    "api_id": "7087d7a11f8a48fc67a22865499314de",
    "org_id": "5b298965040a68000193aed9",
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
