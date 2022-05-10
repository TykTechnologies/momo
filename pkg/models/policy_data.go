package models

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type DriverExtension struct {
	Meta       interface{}
	ExternalID string
}

// Extend a policy object to incude a drivers section so we can store driver-specific metadata
type PolicyMap struct {
	Drivers map[string]DriverExtension
	Policy
}

type Policy struct {
	AccessRights     map[string]AccessDefinition `bson:"access_rights" json:"access_rights"`
	ID               string                      `bson:"id,omitempty" json:"id"`
	OrgID            string                      `bson:"org_id" json:"org_id"`
	LastUpdated      string                      `bson:"last_updated" json:"last_updated"`
	Tags             []string                    `bson:"tags" json:"tags"`
	Per              float64                     `bson:"per" json:"per"`
	QuotaRenewalRate int64                       `bson:"quota_renewal_rate" json:"quota_renewal_rate"`
	Rate             float64                     `bson:"rate" json:"rate"`
	QuotaMax         int64                       `bson:"quota_max" json:"quota_max"`
	KeyExpiresIn     int64                       `bson:"key_expires_in" json:"key_expires_in"`
	MID              primitive.ObjectID          `bson:"_id,omitempty" json:"_id"`
	Partitions       PolicyPartitions            `bson:"partitions" json:"partitions"`
	Active           bool                        `bson:"active" json:"active"`
	IsInactive       bool                        `bson:"is_inactive" json:"is_inactive"`
	HMACEnabled      bool                        `bson:"hmac_enabled" json:"hmac_enabled"`
}

type PolicyPartitions struct {
	Quota     bool `bson:"quota" json:"quota"`
	RateLimit bool `bson:"rate_limit" json:"rate_limit"`
	ACL       bool `bson:"acl" json:"acl"`
}

// AccessDefinition defines which versions of an API a key has access to
type AccessDefinition struct {
	APIName  string   `json:"apiname" msg:"api_name"`
	APIID    string   `json:"apiid" msg:"api_id"`
	Versions []string `json:"versions" msg:"versions"`
}
