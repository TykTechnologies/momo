package tyk_api

import (
	"errors"
	"net/http"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/user"

	"github.com/TykTechnologies/momo/pkg/models"
)

type TykAPIMockHandler struct {
	conf        *TykAPIConfig
	OrgSessions map[string]*user.SessionState
}

func (t *TykAPIMockHandler) getURL(e endpoint) string {
	return "http://localhost:3000"
}

func (t *TykAPIMockHandler) secureReq(r *http.Request) {
	r.Header.Set("admin-auth", "12345")
	r.Header.Set("Content-Type", "application/json")
}

func (t *TykAPIMockHandler) FetchOrg(orgID string) (interface{}, error) {
	return nil, nil
}

func (t *TykAPIMockHandler) UpdateOrg(orgID string, orgData []byte) error {
	return nil
}

func (t *TykAPIMockHandler) CreateOrg(orgName string, portal string) (string, error) {
	return "99999999999", nil
}

func (t *TykAPIMockHandler) CreateUser(fname, lname, email, pass, orgID string) (string, string, error) {
	return "a-sample-key", "123456789", nil
}

func (t *TykAPIMockHandler) ResetPassword(key, uid, old, new string) error {
	return nil
}

func (t *TykAPIMockHandler) GetKeyDetail(key string) (*user.SessionState, error) {
	return &user.SessionState{}, nil
}

func (t *TykAPIMockHandler) ReloadDashboardUrls() error {
	return nil
}

func (t *TykAPIMockHandler) Init(cfg *TykAPIConfig) error {
	t.conf = cfg
	t.OrgSessions = make(map[string]*user.SessionState)
	return nil
}

func (t *TykAPIMockHandler) CreateAccessURL(orgID string) (string, error) {
	return "http://tyk.dashboard/tap?nonce=1234", nil
}

func (t *TykAPIMockHandler) GetAllPolicies() ([]models.Policy, error) {
	return make([]models.Policy, 0), nil
}

func (t *TykAPIMockHandler) CreateAccessToken(org string, accessList []user.AccessDefinition) (string, error) {
	return "12345", nil
}

func (t *TykAPIMockHandler) CreateAPI(apiDef []byte) (string, error) {
	return "54321", nil
}

func (t *TykAPIMockHandler) GetAPIDetail(id string) (*DashboardAPIDefinition, error) {
	def := &DashboardAPIDefinition{
		APIDefinition: apidef.APIDefinition{APIID: "54321"},
	}
	return def, nil
}

func (t *TykAPIMockHandler) DeleteAPI(id string) error {
	if id != "54321" {
		return errors.New("not found")
	}
	return nil
}

func (t *TykAPIMockHandler) GetConf() *TykAPIConfig {
	return t.conf
}

func NewMockHandler(cfg *TykAPIConfig) (Handler, error) {
	t := &TykAPIMockHandler{}
	err := t.Init(cfg)

	return t, err
}

func (t *TykAPIMockHandler) CreateOrgKey(keydata user.SessionState) (string, error) {
	if _, ok := t.OrgSessions[keydata.OrgID]; !ok {
		t.OrgSessions[keydata.OrgID] = &keydata
	}

	return keydata.OrgID, nil
}

func (t *TykAPIMockHandler) UpdateDashboardLicense(license string) error {
	if license == "fail" {
		return errors.New("Tyk Dashboard license update failed")
	}

	return nil
}

func (t *TykAPIMockHandler) GetOrgKey(orgID string) (*user.SessionState, error) {
	session, ok := t.OrgSessions[orgID]
	if !ok {
		return nil, errors.New("not found")
	}

	return session, nil
}
