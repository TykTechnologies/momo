package tyk_api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"text/template"
	"time"

	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/user"
	"github.com/jpillora/backoff"
	"github.com/sirupsen/logrus"

	"github.com/TykTechnologies/momo/pkg/models"

	"github.com/TykTechnologies/momo/pkg/logger"
)

type TykAPIHandler struct {
	conf    *TykAPIConfig
	client  *http.Client
	isAlive bool
}

const moduleName = "ctrl.tyk_api.client"

var log = logger.GetLogger(moduleName)

type endpoint string

const (
	Root endpoint = ""

	License     endpoint = "admin/license"
	AdminOrgs   endpoint = "admin/organisations/"
	AdminOrg    endpoint = "admin/organisations/{org-id}"
	OrgKey      endpoint = "admin/org/keys"
	SSO         endpoint = "admin/sso"
	AdminReload endpoint = "admin/system/reload"
	AdminUser   endpoint = "admin/users"

	APIDef      endpoint = "api/apis/"
	KeyDetail   endpoint = "api/apis/default/keys/{key-id}"
	Keys        endpoint = "api/keys"
	PolicyList  endpoint = "api/portal/policies?p=-1 "
	DashResetPW endpoint = "api/users/{user-id}/actions/reset"
)

const orgTemplate = `
{
	"owner_name": "{{.Owner}}",
	"cname": "{{.PortalHostname}}",
	"cname_enabled": true,
	"hybrid_enabled": true,
	"event_options" : {
		"key_event" : {
			"redis" : true
		},
		"hashed_key_event" : {
			"redis" : true
		}
	}
}
`

const userTemplate = `
{
	"first_name": "{{.FName}}",
	"last_name": "{{.LName}}",
	"email_address": "{{.Email}}",
	"active": true,
	"password": "{{.Pass}}",
	"org_id": "{{.Org}}",
	"user_permissions": {
		"IsAdmin": "admin"
	}
}`

const passTemplate = `
{
	{{if .Old}}"current_password": "{{.Old}}",{{end}}
	"new_password":"{{.New}}"
}`

type APIResponseData struct {
	Status  string
	Message string
	Meta    interface{}
}

type KeyResponseData struct {
	Data  user.SessionState `json:"data"`
	KeyID string            `json:"key_id"`
}

type PolicyListResponse struct {
	Data []models.Policy `json:"data"`
}

type DashboardAPIDefinition struct {
	APIDefinition   apidef.APIDefinition `json:"api_definition"`
	UserGroupOwners []string             `json:"user_group_owners,omitempty"`
	UserOwners      []string             `json:"user_owners,omitempty"`
}

func (t *TykAPIHandler) getURL(e endpoint) (url string) {
	defer func() {
		log.WithFields(logrus.Fields{
			"url": url,
		}).Info("getURL")
	}()

	url = fmt.Sprintf("%s/%s", t.conf.DashboardEndpoint, e)
	if strings.Contains(t.conf.DashboardEndpoint, "https://") || strings.Contains(t.conf.DashboardEndpoint, "http://") {
		return url
	}

	url = fmt.Sprintf("http://%s", url)

	return url
}

// secureReq applies some auth headers to the given request, and will also set the 'Content-Type' header to
// 'application/json'.
func (t *TykAPIHandler) secureReq(r *http.Request) {
	log.Debug("securing api request with: ", t.conf.Secret)

	r.Header.Set("admin-auth", t.conf.Secret)
	r.Header.Set("Authorization", t.conf.Secret)
	r.Header.Set("Content-Type", "application/json")
}

// redirectCheckWithAuth replaces the default http lib check with addition of Tyk auth headers.
//
// This is needed because Go http client doesn't set "Authorization" header when following a redirect unless it's
// on the same domain or its subdomain for security reasons. Yet, due to how it's implemented it's also not set
// on the same domain/subdomain when redirect to a different protocol e.g. "http://" -> "https://".
// At this point we're using "http://" by default, which is then usually redirected to "https://" by infra,
// thus losing the header and getting requests rejected as unauthorised.
func (t *TykAPIHandler) redirectCheckWithAuth(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}

	t.secureReq(req)

	return nil
}

func (t *TykAPIHandler) readRawBody(resp *http.Response) string {
	defer resp.Body.Close()
	body, rErr := io.ReadAll(resp.Body)

	if rErr != nil {
		log.Error("failed to read raw response body")
	}

	return string(body)
}

func (t *TykAPIHandler) readBody(resp *http.Response, as interface{}) error {
	defer resp.Body.Close()
	body, rErr := io.ReadAll(resp.Body)

	log.Debug("body is:", string(body))
	if rErr != nil {
		return rErr
	}

	return json.Unmarshal(body, as)
}

// getClient configures and returns an http.Client instance
func (t *TykAPIHandler) initClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig.InsecureSkipVerify = true

	client := &http.Client{
		Transport:     tr,
		CheckRedirect: t.redirectCheckWithAuth,
	}

	return client
}

func (t *TykAPIHandler) CreateOrg(orgName, portalHostname string) (oID string, err error) {
	defer func() {
		log.WithFields(logrus.Fields{
			"orgID": oID,
			"error": err,
		}).Info("CreateOrg")
	}()

	tpl := template.New("org") // Create a template.
	tpl.Parse(orgTemplate)

	b := &backoff.Backoff{
		Max:    1 * time.Minute,
		Min:    5 * time.Second,
		Factor: 2,
	}
	var resp *http.Response
	reqFail := 0
	for {
		var d bytes.Buffer

		data := map[string]string{
			"Owner": orgName,
		}

		if portalHostname != "" {
			data["PortalHostname"] = portalHostname
		}

		tpl.ExecuteTemplate(&d, "org", data)

		req, err := http.NewRequest("POST", t.getURL(AdminOrgs), &d)
		if err != nil {
			return "", err
		}
		t.secureReq(req)

		if reqFail == 3 {
			return "", errors.New("failure trying to create org (too many errors)")
		}

		resp, err = t.client.Do(req)
		if err != nil {
			d := b.Duration()
			log.Errorf("client error: %s, retrying in %s", err, d)
			reqFail += 1
			time.Sleep(d)
			continue
		}

		b.Reset()
		break
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API retured failure code: %v and error %s", resp.StatusCode, t.readRawBody(resp))
	}

	org := &APIResponseData{}
	if err := t.readBody(resp, org); err != nil {
		return "", err
	}

	orgID, ok := org.Meta.(string)
	if !ok {
		return "", errors.New("org ID expected a string got different type")
	}

	return orgID, nil
}

func (t *TykAPIHandler) FetchOrg(orgID string) (orG interface{}, err error) {
	defer func() {
		log.WithFields(logrus.Fields{
			"error": err,
		}).Info("FetchOrg")
	}()

	tpl := template.New("org") // Create a template.
	tpl.Parse(orgTemplate)

	b := &backoff.Backoff{
		Max:    1 * time.Minute,
		Min:    5 * time.Second,
		Factor: 2,
	}
	var resp *http.Response
	reqFail := 0
	for {
		var d bytes.Buffer

		url := strings.Replace(string(AdminOrg), "{org-id}", orgID, 1)
		req, err := http.NewRequest("GET", t.getURL(endpoint(url)), &d)
		if err != nil {
			return "", err
		}
		t.secureReq(req)

		if reqFail == 3 {
			return "", errors.New("failure trying to fetch org (too many errors)")
		}

		resp, err = t.client.Do(req)
		if err != nil {
			d := b.Duration()
			log.Errorf("client error: %s, retrying in %s", err, d)
			reqFail += 1
			time.Sleep(d)
			continue
		}

		b.Reset()
		break
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API retured failure code: %v and error %s", resp.StatusCode, t.readRawBody(resp))
	}

	org := &map[string]interface{}{}
	if err := t.readBody(resp, org); err != nil {
		return "", err
	}

	return org, nil
}

func (t *TykAPIHandler) UpdateOrg(orgID string, orgData []byte) (err error) {
	defer func() {
		log.WithFields(logrus.Fields{
			"orgID": orgID,
			"error": err,
		}).Info("UpdateOrg")
	}()

	b := &backoff.Backoff{
		Max:    1 * time.Minute,
		Min:    5 * time.Second,
		Factor: 2,
	}
	var resp *http.Response
	reqFail := 0
	for {
		url := strings.Replace(string(AdminOrg), "{org-id}", orgID, 1)
		req, err := http.NewRequest("PUT", t.getURL(endpoint(url)), bytes.NewReader(orgData))
		if err != nil {
			return err
		}
		t.secureReq(req)

		if reqFail == 3 {
			return errors.New("failure trying to update org (too many errors)")
		}

		resp, err = t.client.Do(req)
		if err != nil {
			d := b.Duration()
			log.Errorf("client error: %s, retrying in %s", err, d)
			reqFail += 1
			time.Sleep(d)
			continue
		}

		b.Reset()
		break
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API retured failure code: %v and error %s", resp.StatusCode, t.readRawBody(resp))
	}

	return nil
}

func (t *TykAPIHandler) CreateUser(fname, lname, email, pass, orgID string) (accessKey, id string, err error) {
	defer func() {
		log.WithFields(logrus.Fields{
			"orgID": orgID,
			"uid":   id,
			"error": err,
		}).Info("CreateUser")
	}()

	tpl := template.New("user") // Create a template.
	tpl.Parse(userTemplate)

	b := &backoff.Backoff{
		Max:    1 * time.Minute,
		Min:    5 * time.Second,
		Factor: 2,
	}

	var resp *http.Response
	reqFail := 0
	for {
		var d bytes.Buffer
		data := map[string]string{
			"FName": fname,
			"LName": lname,
			"Email": email,
			"Pass":  pass,
			"Org":   orgID,
		}

		tpl.ExecuteTemplate(&d, "user", data)

		var d2 bytes.Buffer
		tpl.ExecuteTemplate(&d2, "user", data)

		req, err := http.NewRequest("POST", t.getURL(AdminUser), &d)
		if err != nil {
			return "", "", err
		}

		t.secureReq(req)

		if reqFail == 3 {
			return "", "", errors.New("failure trying to create org (too many errors)")
		}

		resp, err = t.client.Do(req)
		if err != nil {
			d := b.Duration()
			log.Errorf("client error: %s, retrying in %s", err, d)
			reqFail += 1
			time.Sleep(d)
			continue
		}

		b.Reset()
		break
	}

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("API retured failure code: %v and error %s", resp.StatusCode, t.readRawBody(resp))
	}

	rData := &APIResponseData{}
	if err := t.readBody(resp, rData); err != nil {
		return "", "", err
	}

	user, ok := rData.Meta.(map[string]interface{})
	if !ok {
		return "", "", errors.New("users expected a map, got something else")
	}

	key := user["access_key"].(string)
	uid := user["id"].(string)

	return key, uid, nil
}

func (t *TykAPIHandler) ResetPassword(key, uid, old, new string) error {
	tpl := template.New("password") // Create a template.
	tpl.Parse(passTemplate)

	b := &backoff.Backoff{
		Max:    1 * time.Minute,
		Min:    5 * time.Second,
		Factor: 2,
	}
	var resp *http.Response
	reqFail := 0
	for {
		var d bytes.Buffer

		data := map[string]string{
			"Old": old,
			"New": new,
		}

		tpl.ExecuteTemplate(&d, "password", data)
		url := t.getURL(DashResetPW)
		url = strings.Replace(url, "{user-id}", uid, 1)

		req, err := http.NewRequest("POST", url, &d)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", key)

		if reqFail == 3 {
			return errors.New("failure trying to reset pw (too many errors)")
		}

		resp, err = t.client.Do(req)
		if err != nil {
			d := b.Duration()
			log.Errorf("client error: %s, retrying in %s", err, d)
			reqFail += 1
			time.Sleep(d)
			continue
		}

		b.Reset()
		break
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API retured failure code: %v and error %s", resp.StatusCode, t.readRawBody(resp))
	}

	return nil
}

func (t *TykAPIHandler) GetAllPolicies() (pols []models.Policy, err error) {
	defer func() {
		log.WithFields(logrus.Fields{
			"error": err,
		}).Info("GetAllPolicies")
	}()

	b := &backoff.Backoff{
		Max:    1 * time.Minute,
		Min:    5 * time.Second,
		Factor: 2,
	}

	URL := t.getURL(PolicyList)

	var resp *http.Response
	reqFail := 0
	for {
		var d bytes.Buffer
		req, err := http.NewRequest("GET", URL, &d)
		if err != nil {
			return nil, err
		}

		t.secureReq(req)

		if reqFail == 3 {
			return nil, errors.New("failure trying to fetch key detail")
		}

		resp, err = t.client.Do(req)
		if err != nil {
			d := b.Duration()
			log.Errorf("client error: %s, retrying in %s", err, d)
			reqFail += 1
			time.Sleep(d)
			continue
		}

		b.Reset()
		break
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API retured failure code: %v and error %s", resp.StatusCode, t.readRawBody(resp))
	}

	rData := &PolicyListResponse{}
	if err := t.readBody(resp, rData); err != nil {
		return nil, err
	}

	// Fix IDs
	ret := make([]models.Policy, len(rData.Data))
	for i, p := range rData.Data {
		p.ID = p.MID.Hex()
		ret[i] = p
	}

	return ret, nil
}

func (t *TykAPIHandler) GetKeyDetail(key string) (us *user.SessionState, err error) {
	defer func() {
		log.WithFields(logrus.Fields{
			"error": err,
		}).Info("GetKeyDetail")
	}()

	b := &backoff.Backoff{
		Max:    1 * time.Minute,
		Min:    5 * time.Second,
		Factor: 2,
	}

	kdURL := strings.Replace(t.getURL(KeyDetail), "{key-id}", key, 1)
	log.Debug("fetching ", kdURL)

	var resp *http.Response
	reqFail := 0
	for {
		var d bytes.Buffer
		req, err := http.NewRequest("GET", kdURL, &d)
		if err != nil {
			return nil, err
		}

		t.secureReq(req)

		if reqFail == 3 {
			return nil, errors.New("failure trying to fetch key detail")
		}

		resp, err = t.client.Do(req)
		if err != nil {
			d := b.Duration()
			log.Errorf("client error: %s, retrying in %s", err, d)
			reqFail += 1
			time.Sleep(d)
			continue
		}

		b.Reset()
		break
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API retured failure code: %v and error %s", resp.StatusCode, t.readRawBody(resp))
	}

	rData := &KeyResponseData{}
	if err := t.readBody(resp, rData); err != nil {
		return nil, err
	}

	return &rData.Data, nil
}

func (t *TykAPIHandler) CreateAPI(apiDef []byte) (id string, err error) {
	defer func() {
		log.WithFields(logrus.Fields{
			"id":    id,
			"error": err,
		}).Info("CreateAPI")
	}()

	b := &backoff.Backoff{
		Max:    1 * time.Minute,
		Min:    5 * time.Second,
		Factor: 2,
	}

	aURL := t.getURL(APIDef)
	log.Info("tyk API client calling ", aURL)

	var resp *http.Response
	reqFail := 0
	for {
		req, err := http.NewRequest("POST", aURL, bytes.NewBuffer(apiDef))
		if err != nil {
			return "", err
		}

		t.secureReq(req)

		if reqFail == 3 {
			return "", errors.New("failure trying to post api def")
		}

		resp, err = t.client.Do(req)
		if err != nil {
			d := b.Duration()
			log.Errorf("client error: %s, retrying in %s", err, d)
			reqFail += 1
			time.Sleep(d)
			continue
		}

		b.Reset()
		break
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API retured failure code: %v and error %s", resp.StatusCode, t.readRawBody(resp))
	}

	rData := &APIResponseData{}
	if err := t.readBody(resp, rData); err != nil {
		return "", err
	}

	idStr, ok := rData.Meta.(string)
	if !ok {
		return "", errors.New("ID is not a string")
	}

	return idStr, nil
}

func (t *TykAPIHandler) GetAPIDetail(id string) (data *DashboardAPIDefinition, err error) {
	defer func() {
		log.WithFields(logrus.Fields{
			"error": err,
		}).Info("GetAPIDetail")
	}()

	b := &backoff.Backoff{
		Max:    1 * time.Minute,
		Min:    5 * time.Second,
		Factor: 2,
	}

	aURL := t.getURL(APIDef) + "/" + id
	log.Debug("fetching ", aURL)

	var resp *http.Response
	reqFail := 0
	for {
		var d bytes.Buffer
		req, err := http.NewRequest("GET", aURL, &d)
		if err != nil {
			return nil, err
		}

		t.secureReq(req)

		if reqFail == 3 {
			return nil, errors.New("failure trying to fetch api detail")
		}

		resp, err = t.client.Do(req)
		if err != nil {
			d := b.Duration()
			log.Errorf("client error: %s, retrying in %s", err, d)
			reqFail += 1
			time.Sleep(d)
			continue
		}

		b.Reset()
		break
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API retured failure code: %v and error %s", resp.StatusCode, t.readRawBody(resp))
	}

	rData := &DashboardAPIDefinition{}
	if err := t.readBody(resp, rData); err != nil {
		return nil, err
	}

	return rData, nil
}

func (t *TykAPIHandler) DeleteAPI(id string) (err error) {
	defer func() {
		log.WithFields(logrus.Fields{
			"id":    id,
			"error": err,
		}).Info("DeleteAPI")
	}()

	b := &backoff.Backoff{
		Max:    1 * time.Minute,
		Min:    5 * time.Second,
		Factor: 2,
	}

	aURL := t.getURL(APIDef) + "/" + id
	log.Debug("deleting ", aURL)

	var resp *http.Response
	reqFail := 0
	for {
		var d bytes.Buffer
		req, err := http.NewRequest("DELETE", aURL, &d)
		if err != nil {
			return err
		}

		t.secureReq(req)

		if reqFail == 3 {
			return errors.New("failure trying to delete api")
		}

		resp, err = t.client.Do(req)
		if err != nil {
			d := b.Duration()
			log.Errorf("client error: %s, retrying in %s", err, d)
			reqFail += 1
			time.Sleep(d)
			continue
		}

		b.Reset()
		break
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API retured failure code: %v and error %s", resp.StatusCode, t.readRawBody(resp))
	}

	rData := &APIResponseData{}
	if err := t.readBody(resp, rData); err != nil {
		return err
	}

	return nil
}

func (t *TykAPIHandler) ReloadDashboardUrls() (err error) {
	defer func() {
		log.WithFields(logrus.Fields{
			"error": err,
		}).Info("ReloadDashboardUrls")
	}()

	b := &backoff.Backoff{
		Max:    1 * time.Minute,
		Min:    5 * time.Second,
		Factor: 2,
	}

	aURL := t.getURL(AdminReload)
	log.Debug("fetching ", aURL)

	var resp *http.Response
	reqFail := 0
	for {
		var d bytes.Buffer
		req, err := http.NewRequest("GET", aURL, &d)
		if err != nil {
			return err
		}

		t.secureReq(req)

		if reqFail == 3 {
			return errors.New("failure trying to reload dashboard urls")
		}

		resp, err = t.client.Do(req)
		if err != nil {
			d := b.Duration()
			log.Errorf("client error: %s, retrying in %s", err, d)
			reqFail += 1
			time.Sleep(d)
			continue
		}

		b.Reset()
		break
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API retured failure code: %v and error %s", resp.StatusCode, t.readRawBody(resp))
	}

	return nil
}

func (t *TykAPIHandler) CreateAccessToken(org string, accessList []user.AccessDefinition) (key string, err error) {
	defer func() {
		log.WithFields(logrus.Fields{
			"org":   org,
			"error": err,
		}).Info("CreateAccessToken")
	}()

	b := &backoff.Backoff{
		Max:    1 * time.Minute,
		Min:    5 * time.Second,
		Factor: 2,
	}

	aURL := t.getURL(Keys)
	log.Debug("fetching ", aURL)

	var resp *http.Response
	reqFail := 0

	aRights := map[string]user.AccessDefinition{}
	for _, ad := range accessList {
		aRights[ad.APIID] = ad
	}

	keyData := user.SessionState{
		Rate:         100,
		Per:          1,
		Allowance:    100,
		Expires:      -1,
		QuotaMax:     -1,
		OrgID:        org,
		Alias:        "mserv-clients",
		AccessRights: aRights,
		Tags:         []string{"mserv-clients"},
		MetaData: map[string]interface{}{
			"created": time.Now().String(),
		},
	}

	asJson, err := json.Marshal(keyData)
	if err != nil {
		return "", err
	}

	log.Debug("Sending: ", string(asJson))

	for {
		req, err := http.NewRequest("POST", aURL, bytes.NewBuffer(asJson))
		if err != nil {
			return "", err
		}

		t.secureReq(req)

		if reqFail == 3 {
			return "", errors.New("failure trying to post key data")
		}

		resp, err = t.client.Do(req)
		if err != nil {
			d := b.Duration()
			log.Errorf("client error: %s, retrying in %s", err, d)
			reqFail += 1
			time.Sleep(d)
			continue
		}

		b.Reset()
		break
	}

	if resp.StatusCode != http.StatusOK {
		log.WithField("url", aURL).Errorf("API call error: %d", resp.StatusCode)
		return "", fmt.Errorf("API retured failure code: %v and error %s", resp.StatusCode, t.readRawBody(resp))
	}

	rData := &KeyResponseData{}
	if err := t.readBody(resp, rData); err != nil {
		return "", err
	}

	return rData.KeyID, nil
}

func (t *TykAPIHandler) CreateOrgKey(keyData user.SessionState) (key string, err error) { //nolint:gocritic
	defer func() {
		log.WithFields(logrus.Fields{
			"error": err,
		}).Info("CreateOrgKey")
	}()

	b := &backoff.Backoff{
		Max:    1 * time.Minute,
		Min:    5 * time.Second,
		Factor: 2,
	}

	aURL := t.getURL(OrgKey)
	log.Debug("fetching ", aURL)

	var resp *http.Response
	reqFail := 0

	keyData.Tags = make([]string, 0)
	keyData.MetaData = make(map[string]interface{})

	asJson, err := json.Marshal(keyData)
	if err != nil {
		return "", err
	}

	log.Debug("Sending: ", string(asJson))

	for {
		req, err := http.NewRequest("POST", aURL, bytes.NewBuffer(asJson))
		if err != nil {
			return "", err
		}

		t.secureReq(req)

		if reqFail == 3 {
			return "", errors.New("failure trying to post key data")
		}

		resp, err = t.client.Do(req)
		if err != nil {
			d := b.Duration()
			log.Errorf("client error: %s, retrying in %s", err, d)
			reqFail += 1
			time.Sleep(d)
			continue
		}

		b.Reset()
		break
	}

	if resp.StatusCode != http.StatusOK {
		// older version of dashboard doesn't have org key creation endpoint
		if resp.StatusCode == http.StatusNotFound {
			log.WithFields(logrus.Fields{
				"url":  aURL,
				"code": resp.StatusCode,
			}).Error("Failed to create org key. Using older Dashboard version")
			return "", nil
		} else {
			log.WithFields(logrus.Fields{
				"url":  aURL,
				"code": resp.StatusCode,
			}).Error("API call error")
			return "", fmt.Errorf("API retured failure code: %v and error %s", resp.StatusCode, t.readRawBody(resp))
		}
	}

	rData := &KeyResponseData{}
	if err := t.readBody(resp, rData); err != nil {
		return "", err
	}

	return rData.KeyID, nil
}

func (t *TykAPIHandler) Init(cfg *TykAPIConfig) error {
	t.conf = cfg

	t.client = t.initClient()

	c1 := make(chan bool, 1)
	go func() {
		errorCount := 0
		okCount := 0
		i := 0
		for {
			if errorCount > 30 {
				break
			}

			i += 1
			time.Sleep(time.Duration(t.conf.AvailabilityWait) * time.Second)

			req, _ := http.NewRequest(http.MethodGet, t.getURL(Root), nil)

			resp, err := t.client.Do(req)
			if err != nil {
				log.WithError(err).WithFields(logrus.Fields{
					"method": req.Method,
					"url":    t.getURL(Root),
				}).Error("client request failed")
				errorCount += 1
				continue
			}

			_ = resp.Body.Close() // it's a loop so must be closed without defer

			if resp.StatusCode != http.StatusOK {
				log.WithFields(logrus.Fields{
					"status": resp.StatusCode,
					"url":    t.getURL(Root),
				}).Error("unexpected status code")
				errorCount += 1
				continue
			}

			log.Debugf("--> Availability OK (sample: %v)", i)
			okCount += 1

			// Make sure we can connect
			if okCount == t.conf.AvailabilityTests {
				c1 <- true
				break
			}
		}
	}()

	select {
	case res := <-c1:
		if res {
			log.Debug("dashboard available, initialising driver")
			return nil
		}
		return errors.New("channel returned false")

	case <-time.After(360 * time.Second):
		return errors.New("dashboard API is unreachable in 360s, failing")
	}
}

func (t *TykAPIHandler) GetConf() *TykAPIConfig {
	return t.conf
}

func (t *TykAPIHandler) UpdateDashboardLicense(license string) (err error) {
	defer func() {
		log.WithFields(logrus.Fields{
			"error": err,
		}).Info("UpdateDashboardLicense")
	}()

	b := &backoff.Backoff{
		Max:    1 * time.Minute,
		Min:    5 * time.Second,
		Factor: 2,
	}
	var resp *http.Response
	reqFail := 0
	v := url.Values{"license": []string{license}}

	for {
		req, err := http.NewRequest(http.MethodPost, t.getURL(License), strings.NewReader(v.Encode()))
		if err != nil {
			return err
		}

		t.secureReq(req)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		if reqFail >= 3 {
			return errors.New("failure trying to update Tyk Dashboard license (too many errors)")
		}

		resp, err = t.client.Do(req)
		if err != nil {
			reqFail++

			d := b.Duration()
			log.WithError(err).Errorf("client error; retrying in %s", d)
			time.Sleep(d)

			continue
		}

		break
	}

	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusNotFound:
		return fmt.Errorf("%w: Tyk Dashboard", ErrNotFound)
	default:
		return fmt.Errorf("Tyk Dashboard license update via API failed with status code %d and error '%s'",
			resp.StatusCode, t.readRawBody(resp))
	}
}

func NewHandler(cfg *TykAPIConfig) (Handler, error) {
	if cfg.Mock {
		return NewMockHandler(cfg)
	}

	t := &TykAPIHandler{}
	err := t.Init(cfg)

	return t, err
}
