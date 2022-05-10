package tyk_api

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/jpillora/backoff"
)

type SSORequest struct {
	ForSection   string
	OrgID        string
	EmailAddress string
}

func (t *TykAPIHandler) CreateAccessURL(orgID string) (string, error) {
	dat := SSORequest{
		ForSection:   "dashboard",
		OrgID:        orgID,
		EmailAddress: "ara-access@ara.app",
	}

	asJson, err := json.Marshal(dat)
	if err != nil {
		return "", err
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	b := &backoff.Backoff{
		Max:    1 * time.Minute,
		Min:    5 * time.Second,
		Factor: 2,
	}

	var resp *http.Response
	reqFail := 0
	for {
		req, err := http.NewRequest("POST", t.getURL(SSO), bytes.NewBuffer(asJson))
		if err != nil {
			return "", err
		}

		t.secureReq(req)

		if reqFail == 3 {
			return "", errors.New("failure trying to create org (too many errors)")
		}

		resp, err = client.Do(req)
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

	nonce, ok := rData.Meta.(string)
	if !ok {
		return "", errors.New("nonce expected a string, got something else")
	}

	accessURL := fmt.Sprintf("https://%s/tap?nonce=%s", t.conf.DashboardEndpoint, nonce)

	return accessURL, nil
}
