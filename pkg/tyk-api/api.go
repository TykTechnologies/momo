package tyk_api

import (
	"sync"

	"github.com/TykTechnologies/tyk/user"

	"github.com/TykTechnologies/momo/pkg/models"
)

type Handler interface {
	CreateOrg(orgName, portalHostname string) (string, error)
	FetchOrg(orgID string) (interface{}, error)
	UpdateOrg(orgID string, orgData []byte) error
	CreateUser(fname, lname, email, pass, orgID string) (string, string, error)
	ResetPassword(key, uid, old, new string) error
	GetKeyDetail(key string) (*user.SessionState, error)
	CreateAccessToken(org string, accessList []user.AccessDefinition) (string, error)
	GetAllPolicies() ([]models.Policy, error)
	CreateAccessURL(orgID string) (string, error)
	CreateAPI(apiDef []byte) (string, error)
	GetAPIDetail(id string) (*DashboardAPIDefinition, error)
	DeleteAPI(id string) error
	ReloadDashboardUrls() error
	Init(cfg *TykAPIConfig) error
	CreateOrgKey(orgKeyData user.SessionState) (string, error)
	GetConf() *TykAPIConfig
	UpdateDashboardLicense(license string) error
}

// cachedClientOnce provides to usage for singleton implementation.
var cachedClientOnce sync.Once

// cachedClient represents singleton value
var cachedClient CachedClient

// CachedClient represents methods in cacheClient
type CachedClient interface {
	Add(name string, h Handler)
	Get(name string) Handler
}

// GetCachedClients returns a singleton CachedClient
func GetCachedClients() CachedClient {
	cachedClientOnce.Do(func() {
		cachedClient = &cacheClient{client: map[string]Handler{}}
	})

	return cachedClient
}

// cacheClient is store client map
type cacheClient struct {
	client map[string]Handler
	mu     sync.RWMutex
}

// Add adds a Handler with the name to the map
func (c *cacheClient) Add(name string, h Handler) {
	c.mu.Lock()
	c.client[name] = h
	c.mu.Unlock()
}

// Get returns Handler by name
func (c *cacheClient) Get(name string) Handler {
	c.mu.RLock()
	h := c.client[name]
	c.mu.RUnlock()

	return h
}
