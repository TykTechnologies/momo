package types

import (
	"github.com/TykTechnologies/tyk/apidef"
	"github.com/TykTechnologies/tyk/user"

	"github.com/TykTechnologies/momo/pkg/models"
)

type GatewayDriver interface {
	Init() error
	Name() string
	CreateOrUpdate(def *apidef.APIDefinition) error
	Delete(apiID string) error
	CreateAPIKey(id string, state *user.SessionState) (string, error)
	DeleteAPIKey(string) error
	DeletePolicy(meta models.DriverExtension) error
	AddPolicy(p models.Policy) (*models.DriverExtension, error)
	UpdatePolicy(p models.PolicyMap) (models.DriverExtension, error)
}
