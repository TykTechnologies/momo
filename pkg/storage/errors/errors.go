// Package errors exports errors for use by the various storage implementations.
package errors

import "errors"

var (
	ErrNotFound                 = errors.New("not found")
	ErrTeamIDRequired           = errors.New("team ID required")
	ErrOrgIDRequired            = errors.New("org ID required")
	ErrLoadoutIDRequired        = errors.New("loadout ID required")
	ErrDeploymentIDRequired     = errors.New("deployment ID required")
	ErrEntitlementIDRequired    = errors.New("entitlement ID cannot be empty")
	ErrMomoAPIIDRequired        = errors.New("api ID cannot be empty")
	ErrMomoKeyIDRequired        = errors.New("key ID cannot be empty")
	ErrMomoPolicyIDRequired     = errors.New("policy ID cannot be empty")
	ErrDeploymentNotFound       = errors.New("deployment not found")
	ErrOrgNotFound              = errors.New("organisation not found")
	ErrLoadoutNotFound          = errors.New("loadout not found")
	ErrTeamNotFound             = errors.New("team not found")
	ErrOwnerNotFound            = errors.New("owner not found")
	ErrAccessGrantNotFound      = errors.New("access grant not found")
	ErrAccessGrantExpired       = errors.New("grant has expired, please renew")
	ErrMomoRefNotFound          = errors.New("momo reference not found")
	ErrMomoKeyNotFound          = errors.New("momo key not found")
	ErrMomoPolicyNotFound       = errors.New("momo policy not found")
	ErrGuestDepNotFound         = errors.New("guest deployment not found")
	ErrGuestNotFound            = errors.New("guest not found")
	ErrEntitlementNotFound      = errors.New("entitlement plan not found")
	ErrTrafficReportNotFound    = errors.New("traffic report not found")
	ErrOrgTrafficReportNotFound = errors.New("org traffic report not found")
	ErrDepStorageReportNotFound = errors.New("storage report for deployment not found")
	ErrOrgStorageReportNotFound = errors.New("storage report for organisation not found")
	ErrNamespaceRequired        = errors.New("namespace required")
	ErrCastToOrganisation       = errors.New("value from Store.organisation cannot be cast into *models.Organisation")

	NotFoundErrors = []error{
		ErrNotFound, ErrOrgNotFound, ErrTeamNotFound, ErrLoadoutNotFound, ErrDeploymentNotFound,
		ErrEntitlementNotFound, ErrAccessGrantNotFound, ErrOwnerNotFound, ErrGuestNotFound, ErrGuestDepNotFound,
		ErrMomoPolicyNotFound, ErrMomoKeyNotFound, ErrMomoRefNotFound, ErrEntitlementNotFound,
		ErrTrafficReportNotFound, ErrOrgTrafficReportNotFound,
	}
)
