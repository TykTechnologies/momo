package api

import (
	"errors"
	"fmt"
	"strings"

	tyk_api "github.com/TykTechnologies/momo/pkg/tyk-api"
	"github.com/TykTechnologies/momo/pkg/models"

	"github.com/TykTechnologies/momo/core/config"
	"github.com/TykTechnologies/momo/core/drivers"
)

type PolicyChecker struct{}

func (p *PolicyChecker) convertToMap(pols []models.Policy) map[string]models.Policy {
	mappedPols := map[string]models.Policy{}
	for _, stP := range pols {
		mappedPols[stP.ID] = stP
	}

	return mappedPols
}

func (p *PolicyChecker) convertPolicyMapArrayToMap(pols []models.PolicyMap) map[string]models.PolicyMap {
	mappedPols := map[string]models.PolicyMap{}
	for _, stP := range pols {
		mappedPols[stP.ID] = stP
	}

	log.Debug(mappedPols)
	return mappedPols
}

func (p *PolicyChecker) Sync() error {
	// Fetch all policies
	apiCfg := tyk_api.GetConf()
	momoConf := config.GetConf()
	taggedConf, ok := apiCfg.TykAPI[momoConf.Momo.TykAPITag]
	if !ok {
		return fmt.Errorf("tag not found: %s", momoConf.Momo.TykAPITag)
	}

	tyk, err := tyk_api.NewHandler(taggedConf)
	if err != nil {
		return err
	}

	// Fetch policies from the gateway
	tykPols, err := tyk.GetAllPolicies()
	if err != nil {
		return err
	}

	tykPolMap := p.convertToMap(tykPols)

	st, err := getStore()
	if err != nil {
		return err
	}

	// Fetch all known mapped policies
	storedPols, err := st.GetSyncedPolicies()
	if err != nil {
		return err
	}

	storedPolMap := p.convertPolicyMapArrayToMap(storedPols)

	// Find *new* policies
	// and *updated* policies
	newPols := map[string]models.Policy{}
	updatedPols := map[string]models.PolicyMap{}

	for id := range tykPolMap {
		_, found := storedPolMap[id]
		if !found {
			newPols[id] = tykPolMap[id]
			continue
		}

		// Found, so we want to know that we have a reference, has it changed?
		if tykPolMap[id].LastUpdated != storedPolMap[id].LastUpdated {
			updatedMap := storedPolMap[id]
			updatedMap.Policy = tykPolMap[id]

			updatedPols[id] = updatedMap
		}
	}

	log.Debug("NEW: ", newPols)

	// Find *deleted* policies
	deletedPols := map[string]models.PolicyMap{}

	for id := range storedPolMap {
		_, found := tykPolMap[id]
		if !found {
			deletedPols[id] = storedPolMap[id]
		}
	}

	// Collect errors
	errs := make([]string, 0)

	// Delete old policies first
	for _, p := range deletedPols {
		storeReference := true
		for driver, meta := range p.Drivers {
			d, err := drivers.GetDriver(strings.ToLower(driver))
			if err != nil {
				log.Error(err)
				continue
			}

			if err == nil {
				err = d.DeletePolicy(meta)
				if err != nil {
					errs = append(errs, fmt.Sprintf("delete: %s", err.Error()))
					storeReference = false
				}
			}
		}

		if storeReference {
			err := st.DeletePolicyMap(p)
			if err != nil {
				errs = append(errs, fmt.Sprintf("add (save): %s", err.Error()))
			}
		}
	}

	// Add new policies
	for _, p := range newPols {
		newPolicyMap := models.PolicyMap{Policy: p, Drivers: map[string]models.DriverExtension{}}
		storeReference := true
		for _, t := range p.Tags {
			d, err := drivers.GetDriver(strings.ToLower(t))
			if err == nil {
				log.Debug("Sending: ", p)
				driverExtensionData, err := d.AddPolicy(p)
				if err != nil {
					errs = append(errs, fmt.Sprintf("add: %s", err.Error()))
					storeReference = false
				}

				if driverExtensionData != nil {
					newPolicyMap.Drivers[strings.ToLower(t)] = *driverExtensionData
				}
			}
		}

		if storeReference {
			_, err := st.AddPolicyMap(newPolicyMap)
			if err != nil {
				errs = append(errs, fmt.Sprintf("add (save): %s", err.Error()))
			}
		}

	}

	// Update existing policies
	for _, p := range updatedPols {
		storeReference := true

		for driver := range p.Drivers {
			d, err := drivers.GetDriver(strings.ToLower(driver))
			if err == nil {
				driverExtensionData, err := d.UpdatePolicy(p)
				p.Drivers[driver] = driverExtensionData
				if err != nil {
					errs = append(errs, fmt.Sprintf("update: %s", err.Error()))
					storeReference = false
				}
			}
		}

		if storeReference {
			err := st.UpdatePolicyMap(p)
			if err != nil {
				errs = append(errs, fmt.Sprintf("update (save): %s", err.Error()))
			}
		}

	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}

	return nil
}
