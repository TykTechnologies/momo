package tyk_api

import (
	conf "github.com/TykTechnologies/momo/core/config"
)

type TykAPIConfig struct {
	DashboardEndpoint string
	Secret            string

	// AvailabilityTests is the number of availability checks that must pass before the API is considered available.
	// Defaults to 3.
	AvailabilityTests int

	// AvailabilityWait is the number of seconds to wait between availability checks.
	// Defaults to 10.
	AvailabilityWait int

	Mock bool
}

type Config struct {
	TykAPI map[string]*TykAPIConfig
}

var sconf *Config

var GetConf = func() *Config {
	if sconf == nil {
		sconf = &Config{}

		err := conf.GetModuleConf(sconf, "ARA_TYKAPI", nil)
		if err != nil {
			log.Fatal("Failed to unmarshal api client config: ", err)
		}

		SetDefaults()
	}

	return sconf
}

func SetDefaults() {
	for t, c := range sconf.TykAPI {
		if c.AvailabilityTests == 0 {
			sconf.TykAPI[t].AvailabilityTests = 3
		}

		if c.AvailabilityWait == 0 {
			sconf.TykAPI[t].AvailabilityWait = 10
		}
	}
}
