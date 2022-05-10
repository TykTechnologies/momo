package server

import (
	"net/http"
	"time"

	"github.com/TykTechnologies/momo/pkg/logger"

	_ "github.com/TykTechnologies/momo/core/drivers/aws"
	_ "github.com/TykTechnologies/momo/core/drivers/kong"
	"github.com/TykTechnologies/momo/core/server/api"
)

var (
	moduleName = "momo.server"
	log        = logger.GetAndExcludeLoggerFromTrace(moduleName)
)

func Start() {
	r := getRouter()
	initEndpoints(r)

	srv := &http.Server{
		Handler: r,
		Addr:    "0.0.0.0:7878",

		WriteTimeout: 60 * time.Second,
		ReadTimeout:  60 * time.Second,
	}

	log.Info("starting up polling jobs")
	policyCheck := &api.PolicyChecker{}
	go func() {
		for {
			err := policyCheck.Sync()
			if err != nil {
				log.Error(err)
			}
			time.Sleep(10 * time.Second)
		}
	}()

	log.Infof("listening on %v", "0.0.0.0")
	if err := srv.ListenAndServe(); err != nil {
		// cannot panic, because this probably is an intentional close
		log.Warning("stopped listening: ", err)
	}
}
