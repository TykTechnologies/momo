package server

import (
	"github.com/gorilla/mux"

	"github.com/TykTechnologies/momo/core/server/handlers"
)

var rt *mux.Router

func getRouter() *mux.Router {
	rt = mux.NewRouter()
	return rt
}

func initEndpoints(r *mux.Router) {
	// Init our wrapper
	h := &handlers.Handler{}

	// Health endpoints
	r.HandleFunc("/health", h.HealthHandler).Methods("GET")
	r.HandleFunc("/events/api", h.APIEventHookHandler).Methods("POST")
	r.HandleFunc("/events/key", h.KeyEventHookHandler).Methods("POST")
}
