package handlers

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/TykTechnologies/momo/pkg/logger"

	"github.com/TykTechnologies/momo/core/server/api"
)

var (
	moduleName = "momo.server.handlers"
	log        = logger.GetAndExcludeLoggerFromTrace(moduleName)
)

type Handler struct{}

func (h *Handler) writeOK(w http.ResponseWriter, r *http.Request, payload interface{}, status int) {
	resp := &RestResponse{
		Status:  StatOK,
		Payload: payload,
	}

	asJS, err := json.Marshal(resp)
	if err != nil {
		h.writeError(w, r, err.Error(), 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(asJS)
}

func (h *Handler) writeError(w http.ResponseWriter, r *http.Request, message string, status int) {
	log.Error(message)
	resp := &RestResponse{
		Status: StatErr,
		Error:  message,
	}

	asJS, err := json.Marshal(resp)
	if err != nil {
		log.Error(err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(asJS)
}

func (h *Handler) HealthHandler(w http.ResponseWriter, r *http.Request) {
	h.writeOK(w, r, "ok", http.StatusOK)
}

func (h *Handler) APIEventHookHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.writeError(w, r, err.Error(), http.StatusBadRequest)
		return
	}

	pl := &WHAPIEvent{}
	err = json.Unmarshal(body, pl)
	if err != nil {
		h.writeError(w, r, err.Error(), http.StatusBadRequest)
		return
	}

	log.Info("hook received: ", string(body))
	log.Info(pl.Data.APIDefinition.APIDefinition.VersionData)

	err = api.ProcessAPIEvent(pl.Event, &pl.Data.APIDefinition.APIDefinition)
	if err != nil {
		h.writeError(w, r, err.Error(), http.StatusInternalServerError)
		return
	}

	h.writeOK(w, r, "payload processed", http.StatusOK)
}

func (h *Handler) KeyEventHookHandler(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		h.writeError(w, r, err.Error(), http.StatusBadRequest)
		return
	}

	pl := &WHKeyEvent{}
	err = json.Unmarshal(body, pl)
	if err != nil {
		h.writeError(w, r, err.Error(), http.StatusBadRequest)
		return
	}

	log.Info("key hook received: ", string(body))

	err = api.ProcessKeyEvent(pl.Event, &pl.Data)
	if err != nil {
		h.writeError(w, r, err.Error(), http.StatusInternalServerError)
		return
	}

	h.writeOK(w, r, "payload processed", http.StatusOK)
}
