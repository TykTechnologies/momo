package handlers

import (
	"github.com/TykTechnologies/tyk/apidef"

	"github.com/TykTechnologies/momo/pkg/models"
)

type Webhook struct {
	Event string `json:"event"`
}

type WHAPIEvent struct {
	Webhook
	Data struct {
		APIDefinition struct {
			apidef.APIDefinition
		} `json:"api_definition"`
	} `json:"data"`
}

type WHKeyEvent struct {
	Webhook
	Data models.KeyData `json:"data"`
}
