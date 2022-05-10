package handlers

const (
	StatOK  = "ok"
	StatErr = "error"
)

type RestResponse struct {
	Status  string
	Payload interface{}
	Error   string
}
