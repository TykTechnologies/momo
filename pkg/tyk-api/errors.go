package tyk_api

import "errors"

var ErrNotFound = errors.New("not found; endpoint may not exist on application")
