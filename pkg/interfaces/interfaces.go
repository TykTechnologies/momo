package interfaces

import "github.com/TykTechnologies/momo/pkg/types"

type BaseStore interface {
	SetTag(string)
	GetTag() string
	Init() error
	Clone() interface{}
	Type() types.StorageDriver
}

type Store interface {
	BaseStore
	Health() map[string]interface{}
}