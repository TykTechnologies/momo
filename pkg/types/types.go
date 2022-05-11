package types

type StorageDriver string

const (
	UNSET_STORE     StorageDriver = ""
	INMEM_STORE     StorageDriver = "Inmem"
	MONGO_STORE     StorageDriver = "Mongo"
	FEDERATED_STORE StorageDriver = "FederatedStore"
	MOCK            StorageDriver = "mock"
)
