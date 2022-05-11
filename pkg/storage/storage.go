package storage

import (
	"errors"
	"fmt"
	"github.com/TykTechnologies/momo/pkg/interfaces"
	"github.com/TykTechnologies/momo/pkg/logger"
	"github.com/TykTechnologies/momo/pkg/models"
	"github.com/TykTechnologies/momo/pkg/storage/mongo"
	"github.com/TykTechnologies/momo/pkg/types"
	"reflect"
	"sync"
)

var log = logger.GetLogger("ctrl.storage")

type MomoStore interface {
	GetReference(id string) (*models.MomoMap, error)
	UpdateReference(id string, mm *models.MomoMap) error
	CreateReference(mm *models.MomoMap) (string, error)
	DeleteReference(id string) error
	CreateKeyMap(key, id string, drivers []models.DriverMeta) error
	GetKeyMap(id string) (*models.KeyMap, error)
	UpdateKeyMap(km *models.KeyMap) error
	DeleteKeyMap(id string) error
	GetSyncedPolicies() ([]models.PolicyMap, error)
	UpdatePolicyMap(models.PolicyMap) error
	AddPolicyMap(models.PolicyMap) (string, error)
	DeletePolicyMap(models.PolicyMap) error
	InitMomoStore(tag string) error
}

type Store interface {
	MomoStore
	Health() map[string]interface{}
}

type storageMap struct {
	st map[string]interface{}
	mu sync.RWMutex
}

func (s *storageMap) Add(name string, store interface{}) {
	s.mu.Lock()
	s.st[name] = store
	s.mu.Unlock()
}

func (s *storageMap) Get(name string) (interface{}, bool) {
	s.mu.RLock()
	store, ok := s.st[name]
	s.mu.RUnlock()

	return store, ok
}

var StorageMap = &storageMap{st: make(map[string]interface{})}

// GetStore is a convenience function to return a composite Store type
func GetStore(name types.StorageDriver, tag string) (interfaces.Store, error) {
	v, ok := StorageMap.Get(tag)
	if ok {
		log.Debugf("store already initialised for tag: %v", tag)

		st, typOk := v.(interfaces.Store)
		if !typOk {
			return nil, fmt.Errorf("store with tag %v does not implement the complete Store interface", tag)
		}

		return st, nil
	}

	ist, err := GetSpecificStoreType(name, tag)
	if ist == nil {
		return nil, fmt.Errorf("no store type configured")
	}
	st, ok := ist.(interfaces.Store)
	if !ok {
		return nil, fmt.Errorf("driver does not fulfill Store interface (%s:%s)", name, tag)
	}

	return st, err
}

// GetSpecificStoreType is used to get a sub-type of the Store interface e.g. DashboardStore,
// the storage specific init function must be called by the caller though.
func GetSpecificStoreType(name types.StorageDriver, tag string) (interface{}, error) {
	nsTag := fmt.Sprintf("%s:%s", name, tag)
	log.WithField("tag", nsTag).Debug("===> Looking up store tag")
	v, ok := StorageMap.Get(nsTag)
	if ok {
		log.WithField("tag", nsTag).Debug("store already initialised for tag")
		return v, nil
	}

	switch name {
	case types.MONGO_STORE:
		store := &mongo.Store{}
		store.SetTag(tag)

		log.Debugf("Mongo store tag is: %v, set to: %v", tag, store.GetTag())

		// cache
		StorageMap.Add(nsTag, store)

		// Set
		return store, nil
	}

	return nil, errors.New("no storage driver set")
}

// GetClone is useful if you need to adjust contextual settings in the storage driver (e.g. crypto)
// without having to dial a new connection
func GetClone(store interface{}) interfaces.Store {
	switch st := store.(type) {
	case interfaces.Store:
		return getStoreClone(st)
	default:
		log.Fatal("could not return correct store for type: ", reflect.TypeOf(store))
	}

	return nil
}

func getStoreClone(st interfaces.Store) interfaces.Store {
	ni := st.Clone()
	newST, ok := ni.(interfaces.Store)
	if !ok {
		return nil
	}

	return newST
}
