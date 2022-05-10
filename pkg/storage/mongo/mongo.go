// Package mongo satisfies storage interfaces for the Ara Controller.
package mongo

import (
	"context"
	"fmt"
	"github.com/pmylund/go-cache"
	"reflect"
	"strings"
	"time"

	//"github.com/patrickmn/go-cache"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"

	"github.com/TykTechnologies/momo/pkg/logger"
	"github.com/TykTechnologies/momo/pkg/models"
	"github.com/TykTechnologies/momo/pkg/interfaces"
	"github.com/TykTechnologies/momo/pkg/types"
)

type Store struct {
	interfaces.BaseStore
	initialised    bool
	tag            string
	ms             *mongo.Client
	conf           *MgoStoreConf
	sStoreSettings *models.SecureStore
	sec            interface{}
	objCache       *cache.Cache
}

var log = logger.GetLogger("ctrl.storage.mgo")

func getAvailableTagsForErr() string {
	tags := ""
	for t := range GetConf().MongoStore {
		tags = " " + t
	}

	return tags
}

func (m *Store) InitAllStores(tag string) error {
	if err := m.InitMomoStore(tag); err != nil {
		return err
	}

	return nil
}

func (m *Store) Init() error {
	if m.initialised {
		return nil
	}

	c, ok := GetConf().MongoStore[m.tag]
	if !ok {
		return fmt.Errorf("no matching store config tag found for tag: %v (available:%v)", m.tag, getAvailableTagsForErr())
	}

	m.conf = c
	log.Info("initialising mgo store")

	if m.conf.Crypto != nil {
		if m.conf.Crypto.Enabled {
			log.Info("secure storage enabled")
			if err := m.SetSecureConf(m.conf.Crypto); err != nil {
				return err
			}
		}
	}

	var mgo *mongo.Client
	log.WithField("uri", m.conf.ConnStr).Debug("Connecting to MongoDB")
	opts := options.Client().ApplyURI(m.conf.ConnStr)
	if err := opts.Validate(); err != nil {
		return err
	}

	mgo, err := mongo.Connect(m.defaultContext(), opts)
	if err != nil {
		return err
	}

	// Verify that we have active DB connection
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	if err := mgo.Ping(ctx, readpref.Primary()); err != nil {
		return err
	}

	m.ms = mgo

	log.Info("Initialising cache")
	m.objCache = cache.New(1*time.Minute, 5*time.Minute)
	m.initialised = true
	return nil
}

func (m *Store) GetTag() string {
	return m.tag
}

func (m *Store) SetSecureConf(storageConf *models.SecureStore) error {
	return nil
}

//func (m *Store) SetSecureEncoder(enc *harpokrates.Encoder) error {
//	m.sec = enc
//	return nil
//}
//
//func (m *Store) GetSecureEncoder() *harpokrates.Encoder {
//	return m.sec
//}

func (m *Store) Clone() interface{} {
	return &Store{
		initialised:    m.initialised,
		tag:            m.tag,
		ms:             m.ms,
		conf:           m.conf,
		sStoreSettings: m.sStoreSettings,
		sec:            m.sec,
		objCache:       m.objCache,
	}
}

func (m *Store) GetSecureConf() *models.SecureStore {
	if m.sStoreSettings == nil {
		return &models.SecureStore{
			Enabled: false,
		}
	}

	return m.sStoreSettings
}

func (m *Store) Health() map[string]interface{} {
	return map[string]interface{}{
		"ok": m.initialised,
	}
}

func (s *Store) Type() types.StorageDriver {
	return types.MONGO_STORE
}

func (s *Store) GetLocalStore() interfaces.Store {
	return s
}

func (s *Store) SetLocalStore(st interfaces.Store) {
	// no op
}

func (s *Store) defaultContext() context.Context {
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	return ctx
}

func (s *Store) defaultDb() *mongo.Database {
	return s.ms.Database(s.conf.ControllerDb, nil)
}

// buildFieldSet maps MongoDB document update paths to values of the fields of 'obj', prefixed with 'path'.
// TODO: probably too simplistic and doesn't check anything relying on bson lib to do the right thing, revise as needed
func (s *Store) buildFieldSet(path string, obj interface{}, fields []string) bson.M {
	log := log.WithField("func", "storage/mongo/Store.buildFieldSet") //nolint:govet // Func scope

	log.Trace("start")
	defer log.Trace("finish")

	fieldSet := bson.M{}
	v := reflect.ValueOf(obj)

	if !v.IsValid() || v.IsZero() {
		log.WithField("obj", fmt.Sprintf("%#v", obj)).Debug("obj was invalid/zero")

		return fieldSet
	}

	r := v.Elem()

	for _, f := range fields {
		key := path + "." + strings.ToLower(f)
		valField := reflect.Indirect(r).FieldByName(f)

		if !valField.IsValid() || valField.IsZero() {
			z := reflect.Zero(valField.Type())

			switch valField.Kind() {
			case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
				fieldSet[key] = z.Int()

			case reflect.Uint, reflect.Uintptr, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
				fieldSet[key] = z.Uint()

			case reflect.Bool:
				fieldSet[key] = z.Bool()

			case reflect.String:
				fieldSet[key] = z.String()

			case reflect.Map, reflect.Slice:
				// leave empty maps and slices as they are

			case
				reflect.Array, reflect.Chan, reflect.Complex64, reflect.Complex128,
				reflect.Float32, reflect.Float64, reflect.Func, reflect.Interface,
				reflect.Ptr, reflect.Struct, reflect.UnsafePointer:
				// TODO(jlucktay): cover remaining field type zero values
				log.WithFields(logrus.Fields{
					"field": f,
					"kind":  valField.Kind(),
					"z":     z,
					"obj":   fmt.Sprintf("%#v", obj),
				}).Debug("field on obj was invalid or zero value of unspecified field type")
			}

			continue
		}

		fieldSet[key] = valField.Interface()
	}

	return fieldSet
}
