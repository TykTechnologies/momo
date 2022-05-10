package mongo

import (
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"github.com/TykTechnologies/momo/pkg/models"
	"github.com/TykTechnologies/momo/pkg/storage/errors"
)

const (
	MomoCol       = "momos"
	MomoKeyCol    = "momo_keys"
	MomoPolicyCol = "momo_policies"
)

func (m *Store) ensureMomoApiIndexes() error {
	apiIndex := mongo.IndexModel{
		Keys:    bson.M{"momomap.apiid": 1},
		Options: options.Index().SetUnique(true),
	}

	coll := m.defaultDb().Collection(MomoCol)
	_, err := coll.Indexes().CreateMany(m.defaultContext(), []mongo.IndexModel{apiIndex})
	return err
}

func (m *Store) ensureMomoKeyIndexes() error {
	keyIndex := mongo.IndexModel{
		Keys:    bson.M{"keymap.keyidhash": 1},
		Options: options.Index().SetUnique(true),
	}

	coll := m.defaultDb().Collection(MomoKeyCol)
	_, err := coll.Indexes().CreateMany(m.defaultContext(), []mongo.IndexModel{keyIndex})
	return err
}

func (m *Store) ensureMomoPolicyIndexes() error {
	policyIndex := mongo.IndexModel{
		Keys:    bson.M{"policy.id": 1},
		Options: options.Index().SetUnique(true),
	}

	coll := m.defaultDb().Collection(MomoPolicyCol)
	_, err := coll.Indexes().CreateMany(m.defaultContext(), []mongo.IndexModel{policyIndex})
	return err
}

func (m *Store) InitMomoStore(tag string) error {
	m.tag = tag
	if err := m.Init(); err != nil {
		return err
	}

	if err := m.ensureMomoApiIndexes(); err != nil {
		log.WithError(err).Debug("Couldn't ensure indexes on the momo api storage")
	}
	if err := m.ensureMomoKeyIndexes(); err != nil {
		log.WithError(err).Debug("Couldn't ensure indexes on the momo key storage")
	}
	if err := m.ensureMomoPolicyIndexes(); err != nil {
		log.WithError(err).Debug("Couldn't ensure indexes on the momo policy storage")
	}
	return nil
}

func (m *Store) GetReference(id string) (*models.MomoMap, error) {
	mm := &models.MgoMomoMap{}
	query := bson.M{"momomap.apiid": id}
	if err := m.defaultDb().Collection(MomoCol).FindOne(m.defaultContext(), query).Decode(mm); err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, errors.ErrMomoRefNotFound
		}

		return nil, err
	}

	return mm.MomoMap, nil
}

func (m *Store) UpdateReference(id string, mm *models.MomoMap) error {
	if mm.APIID == "" {
		return errors.ErrMomoAPIIDRequired
	}

	query := bson.M{"momomap.apiid": mm.APIID}
	update := bson.M{"$set": bson.M{"momomap": mm}}

	res, err := m.defaultDb().Collection(MomoCol).UpdateOne(m.defaultContext(), query, update)
	if err != nil {
		return err
	}
	if res.MatchedCount == 0 {
		return errors.ErrMomoRefNotFound
	}

	return nil
}

func (m *Store) CreateReference(mm *models.MomoMap) (string, error) {
	if mm.APIID == "" {
		return "", errors.ErrMomoAPIIDRequired
	}

	asMMM := &models.MgoMomoMap{
		MomoMap: mm,
		MID:     primitive.NewObjectID(),
	}

	if _, err := m.defaultDb().Collection(MomoCol).InsertOne(m.defaultContext(), asMMM); err != nil {
		return "", err
	}

	return asMMM.MID.Hex(), nil
}

func (m *Store) DeleteReference(id string) error {
	query := bson.M{"momomap.apiid": id}
	if _, err := m.defaultDb().Collection(MomoCol).DeleteOne(m.defaultContext(), query); err != nil {
		return err
	}

	return nil
}

func (m *Store) CreateKeyMap(key string, id string, drivers []models.DriverMeta) error {
	if key == "" {
		return errors.ErrMomoKeyIDRequired
	}

	asMKM := &models.MgoKeyMap{
		KeyMap: &models.KeyMap{
			KeyIDHash: key,
			Drivers:   drivers,
		},
		MID: primitive.NewObjectID(),
	}

	if _, err := m.defaultDb().Collection(MomoKeyCol).InsertOne(m.defaultContext(), asMKM); err != nil {
		return err
	}

	return nil
}

func (m *Store) UpdateKeyMap(km *models.KeyMap) error {
	if km.KeyIDHash == "" {
		return errors.ErrMomoKeyIDRequired
	}

	query := bson.M{"keymap.keyidhash": km.KeyIDHash}
	update := bson.M{"$set": bson.M{"keymap": km}}

	res, err := m.defaultDb().Collection(MomoKeyCol).UpdateOne(m.defaultContext(), query, update)
	if err != nil {
		return err
	}
	if res.MatchedCount == 0 {
		return errors.ErrMomoKeyNotFound
	}

	return nil
}

func (m *Store) DeleteKeyMap(id string) error {
	if id == "" {
		return errors.ErrMomoKeyIDRequired
	}

	query := bson.M{"keymap.keyidhash": id}
	if _, err := m.defaultDb().Collection(MomoKeyCol).DeleteOne(m.defaultContext(), query); err != nil {
		return err
	}

	return nil
}

func (m *Store) GetKeyMap(id string) (*models.KeyMap, error) {
	if id == "" {
		return nil, errors.ErrMomoKeyIDRequired
	}

	mKm := &models.MgoKeyMap{}
	query := bson.M{"keymap.keyidhash": id}

	if err := m.defaultDb().Collection(MomoKeyCol).FindOne(m.defaultContext(), query).Decode(mKm); err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, errors.ErrMomoKeyNotFound
		}

		return nil, err
	}

	return mKm.KeyMap, nil
}

func (m *Store) DeletePolicyMap(pm models.PolicyMap) error {
	if pm.ID == "" {
		return errors.ErrMomoPolicyIDRequired
	}

	query := bson.M{"policy.id": pm.ID}
	if _, err := m.defaultDb().Collection(MomoPolicyCol).DeleteOne(m.defaultContext(), query); err != nil {
		return err
	}

	return nil
}

func (m *Store) UpdatePolicyMap(pm models.PolicyMap) error {
	if pm.ID == "" {
		return errors.ErrMomoPolicyIDRequired
	}

	query := bson.M{"policy.id": pm.ID}
	update := bson.M{"$set": bson.M{"policy": pm}}

	res, err := m.defaultDb().Collection(MomoPolicyCol).UpdateOne(m.defaultContext(), query, update)
	if err != nil {
		return err
	}
	if res.MatchedCount == 0 {
		return errors.ErrMomoPolicyNotFound
	}

	return nil
}

func (m *Store) AddPolicyMap(pm models.PolicyMap) (string, error) {
	if pm.ID == "" {
		return "", errors.ErrMomoPolicyIDRequired
	}

	mKm := &models.MgoPolicyMap{PolicyMap: &pm, MID: primitive.NewObjectID()}
	if _, err := m.defaultDb().Collection(MomoPolicyCol).InsertOne(m.defaultContext(), mKm); err != nil {
		return "", err
	}

	return mKm.MID.Hex(), nil
}

func (m *Store) GetSyncedPolicies() ([]models.PolicyMap, error) {
	mpms := make([]models.MgoPolicyMap, 0)
	cur, err := m.defaultDb().Collection(MomoPolicyCol).Find(m.defaultContext(), bson.D{})
	if err != nil {
		return nil, err
	}
	if err := cur.All(m.defaultContext(), &mpms); err != nil {
		return nil, err
	}

	pms := make([]models.PolicyMap, len(mpms))
	for i, mpm := range mpms {
		pms[i] = *mpm.PolicyMap
	}

	return pms, nil
}
