package models

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)

type LogItem struct {
	Time    time.Time
	Payload interface{}
	Message string
}

type LogMap map[string][]LogItem

type KeyMap struct {
	KeyIDHash string
	Drivers   []DriverMeta
}

type MgoMomoMap struct {
	*MomoMap
	MID primitive.ObjectID `bson:"_id,omitempty"`
}

type MgoKeyMap struct {
	*KeyMap
	MID primitive.ObjectID `bson:"_id,omitempty"`
}

type MgoPolicyMap struct {
	*PolicyMap
	MID primitive.ObjectID `bson:"_id,omitempty"`
}

type MomoMap struct {
	DriverData map[string]interface{}
	Log        LogMap
	APIID      string
}

type DriverMeta struct {
	ExternalID string
	Name       string
}

func (l LogMap) Add(driver, message string, payload interface{}) {
	lItem := LogItem{
		Time:    time.Now().UTC(),
		Message: message,
		Payload: payload,
	}

	_, ok := l[driver]
	if !ok {
		l[driver] = []LogItem{lItem}
		return
	}

	l[driver] = append(l[driver], lItem)
}

func (k *KeyMap) AddDriver(name, extID string) {
	dat := DriverMeta{Name: name, ExternalID: extID}
	if k.Drivers == nil {
		k.Drivers = []DriverMeta{dat}
		return
	}

	k.Drivers = append(k.Drivers, dat)
}