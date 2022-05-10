package atlas

import (
	"net/http"

	dac "github.com/akshaykarle/go-http-digest-auth-client"
	ma "github.com/akshaykarle/go-mongodbatlas/mongodbatlas"
	uuid "github.com/satori/go.uuid"

	"github.com/TykTechnologies/momo/pkg/logger"
)

var moduleName = "ctrl.storage.mgo.atlas"
var log = logger.GetLogger(moduleName)

// Will create a DB user using the atlas API because DBs do not support creating
// users using the standard mongoDB admin user
func CreateDBUser(username, key, projectID, dbName string) (string, string, error) {
	t := dac.NewTransport(username, key)
	httpClient := &http.Client{Transport: &t}
	client := ma.NewClient(httpClient)

	newU := uuid.NewV4().String()
	newP := uuid.NewV4().String()

	_, _, err := client.DatabaseUsers.Create(projectID, &ma.DatabaseUser{
		GroupID:      projectID,
		Username:     newU,
		Password:     newP,
		DatabaseName: "admin",
		Roles: []ma.Role{
			{
				DatabaseName: dbName,
				RoleName:     "dbAdmin",
			},
			{
				DatabaseName: dbName,
				RoleName:     "readWrite",
			},
		},
	})

	if err != nil {
		return "", "", err
	}

	log.WithField("user", newU).Info("Atlas user created")

	return newU, newP, nil
}

// Deletes a MongoDB Atlas user through its API
func DeleteDBUser(username, key, projectID, dbUser string) error {
	t := dac.NewTransport(username, key)
	httpClient := &http.Client{Transport: &t}
	client := ma.NewClient(httpClient)

	_, err := client.DatabaseUsers.Delete(projectID, dbUser)

	if err == nil {
		log.WithField("user", dbUser).Info("Atlas user deleted")
	}

	return err
}
