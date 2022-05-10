package mongo

import (
	"errors"
	"net/url"
	"strings"
)

// MongoDB connection string representation for mgo library
type MURL struct {
	Proto      string
	User       string
	Pass       string
	Servers    []string
	DB         string
	UseSSL     bool
	ReplicaSet string
	AuthSource string
}

func (mu *MURL) Parse(connStr string) error {
	parsedUrl, parseErr := url.Parse(connStr)
	if parseErr != nil {
		return parseErr
	}

	if parsedUrl.Scheme != "mongodb" {
		return errors.New("Unsupported connection string scheme")
	}
	mu.Proto = parsedUrl.Scheme
	mu.User = parsedUrl.User.Username()
	mu.Pass, _ = parsedUrl.User.Password()
	mu.Servers = strings.Split(parsedUrl.Host, ",")

	if len(parsedUrl.Path) > 1 {
		mu.DB = parsedUrl.Path[1:]
	}

	query := parsedUrl.Query()
	mu.UseSSL = query.Get("ssl") == "true"
	mu.ReplicaSet = query.Get("replicaSet")
	mu.AuthSource = query.Get("authSource")

	return nil
}

func (mu *MURL) String() string {
	u := url.URL{
		Scheme: "mongodb",
		Host:   strings.Join(mu.Servers, ","),
	}
	if mu.DB != "" {
		u.Path = "/" + mu.DB
	}
	if mu.User != "" {
		u.User = url.UserPassword(mu.User, mu.Pass)
	}

	query := u.Query()
	if mu.ReplicaSet != "" {
		query.Set("replicaSet", mu.ReplicaSet)
	}
	if mu.AuthSource != "" {
		query.Set("authSource", mu.AuthSource)
	}
	u.RawQuery = query.Encode()

	return u.String()
}
