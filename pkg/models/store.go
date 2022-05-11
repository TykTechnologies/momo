package models

type SecureStore struct {
	Enabled bool
	KeySets map[string]*KeyDef
}

type KeyDef struct {
	PrivateKeyFile string
	PublicKeyFile  string
}
