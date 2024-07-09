package keychain

import (
	"log"
	"sort"
	"strings"

	"github.com/zalando/go-keyring"
)

type OsKeychain struct {
	service string
	index   string
	keys    []string
}

func GetOsKeychain() *OsKeychain {
	c := &OsKeychain{
		service: "s2fa",
		index:   "index",
		keys:    make([]string, 0),
	}

	concatKeys, err := keyring.Get(c.service, c.index)
	if err != nil {
		log.Fatal(err)
	}

	keys := strings.Split(concatKeys, ",")
	c.keys = keys
	return c
}

func (c *OsKeychain) List() []string {
	var names []string
	for _, name := range c.keys {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (c *OsKeychain) Set(name string, key *Key) {
	keyring.Set(c.service, name, serializeKey(key))
}

func (c *OsKeychain) Get(name string) *Key {
	encodedKey, err := keyring.Get(c.service, name)
	if err != nil {
		log.Fatalf("getting key: %v", err)
	}

	return deserializeKey(encodedKey)
}
