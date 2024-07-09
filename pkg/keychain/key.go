package keychain

import (
	"encoding/base32"
	"fmt"
	"log"
	"strconv"
	"strings"
	"unicode"
)

type Key struct {
	raw    []byte
	digits int
	offset int // offset of counter
}

type Keychain interface {
	List()
	Get(keyName string) Key
	Set(keyName string, key Key)
}

const counterLen = 20

func noSpace(r rune) rune {
	if unicode.IsSpace(r) {
		return -1
	}
	return r
}

func decodeKey(key string) ([]byte, error) {
	return base32.StdEncoding.DecodeString(strings.ToUpper(key))
}

func serializeKey(k *Key) string {
	encodedKey := base32.StdEncoding.EncodeToString(k.raw)
	// if err != nil {
	// 	log.Fatalf("encoding key: %v", err)
	// }
	return fmt.Sprintf("%d %s", k.digits, encodedKey)
}

func deserializeKey(s string) *Key {
	k := &Key{}
	parts := strings.Split(s, " ")
	if len(parts) < 2 {
		log.Fatalf("malformed key: %v", s)
	}

	digits, err := strconv.ParseInt(parts[0], 10, 0)
	if err != nil {
		log.Fatalf("decoding key: %v", err)
	}
	k.digits = int(digits)

	raw, err := decodeKey(parts[1])
	if err != nil {
		log.Fatalf("decoding key: %v", err)
	}
	k.raw = raw

	return k
}
