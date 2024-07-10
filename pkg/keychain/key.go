package keychain

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type Key struct {
	Raw    []byte
	Digits int
	Offset int // offset of counter
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
	encodedKey := base32.StdEncoding.EncodeToString(k.Raw)
	// if err != nil {
	// 	log.Fatalf("encoding key: %v", err)
	// }
	return fmt.Sprintf("%d %s", k.Digits, encodedKey)
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
	k.Digits = int(digits)

	raw, err := decodeKey(parts[1])
	if err != nil {
		log.Fatalf("decoding key: %v", err)
	}
	k.Raw = raw

	return k
}

func GetKeyFromStdin() []byte {
	fmt.Fprintf(os.Stderr, "2fa key: ")
	text, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		log.Fatalf("error reading key: %v", err)
	}
	text = strings.Map(noSpace, text)
	text += strings.Repeat("=", -len(text)&7) // pad to 8 bytes
	bytes, err := decodeKey(text)
	if err != nil {
		log.Fatalf("invalid key: %v", err)
	}
	return bytes
}

func hotp(key []byte, counter uint64, digits int) int {
	h := hmac.New(sha1.New, key)
	binary.Write(h, binary.BigEndian, counter)
	sum := h.Sum(nil)
	v := binary.BigEndian.Uint32(sum[sum[len(sum)-1]&0x0F:]) & 0x7FFFFFFF
	d := uint32(1)
	for i := 0; i < digits && i < 8; i++ {
		d *= 10
	}
	return int(v % d)
}

func totp(key []byte, t time.Time, digits int) int {
	return hotp(key, uint64(t.UnixNano())/30e9, digits)
}

func (k *Key) Code() string {
	var code int
	// if k.offset != 0 {
	// 	n, err := strconv.ParseUint(string(c.data[k.offset:k.offset+counterLen]), 10, 64)
	// 	if err != nil {
	// 		log.Fatalf("malformed key counter for %q (%q)", name, c.data[k.offset:k.offset+counterLen])
	// 	}
	// 	n++
	// 	code = hotp(k.raw, n, k.digits)
	// 	f, err := os.OpenFile(c.file, os.O_RDWR, 0600)
	// 	if err != nil {
	// 		log.Fatalf("opening keychain: %v", err)
	// 	}
	// 	if _, err := f.WriteAt([]byte(fmt.Sprintf("%0*d", counterLen, n)), int64(k.offset)); err != nil {
	// 		log.Fatalf("updating keychain: %v", err)
	// 	}
	// 	if err := f.Close(); err != nil {
	// 		log.Fatalf("updating keychain: %v", err)
	// 	}
	// } else {
	// Time-based key.
	code = totp(k.Raw, time.Now(), k.Digits)
	// }
	return fmt.Sprintf("%0*d", k.Digits, code)
}
