package keychain

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
)

type TextKeychain struct {
	file string
	keys map[string]Key
}

func GetTextKeychain(file string) *TextKeychain {
	c := &TextKeychain{
		file: file,
		keys: make(map[string]Key),
	}
	data, err := os.ReadFile(file)
	if err != nil {
		if os.IsNotExist(err) {
			return c
		}
		log.Fatal(err)
	}

	lines := bytes.SplitAfter(data, []byte("\n"))
	offset := 0
	for i, line := range lines {
		lineno := i + 1
		offset += len(line)
		f := bytes.Split(bytes.TrimSuffix(line, []byte("\n")), []byte(" "))
		if len(f) == 1 && len(f[0]) == 0 {
			continue
		}
		if len(f) >= 3 && len(f[1]) == 1 && '6' <= f[1][0] && f[1][0] <= '8' {
			var k Key
			name := string(f[0])
			k.Digits = int(f[1][0] - '0')
			raw, err := decodeKey(string(f[2]))
			if err == nil {
				k.Raw = raw
				if len(f) == 3 {
					c.keys[name] = k
					continue
				}
				if len(f) == 4 && len(f[3]) == counterLen {
					_, err := strconv.ParseUint(string(f[3]), 10, 64)
					if err == nil {
						// Valid counter.
						k.Offset = offset - counterLen
						if line[len(line)-1] == '\n' {
							k.Offset--
						}
						c.keys[name] = k
						continue
					}
				}
			}
		}
		log.Printf("%s:%d: malformed key", c.file, lineno)
		// check is this log is prefixed with "2fa: " as defined in main.go
	}
	return c
}

func (c *TextKeychain) List() []string {
	var names []string
	for name := range c.keys {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (c *TextKeychain) Set(name string, key *Key) {
	size := key.Digits

	fmt.Fprintf(os.Stderr, "2fa key for %s: ", name)
	text, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		log.Fatalf("error reading key: %v", err)
	}
	text = strings.Map(noSpace, text)
	text += strings.Repeat("=", -len(text)&7) // pad to 8 bytes
	if _, err := decodeKey(text); err != nil {
		log.Fatalf("invalid key: %v", err)
	}

	line := fmt.Sprintf("%s %d %s", name, size, text)
	// if *flagHotp {
	// 	line += " " + strings.Repeat("0", 20)
	// }
	line += "\n"

	f, err := os.OpenFile(c.file, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
	if err != nil {
		log.Fatalf("opening keychain: %v", err)
	}
	f.Chmod(0600)

	if _, err := f.Write([]byte(line)); err != nil {
		log.Fatalf("adding key: %v", err)
	}
	if err := f.Close(); err != nil {
		log.Fatalf("adding key: %v", err)
	}
}

func (c *TextKeychain) Get(name string) *Key {
	key := c.keys[name]
	return &key
}
