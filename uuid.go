// Copyright 2013 The Go Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Universally Unique IDentifier (UUID).
package uuid

// RFC 4122: A Universally Unique IDentifier (UUID) URN Namespace.

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"sync"
)

type Uuid []byte

func Make() Uuid {
	return make(Uuid, 16)
}

var stream cipher.Stream
var streamLock sync.Mutex

func init() {
	InitState()
}

func InitState() {
	// select AES-256
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err)
	}

	streamLock.Lock()
	defer streamLock.Unlock()

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	stream = cipher.NewCTR(block, iv)
}

// Make Version 4 (random data based) UUID.
func MakeV4() Uuid {
	// V4 UUID is of the form: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
	// where x is any hexadecimal digit and y is one of 8, 9, A, or B.
	id := make(Uuid, 16)

	streamLock.Lock()
	stream.XORKeyStream(id, id)
	streamLock.Unlock()

	// Set the four most significant bits (bits 12 through 15) of the
	// time_hi_and_version field to the 4-bit version number from
	// Section 4.1.3.
	id[6] = (id[6] & 0xf) | 0x40

	// Set the two most significant bits (bits 6 and 7) of the
	// clock_seq_hi_and_reserved to zero and one, respectively.
	id[8] = (id[8] & 0x3f) | 0x80

	return id
}

var errParseFailed = errors.New("uuid: Parse: invalid value")

func Parse(str string) (Uuid, error) {
	if len(str) == 38 {
		if str[0] != '{' || str[37] != '}' {
			return nil, errParseFailed
		}
		str = str[1:37]
	}
	if len(str) != 36 {
		return nil, errParseFailed
	}
	uuid := Make()
	j := 0
	for i, c := range str {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return nil, errParseFailed
			}
			continue
		}
		var v byte
		if c >= '0' && c <= '9' {
			v = byte(c - '0')
		} else if c >= 'a' && c <= 'f' {
			v = 10 + byte(c-'a')
		} else if c >= 'A' && c <= 'F' {
			v = 10 + byte(c-'A')
		} else {
			return nil, errParseFailed
		}
		if j&0x1 == 0 {
			uuid[j>>1] = v << 4
		} else {
			uuid[j>>1] |= v
		}
		j++
	}
	version := uuid.Version()
	if version < 1 || version > 5 {
		return nil, errParseFailed
	}
	return uuid, nil
}

func MustParse(str string) Uuid {
	id, err := Parse(str)
	if err != nil {
		panic("uuid: MustParse: " + err.Error())
	}
	return id
}

func (uuid Uuid) Version() int {
	if len(uuid) != 16 {
		panic("invalid uuid: not 16 bytes")
	}
	return int(uuid[6] >> 4)
}

func (uuid Uuid) Equal(other Uuid) bool {
	return bytes.Equal(uuid, other)
}

func (uuid Uuid) Less(other Uuid) bool {
	return bytes.Compare(uuid, other) == -1
}

var lut = [16]byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'}

func (uuid Uuid) String() string {
	if len(uuid) == 0 {
		return "<empty uuid>"
	}
	if len(uuid) != 16 {
		panic("invalid uuid: not 16 bytes")
	}
	b := make([]byte, 36)
	j := 0
	for i := 0; i < len(uuid); i++ {
		b[j] = lut[uuid[i]>>4]
		j++
		b[j] = lut[uuid[i]&0xf]
		j++
		if j == 8 || j == 13 || j == 18 || j == 23 {
			b[j] = '-'
			j++
		}
	}
	return string(b)
}

func (this Uuid) Compare(other Uuid) int {
	return bytes.Compare(this, other)
}

func (uuid Uuid) MarshalJSON() ([]byte, error) {
	return json.Marshal(uuid.String())
}

func (uuid *Uuid) UnmarshalJSON(data []byte) error {
	var s string
	err := json.Unmarshal(data, &s)
	if err != nil {
		return err
	}

	if s == "<empty uuid>" {
		*uuid = nil
		return nil
	}
	*uuid, err = Parse(s)
	return err
}

func NewPopulatedUuid(r int63) *Uuid {
	u := RandV4(r)
	return &u
}

func (uuid Uuid) Marshal() ([]byte, error) {
	return []byte(uuid), nil
}

func (uuid Uuid) MarshalTo(data []byte) (n int, err error) {
	copy(data, uuid)
	return 16, nil
}

func (uuid *Uuid) Unmarshal(data []byte) error {
	if data == nil {
		uuid = nil
		return nil
	}
	id := Uuid(make([]byte, 16))
	copy(id, data)
	*uuid = id
	return nil
}

func (uuid *Uuid) Size() int {
	return 16
}

type int63 interface {
	Int63() int64
}

func RandV4(r int63) Uuid {
	uuid := Make()
	uuid.RandV4(r)
	return uuid
}

func (uuid Uuid) RandV4(r int63) {
	putLittleEndianUint64(uuid, 0, uint64(r.Int63()))
	putLittleEndianUint64(uuid, 8, uint64(r.Int63()))
	uuid[6] = (uuid[6] & 0xf) | 0x40
	uuid[8] = (uuid[8] & 0x3f) | 0x80
}

type UuidKey [16]byte

func (uuid Uuid) Key() UuidKey {
	var key UuidKey
	copy(key[:], uuid)
	return key
}

func (key UuidKey) String() string {
	return key.Uuid().String()
}

func (key UuidKey) Uuid() Uuid {
	return Uuid(key[:])
}

func (key UuidKey) MarshalJSON() ([]byte, error) {
	return key.Uuid().MarshalJSON()
}

func (this UuidKey) Compare(other UuidKey) int {
	return bytes.Compare(this[:], other[:])
}

func (uuid Uuid) Uint64() uint64 {
	var v uint64
	binary.Read(bytes.NewBuffer([]byte(uuid)), binary.LittleEndian, &v)
	return v
}

func putLittleEndianUint64(b []byte, offset int, v uint64) {
	b[offset] = byte(v)
	b[offset+1] = byte(v >> 8)
	b[offset+2] = byte(v >> 16)
	b[offset+3] = byte(v >> 24)
	b[offset+4] = byte(v >> 32)
	b[offset+5] = byte(v >> 40)
	b[offset+6] = byte(v >> 48)
	b[offset+7] = byte(v >> 56)
}

type Uuids []Uuid

func (ids Uuids) Len() int           { return len(ids) }
func (ids Uuids) Less(i, j int) bool { return ids[i].Less(ids[j]) }
func (ids Uuids) Swap(i, j int)      { ids[i], ids[j] = ids[j], ids[i] }
