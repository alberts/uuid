// Copyright 2013 The Go Authors.  All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package uuid

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"strings"
	"testing"
)

func TestV4(t *testing.T) {
	uuid := MakeV4()
	if uuid.Version() != 4 {
		t.Fatalf("Invalid V4 UUID: version != 4")
	}
	if uuid[6]>>4 != 4 {
		t.Fatalf("Invalid V4 UUID: version != 4")
	}
	msb := uuid[8] >> 4
	if msb != 0x8 && msb != 0x9 && msb != 0xa && msb != 0xb {
		t.Fatalf("Invalid V4 UUID: some bits [0x%x] are wrong", msb)
	}
	if len(uuid.String()) != 36 {
		t.Fatalf("Invalid V4 UUID: %s", uuid.String())
	}
	if uuid.String()[8] != '-' {
		t.Fatal("Expected dash in position 8")
	}
	if uuid.String()[13] != '-' {
		t.Fatal("Expected dash in position 13")
	}
	if uuid.String()[18] != '-' {
		t.Fatal("Expected dash in position 18")
	}
	if uuid.String()[23] != '-' {
		t.Fatal("Expected dash in position 23")
	}
}

func TestParse(t *testing.T) {
	str := "9b78d54c-8cc9-46bc-ae29-efcba10e1abb"
	uuid, err := Parse(str)
	if err != nil {
		t.Fatalf("Parsing failed")
	}
	if uuid.Version() != 4 {
		t.Fatalf("UUID version should be 4")
	}
	if uuid[0] != 0x9b || uuid[len(uuid)-1] != 0xbb {
		t.Fatalf("UUID value is wrong")
	}
	if str != uuid.String() {
		t.Fatalf("UUID value is wrong")
	}
	uuid2, err := Parse(strings.ToUpper(str))
	if err != nil {
		t.Fatalf("Parsing failed")
	}
	if !uuid2.Equal(uuid) {
		t.Fatalf("UUIDs are not equal")
	}
}

func TestParseV4(t *testing.T) {
	for i := 0; i < 100; i++ {
		uuid := MakeV4()
		uuid2, err := Parse(uuid.String())
		if err != nil {
			t.Fatalf("Parsing of %v failed", uuid)
		}
		if !uuid2.Equal(uuid) {
			t.Fatalf("UUIDs are not equal")
		}
	}
}

func TestParseGood(t *testing.T) {
	good := []string{
		"9ABCDEF0-8cc9-46bc-ae29-efcba10e1abb",
		"{9ABCDEF0-8cc9-46bc-ae29-efcba10e1abb}",
	}
	for _, str := range good {
		if _, err := Parse(str); err != nil {
			t.Fatalf("Parsing of %s should succeed", str)
		}
	}
}

func TestParseErrors(t *testing.T) {
	bad := []string{
		"9b78d54c-8cc9-46bc-ae29-efcba10e1ab",
		"{9b78d54c-8cc9-46bc-ae29-efcba10e1abb",
		"9b78d54c-8cc9-46bc-ae29-efcba10e1abb}",
		"{9b78d54cx8cc9-46bc-ae29-efcba10e1abb}",
		"{9b78d54c-8cc9-46bc-ae29-efcba10e1abb]",
		"[9b78d54c-8cc9-46bc-ae29-efcba10e1abb]",
		"9b78d54cx8cc9-46bc-ae29-efcba10e1abb",
		"9b78d54c-8cc9x46bc-ae29-efcba10e1abb",
		"9b78d54c-8cc9-46bcxae29-efcba10e1abb",
		"9b78d54c-8cc9-46bc-ae29xefcba10e1abb",
		"9bP8d54c-8cc9-46bc-ae29-efcba10e1abb",
		"9b78d54c-8cc9-46bc-ae29-efcba10e1abX",
		"9ABCDEF0-8cc9-06bc-ae29-efcba10e1abb",
		"9ABCDEF0-8cc9-66bc-ae29-efcba10e1abb",
	}
	for _, str := range bad {
		if _, err := Parse(str); err != errParseFailed {
			t.Fatalf("Parsing of %s should have failed", str)
		}
	}
}

func TestProto(t *testing.T) {
	id := MakeV4()
	data, err := id.Marshal()
	if err != nil {
		panic(err)
	}
	id2 := new(Uuid)
	err = id2.Unmarshal(data)
	if err != nil {
		panic(err)
	}
	if !id.Equal(*id2) {
		t.Fatalf("want %v got %v", id, *id2)
	}
}

func TestJSON(t *testing.T) {
	id := MakeV4()
	data, err := id.MarshalJSON()
	if err != nil {
		panic(err)
	}
	id2 := new(Uuid)
	err = id2.UnmarshalJSON(data)
	if err != nil {
		panic(err)
	}
	if !id.Equal(*id2) {
		t.Fatalf("want %v got %v", id, *id2)
	}
}

type MyIdStruct struct {
	Id Uuid
}

func TestJSONStruct(t *testing.T) {
	m := &MyIdStruct{Id: MakeV4()}
	data, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	u := &MyIdStruct{}
	err = json.Unmarshal(data, u)
	if err != nil {
		panic(err)
	}
	if !m.Id.Equal(u.Id) {
		t.Fatalf("want %v got %v", m, u)
	}
}

func TestKey(t *testing.T) {
	uuid := MakeV4()
	if len(uuid.Key()) != 16 {
		t.Fatal("Key for V4 UUID is wrong")
	}
	if uuid.String() != uuid.Key().String() {
		t.Fatal("Uuid.String != UuidKey.String")
	}
}

func TestNewRandV4(t *testing.T) {
	r := rand.New(rand.NewSource(0))
	RandV4(r)
}

func TestMarshal(t *testing.T) {
	id := MakeV4()
	b, err := id.Key().MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	s = strings.Trim(s, "\"")
	uuid, err := Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	if !uuid.Equal(id) {
		t.Fatalf("UUID mismatch")
	}
}

func TestString(t *testing.T) {
	id := Uuid{0, 1, 2, 3, 4, 5, 70, 7, 136, 9, 10, 11, 12, 13, 14, 15}
	const expected = "00010203-0405-4607-8809-0a0b0c0d0e0f"
	actual := id.String()
	if actual != expected {
		t.Fatalf("strings not equal: expected: %v, actual: %v", expected, actual)
	}
	if _, err := Parse(actual); err != nil {
		t.Fatalf("Parsing of %s should succeed", actual)
	}
}

func TestUint64(t *testing.T) {
	b := make([]byte, 0, 16)
	buf := new(bytes.Buffer)
	n := uint64(math.MaxUint64 - 1)
	binary.Write(buf, binary.LittleEndian, n)
	b = append(b, buf.Bytes()...)
	b = append(b, buf.Bytes()...)
	u := Uuid(b)
	if u.Uint64() != n {
		t.Fatalf("Encoding Uuid to and from Uint64 did not succeed")
	}
}

func BenchmarkMakeV4(b *testing.B) {
	b.SetBytes(16)
	for n := b.N; n > 0; n-- {
		_ = MakeV4()
	}
}

func BenchmarkRandV4(b *testing.B) {
	b.SetBytes(16)
	r := rand.New(rand.NewSource(0))
	u := Make()
	b.ResetTimer()
	b.StartTimer()
	for n := b.N; n > 0; n-- {
		u.RandV4(r)
	}
	b.StopTimer()
}

func BenchmarkNewRandV4(b *testing.B) {
	b.SetBytes(16)
	r := rand.New(rand.NewSource(0))
	b.ResetTimer()
	b.StartTimer()
	for n := b.N; n > 0; n-- {
		RandV4(r)
	}
	b.StopTimer()
}

func TestMustParse(t *testing.T) {
	MustParse("6ba7b810-9dad-11d1-80b4-00c04fd430c8")
	MustParse("e902893a-9d22-3c7e-a7b8-d6e313b71d9f")
	MustParse("3722b9a0-9889-11e2-871e-844bf591482a")
	MustParse("d9428888-f500-11e0-b85c-61cd3cbb3210")
	MustParse("0fc6a4b0-914e-439b-83cc-d57c8a731749")
	MustParse("109156be-c4fb-41ea-b1b4-efe1671c5836")
	// uuid.uuid5(uuid.NAMESPACE_DNS, "www.google.com")
	MustParse("488416f4-fcaf-5027-8c63-0105cfa213ea")
}

func TestParseWhatYouStrung(t *testing.T) {
	id := MakeV4()
	MustParse(id.String())
	s := id.String()
	u, err := Parse(s)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if s != u.String() {
		t.Fatal("strings don't match")
	}
}

func BenchmarkFmtSprintf(b *testing.B) {
	id := MakeV4()
	for i := 0; i < b.N; i++ {
		fmt.Sprintf("%x-%x-%x-%x-%x", []byte(id[0:4]), []byte(id[4:6]), []byte(id[6:8]), []byte(id[8:10]), []byte(id[10:]))
	}
}

func BenchmarkString(b *testing.B) {
	id := MakeV4()
	for i := 0; i < b.N; i++ {
		id.String()
	}
}
