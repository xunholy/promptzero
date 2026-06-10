// Package kdbx decodes the outer header of a KeePass database (.kdbx) into the
// crack-triage facts an operator needs when one turns up in loot: the format
// version, the encryption cipher, and — critically — the key-derivation
// function and its cost parameters.
//
// A .kdbx is one of the most common high-value loot artifacts, and whether it
// is crackable in practice hinges almost entirely on the KDF: a legacy AES-KDF
// database with a low transform-round count is tractable, whereas a modern
// KDBX4 file using memory-hard Argon2 (e.g. 64 MiB × 14 iterations) throttles
// GPU cracking by orders of magnitude. This decoder surfaces exactly those
// parameters offline, and names the hashcat mode (13400) so the result feeds
// straight into the project's hash/cracking tooling.
//
// It parses the OUTER HEADER only — it does not derive the master key, decrypt
// the database, or emit the keepass2john `$keepass$` hash string (extracting
// that needs the encrypted payload and is deliberately out of scope). No
// confidently-wrong output: the magic signature is validated, an unknown
// cipher/KDF UUID is surfaced as raw hex rather than guessed, and malformed
// input is rejected.
//
// Wrap-vs-native: native — encoding/binary over the documented KDBX header
// format (KeePass KdbxFile.Read.cs + the KDBX4 VariantDictionary), stdlib only,
// no new go.mod dependency. Anchored to a real pykeepass-generated KDBX4 file.
package kdbx

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

// Known cipher UUIDs, as the raw 16 bytes stored in the header (hex).
var cipherNames = map[string]string{
	"31c1f2e6bf714350be5805216afc5aff": "AES-256",
	"61ab05a1946441c38d743a563df8dd35": "AES-128",
	"d6038a2b8b6f4cb5a524339a31dbb59a": "ChaCha20",
	"ad68f29f576f4bb9a36ad47af965346c": "Twofish",
}

// Known KDF UUIDs (raw header bytes, hex).
var kdfNames = map[string]string{
	"c9d9f39a628a4460bf740d08c18a4fea": "AES-KDF",
	"ef636ddf8c29444b91f7a9a403e30a0c": "Argon2d",
	"9e298b1956db4773b23dfc3ec6f0a1e6": "Argon2id",
}

// Result is the decoded KDBX outer header.
type Result struct {
	Format       string `json:"format"`
	VersionMajor int    `json:"version_major"`
	VersionMinor int    `json:"version_minor"`

	Cipher     string `json:"cipher"`
	CipherUUID string `json:"cipher_uuid"`

	Compression string `json:"compression"`

	KDF     string `json:"kdf"`
	KDFUUID string `json:"kdf_uuid"`

	// AES-KDF cost (KDBX3, or KDBX4 with the AES-KDF).
	TransformRounds uint64 `json:"transform_rounds,omitempty"`
	// Argon2 cost (KDBX4).
	Argon2Iterations  uint64 `json:"argon2_iterations,omitempty"`
	Argon2MemoryBytes uint64 `json:"argon2_memory_bytes,omitempty"`
	Argon2Parallelism uint32 `json:"argon2_parallelism,omitempty"`

	// HashcatMode is KeePass's hashcat mode; JohnTool names the keepass2john format.
	HashcatMode int    `json:"hashcat_mode"`
	JohnTool    string `json:"john_tool"`
	Note        string `json:"note"`
}

const (
	sig1 = 0x9AA2D903
	sig2 = 0xB54BFB67
)

// Outer-header field IDs (KeePass KdbxHeaderFieldID).
const (
	fEndOfHeader     = 0
	fCipherID        = 2
	fCompression     = 3
	fTransformRounds = 6
	fKdfParameters   = 11
)

// Decode parses a KDBX file's outer header from its raw bytes.
func Decode(raw []byte) (*Result, error) {
	if len(raw) < 12 {
		return nil, errors.New("kdbx: too short for a KDBX header")
	}
	if binary.LittleEndian.Uint32(raw[0:4]) != sig1 || binary.LittleEndian.Uint32(raw[4:8]) != sig2 {
		return nil, fmt.Errorf("kdbx: bad magic signature (not a .kdbx file)")
	}
	minor := int(binary.LittleEndian.Uint16(raw[8:10]))
	major := int(binary.LittleEndian.Uint16(raw[10:12]))
	if major < 1 || major > 4 {
		return nil, fmt.Errorf("kdbx: unsupported major version %d", major)
	}

	res := &Result{
		Format:       "KDBX",
		VersionMajor: major,
		VersionMinor: minor,
		Compression:  "none",
		HashcatMode:  13400,
		JohnTool:     "keepass2john",
		Note: "Outer header only — the master key is not derived, the database is not decrypted, and the " +
			"keepass2john $keepass$ hash is not produced (that needs the encrypted payload). Crackability " +
			"hinges on the KDF below.",
	}

	r := &reader{buf: raw, pos: 12}
	sizeWidth := 2
	if major >= 4 {
		sizeWidth = 4 // KDBX4 widened the header field-size prefix to uint32
	}
	for {
		id, ok := r.u8()
		if !ok {
			return nil, errors.New("kdbx: truncated header (no end-of-header marker)")
		}
		var size int
		if sizeWidth == 4 {
			v, ok := r.u32()
			if !ok {
				return nil, errors.New("kdbx: truncated header field size")
			}
			size = int(v)
		} else {
			v, ok := r.u16()
			if !ok {
				return nil, errors.New("kdbx: truncated header field size")
			}
			size = int(v)
		}
		data, ok := r.bytes(size)
		if !ok {
			return nil, fmt.Errorf("kdbx: header field %d extends past end of buffer", id)
		}
		if id == fEndOfHeader {
			break
		}
		applyHeaderField(res, int(id), data)
	}

	if res.KDF == "" && major < 4 {
		// KDBX3 has no KDF UUID field — the KDF is implicitly AES-KDF.
		res.KDF = "AES-KDF"
	}
	res.addCostNote()
	return res, nil
}

// applyHeaderField stores one decoded outer-header field.
func applyHeaderField(res *Result, id int, data []byte) {
	switch id {
	case fCipherID:
		res.CipherUUID = hex.EncodeToString(data)
		if name, ok := cipherNames[res.CipherUUID]; ok {
			res.Cipher = name
		} else {
			res.Cipher = "unknown (" + res.CipherUUID + ")"
		}
	case fCompression:
		if len(data) >= 4 && binary.LittleEndian.Uint32(data[:4]) == 1 {
			res.Compression = "gzip"
		}
	case fTransformRounds:
		if len(data) >= 8 {
			res.TransformRounds = binary.LittleEndian.Uint64(data[:8])
		}
	case fKdfParameters:
		parseKdfParameters(res, data)
	}
}

// parseKdfParameters decodes the KDBX4 KdfParameters VariantDictionary, pulling
// out the KDF UUID and its cost parameters.
func parseKdfParameters(res *Result, data []byte) {
	vd, err := parseVariantDictionary(data)
	if err != nil {
		res.Note = "KDF parameters did not parse (" + err.Error() + "); " + res.Note
		return
	}
	if u, ok := vd["$UUID"]; ok {
		res.KDFUUID = hex.EncodeToString(u.b)
		if name, ok := kdfNames[res.KDFUUID]; ok {
			res.KDF = name
		} else {
			res.KDF = "unknown (" + res.KDFUUID + ")"
		}
	}
	// AES-KDF rounds ("R"), Argon2 iterations/memory/parallelism ("I"/"M"/"P").
	if v, ok := vd["R"]; ok {
		res.TransformRounds = v.u
	}
	if v, ok := vd["I"]; ok {
		res.Argon2Iterations = v.u
	}
	if v, ok := vd["M"]; ok {
		res.Argon2MemoryBytes = v.u
	}
	if v, ok := vd["P"]; ok {
		res.Argon2Parallelism = uint32(v.u)
	}
}

// addCostNote appends a qualitative crack-difficulty note from the KDF cost.
func (res *Result) addCostNote() {
	switch {
	case res.Argon2MemoryBytes > 0:
		res.Note = fmt.Sprintf("memory-hard Argon2 (%d MiB × %d iterations, parallelism %d) heavily throttles "+
			"GPU cracking; hashcat 13400 needs a recent build for Argon2-KDF KDBX4. ",
			res.Argon2MemoryBytes/(1024*1024), res.Argon2Iterations, res.Argon2Parallelism) + res.Note
	case res.TransformRounds > 0:
		res.Note = fmt.Sprintf("AES-KDF with %d transform rounds (higher = slower per guess). ", res.TransformRounds) + res.Note
	}
}

// vdValue is one VariantDictionary entry: a uint (for u32/u64) or raw bytes.
type vdValue struct {
	u uint64
	b []byte
}

// VariantDictionary value type tags.
const (
	vdUint32 = 0x04
	vdUint64 = 0x05
	vdBool   = 0x08
	vdInt32  = 0x0C
	vdInt64  = 0x0D
	vdString = 0x18
	vdBytes  = 0x42
	vdEnd    = 0x00
)

// parseVariantDictionary decodes the KeePass VariantDictionary format: a uint16
// version, then (type, keyLen, key, valLen, val) entries terminated by a zero
// type byte.
func parseVariantDictionary(data []byte) (map[string]vdValue, error) {
	r := &reader{buf: data}
	if _, ok := r.u16(); !ok { // version
		return nil, errors.New("missing version")
	}
	out := map[string]vdValue{}
	for {
		t, ok := r.u8()
		if !ok {
			return nil, errors.New("truncated entry type")
		}
		if t == vdEnd {
			return out, nil
		}
		klen, ok := r.u32()
		if !ok {
			return nil, errors.New("truncated key length")
		}
		key, ok := r.bytes(int(klen))
		if !ok {
			return nil, errors.New("truncated key")
		}
		vlen, ok := r.u32()
		if !ok {
			return nil, errors.New("truncated value length")
		}
		val, ok := r.bytes(int(vlen))
		if !ok {
			return nil, errors.New("truncated value")
		}
		v := vdValue{b: val}
		switch t {
		case vdUint32, vdInt32:
			if len(val) >= 4 {
				v.u = uint64(binary.LittleEndian.Uint32(val[:4]))
			}
		case vdUint64, vdInt64:
			if len(val) >= 8 {
				v.u = binary.LittleEndian.Uint64(val[:8])
			}
		}
		out[string(key)] = v
	}
}

// reader is a bounds-checked little-endian byte cursor.
type reader struct {
	buf []byte
	pos int
}

func (r *reader) u8() (byte, bool) {
	if r.pos+1 > len(r.buf) {
		return 0, false
	}
	b := r.buf[r.pos]
	r.pos++
	return b, true
}

func (r *reader) u16() (uint16, bool) {
	if r.pos+2 > len(r.buf) {
		return 0, false
	}
	v := binary.LittleEndian.Uint16(r.buf[r.pos:])
	r.pos += 2
	return v, true
}

func (r *reader) u32() (uint32, bool) {
	if r.pos+4 > len(r.buf) {
		return 0, false
	}
	v := binary.LittleEndian.Uint32(r.buf[r.pos:])
	r.pos += 4
	return v, true
}

func (r *reader) bytes(n int) ([]byte, bool) {
	if n < 0 || r.pos+n > len(r.buf) {
		return nil, false
	}
	b := r.buf[r.pos : r.pos+n]
	r.pos += n
	return b, true
}
