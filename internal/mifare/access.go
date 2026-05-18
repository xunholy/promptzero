package mifare

// AccessBits is the structured view of a sector's access
// conditions — three bits per block (C1, C2, C3), expanded into
// the documented permission catalog per NXP AN10833 Table 6
// (data blocks) and Table 7 (sector trailer).
type AccessBits struct {
	// Blocks holds the per-block access view. For a 1K sector
	// the slice has 4 entries (blocks 0-3); for 4K large
	// sectors the slice has 4 entries representing the four
	// block groups (5-block chunks); we render the layout in
	// the small-sector form since 1K is the common case and
	// the bit-packing matches.
	Blocks [4]BlockAccess `json:"blocks"`
}

// BlockAccess names the access bit triplet for one block.
type BlockAccess struct {
	// C1, C2, C3 are the three access bits.
	C1 int `json:"c1"`
	C2 int `json:"c2"`
	C3 int `json:"c3"`
	// Read, Write, Increment, Decrement enumerate the operations
	// allowed for each key. Values: "A", "B", "A|B", "never".
	// For the trailer block (Blocks[3]) the names map differently
	// (read/write of Key A, access bits, Key B); see TrailerAccess.
	Read      string `json:"read,omitempty"`
	Write     string `json:"write,omitempty"`
	Increment string `json:"increment,omitempty"`
	Decrement string `json:"decrement,omitempty"`
	// TrailerAccess is non-nil only for the trailer block
	// (Blocks[3]), carrying the four trailer-specific permission
	// slots from AN10833 Table 7.
	TrailerAccess *TrailerAccess `json:"trailer_access,omitempty"`
}

// TrailerAccess is the trailer-block permission table — what each
// key can do with Key A, the access bits themselves, and Key B.
type TrailerAccess struct {
	KeyAWrite       string `json:"key_a_write"`
	AccessBitsRead  string `json:"access_bits_read"`
	AccessBitsWrite string `json:"access_bits_write"`
	KeyBRead        string `json:"key_b_read"`
	KeyBWrite       string `json:"key_b_write"`
}

// decodeAccessBits unpacks the three access bytes per NXP AN10833
// Table 5:
//
//	byte 6 high nibble = ~C2 (~C2_3 ~C2_2 ~C2_1 ~C2_0)
//	byte 6 low nibble  = ~C1
//	byte 7 high nibble =  C1
//	byte 7 low nibble  = ~C3
//	byte 8 high nibble =  C3
//	byte 8 low nibble  =  C2
//
// The "~" entries are the bitwise inverse of the matching bits in
// the non-inverted nibbles. We verify the inversion as the
// integrity check; a sector whose access bytes fail this check is
// either malformed or has been intentionally bricked (some keys
// won't authenticate after this point).
//
// Returns the structured view and a validity flag.
func decodeAccessBits(b6, b7, b8 byte) (AccessBits, bool) {
	c2Inv := (b6 >> 4) & 0x0F
	c1Inv := b6 & 0x0F
	c1 := (b7 >> 4) & 0x0F
	c3Inv := b7 & 0x0F
	c3 := (b8 >> 4) & 0x0F
	c2 := b8 & 0x0F

	if c1^c1Inv != 0x0F || c2^c2Inv != 0x0F || c3^c3Inv != 0x0F {
		return AccessBits{}, false
	}

	var ab AccessBits
	for blk := 0; blk < 4; blk++ {
		bit := byte(1 << blk)
		v := BlockAccess{
			C1: int(c1 & bit >> blk),
			C2: int(c2 & bit >> blk),
			C3: int(c3 & bit >> blk),
		}
		if blk == 3 {
			ta := trailerPermissions(v.C1, v.C2, v.C3)
			v.TrailerAccess = &ta
		} else {
			r, w, inc, dec := dataPermissions(v.C1, v.C2, v.C3)
			v.Read = r
			v.Write = w
			v.Increment = inc
			v.Decrement = dec
		}
		ab.Blocks[blk] = v
	}
	return ab, true
}

// dataPermissions returns (read, write, increment, decrement) for
// a data block per AN10833 Table 6.
//
// Encoding of the four columns:
//
//	"A"     — only Key A
//	"B"     — only Key B
//	"A|B"   — either key
//	"never" — neither key can perform this operation
func dataPermissions(c1, c2, c3 int) (read, write, increment, decrement string) {
	switch (c1 << 2) | (c2 << 1) | c3 {
	case 0b000:
		return "A|B", "A|B", "A|B", "A|B"
	case 0b010:
		return "A|B", "never", "never", "never"
	case 0b100:
		return "A|B", "B", "never", "never"
	case 0b110:
		return "A|B", "B", "B", "A|B"
	case 0b001:
		return "A|B", "never", "never", "A|B"
	case 0b011:
		return "B", "B", "never", "never"
	case 0b101:
		return "B", "never", "never", "never"
	case 0b111:
		return "never", "never", "never", "never"
	}
	return "?", "?", "?", "?"
}

// trailerPermissions returns the AN10833 Table 7 permission set
// for the trailer block (5 columns: KeyA write, access-bits read,
// access-bits write, KeyB read, KeyB write).
func trailerPermissions(c1, c2, c3 int) TrailerAccess {
	switch (c1 << 2) | (c2 << 1) | c3 {
	case 0b000:
		return TrailerAccess{
			KeyAWrite: "A", AccessBitsRead: "A",
			AccessBitsWrite: "never", KeyBRead: "A", KeyBWrite: "A",
		}
	case 0b010:
		return TrailerAccess{
			KeyAWrite: "never", AccessBitsRead: "A",
			AccessBitsWrite: "never", KeyBRead: "A", KeyBWrite: "never",
		}
	case 0b100:
		return TrailerAccess{
			KeyAWrite: "B", AccessBitsRead: "A|B",
			AccessBitsWrite: "never", KeyBRead: "never", KeyBWrite: "B",
		}
	case 0b110:
		return TrailerAccess{
			KeyAWrite: "never", AccessBitsRead: "A|B",
			AccessBitsWrite: "never", KeyBRead: "never", KeyBWrite: "never",
		}
	case 0b001:
		return TrailerAccess{
			KeyAWrite: "A", AccessBitsRead: "A",
			AccessBitsWrite: "A", KeyBRead: "A", KeyBWrite: "A",
		}
	case 0b011:
		return TrailerAccess{
			KeyAWrite: "B", AccessBitsRead: "A|B",
			AccessBitsWrite: "B", KeyBRead: "never", KeyBWrite: "B",
		}
	case 0b101:
		return TrailerAccess{
			KeyAWrite: "never", AccessBitsRead: "A|B",
			AccessBitsWrite: "B", KeyBRead: "never", KeyBWrite: "never",
		}
	case 0b111:
		return TrailerAccess{
			KeyAWrite: "never", AccessBitsRead: "A|B",
			AccessBitsWrite: "never", KeyBRead: "never", KeyBWrite: "never",
		}
	}
	return TrailerAccess{}
}
