/*
Copyright (C) Philip Schlump, 2012-2026.

BSD 3 Clause Licensed.
*/

package zipfmt

import "crypto/rand"

// Traditional PKWARE ZipCrypto.  This is obfuscation, not security —
// kept for compatibility with the installed base, exactly like every
// other zip tool.

const zcMult = 134775813

type zkeys struct{ k0, k1, k2 uint32 }

func newKeys(password string) *zkeys {
	k := &zkeys{0x12345678, 0x23456789, 0x34567890}
	for i := 0; i < len(password); i++ {
		k.update(password[i])
	}
	return k
}

func (k *zkeys) update(c byte) {
	k.k0 = (k.k0 >> 8) ^ zipCRCTab[(k.k0^uint32(c))&0xff]
	k.k1 = (k.k1+(k.k0&0xff))*zcMult + 1
	k.k2 = (k.k2 >> 8) ^ zipCRCTab[(k.k2^(k.k1>>24))&0xff]
}

// stream decrypts one byte and folds it into the key state.
func (k *zkeys) stream(c byte) byte {
	temp := k.k2 | 2
	d := c ^ byte(((temp*(temp^1))>>8)&0xff)
	k.update(d)
	return d
}

// zipDecrypt removes the 12-byte encryption header and decrypts the
// payload.  ok reports whether the check byte matched: the header's
// last byte is the high byte of the CRC-32 (or of the DOS time when
// the entry was written with data descriptors — untestable here, so
// those are accepted on faith).
func zipDecrypt(password string, data []byte, crc uint32, flags uint16) (plain []byte, ok bool) {
	k := newKeys(password)
	hdr := make([]byte, 12)
	for i := range hdr {
		hdr[i] = k.stream(data[i])
	}
	if flags&flagDataDesc == 0 && hdr[11] != byte(crc>>24) {
		return nil, false
	}
	out := make([]byte, 0, len(data)-12)
	for _, c := range data[12:] {
		out = append(out, k.stream(c))
	}
	return out, true
}

// zipEncrypt produces the encrypted payload: 12 random-ish header
// bytes (the last one the check byte) followed by the ciphertext.
func zipEncrypt(password string, data []byte, check byte) []byte {
	hdr := make([]byte, 12)
	if _, err := rand.Read(hdr); err != nil {
		for i := range hdr {
			hdr[i] = byte(i * 7)
		}
	}
	hdr[11] = check
	k := newKeys(password)
	out := make([]byte, 0, 12+len(data))
	for _, c := range hdr {
		temp := k.k2 | 2
		out = append(out, c^byte(((temp*(temp^1))>>8)&0xff))
		k.update(c)
	}
	for _, c := range data {
		temp := k.k2 | 2
		out = append(out, c^byte(((temp*(temp^1))>>8)&0xff))
		k.update(c)
	}
	return out
}
