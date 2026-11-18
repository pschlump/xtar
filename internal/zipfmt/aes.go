/*
Copyright (C) Philip Schlump, 2012-2026.

MIT Licensed.
*/

package zipfmt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
)

// WinZip AES encryption (AE-2): method 99 entries whose extra field
// 0x9901 carries the strength and the real compression method.  Keys
// come from PBKDF2-HMAC-SHA1 over salt+password (1000 rounds); the
// data is salt || 2-byte verifier || AES-CTR ciphertext || 10-byte
// HMAC-SHA1 tag.  The CTR counter is a 128-bit LITTLE-endian integer
// starting at 1 (verified against 7-Zip output), and the HMAC covers
// the ciphertext.

const (
	methodWinZipAES uint16 = 99
	aesExtraID      uint16 = 0x9901
)

// aesStrength maps the extra field's strength byte: 1=128, 2=192,
// 3=256-bit keys (salt length is half the key length).
func aesStrength(s int) (keyLen, saltLen int, ok bool) {
	switch s {
	case 1:
		return 16, 8, true
	case 2:
		return 24, 12, true
	case 3:
		return 32, 16, true
	}
	return 0, 0, false
}

// findAESExtra returns the strength and real method from an entry's
// extra fields.
func findAESExtra(extra []byte) (strength, method int, ok bool) {
	for len(extra) >= 4 {
		id := binary.LittleEndian.Uint16(extra)
		sz := int(binary.LittleEndian.Uint16(extra[2:]))
		if id == aesExtraID && sz >= 7 && len(extra) >= 4+7 {
			d := extra[4:]
			if string(d[2:4]) != "AE" {
				return 0, 0, false
			}
			s := int(d[4])
			m := int(binary.LittleEndian.Uint16(d[5:7]))
			if _, _, valid := aesStrength(s); valid {
				return s, m, true
			}
			return 0, 0, false
		}
		if sz < 0 || 4+sz > len(extra) {
			return 0, 0, false
		}
		extra = extra[4+sz:]
	}
	return 0, 0, false
}

// buildAESExtra writes the 0x9901 record for the strength and real
// method (AE-2 form).
func buildAESExtra(strength int, method uint16) []byte {
	out := make([]byte, 4+7)
	binary.LittleEndian.PutUint16(out, aesExtraID)
	binary.LittleEndian.PutUint16(out[2:], 7)
	binary.LittleEndian.PutUint16(out[4:], 2) // AE-2: CRC is carried by the HMAC
	copy(out[6:], "AE")
	out[8] = byte(strength)
	binary.LittleEndian.PutUint16(out[9:], method)
	return out
}

// pbkdf2SHA1 is PBKDF2 with HMAC-SHA1 (RFC 2898) — the WinZip AES key
// schedule's only derivation.
func pbkdf2SHA1(password, salt []byte, iter, dkLen int) []byte {
	var out []byte
	block := 1
	for len(out) < dkLen {
		mac := hmac.New(sha1.New, password)
		var ib [4]byte
		binary.BigEndian.PutUint32(ib[:], uint32(block))
		mac.Write(salt)
		mac.Write(ib[:])
		u := mac.Sum(nil)
		f := make([]byte, len(u))
		copy(f, u)
		for i := 1; i < iter; i++ {
			mac.Reset()
			mac.Write(u)
			u = mac.Sum(nil)
			for j := range f {
				f[j] ^= u[j]
			}
		}
		out = append(out, f...)
		block++
	}
	return out[:dkLen]
}

// ctrLE encrypts/decrypts b in AES-CTR mode with a little-endian
// 128-bit counter starting at 1.
func ctrLE(block cipher.Block, b []byte) {
	ctr := make([]byte, aes.BlockSize)
	ctr[0] = 1
	var ks [aes.BlockSize]byte
	for off := 0; off < len(b); off += aes.BlockSize {
		block.Encrypt(ks[:], ctr)
		n := len(b) - off
		if n > aes.BlockSize {
			n = aes.BlockSize
		}
		for i := 0; i < n; i++ {
			b[off+i] ^= ks[i]
		}
		for i := 0; i < aes.BlockSize; i++ { // increment little-endian
			ctr[i]++
			if ctr[i] != 0 {
				break
			}
		}
	}
}

var errAES = errors.New("zip: bad AES data")

// aesUnwrap strips and verifies the AES framing of one member's
// payload, returning the still-compressed plaintext.  onDisk is the
// entry's stored (encrypted) byte count.
func aesUnwrap(payload []byte, strength int, password string) ([]byte, error) {
	keyLen, saltLen, _ := aesStrength(strength)
	if len(payload) < saltLen+2+10 {
		return nil, errAES
	}
	salt := payload[:saltLen]
	verifier := payload[saltLen : saltLen+2]
	ct := payload[saltLen+2 : len(payload)-10]
	tag := payload[len(payload)-10:]

	dk := pbkdf2SHA1([]byte(password), salt, 1000, 2*keyLen+2)
	key := dk[:keyLen]
	hkey := dk[keyLen : 2*keyLen]
	if !hmac.Equal(dk[2*keyLen:], verifier) {
		return nil, errors.New("zip: member is encrypted; wrong password")
	}
	mac := hmac.New(sha1.New, hkey)
	mac.Write(ct)
	if !hmac.Equal(mac.Sum(nil)[:10], tag) {
		return nil, errAES
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errAES
	}
	ct = append([]byte{}, ct...) // the payload aliases the caller's buffer
	ctrLE(block, ct)
	return ct, nil
}

// aesWrap encrypts the still-compressed data into the on-disk form:
// fresh salt, password verifier, CTR ciphertext, HMAC tag.
func aesWrap(data []byte, strength int, password string) ([]byte, error) {
	keyLen, saltLen, _ := aesStrength(strength)
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	dk := pbkdf2SHA1([]byte(password), salt, 1000, 2*keyLen+2)
	block, err := aes.NewCipher(dk[:keyLen])
	if err != nil {
		return nil, err
	}
	ct := append([]byte{}, data...)
	ctrLE(block, ct)
	mac := hmac.New(sha1.New, dk[keyLen:2*keyLen])
	mac.Write(ct)
	out := append([]byte{}, salt...)
	out = append(out, dk[2*keyLen:]...)
	out = append(out, ct...)
	return append(out, mac.Sum(nil)[:10]...), nil
}
