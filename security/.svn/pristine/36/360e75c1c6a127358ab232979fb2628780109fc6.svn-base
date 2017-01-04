// Package fdh implements a Full Domain Hash (FDH) algorithm.
//
// An FDH is a useful cryptographic construction that extends the size of a hash digest to an arbitrary length.
//
// We construct an FDH by computing a number of `cycles` where cycles=(target length)/(digest length) + 1.
// We then compute FDH(M) = HASH(M||0)||HASH(M||1)||...||HASH(M||cycles−1) where HASH is any hash function defined in package `crypto` and || denotes c oncatenation.
//
// This is usually used with an RSA signature scheme where the target length is the size of the key.
// See https://en.wikipedia.org/wiki/Full_Domain_Hash
package fdh

import (
	"crypto"
	"hash"
	"strconv"
	"sync"
)

// digest represents the partial evaluation of a Full Domain Hash checksum.
type digest struct {
	base  crypto.Hash
	bits  int
	parts []hash.Hash
	final bool // Unlike many hash functions Full Domain Hashes are "finalized" after a call to Sum() and cannot be furthur written to.
}

// Given a base hash function and a target bit length, returns a new hash.Hash computing a Full Domain Hash checksum.
// It will panic if the bitlen is not a multiple of the hash length or if the hash library is not imported.
func New(h crypto.Hash, bitlen int) hash.Hash {
	if !h.Available() {
		panic("fdh: requested hash function #" + strconv.Itoa(int(h)) + " is unavailable. Make sure your hash function is proprely imported.")
	} else if bitlen < h.Size()*8 {
		panic("fdh: bitlen cannot be smaller than hash length")
	} else if bitlen%(h.Size()*8) != 0 {
		panic("fdh: hash digest size does not fit into bitlen")
	}

	numparts := bitlen / (h.Size() * 8)
	d := digest{
		base:  h,
		bits:  bitlen,
		parts: make([]hash.Hash, numparts),
	}
	d.Reset()
	return &d
}

// Reset resets the Hash to its initial state.
func (d *digest) Reset() {
	for i, _ := range d.parts {
		d.parts[i] = d.base.New()
	}
	d.final = false
}

// BlockSize returns the hash's underlying block size.
func (d *digest) BlockSize() int {
	return d.parts[0].BlockSize()
}

// Size returns the number of bytes Sum will return. This will be the same as the bitlen (with conversion from bits to bytes)
func (d *digest) Size() int {
	return d.bits / 8
}

// Add more data to the running hash.
// Once Sum() is called the hash is finalized and writing to the hash will panic
func (d *digest) Write(p []byte) (int, error) {
	if d.final {
		panic("Cannot write to Full Domain Hash after a call has been made to Sum() and the hash has been finalized.")
	}

	// Write to each component hash asyncronously
	var wg sync.WaitGroup
	for i, h := range d.parts {
		wg.Add(1)
		go func(i int, h hash.Hash) {
			h.Write(p) // Hashes in crypto library don't return errors
			wg.Done()
		}(i, h)
	}
	wg.Wait()

	return len(p), nil
}

// Sum appends the current hash to b and returns the resulting slice.
// Once Sum is called, the hash is finalized and can no longer be written to
func (d *digest) Sum(in []byte) []byte {
	hash := d.checkSum()
	return append(in, hash[:]...)
}

func (d *digest) checkSum() []byte {
	var sum []byte
	for i, h := range d.parts {
		finalByte := byte(i)
		h.Write([]byte{finalByte})
		sum = append(sum, h.Sum(nil)...)
	}
	d.final = true
	return sum
}

// Sum returns the the Full Domain Hash checksum of the data.
func Sum(h crypto.Hash, bitlen int, message []byte) []byte {
	hash := New(h, bitlen)
	hash.Write(message)
	return hash.Sum(nil)
}
