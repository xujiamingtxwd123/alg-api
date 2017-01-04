package fdh

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"testing"
)

var message = []byte("ATTACK AT DAWN")

func TestSHA256(t *testing.T) {
	h := New(crypto.SHA256, 1024)
	h.Write(message)
	result := h.Sum(nil)

	if len(result) != 1024/8 {
		t.Error("Hash result not the same length as bit length")
	}
	if h.Size() != len(result) {
		t.Error("Hash result not the same length Size()")
	}
	if h.BlockSize() != sha256.BlockSize {
		t.Error("Incorrect block size")
	}

	// Now let's do it manually and confirm they are the same
	var manual []byte
	h0 := sha256.New()
	h0.Write(message)
	h0.Write([]byte{byte(0)})
	manual = h0.Sum(manual)

	h1 := sha256.New()
	h1.Write(message)
	h1.Write([]byte{byte(1)})
	manual = h1.Sum(manual)

	h2 := sha256.New()
	h2.Write(message)
	h2.Write([]byte{byte(2)})
	manual = h2.Sum(manual)

	h3 := sha256.New()
	h3.Write(message)
	h3.Write([]byte{byte(3)})
	manual = h3.Sum(manual)

	if !bytes.Equal(result, manual) {
		t.Error("Hash result not the same as manually constructed result")
	}

	// Test calling the utility Sum function
	if !bytes.Equal(result, Sum(crypto.SHA256, 1024, message)) {
		t.Error("Hash result not the same when called via Sum")
	}
}

// Writing after calling Sum() should panic
func TestPanicFinalized(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			return
		} else {
			t.Error("Failed to panic for writing after being finalized")
		}
	}()

	h := New(crypto.SHA256, 1024)
	h.Write(message)
	h.Sum(nil)
	h.Write(message)
}

// Using an unimported hash should panic
func TestPanicNoImport(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			return
		} else {
			t.Error("Failed to panic for using unimported hash")
		}
	}()

	h := New(crypto.MD5, 1024)
	h.Write(message)
	h.Sum(nil)
}

// using a bitlen that does not fit hash should panic
func TestPanicOddBitlen(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			return
		} else {
			t.Error("Failed to panic when using a bitlen that does not fit hash")
		}
	}()

	h := New(crypto.SHA256, 2379)
	h.Write(message)
	h.Sum(nil)
}

// Using a small bielen should panic
func TestPanicZeroBitlen(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			return
		} else {
			t.Error("Failed to panic when using a small bitlen")
		}
	}()

	h := New(crypto.SHA256, 0)
	h.Write(message)
	h.Sum(nil)
}
