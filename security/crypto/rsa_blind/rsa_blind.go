package rsablind

// In cryptography, a blind signature is a form of digital signature in which the content of a message is disguised (blinded) before it is signed. The entity signing the message does not know the contents of the message being signed.
// 1. The key used to sign the blinded messages should not be used for any other purpose. Re-using this key in other contexts opens it up to attack.
//
// 2. Use the Full-Domain-Hash package (https://github.com/cryptoballot/fdh) to expand the size of your hash to a secure size. You should use a full-domain-hash size of at least 1024 bits, but bigger is better. However, this hash size needs to remain significantly smaller than your key size to avoid RSA verification failures. A good rule of thumb is to use 2048 bit keys and 1536 bit hashes, or 4096 bit keys and 3072 bit hashes (hash size is 3/4 the key size).
//
// 3. Because we use a full-domain hash size that is less than the key size, this scheme is theoretically open to an Index Calculation Attack (see http://www.jscoron.fr/publications/isodcc.pdf). However, with a large enough RSA key (recommended 2048 bits or larger), and a large enough full-domain-hash (1024 bits or larger) this attack in infeasable.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"errors"
	"io"
	"math/big"
	"security/crypto/fdh"
	"crypto"
	ckey"security/crypto/key"
	crsa"security/crypto/rsa"
)


//if need OOP,as follows
//#########################################################################################
//type rsablindImpl struct {
//	key *rsa.PrivateKey
//	hash hash.Hash
//	msg []byte
//	hashType hs.HashType
//}
//
//func NewRSABlind()(*rsablindImpl){
//	return &rsablindImpl{};
//}
//
//func (inst *rsablindImpl)Init(key interface{}) error{
//	switch kt:=key.(type) {
//	case  (*rsa.PrivateKey):
//		inst.key = kt
//		inst.msg = nil
//		inst.hash = crypto.SHA256
//	default:
//		return errors.New("Error: invalid rsa key type in Init")
//	}
//	return nil
//}
//
//func (inst *rsablindImpl)SetConfig(config interface{}) error{
//	if(config == nil){
//		return errors.New("Error: invalid config is null")
//	}
//	switch cf:=config.(type){
//	case hs.HashType:
//		inst.hashType = cf
//		var err error
//		inst.hash ,err= hs.GetHashInstance(inst.hashType)
//		return err
//
//	default:
//		return errors.New("Error: invalid rsablind config type")
//
//	}
//	return nil
//}
//
//func (inst *rsablindImpl)Update(msg []byte) error{
//	inst.msg = tools.BytesCombine(inst.msg,msg)
//	return nil
//}
//
//func (inst *rsablindImpl) Clear(){
//	inst.msg = nil
//}
//############################################################################################


// Given the Public Key of the signing entity and a hashed message, blind the message so it cannot be inspected by the signing entity.
//
// Use the Full-Domain-Hash package (https://github.com/cryptoballot/fdh) to expand the size of your hash to a secure size. You should
// use a full-domain-hash size of at least 1024 bits, but bigger is better. However, this hash size needs to remain significantly
// smaller than your key size to avoid RSA verification failures. A good rule of thumb is to use 2048 bit keys and 1536 bit hashes,
// or 4096 bit keys and 3072 bit hashes (hash size is 3/4 the key size).
//
// This function returns the blinded message and an unblinding factor that can be used in conjuction with the `Unblind()` function to
// unblind the signature after the message has been signed.


// func Blind(key *rsa.PublicKey,message []byte) (blindedData []byte, unblinder []byte, err error) {
func Blind(key ckey.Key,message []byte) (blindedData []byte, unblinder []byte, err error) {
	rpk,ok :=key.(crsa.RSAPublicKey)
	if(!ok){
		return nil,nil,errors.New("invaild key type")
	}

	rsakey:=rpk.GetRSAPublicKey()

	bitlen := rsakey.N.BitLen()
	hashed := fdh.Sum(crypto.SHA256, bitlen * 3/4, message)

	blinded, unblinderBig, err := blind(rand.Reader, rsakey, new(big.Int).SetBytes(hashed))
	if err != nil {
		return nil, nil, err
	}

	return blinded.Bytes(), unblinderBig.Bytes(), nil
}

// Given a private key and a hashed message, blind sign the hashed message.
//
// The private key used here should not be used for any other purpose other than blind signing (use for other purposes is insecure
// when also using it for blind signatures)
func BlindSign(key ckey.Key, hashed []byte) ([]byte, error) {

	rpk,ok :=key.(crsa.RSAPrivateKey)
	if(!ok){
		return nil,errors.New("invaild key type")
	}

	rsakey:=rpk.GetRSAPrivateKey()

	bitlen := rsakey.PublicKey.N.BitLen()
	if len(hashed)*8 > bitlen {
		return nil, rsa.ErrMessageTooLong
	}

	c := new(big.Int).SetBytes(hashed)
	m, err := decryptAndCheck(rand.Reader, rsakey, c)
	if err != nil {
		return nil, err
	}

	return m.Bytes(), nil
}

// Given the Public Key of the signing entity, the blind signature, and the unblinding factor (obtained from `Blind()`), recover a new
// signature that will validate against the original hashed message.
func Unblind(pub ckey.Key, blindedSig, unblinder []byte) ([]byte,error) {

	rpk,ok :=pub.(crsa.RSAPublicKey)
	if(!ok){
		return nil,errors.New("invaild key type")
	}

	rsakey:=rpk.GetRSAPublicKey()

	m := new(big.Int).SetBytes(blindedSig)
	unblinderBig := new(big.Int).SetBytes(unblinder)
	m.Mul(m, unblinderBig)
	m.Mod(m, rsakey.N)
	return m.Bytes(),nil
}

// Verify that the unblinded signature properly signs the non-blinded (original) hashed message
func VerifyBlindSignature(pub ckey.Key, message, sig []byte) (bool,error) {

	rpk,ok :=pub.(crsa.RSAPublicKey)
	if(!ok){
		return false,errors.New("invaild key type")
	}

	rsakey:=rpk.GetRSAPublicKey()

	bitlen := rsakey.N.BitLen()
	hashed := fdh.Sum(crypto.SHA256, bitlen * 3/4, message)

	m := new(big.Int).SetBytes(hashed)
	bigSig := new(big.Int).SetBytes(sig)

	c := encrypt(new(big.Int), rsakey, bigSig)

	if subtle.ConstantTimeCompare(m.Bytes(), c.Bytes()) == 1 {
		return true,nil
	} else {
		return false,nil
	}
}

func VerifySignature(pub ckey.Key, hashed, sig []byte) (bool,error) {


	rpk,ok :=pub.(crsa.RSAPublicKey)
	if(!ok){
		return false,errors.New("invaild key type")
	}

	rsakey:=rpk.GetRSAPublicKey()


	m := new(big.Int).SetBytes(hashed)
	bigSig := new(big.Int).SetBytes(sig)

	c := encrypt(new(big.Int), rsakey, bigSig)

	if subtle.ConstantTimeCompare(m.Bytes(), c.Bytes()) == 1 {
		return true,nil
	} else {
		return false,rsa.ErrVerification
	}
}

// Adapted from from crypto/rsa decrypt
func blind(random io.Reader, key *rsa.PublicKey, c *big.Int) (blinded, unblinder *big.Int, err error) {
	// Blinding enabled. Blinding involves multiplying c by r^e.
	// Then the decryption operation performs (m^e * r^e)^d mod n
	// which equals mr mod n. The factor of r can then be removed
	// by multiplying by the multiplicative inverse of r.

	var r *big.Int

	for {
		r, err = rand.Int(random, key.N)
		if err != nil {
			return
		}
		if r.Cmp(bigZero) == 0 {
			r = bigOne
		}
		ir, ok := modInverse(r, key.N)

		if ok {
			bigE := big.NewInt(int64(key.E))
			rpowe := new(big.Int).Exp(r, bigE, key.N)
			cCopy := new(big.Int).Set(c)
			cCopy.Mul(cCopy, rpowe)
			cCopy.Mod(cCopy, key.N)
			return cCopy, ir, nil
		}
	}
}

// All variables and functions below are carbon copy-paste from the standard library crypto/rsa

var bigZero = big.NewInt(0)
var bigOne = big.NewInt(1)

// Carbon copy of crypto/rsa encrypt()
func encrypt(c *big.Int, pub *rsa.PublicKey, m *big.Int) *big.Int {
	e := big.NewInt(int64(pub.E))
	c.Exp(m, e, pub.N)
	return c
}

// Carbon copy of crypto/rsa decrypt()
// decrypt performs an RSA decryption, resulting in a plaintext integer. If a
// random source is given, RSA blinding is used.
func decrypt(random io.Reader, priv *rsa.PrivateKey, c *big.Int) (m *big.Int, err error) {
	// TODO(agl): can we get away with reusing blinds?
	if c.Cmp(priv.N) > 0 {
		err = rsa.ErrDecryption
		return
	}

	var ir *big.Int
	if random != nil {
		// Blinding enabled. Blinding involves multiplying c by r^e.
		// Then the decryption operation performs (m^e * r^e)^d mod n
		// which equals mr mod n. The factor of r can then be removed
		// by multiplying by the multiplicative inverse of r.

		var r *big.Int

		for {
			r, err = rand.Int(random, priv.N)
			if err != nil {
				return
			}
			if r.Cmp(bigZero) == 0 {
				r = bigOne
			}
			var ok bool
			ir, ok = modInverse(r, priv.N)
			if ok {
				break
			}
		}
		bigE := big.NewInt(int64(priv.E))
		rpowe := new(big.Int).Exp(r, bigE, priv.N)
		cCopy := new(big.Int).Set(c)
		cCopy.Mul(cCopy, rpowe)
		cCopy.Mod(cCopy, priv.N)
		c = cCopy
	}

	if priv.Precomputed.Dp == nil {
		m = new(big.Int).Exp(c, priv.D, priv.N)
	} else {
		// We have the precalculated values needed for the CRT.
		m = new(big.Int).Exp(c, priv.Precomputed.Dp, priv.Primes[0])
		m2 := new(big.Int).Exp(c, priv.Precomputed.Dq, priv.Primes[1])
		m.Sub(m, m2)
		if m.Sign() < 0 {
			m.Add(m, priv.Primes[0])
		}
		m.Mul(m, priv.Precomputed.Qinv)
		m.Mod(m, priv.Primes[0])
		m.Mul(m, priv.Primes[1])
		m.Add(m, m2)

		for i, values := range priv.Precomputed.CRTValues {
			prime := priv.Primes[2+i]
			m2.Exp(c, values.Exp, prime)
			m2.Sub(m2, m)
			m2.Mul(m2, values.Coeff)
			m2.Mod(m2, prime)
			if m2.Sign() < 0 {
				m2.Add(m2, prime)
			}
			m2.Mul(m2, values.R)
			m.Add(m, m2)
		}
	}

	if ir != nil {
		// Unblind.
		m.Mul(m, ir)
		m.Mod(m, priv.N)
	}

	return
}

// Carbon-copy of crypto/rsa decryptAndCheck()
func decryptAndCheck(random io.Reader, priv *rsa.PrivateKey, c *big.Int) (m *big.Int, err error) {
	m, err = decrypt(random, priv, c)
	if err != nil {
		return nil, err
	}

	// In order to defend against errors in the CRT computation, m^e is
	// calculated, which should match the original ciphertext.
	check := encrypt(new(big.Int), &priv.PublicKey, m)
	if c.Cmp(check) != 0 {
		return nil, errors.New("rsa: internal error")
	}
	return m, nil
}

// Carbon-copy of crypto/rsa modInverse()
// modInverse returns ia, the inverse of a in the multiplicative group of prime
// order n. It requires that a be a member of the group (i.e. less than n).
func modInverse(a, n *big.Int) (ia *big.Int, ok bool) {
	g := new(big.Int)
	x := new(big.Int)
	y := new(big.Int)
	g.GCD(x, y, a, n)
	if g.Cmp(bigOne) != 0 {
		// In this case, a and n aren't coprime and we cannot calculate
		// the inverse. This happens because the values of n are nearly
		// prime (being the product of two primes) rather than truly
		// prime.
		return
	}

	if x.Cmp(bigOne) < 0 {
		// 0 is not the multiplicative inverse of any element so, if x
		// < 1, then x is negative.
		x.Add(x, n)
	}

	return x, true
}
