package ecdsa

import (
	"math/big"
	"crypto/ecdsa"
	"hash"
	chash"security/crypto/hash"
	ckey"security/crypto/key"
	csign"security/crypto/sign"
	"errors"
	"security/crypto/tools"
	"encoding/asn1"
	"crypto/rand"
//	"fmt"
)

type ecdsaSignature struct {
	R, S *big.Int
}

type ecdsaImpl struct {
	privkey *ecdsa.PrivateKey
	pubkey *ecdsa.PublicKey
	hash hash.Hash
	msg []byte
	hashType chash.HashType
}

type ECDSASign interface {
	csign.SignAlg
	SetHashType(ht chash.HashType) error
}


func NewECDSA()(*ecdsaImpl){
	return &ecdsaImpl{};
}

func (inst *ecdsaImpl)Init(key ckey.Key) error{
	switch kt:=key.(type) {
	case  (*ecdsaPubKey):
		inst.pubkey = kt.pub
		inst.msg = nil
		inst.hashType = chash.HASHTYPE_SHA256
	case  (*ecdsaPrivKey):
		inst.privkey = kt.priv
		inst.msg = nil
		inst.hashType = chash.HASHTYPE_SHA256
	default:
		return errors.New("Error: invalid ecdsa key type in Init")
	}
	return nil
}

func (inst *ecdsaImpl)SetHashType(ht chash.HashType) error{
	inst.hashType = ht
	return nil
}

func (inst *ecdsaImpl)Update(msg []byte) error{
	inst.msg = tools.BytesCombine(inst.msg,msg)
	return nil
}



func (inst *ecdsaImpl) Reset(){
	inst.msg = nil
}

func (inst *ecdsaImpl)Sign(msg []byte) ([]byte,error){

	inst.msg = tools.BytesCombine(inst.msg,msg)
	if((inst.msg == nil) || (len(inst.msg) == 0)){
		return nil,errors.New("Error: invalid msg in sign");
	}

	if(inst.privkey == nil){
		return nil,errors.New("Error: no exist valid key in sign")
	}

	if((inst.privkey.D == nil) || (inst.privkey.Curve == nil)){
		return nil,errors.New("Error: no exist private key in sign")
	}



	if(inst.hash == nil){
		var err error
		inst.hash, err = chash.GetHashInstance(inst.hashType)
		if(err != nil){
			return nil,err
		}
	}

	hv := GetHash(inst.msg, inst.hash)
	//	inst.msg = nil
	r,s,err := ecdsa.Sign(rand.Reader, inst.privkey, hv)
	if(err != nil){
		return nil,err
	}
	raw,err := SignExport(r,s)
	if(err != nil){
		return nil,err
	}
	return raw,nil
}

func (inst *ecdsaImpl)Verify(msg []byte, sig []byte) (bool,error){

	if((msg == nil)||(sig == nil)) {
		return false,errors.New("Error: invalid msg or sig in sign")
	}

	if((len(msg) == 0)||(len(sig) == 0)) {
		return false,errors.New("Error: invalid msg or sig in sign")
	}

	if(inst.pubkey == nil){
		return false,errors.New("Error: no exist public key in sign")
	}
	if(inst.hash == nil){
		var err error
		inst.hash, err = chash.GetHashInstance(inst.hashType)
		if(err != nil){
			return false,err
		}
	}

	r,s,err := SignImport(sig)
	if(err != nil){
		return false,err
	}
	inst.msg = tools.BytesCombine(inst.msg,msg)
	hv := GetHash(inst.msg, inst.hash)
	//	inst.msg = nil
	return ecdsa.Verify(inst.pubkey,hv,r,s),nil
}

func SignExport(r, s *big.Int) ([]byte, error){
	return asn1.Marshal(ecdsaSignature{r, s})
}

func SignImport(sig []byte)(*big.Int, *big.Int, error){
	es := new(ecdsaSignature)
	_, err := asn1.Unmarshal(sig, es)
	return es.R,es.S,err
}
func GetHash(msg []byte, hash hash.Hash)([]byte){
	//hs := hash()
	hash.Reset()
	hash.Write(msg)
	return hash.Sum(nil)
}




