package RSA

import (
	"hash"
	"crypto/sha256"
	"crypto/rsa"
	"crypto/rand"
	"security/crypto/tools"
	chash"security/crypto/hash"
	"errors"
	"crypto"
	csign"security/crypto/sign"
	ckey"security/crypto/key"

)

type SignMode string

const(
//	_
	SIGNMODE_PKCS1V15 SignMode = "SIGNMODE_PKCS1V15"
	SIGNMODE_PSS SignMode = "SIGNMODE_PSS"
)

type RSASign interface {
	csign.SignAlg
	SetHashType(ht chash.HashType) error
}
type rsaSignImpl struct {
	privkey *rsa.PrivateKey
	pubkey *rsa.PublicKey
	hash hash.Hash
	hashType crypto.Hash
	msg []byte
	mode SignMode
}

func NewSignPKCS1V15RSA()(*rsaSignImpl){
	return &rsaSignImpl{mode:SIGNMODE_PKCS1V15};
}

func NewSignPSSRSA()(*rsaSignImpl){
	return &rsaSignImpl{mode:SIGNMODE_PSS};
}


func (inst *rsaSignImpl)Init(key ckey.Key) error{
	switch kt:=key.(type) {
	case  (*rsaPubKey):
		inst.pubkey = kt.pub
		inst.msg = nil
	case (*rsaPrivKey):
		inst.privkey = kt.priv
		inst.msg = nil
	default:
		return errors.New("Error: invalid rsa key type in Init")

	}
	return nil
}


func (inst *rsaSignImpl)SetHashType(ht chash.HashType) error{
	var err error
	inst.hash ,err= chash.GetHashInstance(ht)
	if(err == nil){
		inst.hashType = chash.GetDigest(int16(ht))
	}
	return err

}

func (inst *rsaSignImpl)Update(msg []byte) error{
	inst.msg = tools.BytesCombine(inst.msg,msg)
	return nil
}

func (inst *rsaSignImpl)Sign(msg []byte) ([]byte,error){

	inst.msg = tools.BytesCombine(inst.msg,msg)
	if((inst.msg == nil) || (len(inst.msg) == 0)){
		return nil,errors.New("Error: invalid msg in sign");
	}
	if(inst.privkey == nil){
		return nil,errors.New("Error: no exist valid key in sign")
	}

	if(inst.hash == nil){
		inst.hash=sha256.New()
		inst.hashType = chash.GetDigest(int16(chash.HASHTYPE_SHA256))
	}


	hv := GetHash(inst.msg, inst.hash)


	if(inst.mode == SIGNMODE_PKCS1V15){

		return rsa.SignPKCS1v15(rand.Reader, inst.privkey, inst.hashType,hv)
	}else if(inst.mode == SIGNMODE_PSS){

		return rsa.SignPSS(rand.Reader,inst.privkey,inst.hashType,hv,nil)
	}

	return nil,nil
}
func (inst *rsaSignImpl) Reset(){
	inst.msg = nil
}
func (inst *rsaSignImpl)Verify(msg []byte, sig []byte) (bool,error){

	inst.msg = tools.BytesCombine(inst.msg,msg)

	if((msg == nil)||(sig == nil)) {
		return false,errors.New("Error: invalid msg or sig in sign")
	}

	if((len(msg) == 0)||(len(sig) == 0)) {
		return false,errors.New("Error: invalid msg or sig in sign")
	}
	if(inst.hash == nil){
		return false,errors.New("Error: invalid hash alg in sign")
	}

	if(inst.pubkey == nil){
		return false,errors.New("Error: no exist valid key in sign")
	}
	if(inst.hash == nil){
		inst.hash=sha256.New()
		inst.hashType = chash.GetDigest(int16(chash.HASHTYPE_SHA256))
	}



	hv := GetHash(inst.msg, inst.hash)
	if(inst.mode == SIGNMODE_PKCS1V15){
		err :=rsa.VerifyPKCS1v15((inst.pubkey),inst.hashType,hv,sig)
		if(err == nil){
			return true,nil
		}else{
			return false,err
		}
	}else if(inst.mode == SIGNMODE_PSS){
		err := rsa.VerifyPSS((inst.pubkey),inst.hashType,hv,sig,nil)
		if(err == nil){
			return true,nil
		}else{
			return false,err
		}
	}
	return false,nil

}

func GetHash(msg []byte, hash hash.Hash)([]byte){
	hash.Reset()
	hash.Write(msg)
	return hash.Sum(nil)
}