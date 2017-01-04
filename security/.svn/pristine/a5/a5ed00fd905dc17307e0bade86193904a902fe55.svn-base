package RSA

import (
	"crypto/sha256"
	"hash"
	"crypto/rsa"
	"crypto/rand"
	"security/crypto/tools"
	ccipher"security/crypto/cipher"
	chash"security/crypto/hash"
	"errors"
	ckey"security/crypto/key"
)

type EncType string
const(
//	_
	ENCTYPE_PKCS1V15 EncType = "ENCTYPE_PKCS1V15"
	ENCTYPE_OAEP EncType = "ENCTYPE_OAEP"
)

type RSACipher interface {
	ccipher.CipherAlg
	SetHashType(ht chash.HashType) error
}

type rsaImpl struct {
	privkey *rsa.PrivateKey
	pubkey *rsa.PublicKey
	hash  hash.Hash
	msg []byte
	alg EncType
	mode ccipher.CipherMode
}

func NewENCPKCS1V15RSA()(*rsaImpl){
	return &rsaImpl{alg:ENCTYPE_PKCS1V15};
}

func NewENCOAEPRSA()(*rsaImpl){
	return &rsaImpl{alg:ENCTYPE_OAEP};
}

func (rp *rsaImpl)InitIV(mode ccipher.CipherMode, key ckey.Key, iv []byte) error{
	return rp.Init(mode,key)
}

func (rp *rsaImpl)Reset(){
	rp.msg = nil
}
func (rp *rsaImpl) Init(cipherMode ccipher.CipherMode, key ckey.Key) error{
	if(cipherMode == ccipher.CIPHERMODE_ENCRYPTO){
		rpk,ok :=key.(*rsaPubKey)
		if(!ok){
			return errors.New("invaild key type in init")
		}
		rp.pubkey = rpk.pub
	}else if(cipherMode == ccipher.CIPHERMODE_DECRYPTO){
		rprivk,ok :=key.(*rsaPrivKey)
		if(!ok){
			return errors.New("invaild key type in init")
		}
		rp.privkey = rprivk.priv
	}else{
		return errors.New("invaild cipher mode in init")
	}
	rp.mode = cipherMode
	rp.msg = nil
	return nil
}

func (rp *rsaImpl)SetHashType(ht chash.HashType) error{
	var err error
	rp.hash ,err= chash.GetHashInstance(ht)
	return err

}
func (rp *rsaImpl) Update(msg []byte) error{
	rp.msg = tools.BytesCombine(rp.msg,msg)
	return nil
}
func (rp *rsaImpl) DoFinal(msg []byte) ([]byte, error){
	rp.msg = tools.BytesCombine(rp.msg,msg)


	if((rp.msg == nil) || (len(rp.msg) == 0)){
		return nil,errors.New("Error: invalid msg in sign");
	}

	switch rp.alg {
	case ENCTYPE_PKCS1V15:
		if(ccipher.CIPHERMODE_ENCRYPTO == rp.mode){
			if(rp.pubkey == nil){
				return nil,errors.New("Error: no exist valid key in sign")
			}
			return rsa.EncryptPKCS1v15(rand.Reader,(rp.pubkey),rp.msg)
		}else if(ccipher.CIPHERMODE_DECRYPTO == rp.mode){
			if(rp.privkey == nil){
				return nil,errors.New("Error: no exist valid key in sign")
			}
			return rsa.DecryptPKCS1v15(rand.Reader,rp.privkey,rp.msg)
		}
	case ENCTYPE_OAEP:
		if(rp.hash == nil){
			rp.hash = sha256.New()
		}

		if(ccipher.CIPHERMODE_ENCRYPTO == rp.mode){
			if(rp.pubkey == nil){
				return nil,errors.New("Error: no exist valid key in sign")
			}
			return rsa.EncryptOAEP(rp.hash,rand.Reader,(rp.pubkey),rp.msg,nil)

		}else if(ccipher.CIPHERMODE_DECRYPTO == rp.mode){
			if(rp.privkey == nil){
				return nil,errors.New("Error: no exist valid key in sign")
			}
			return rsa.DecryptOAEP(rp.hash,rand.Reader,(rp.privkey),rp.msg,nil)
		}
	default:
		return nil,errors.New("Error: invalid alg type in dofinal")
	}


	return nil,nil
}
