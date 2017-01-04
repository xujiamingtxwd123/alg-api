package cbc_ecb_ctr_ofb_cfb


import (
	"crypto/cipher"
	"security/crypto/tools"
	"errors"
	ccipher"security/crypto/cipher"
	ckey"security/crypto/key"
)



type EncType string
const(
//	_
	ECB EncType = "ECB"
	CBC EncType = "CBC"
	CFB EncType = "CFB"
	CTR EncType = "CTR"
	OFB EncType = "OFB"
)


type modeImpl struct {
	key []byte
	msg []byte
	alg EncType
	mode ccipher.CipherMode
	iv []byte
	cp cipher.Block
	bm cipher.BlockMode
	newCipher func([]byte) (cipher.Block,error)
	sm cipher.Stream
}

func NewECB(np func([]byte) (cipher.Block,error))(*modeImpl){
	return &modeImpl{alg:ECB,newCipher:np}
}
func NewCBC(np func([]byte) (cipher.Block,error))(*modeImpl){
	return &modeImpl{alg:CBC,newCipher:np}
}
func NewCFB(np func([]byte) (cipher.Block,error))(*modeImpl){
	return &modeImpl{alg:CFB,newCipher:np}
}
func NewCTR(np func([]byte) (cipher.Block,error))(*modeImpl){
	return &modeImpl{alg:CTR,newCipher:np}
}
func NewOFB(np func([]byte) (cipher.Block,error))(*modeImpl) {
	return &modeImpl{alg:OFB, newCipher:np}
}


func (mp* modeImpl)InitIV(mode ccipher.CipherMode, key ckey.Key, iv []byte) error{
	err:=mp.Init(mode,key)
	mp.iv = iv
	return err
}


func (mp* modeImpl) Init(cipherMode ccipher.CipherMode, key ckey.Key) error{
	switch kt:=key.(type) {
	case  (ckey.SymmKey):
		mp.key,_ = kt.GetKey()
		mp.mode = cipherMode
		mp.iv = nil
		mp.msg = nil
		return nil
	default:
		return errors.New("Error: invalid  key type in init")
	}
	return nil
}
func (mp* modeImpl) Reset(){
	mp.msg = nil
}

func (mp* modeImpl) Update(msg []byte) error{
	mp.msg = tools.BytesCombine(mp.msg,msg)
	return nil
}

func (mp* modeImpl) DoFinal(msg []byte) ([]byte, error){
	mp.msg = tools.BytesCombine(mp.msg,msg)

	if((mp.msg == nil) || (len(mp.msg) == 0)){
		return nil,errors.New("Error: invalid msg in dofinal");
	}

	if(mp.key == nil){
		return nil,errors.New("Error: no exist valid key in dofinal")
	}

	if(mp.cp == nil){
		var err error
		mp.cp,err = mp.newCipher(mp.key)
		if(err != nil){
			return nil,err
		}
	}

	if(ccipher.CIPHERMODE_ENCRYPTO == mp.mode){
		switch mp.alg {
		case CBC:
			mp.bm = cipher.NewCBCEncrypter(mp.cp, mp.iv)
		case CFB:
			mp.sm = cipher.NewCFBEncrypter(mp.cp,mp.iv)
		case CTR:
			mp.sm = cipher.NewCTR(mp.cp,mp.iv)
		case OFB:
			mp.sm = cipher.NewOFB(mp.cp,mp.iv)
		}


	}else if(ccipher.CIPHERMODE_DECRYPTO == mp.mode) {
		switch mp.alg {
		case CBC:
			mp.bm = cipher.NewCBCDecrypter(mp.cp, mp.iv)
		case CFB:
			mp.sm = cipher.NewCFBDecrypter(mp.cp,mp.iv)
		case CTR:
			mp.sm = cipher.NewCTR(mp.cp,mp.iv)
		case OFB:
			mp.sm = cipher.NewOFB(mp.cp,mp.iv)
		}

	}

	switch mp.alg {
	case ECB:
		if((len(mp.msg)%mp.cp.BlockSize()) != 0){
			return nil,errors.New("invalid msg length")
		}

		if((len(mp.key)%mp.cp.BlockSize()) != 0){
			return nil,errors.New("invalid key length")
		}

		var length int =len(mp.msg)
		dst := make([]byte, length)
		var  offset int = 0

		for length > 0 {
			if(ccipher.CIPHERMODE_ENCRYPTO == mp.mode) {
				mp.cp.Encrypt(dst[offset:], mp.msg[offset:])
			}else if(ccipher.CIPHERMODE_DECRYPTO == mp.mode) {
				mp.cp.Decrypt(dst[offset:], mp.msg[offset:])
			}
			offset += mp.cp.BlockSize()
			length -= mp.cp.BlockSize()

		}
		return dst,nil
	case CBC:
		if(mp.iv == nil){
			return nil,errors.New("Error: no exist iv in dofinal")
		}
		dst := make([]byte, len(mp.msg))
		mp.bm.CryptBlocks(dst,mp.msg)
		return dst,nil
	case CFB,CTR,OFB:
		dst := make([]byte, len(mp.msg))
		mp.sm.XORKeyStream(dst,mp.msg)
		return dst,nil
	default:
		return nil,errors.New("Error: invalid alg type in dofinal")

	}
	return nil,nil
}


