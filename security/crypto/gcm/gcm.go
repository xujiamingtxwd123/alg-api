package gcm

import (
	"crypto/cipher"
	"security/crypto/tools"
	ccipher"security/crypto/cipher"
	ckey"security/crypto/key"
	"errors"
)
type gcmImpl struct {
	key []byte
	msg []byte
	//cp cipher.Block
	mode ccipher.CipherMode
	newCipher func([]byte) (cipher.Block,error)
	conf Conf
	ae cipher.AEAD
}

type Conf struct{
	Nonce []byte
	AdditionalData []byte
}


type GCMCipher interface {
	SetNonce([]byte)
	SetAdditional([]byte)
}

func NewGCM(np func([]byte) (cipher.Block,error))(*gcmImpl){
	return &gcmImpl{newCipher:np}
}


func (gp* gcmImpl)InitIV(mode ccipher.CipherMode, key ckey.Key, iv []byte) error{
	err:=gp.Init(mode,key)
	//gp.iv = iv
	return err
}


func (gp *gcmImpl)SetNonce(nonce []byte){
	gp.conf.Nonce = nonce
}

func (gp *gcmImpl)SetAdditional(additional []byte){
	gp.conf.AdditionalData = additional
}

func (gp *gcmImpl) Init(cipherMode ccipher.CipherMode, key ckey.Key ) error{
	switch kt:=key.(type) {
	case  (ckey.SymmKey):
		gp.key,_ = kt.GetKey()
		gp.mode = cipherMode
		gp.msg = nil
	default:
		return errors.New("Error: invalid  key type in init")
	}
	return nil
}
func (gp *gcmImpl) Reset(){
	gp.msg = nil
}

func (gp *gcmImpl) SetConfig(config interface{}) error{
	switch cf:=config.(type){
	case Conf:
		gp.conf = cf
	//fmt.Println("set Config")
	default:
		return errors.New("Error: invalid mode config type")
	}


	return nil
}
func (gp *gcmImpl) Update(msg []byte) error{
	gp.msg = tools.BytesCombine(gp.msg,msg)
	return nil
}

func (gp *gcmImpl) DoFinal(msg []byte) ([]byte, error){
	gp.msg = tools.BytesCombine(gp.msg,msg)


	if(gp.ae == nil){
		cp,err := gp.newCipher(gp.key)
		if(err != nil){
			return nil, err
		}
		gp.ae,err=cipher.NewGCM(cp)
		if(err != nil){
			return nil,err
		}
	}

	if(ccipher.CIPHERMODE_ENCRYPTO == gp.mode){
		return gp.ae.Seal(nil, gp.conf.Nonce, gp.msg, gp.conf.AdditionalData),nil
	}else if(ccipher.CIPHERMODE_DECRYPTO == gp.mode){
		//fmt.Println("dec")
		return gp.ae.Open(nil, gp.conf.Nonce, gp.msg, gp.conf.AdditionalData)
	}else {
		return nil,errors.New("Error: invalid alg type in dofinal")
	}

	return nil,nil
}
