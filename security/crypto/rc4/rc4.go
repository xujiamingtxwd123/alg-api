package rc4

import (
	"security/crypto/tools"
	"crypto/rc4"
	ccipher"security/crypto/cipher"
	"errors"
	ckey"security/crypto/key"
//	"debug/elf"
)

type rc4Impl struct {
	key []byte
	msg []byte
	mode ccipher.CipherMode
	rp *rc4.Cipher
}

func NewRC4()(*rc4Impl){
	return &rc4Impl{};
}

func (rp *rc4Impl)InitIV(mode ccipher.CipherMode, key ckey.Key, iv []byte) error{
	return rp.Init(mode,key)
}

func (rp *rc4Impl) Init(cipherMode ccipher.CipherMode, key ckey.Key) error{
	switch kt:=key.(type) {
	case  (ckey.SymmKey):
		rp.key,_ = kt.GetKey()
		rp.msg = nil
		return nil
	default:
		return errors.New("Error: invalid rc4 enc key type in init")
	}
	return nil
}


func (rp *rc4Impl) Update(msg []byte) error{
	rp.msg = tools.BytesCombine(rp.msg,msg)
	return nil
}

func (rp *rc4Impl) Reset(){
	rp.msg = nil
}

func (rp *rc4Impl) DoFinal(msg []byte) ([]byte, error){
	rp.msg = tools.BytesCombine(rp.msg,msg)

	if((rp.msg == nil) || (len(rp.msg) == 0)){
		return nil,errors.New("Error: invalid msg in sign");
	}

	if(rp.rp == nil){
		var err error
		rp.rp,err= rc4.NewCipher(rp.key)
		if(err == nil){
			rp.rp.Reset()
		}
	}

	dst := make([]byte, len(rp.msg))
	rp.rp.XORKeyStream(dst,msg)
	return dst,nil
}

