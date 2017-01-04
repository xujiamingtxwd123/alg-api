package hmac


import "hash"
import (
	chash "security/crypto/hash"
	"errors"
	ckey"security/crypto/key"
	"crypto/hmac"
	"security/crypto/tools"
)

type HmacImpl struct {
	ht chash.HashType
	msg []byte
	hash hash.Hash
	key []byte
}


func NewHMAC()(*HmacImpl){
	return &HmacImpl{ht:chash.HASHTYPE_SHA256};
}
func (hc *HmacImpl)SetHashType(ht chash.HashType) error{
	hc.ht = ht
	return nil
}

func (hc *HmacImpl)Init(ht chash.HashType,key ckey.Key) error{

	hc.ht = ht
	switch k := key.(type) {
	case (ckey.SymmKey):
		hc.key,_ = k.GetKey()
	default:
		return  errors.New("Error: invalid  mac key type in init")
	}
	return nil

}


func (hc *HmacImpl)Update(msg []byte) error{
	hc.msg = tools.BytesCombine(hc.msg,msg)
	return nil
}


func (hc *HmacImpl)DoFinal(msg []byte) ([]byte,error){
	hc.msg = tools.BytesCombine(hc.msg,msg)
	if(hc.hash == nil){
		hs,err := chash.GetHashFunc(hc.ht)
		if(err != nil){
			return nil,err
		}
		hc.hash = hmac.New(hs,hc.key)
	}

	hc.hash.Write(hc.msg)
	return hc.hash.Sum(nil),nil
}
func (hc *HmacImpl)Reset(){
	hc.msg = nil
	if(hc.hash == nil){
		hs,err := chash.GetHashFunc(hc.ht)
		if(err != nil){
			return //nil,err
		}
		hc.hash = hmac.New(hs,hc.key)
	}
	hc.hash.Reset()
}
