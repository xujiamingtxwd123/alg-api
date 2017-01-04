package cbc_ecb_ctr_ofb_cfb

import ckey"security/crypto/key"
type modekey struct {
	key []byte
	kt ckey.KeyType
}

func (rk *modekey)SetKey(key []byte) error{
	//做长度检查
	rk.key = key
	return nil
}

func (rk *modekey)GetKey() ([]byte,error){
	return rk.key,nil
}

func (rk *modekey)GetType() ckey.KeyType{
	return rk.kt
}

func BuildKey(keyType ckey.KeyType)(ckey.Key,error){
	return &modekey{kt:keyType},nil
}
