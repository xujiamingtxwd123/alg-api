package rc4

import ckey"security/crypto/key"



type rc4key struct {
	key []byte
	kt ckey.KeyType
}

func (rk *rc4key)SetKey(key []byte) error{
	//做长度检查
	rk.key = key
	return nil
}

func (rk *rc4key)GetKey() ([]byte,error){
	return rk.key,nil
}

func (rk *rc4key)GetType() ckey.KeyType{
	return ckey.KEYTYPE_RC4
}

func BuildKey(keyType ckey.KeyType)(ckey.Key,error){
	return &rc4key{kt:keyType},nil
}
