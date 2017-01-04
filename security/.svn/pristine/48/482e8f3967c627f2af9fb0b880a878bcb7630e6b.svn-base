package hmac

import ckey"security/crypto/key"
type hmackey struct {
	key []byte
	kt ckey.KeyType
}

func (rk *hmackey)SetKey(key []byte) error{
	//做长度检查
	rk.key = key
	return nil
}

func (rk *hmackey)GetKey() ([]byte,error){
	return rk.key,nil
}

func (rk *hmackey)GetType() ckey.KeyType{
	return rk.kt
}

func BuildKey(keyType ckey.KeyType)(ckey.Key,error){
	return &hmackey{kt:keyType},nil
}
