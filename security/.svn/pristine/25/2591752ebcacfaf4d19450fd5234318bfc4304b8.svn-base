package hash

import (
	"hash"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto"
	"errors"
)
type HashType int16
const(
//	_
	HASHTYPE_MD5 HashType = iota
	HASHTYPE_SHA1
	HASHTYPE_SHA224
	HASHTYPE_SHA256
	HASHTYPE_SHA384
	HASHTYPE_SHA512
)
var digest = []crypto.Hash{
	crypto.MD5,
	crypto.SHA1 ,                      // import crypto/sha1
	crypto.SHA224 ,                    // import crypto/sha256
	crypto.SHA256 ,                    // import crypto/sha256
	crypto.SHA384 ,                    // import crypto/sha512
	crypto.SHA512,
}

func GetDigest(hash int16) crypto.Hash{
	return digest[hash];
}
func GetHashInstance(hashType HashType) (hash.Hash,error) {
	hf,err := GetHashFunc(hashType)
	return hf(),err
}

func GetHashFunc(hashType HashType)(func() hash.Hash,error){
	switch hashType {
	case HASHTYPE_MD5:
		return md5.New, nil
	case HASHTYPE_SHA1:
		return sha1.New, nil
	case HASHTYPE_SHA224:
		return sha256.New224, nil
	case HASHTYPE_SHA256:
		return sha256.New, nil
	case HASHTYPE_SHA384:
		return sha512.New384, nil
	case HASHTYPE_SHA512:
		return sha512.New, nil
	}
	return nil, errors.New("Error: Don't find this hash type in GetHashInstance")

}
