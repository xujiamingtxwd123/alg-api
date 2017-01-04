package TestAlg

import (
	"crypto/sha1"
	"fmt"
	"security/crypto"
	cmac"security/crypto/mac"
	chash"security/crypto/hash"
	ckey"security/crypto/key"
//	chmac"security/crypto/hmac"
	"crypto/hmac"
)

func HMACTest(index int){
	switch index {
	case 1:
		key := []byte{1,2,3,4,5,6,7,8}
		mact,_ := crypto.GetMacInstance(cmac.MACTYPE_HMAC)
		mo,_:=crypto.BuildKey(ckey.KEYTYPE_MAC)
		mo.(ckey.SymmKey).SetKey(key)
		mact.Init(chash.HASHTYPE_SHA1,mo)

		msg :=[]byte{1,2,3,4,5,6,7,8,1,2,3,4}
		result,_:=mact.DoFinal(msg)
		//fmt.Printf("%x\n",result)

		ss:=hmac.New(sha1.New,key)
		ss.Reset()
		ss.Write(msg)
		s1:=ss.Sum(nil)
		//fmt.Printf("%x\n",s1)
		if(comp(result,s1) == true){
			fmt.Println("hmacTest1.success")
		}else{
			fmt.Println("false")
		}

	}
}
