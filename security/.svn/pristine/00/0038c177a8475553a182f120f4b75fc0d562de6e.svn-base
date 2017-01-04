package TestAlg

import (
	cring "security/crypto/ring_sign"
	"security/crypto"
	ckey"security/crypto/key"
	"crypto/rand"
//	cecdsa"security/crypto/ecdsa"
	"fmt"
)

func RingSignTest(index int) {
	switch index {
	case 1:
		pr:=cring.NewPublicKeyRing(10)

		for j:=1;j < 10;j++ {
			key,_:=crypto.KeyPair(ckey.KEYPAIRTYPE_ECDSA,ckey.KEYLENGTH_ECDSA_P256)
			pr.Add(key.GetPublic())
		}
		keyself,_:=crypto.KeyPair(ckey.KEYPAIRTYPE_ECDSA,ckey.KEYLENGTH_ECDSA_P256)

		pr.Add(keyself.GetPublic())

		msg := make([]byte, 100)
		rand.Read(msg)
		sig,_:=pr.Sign(keyself.GetPrivate(),msg)

		result := pr.Verify(msg,sig)
		if(result == true){
			fmt.Println("RingSignTest0.success")
		}else{
			fmt.Println("false")
		}


	}

}
