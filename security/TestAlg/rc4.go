package TestAlg


import(
	"fmt"
	"security/crypto"
	ccipher"security/crypto/cipher"
	ckey"security/crypto/key"

)
func RC4EncTest(index int){
	switch index {
	case 1:
		rc,_ := crypto.GetCipherInstance(ccipher.ENC_RC4)
		key := []byte{2,3,4,5}
		ko,_:=crypto.BuildKey(ckey.KEYTYPE_RC4)
		ko.(ckey.SymmKey).SetKey(key)

		rc.Init(ccipher.CIPHERMODE_ENCRYPTO,ko)
		msg := []byte{2,1,2,3,4}
		ciphertext,_:=rc.DoFinal(msg)

		rc.Init(ccipher.CIPHERMODE_DECRYPTO,ko)
		ko.(ckey.SymmKey).SetKey(key)
		ciphertext1,_:=rc.DoFinal(msg)

		if(comp(ciphertext,ciphertext1) == false){
			fmt.Println("fail")
		}

		rc.Init(ccipher.CIPHERMODE_ENCRYPTO,ko)
		co,_:=rc.DoFinal(ciphertext)
		if(comp(co,msg) == true){
			fmt.Println("rc4EncTest1.success")
		}else{
			fmt.Println("fail")
		}

	}
}
