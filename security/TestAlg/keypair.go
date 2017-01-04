package TestAlg

import(
	"fmt"
	ckey"security/crypto/key"
	c"security/crypto"
//	"crypto"
	"strings"
)

func RsaKeyTest(index int){
	switch index {
	case 1:
		_,err := c.KeyPair(ckey.KEYPAIRTYPE_RSA,1024)
		if(err == nil){
			fmt.Println("rsaKeyTest1.success")
		}else {
			fmt.Println(err)
		}
	case 2:
		_,err := c.KeyPair(ckey.KEYPAIRTYPE_RSA,2048)
		if(err == nil){
			fmt.Println("rsaKeyTest2.success")
		}else {
			fmt.Println(err)
		}
	case 3:
		_,err := c.KeyPair(ckey.KEYPAIRTYPE_RSA,512)
		if(err == nil){
			fmt.Println("rsaKeyTest3.success")
		}else {
			fmt.Println(err)
		}

	case 4:
		_,err :=c.KeyPair(ckey.KEYPAIRTYPE_RSA,768)
		if(err == nil){
			fmt.Println("rsaKeyTest4.success")
		}else {
			fmt.Println(err)
		}
	}
}
func EcdsaKeyTest(index int){
	switch index {
	case 1:
		
		_,err := c.KeyPair(ckey.KEYPAIRTYPE_ECDSA,ckey.KEYLENGTH_ECDSA_P224)
		if(err == nil){
			fmt.Println("ecdsaKeyTest1.success")
		}else{
			fmt.Println(err)
		}
	case 2:
		_,err := c.KeyPair(ckey.KEYPAIRTYPE_ECDSA,ckey.KEYLENGTH_ECDSA_P256)
		if(err == nil){
			fmt.Println("ecdsaKeyTest2.success")
		}else{
			fmt.Println(err)
		}
	case 3:
		_,err := c.KeyPair(ckey.KEYPAIRTYPE_ECDSA,ckey.KEYLENGTH_ECDSA_P384)
		if(err == nil){
			fmt.Println("ecdsaKeyTest3.success")
		}else{
			fmt.Println(err)
		}
	case 4:
		_,err := c.KeyPair(ckey.KEYPAIRTYPE_ECDSA,ckey.KEYLENGTH_ECDSA_P521)
		if(err == nil){
			fmt.Println("ecdsaKeyTest4.success")
		}else{
			fmt.Println(err)
		}
	case 5: _,err := c.KeyPair(ckey.KEYPAIRTYPE_ECDSA,20)
		if(strings.EqualFold(err.Error(),"Error: invalid ecdsa key type in keypair") == true){
			fmt.Println("ecdsaKeyTest5.success")
		}else{
			fmt.Println(err)
		}


	}

}
