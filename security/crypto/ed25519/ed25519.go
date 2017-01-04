package ed25519

import (
	ckey "security/crypto/key"
	"errors"
	"security/crypto/tools"
	"golang.org/x/crypto/ed25519"
)
type ed25519Impl struct {
	privkey ed25519.PrivateKey
	pubkey ed25519.PublicKey
	msg []byte
}

func NewED25519()(*ed25519Impl){
	return &ed25519Impl{};
}

func (inst *ed25519Impl)Init(key ckey.Key) error{//定义统一密钥对类型 明确传入参数类型
	switch kt:=key.(type) {
	case  (*ed25519PubKey):
		inst.pubkey = kt.pub
		inst.msg = nil
	case (*ed25519PrivKey):
		inst.privkey = kt.priv
		inst.msg = nil
	default:
		return errors.New("Error: invalid ecdsa key type in Init")
	}
	return nil
}

func (inst *ed25519Impl)Update(msg []byte) error{
	inst.msg = tools.BytesCombine(inst.msg,msg)
	return nil
}
func (inst *ed25519Impl) Reset(){
	inst.msg = nil
}

func (inst *ed25519Impl)Sign(msg []byte) ([]byte,error){

	inst.msg = tools.BytesCombine(inst.msg,msg)
	if((inst.msg == nil) || (len(inst.msg) == 0)){
		return nil,errors.New("Error: invalid msg in sign");
	}


	if(inst.privkey == nil){
		return nil,errors.New("Error: no exist valid key in sign")
	}


	return ed25519.Sign(inst.privkey,msg),nil
}

func (inst *ed25519Impl)Verify(msg []byte, sig []byte) (bool,error){

	inst.msg = tools.BytesCombine(inst.msg,msg)

	if((msg == nil)||(sig == nil)) {
		return false,errors.New("Error: invalid msg or sig in sign")
	}

	if((len(msg) == 0)||(len(sig) == 0)) {
		return false,errors.New("Error: invalid msg or sig in sign")
	}

	if(inst.pubkey == nil){
		return false,errors.New("Error: no exist valid key in sign")
	}



	return ed25519.Verify(inst.pubkey,msg,sig),nil
}