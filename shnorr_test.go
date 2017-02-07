package shnorr

import (
	"testing"

	"github.com/dedis/crypto/config"
	"github.com/dedis/crypto/ed25519"
)

func TestVerify(t *testing.T) {
	msg := []byte("hello World!")
	kp := config.NewKeyPair(ed25519.NewAES128SHA256Ed25519(true))
	sig := NewSignature(msg, kp.Secret)
	if !sig.verify(msg, kp.Public) {
		t.Fatalf("Couldn't verify signature: \n%+v\nfor msg:'%s'", sig, msg)
	}

	msg2 := []byte("hello World!!")
	if sig.verify(msg2, kp.Public) {
		t.Fatalf("Couldn't verify signature: \n%+v\nfor msg:'%s'", sig, msg)
	}

}

func TestMarshaling(t *testing.T) {
	msg := []byte("hello World!")
	kp := config.NewKeyPair(ed25519.NewAES128SHA256Ed25519(true))
	sig := NewSignature(msg, kp.Secret)
	b, err := sig.MarshalBinary()
	if err != nil {
		t.Fatalf("error in marshaling %v", err)
	}

	sig1 := Signature{}
	if err := sig1.UnmarshalBinary(b); err != nil {
		t.Fatalf("error in unmarshaling %v", err)
	}

	if sig1.e == sig.e && sig1.s == sig.s {
		t.Fatalf("the two signatures should be the same\n %v,\n %v", sig, sig1)
	}

}
