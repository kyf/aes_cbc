package aes_cbc

import (
	"testing"
)

var (
	test_file string = "./kyf"
	test_key  []byte = []byte("keyongfengkeyong")
)

func TestEncryptFile(t *testing.T) {
	err := Init(test_key)
	if err != nil {
		t.Errorf("error is %v\n", err)
	}
	err = EncryptFile("encrypt_file", test_file)
	if err != nil {
		t.Errorf("error is %v\n", err)
	}
}

func TestDecryptFile(t *testing.T) {
	err := Init(test_key)
	if err != nil {
		t.Errorf("error is %v\n", err)
	}
	err = EncryptFile("decrypt_file", "encrypt_file")
	if err != nil {
		t.Errorf("error is %v\n", err)
	}
}
