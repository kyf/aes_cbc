package aes_cbc

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"io/ioutil"
	"os"
)

var (
	key   []byte
	block cipher.Block
)

func PKCS7Pad(data []byte) []byte {
	padLen := aes.BlockSize - len(data)%aes.BlockSize
	if padLen == 0 {
		padLen = aes.BlockSize
	}
	pad := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, pad...)
}

func Init(k []byte) error {
	key = k
	var err error
	block, err = aes.NewCipher(key)
	if err != nil {
		return err
	}
	return nil
}

func envCheck() error {
	if key == nil {
		return errors.New("key is not initialized!")
	}

	if block == nil {
		return errors.New("cipher block is not initialized!")
	}

	return nil
}

func getContent(pathStr string) ([]byte, error) {
	fp, err := os.Open(pathStr)
	if err != nil {
		return nil, err
	}
	defer fp.Close()

	content, err := ioutil.ReadAll(fp)
	if err == nil {
		return nil, err
	}
	return content, nil
}

func write2File(pathStr string, out []byte) error {
	fp1, err := os.Create(pathStr)
	if err != nil {
		return err
	}
	defer fp1.Close()
	_, err = fp1.Write(out)
	if err != nil {
		return err
	}
	return nil
}

func EncryptFile(destPath, srcPath string) error {
	err := envCheck()
	if err != nil {
		return err
	}

	content, err := getContent(srcPath)
	if err != nil {
		return err
	}
	content = PKCS7Pad(content)

	out := make([]byte, len(content)+aes.BlockSize)
	iv := out[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(out[aes.BlockSize:], content)
	return write2File(destPath, out)
}

func DecryptFile(destPath, srcPath string) error {
	err := envCheck()
	if err != nil {
		return err
	}

	content, err := getContent(srcPath)
	if err != nil {
		return err
	}

	out := make([]byte, len(content)-aes.BlockSize)
	iv := content[:aes.BlockSize]
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(out, content[aes.BlockSize:])
	last_bytes := out[(len(out) - 1):]
	last_byte := int(last_bytes[0])
	return write2File(destPath, out[:len(out)-last_byte])
}
