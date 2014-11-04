// Package conceal provides the ability to encrypt/decrypt byte slices using aes encryption.
package conceal

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/md5"
    "crypto/rand"
    "encoding/base64"
    "io"
)

type CloakInterface interface {
    Veil([]byte) ([]byte, error)
    Unveil([]byte) ([]byte, error)
}

type CipherLengthError struct{}

// CipherLengthError occurs when the data passed in to Unveil is shorter than the length of the 16 byte encryption key.
func (err CipherLengthError) Error() string {
    return "Data length should be at least 16 bytes"
}

// A Cloak encrypts and decrypts []byte using Veil and Unveil.
type Cloak struct {
    cipherBlock cipher.Block
}

// NewCloak takes a pin that is resized to 16 bytes and used as a key in aes encryption.
// It returns a Cloak. If the pin cannot be used to create a cipherBlock, an error is returned.
func NewCloak(pin []byte) (Cloak, error) {
    resizedPin := resizePin(pin)

    cipherBlock, err := aes.NewCipher(resizedPin)
    if err != nil {
        return Cloak{}, err
    }

    return Cloak{
        cipherBlock: cipherBlock,
    }, nil
}

func resizePin(pin []byte) []byte {
    resizedPin := md5.Sum(pin)
    return resizedPin[:]
}

// Veil base64 encodes a slice of bytes and uses aes encryption. It returns an encrypted slice of bytes,
// and an error.
func (cloak Cloak) Veil(data []byte) ([]byte, error) {
    encodedText := base64.StdEncoding.EncodeToString(data)
    cipherText := make([]byte, aes.BlockSize+len(encodedText))

    initializationVector := cipherText[:aes.BlockSize]
    _, err := io.ReadFull(rand.Reader, initializationVector)

    if err != nil {
        return []byte{}, err
    }

    cipherEncrypter := cipher.NewCFBEncrypter(cloak.cipherBlock, initializationVector)
    cipherEncrypter.XORKeyStream(cipherText[aes.BlockSize:], []byte(encodedText))

    base64CipherText := base64.URLEncoding.EncodeToString(cipherText)
    return []byte(base64CipherText), nil
}

// Unveil base64 decodes a slice of bytes and uses aes encryption to decrypt. It returns a decrypted slice of bytes,
// and an error. A CipherLengthError is returned if the data is less than 16 bytes.
func (cloak Cloak) Unveil(data []byte) ([]byte, error) {
    decodedData, err := base64.URLEncoding.DecodeString(string(data))
    if err != nil {
        return []byte{}, err
    }

    byteData := decodedData

    if len(byteData) < aes.BlockSize {
        return []byte{}, CipherLengthError{}
    }

    initializationVector := byteData[:aes.BlockSize]
    byteData = byteData[aes.BlockSize:]

    cipherDecrypter := cipher.NewCFBDecrypter(cloak.cipherBlock, initializationVector)
    cipherDecrypter.XORKeyStream(byteData, byteData)

    decoded, err := base64.StdEncoding.DecodeString(string(byteData))
    if err != nil {
        return []byte{}, err
    }

    return []byte(decoded), nil
}
