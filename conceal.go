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

func (err CipherLengthError) Error() string {
    return "Data length is too short"
}

type Cloak struct {
    pin         []byte
    cipherBlock cipher.Block
}

func NewCloak(pin []byte) (Cloak, error) {
    resizedPin := resizePin(pin)

    cipherBlock, err := aes.NewCipher(resizedPin)
    if err != nil {
        return Cloak{}, err
    }

    return Cloak{
        pin:         resizedPin,
        cipherBlock: cipherBlock,
    }, nil
}

func resizePin(pin []byte) []byte {
    resizedPin := md5.Sum(pin)
    return resizedPin[:]
}

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
