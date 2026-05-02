package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

func Pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func Pkcs7Unpad(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("invalid padding size")
	}
	padLen := int(data[length-1])
	if padLen > length {
		return nil, errors.New("invalid padding size")
	}
	return data[:(length - padLen)], nil
}

func EncryptCBC(plaintext string) (string, error) {
	keyStr := os.Getenv("ENCRYPTION_KEY")

	key := []byte(keyStr)
	if len(key) != 32 {
		return "", fmt.Errorf("key must be 32 bytes for AES-256")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Generate random IV (16 bytes for AES)
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	// PKCS7 pad the plaintext
	padded := Pkcs7Pad([]byte(plaintext), aes.BlockSize)

	// Encrypt
	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)

	// Encode IV and ciphertext separately in Base64
	ivBase64 := base64.StdEncoding.EncodeToString(iv)
	ctBase64 := base64.StdEncoding.EncodeToString(ciphertext)

	// Concatenate like in JS: ivBase64 + ciphertextBase64
	return ivBase64 + ctBase64, nil
}

func DecryptCBC(plaintext string) (string, error) {
	keyStr := os.Getenv("ENCRYPTION_KEY")
	if len(plaintext) < 24 {
		return "", fmt.Errorf("invalid encrypted text format")
	}
	// First 24 chars of Base64 string = 16 bytes IV
	ivBase64 := plaintext[:24]
	cipherTextBase64 := plaintext[24:]

	// Decode IV and Ciphertext
	iv, err := base64.StdEncoding.DecodeString(ivBase64)
	if err != nil {
		return "", err
	}
	cipherText, err := base64.StdEncoding.DecodeString(cipherTextBase64)
	if err != nil {
		return "", err
	}

	// Convert key to bytes
	keyBytes := []byte(keyStr)
	if len(keyBytes) != 32 {
		return "", fmt.Errorf("key must be 32 bytes for AES-256")
	}

	// Create AES cipher
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", err
	}

	// Decrypt
	mode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(cipherText))
	mode.CryptBlocks(decrypted, cipherText)

	// Remove PKCS7 padding
	unpadded, err := Pkcs7Unpad(decrypted)
	if err != nil {
		return "", err
	}

	return string(unpadded), nil
}

func getKey() ([]byte, error) {
	key := []byte(os.Getenv("ENCRYPTION_KEY"))
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes")
	}
	return key, nil
}

// Helper: buat AEAD (AES-GCM)
func getAEAD() (cipher.AEAD, error) {
	key, err := getKey()
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func EncryptGCM(plaintext string) (string, error) {
	aead, err := getAEAD()
	if err != nil {
		return "", err
	}

	iv := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	ct := aead.Seal(nil, iv, []byte(plaintext), nil)

	// concat iv || ct
	full := make([]byte, 0, 12+len(ct))
	full = append(full, iv...)
	full = append(full, ct...)

	return base64.StdEncoding.EncodeToString(full), nil
}

func EncryptGCMDeterministic(plaintext string) (string, error) {
	aead, err := getAEAD()
	if err != nil {
		return "", err
	}

	key, err := getKey()
	if err != nil {
		return "", err
	}

	// Derive nonce dari plaintext (HMAC-SHA256)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(plaintext))
	nonce := mac.Sum(nil)[:12] // ambil 12 byte pertama

	ct := aead.Seal(nil, nonce, []byte(plaintext), nil)

	// concat nonce || ct (sama format)
	full := append(nonce, ct...)
	return base64.StdEncoding.EncodeToString(full), nil
}

func DecryptGCM(encoded string) (string, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return "", errors.New("empty encrypted data")
	}
	padLen := (4 - len(encoded)%4) % 4
	padded := encoded + strings.Repeat("=", padLen)
	blob, err := base64.URLEncoding.DecodeString(padded)
	if err != nil {
		// Fallback ke standard encoding jika URL-safe gagal
		blob, err = base64.StdEncoding.DecodeString(padded)
		if err != nil {
			return "", fmt.Errorf("invalid base64: %v", err)
		}
	}
	if len(blob) < 12 {
		return "", errors.New("ciphertext too short")
	}

	iv := blob[:12]
	ct := blob[12:]

	key := []byte(os.Getenv("ENCRYPTION_KEY"))
	if len(key) != 32 {
		return "", fmt.Errorf("key must be 32 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	pt, err := aesgcm.Open(nil, iv, ct, nil)
	if err != nil {
		return "", errors.New("decryption failed: auth failed or corrupted")
	}
	return string(pt), nil
}
