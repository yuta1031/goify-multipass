package multipass

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"regexp"
	"time"
)

// New comment
func New(secret string, location *time.Location) (ctx *Multipass, err error) {
	if len(secret) == 0 {
		err = errors.New("Invalid Secret")
		return nil, err
	}

	// Use the Multipass secret to derive two cryptographic keys,
	// one for encryption, one for signing
	digestHash := sha256.New()
	if _, err := digestHash.Write([]byte(secret)); err != nil {
		return nil, err
	}
	key := digestHash.Sum(nil)

	ctx = &Multipass{
		EncryptionKey: key[0:aes.BlockSize],
		SignatureKey:  key[aes.BlockSize:32],
		Location:      location,
	}
	return ctx, err
}

// Encode comment
func (ctx *Multipass) Encode(customerInfo map[string]interface{}) (token string, err error) {
	if customerInfo == nil {
		err = errors.New("Customer info must be provided")
		return token, err
	}

	if customerInfo["email"] == "" {
		err = errors.New("Customer email must be provided")
		return token, err
	}

	// Store the current time in ISO8601 format.
	// The token will only be valid for a small timeframe around this timestamp.
	customerInfo["created_at"] = time.Now().In(ctx.Location).Format(TimeISO8601Layout)

	// Serialize the customer data to JSON and encrypt it
	var cipherBytes []byte
	if b, err := json.Marshal(customerInfo); err == nil {
		if cipherBytes, err = ctx.encrypt(b); err != nil {
			return token, err
		}
	} else {
		return token, err
	}

	// Create a signature (message authentication code) of the ciphertext
	// and encode everything using URL-safe Base64 (RFC 4648)
	b := bytes.NewBuffer(nil)
	b.Write(cipherBytes)
	b.Write(ctx.sign(cipherBytes))

	token = base64.URLEncoding.EncodeToString(b.Bytes())

	var re *regexp.Regexp

	// Replace + with -
	re = regexp.MustCompile(`/\+/g`)
	token = re.ReplaceAllString(token, `-`)

	// Replace / with _
	re = regexp.MustCompile(`/\//g`)
	token = re.ReplaceAllString(token, `_`)

	return token, err
}

// GenerateURL comment
func (ctx *Multipass) GenerateURL(customerInfo map[string]interface{}, domain string) (u *url.URL, err error) {
	if domain == "" {
		err = errors.New("Shopify domain url must be provided")
		return u, err
	}

	var token string
	if token, err = ctx.Encode(customerInfo); err != nil {
		return u, nil
	}

	urlString := buildString("https://", domain, "/account/login/multipass/", token)
	return url.Parse(urlString)
}

func (ctx *Multipass) sign(data []byte) (signed []byte) {
	mac := hmac.New(sha256.New, ctx.SignatureKey)
	mac.Write(data)
	return mac.Sum(nil)
}

// encrypt comment
func (ctx *Multipass) encrypt(data []byte) (cipherBytes []byte, err error) {
	//use PKCS5Padding
	src := pkcs5Padding(data, aes.BlockSize)
	if (len(src) % aes.BlockSize) != 0 {
		err = errors.New("crypto/cipher input not full blocks")
		return cipherBytes, err
	}

	// use the AES algorithm (128 bit key length, CBC mode of operation, random initialization vector).
	var block cipher.Block
	block, err = aes.NewCipher(ctx.EncryptionKey)
	if err != nil {
		return cipherBytes, err
	}

	cipherBytes = make([]byte, aes.BlockSize+len(src))

	// Use a random IV
	iv := cipherBytes[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return cipherBytes, err
	}

	aesEncrypter := cipher.NewCBCEncrypter(block, iv)
	aesEncrypter.CryptBlocks(cipherBytes[aes.BlockSize:], src)

	return cipherBytes, err
}
