package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: deco-web <host> [action]")
	}
	host := os.Args[1]
	action := "login"
	if len(os.Args) > 2 {
		action = os.Args[2]
	}

	password := os.Getenv("TPLINK_PASSWORD")
	if password == "" {
		log.Fatal("TPLINK_PASSWORD required")
	}

	base := fmt.Sprintf("http://%s/cgi-bin/luci/;stok=", host)

	// Get RSA keys
	resp, err := http.Get(base + "/login?form=keys&operation=read")
	if err != nil {
		log.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	var keysResp struct {
		Result struct {
			Password []string `json:"password"`
		} `json:"result"`
	}
	json.Unmarshal(body, &keysResp)
	if len(keysResp.Result.Password) < 2 {
		log.Fatalf("bad keys: %s", string(body))
	}

	rsaN := new(big.Int)
	rsaN.SetString(keysResp.Result.Password[0], 16)
	rsaE := new(big.Int)
	rsaE.SetString(keysResp.Result.Password[1], 16)
	rsaPub := &rsa.PublicKey{N: rsaN, E: int(rsaE.Int64())}

	// Generate AES key and IV (16 bytes each, as hex-like strings)
	aesKey := randomString(16)
	aesIV := randomString(16)

	// Hash = MD5("" + password) = MD5(password)
	h := md5.Sum([]byte(password))
	hash := hex.EncodeToString(h[:])

	seq := 0

	switch action {
	case "login":
		// Step 1: RSA encrypt the password for the login body
		encPwd, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPub, []byte(password))
		if err != nil {
			log.Fatal(err)
		}
		encPwdHex := hex.EncodeToString(encPwd)

		// Login body (JSON)
		loginBody := fmt.Sprintf(`{"password":"%s"}`, encPwdHex)

		// Step 2: AES encrypt the body
		aesEnc := aesEncrypt(loginBody, aesKey, aesIV)
		dataLen := len(aesEnc)

		// Step 3: Build signature
		// sig_data = "k=<key>&i=<iv>&h=<hash>&s=<seq>"
		sigData := fmt.Sprintf("k=%s&i=%s&h=%s&s=%d", aesKey, aesIV, hash, seq+dataLen)
		sig := rsaEncryptChunks(sigData, rsaPub)

		// Step 4: Send request
		payload := fmt.Sprintf(`{"data":"%s","sign":"%s"}`, aesEnc, sig)
		fmt.Printf("Payload (first 200): %s...\n\n", payload[:min(200, len(payload))])

		resp, err := http.Post(base+"/login?form=login&operation=login",
			"application/json", strings.NewReader(payload))
		if err != nil {
			log.Fatal(err)
		}
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		fmt.Printf("HTTP %d\n", resp.StatusCode)
		fmt.Printf("Response (raw): %s\n\n", string(respBody))

		// If response is AES encrypted, decrypt it
		if len(respBody) > 0 {
			decrypted := aesDecrypt(string(respBody), aesKey, aesIV)
			fmt.Printf("Decrypted: %s\n", decrypted)
		}

	default:
		fmt.Println("Only 'login' action implemented")
	}
	_ = action
	_ = host
}

func randomString(n int) string {
	b := make([]byte, n)
	for i := range b {
		rb := make([]byte, 1)
		rand.Read(rb)
		b[i] = '0' + (rb[0] % 10) // digits only for simplicity
	}
	return string(b)
}

func aesEncrypt(plaintext, key, iv string) string {
	block, _ := aes.NewCipher([]byte(key))
	// PKCS7 padding
	padLen := aes.BlockSize - (len(plaintext) % aes.BlockSize)
	padded := append([]byte(plaintext), bytes.Repeat([]byte{byte(padLen)}, padLen)...)
	mode := cipher.NewCBCEncrypter(block, []byte(iv))
	encrypted := make([]byte, len(padded))
	mode.CryptBlocks(encrypted, padded)
	// Return base64... actually CryptoJS returns base64
	return encodeBase64(encrypted)
}

func aesDecrypt(ciphertext, key, iv string) string {
	data := decodeBase64(ciphertext)
	if len(data) == 0 {
		return ciphertext
	}
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return fmt.Sprintf("aes error: %v", err)
	}
	if len(data)%aes.BlockSize != 0 {
		return fmt.Sprintf("bad length: %d", len(data))
	}
	mode := cipher.NewCBCDecrypter(block, []byte(iv))
	mode.CryptBlocks(data, data)
	// Remove PKCS7 padding
	if len(data) > 0 {
		padLen := int(data[len(data)-1])
		if padLen > 0 && padLen <= aes.BlockSize {
			data = data[:len(data)-padLen]
		}
	}
	return string(data)
}

func encodeBase64(data []byte) string {
	import_path := "encoding/base64"
	_ = import_path
	// Use standard encoding
	return b64Encode(data)
}

func b64Encode(data []byte) string {
	const enc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	result := make([]byte, 0, (len(data)+2)/3*4)
	for i := 0; i < len(data); i += 3 {
		var b uint32
		n := 0
		for j := 0; j < 3 && i+j < len(data); j++ {
			b = b<<8 | uint32(data[i+j])
			n++
		}
		b <<= uint(8 * (3 - n))
		result = append(result, enc[(b>>18)&0x3f])
		result = append(result, enc[(b>>12)&0x3f])
		if n > 1 {
			result = append(result, enc[(b>>6)&0x3f])
		} else {
			result = append(result, '=')
		}
		if n > 2 {
			result = append(result, enc[b&0x3f])
		} else {
			result = append(result, '=')
		}
	}
	return string(result)
}

func decodeBase64(s string) []byte {
	const dec = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	s = strings.TrimRight(s, "\r\n ")
	if len(s) == 0 || len(s)%4 != 0 {
		return nil
	}
	result := make([]byte, 0, len(s)/4*3)
	for i := 0; i < len(s); i += 4 {
		var b uint32
		padCount := 0
		for j := 0; j < 4; j++ {
			c := s[i+j]
			if c == '=' {
				padCount++
			} else {
				idx := strings.IndexByte(dec, c)
				if idx < 0 {
					return nil
				}
				b = b<<6 | uint32(idx)
			}
		}
		b <<= uint(6 * padCount)
		result = append(result, byte(b>>16))
		if padCount < 2 {
			result = append(result, byte(b>>8))
		}
		if padCount < 1 {
			result = append(result, byte(b))
		}
	}
	return result
}

func rsaEncryptChunks(data string, pub *rsa.PublicKey) string {
	// TP-Link splits data at 53 chars for 1024-bit key (128 - 11 padding = 117 max, but they use 53)
	chunkSize := 53
	var result string
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk := data[i:end]
		enc, err := rsa.EncryptPKCS1v15(rand.Reader, pub, []byte(chunk))
		if err != nil {
			log.Fatalf("rsa encrypt chunk: %v", err)
		}
		result += hex.EncodeToString(enc)
	}
	return result
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
