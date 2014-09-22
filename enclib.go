package enclib

import "crypto/sha256"
import "encoding/base64"
import "errors"
import "crypto/aes"
import "crypto/rsa"
import "crypto/rand"
import "crypto/x509"
import "crypto/cipher"
import "encoding/pem"
import "strings"

// Encrypt String using AES256 with another persons public key
func Encrypt_AESPublic(message string, key interface{}) (str string,err error) {

  if message == "" {
    err = errors.New("String to Encrypt Cannot Be Empty\n")
    return
  }

  if key == nil {
    err = errors.New("Encryption Public Key Cannot Be nil\n")
    return
  }

  cipherkey,err := Random(32)
  if err != nil {
    return
  }

  ciphertext, err := AESEncrypt(cipherkey, []byte(message))
  if err != nil {
    return
  }

  encryptedkey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, key.(*rsa.PublicKey), cipherkey, []byte(""))
  if err != nil {
    return
  }

  odata := base64.StdEncoding.EncodeToString(ciphertext)
  okey := base64.StdEncoding.EncodeToString(encryptedkey)
  str = odata + ":" + okey

  return
}

// Decrypt an AES256 bit message to a string using a private key
func Decrypt_AESPublic(combinedmessage string, key interface{}) (str string,err error) {

  if combinedmessage == "" {
    err = errors.New("Combined Message String cannot be Empty\n")
    return
  }
  if key == nil {
    err = errors.New("Decryption Private Key Cannot Be nil\n")
    return
  }
  if strings.Index(combinedmessage,":") == -1 {
    err = errors.New("Malformed Combined Message\n")
    return
  }

  arr := strings.Split(combinedmessage, ":")

  ciphertext,err  := base64.StdEncoding.DecodeString(arr[0])
  if err != nil {
    return
  }
  encryptedkey,err := base64.StdEncoding.DecodeString(arr[1])
  if err != nil {
    return
  }

  cipherkey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key.(*rsa.PrivateKey), encryptedkey, []byte(""))
  if err != nil {
    return
  }

  message, err := AESDecrypt(cipherkey,ciphertext)
  if err != nil {
    return
  }

  str = string(message)

  return
}

// Encrypt a short message via RSA
func Encrypt_RSAPublic(message string, key interface{}) (str string,err error) {
  if message == "" {
    err = errors.New("String to Encrypt Cannot Be Empty\n")
    return
  }
  if key == nil {
    err = errors.New("Encryption Public Key Cannot Be nil\n")
    return
  }

  ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, key.(*rsa.PublicKey), []byte(message), []byte(""))
  if err != nil {
    return
  }

  str = base64.StdEncoding.EncodeToString(ciphertext)
  return
}

// Decrypt a short message via RSA
func Decrypt_RSAPublic(message string, key interface{}) (str string,err error) {
  if message == "" {
    err = errors.New("String to Decrypt Cannot Be Empty\n")
    return
  }
  if key == nil {
    err = errors.New("Encryption Private Key Cannot Be nil\n")
    return
  }
  decodedmessage, err := base64.StdEncoding.DecodeString(message)
  if err != nil {
    return
  }
  plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, key.(*rsa.PrivateKey), decodedmessage, []byte(""))
  if err != nil {
    return
  }

  str = string(plaintext)
  return
}

// Random Number generator
func Random(size int) (b []byte,err error) {
  b = make([]byte, size)
  sz, err := rand.Read(b)
  if err != nil {
    return
  } else if sz != size {
    err = errors.New("Could not Read enough Numbers from Random Number Generator\n")
    return
  }
  return
}

// Generate IV
func GenerateIV() (iv []byte, err error) {
  iv, err = Random(aes.BlockSize)
  if err != nil {
    return
  }
  return
}

// Padding function for AES
func AESPadBuffer(m []byte) (p []byte,err error) {
  mLen := len(m)

  p = make([]byte, mLen)
  copy(p, m)

  if len(p) != mLen {
    err = errors.New("Could not Allocate AESPadBuffer\n")
    return
  }

  padding := aes.BlockSize - mLen%aes.BlockSize

  p = append(p, 0x80)
  for i := 1; i < padding; i++ {
    p = append(p, 0x0)
  }

  return
}

// Unpadding function for AES
func AESUnpadBuffer(p []byte) (m []byte, err error) {
  m = p
  var pLen int
  origLen := len(m)

  for pLen = origLen - 1; pLen >= 0; pLen-- {
    if m[pLen] == 0x80 {
      break
    }

    if m[pLen] != 0x0 || (origLen-pLen) > aes.BlockSize {
      err = errors.New("Could not Allocate AESUnpadBuffer\n")
      return
    }
  }
  m = m[:pLen]

  return
}

// Encrypt a message
func AESEncrypt(key []byte, msg []byte) (ct []byte, err error) {
  c, err := aes.NewCipher(key)
  if err != nil {
    return
  }
  iv, err := GenerateIV()
  if err != nil {
    return
  }
  padded, err := AESPadBuffer(msg)
  if err != nil {
    return
  }
  cbc := cipher.NewCBCEncrypter(c, iv)
  cbc.CryptBlocks(padded, padded)
  ct = iv
  ct = append(ct, padded...)

  return
}

// Decrypt a message
func AESDecrypt(key []byte, ct []byte) (msg []byte, err error) {
    c, err := aes.NewCipher(key)
    if err != nil {
      return
    }

    tmp_ct := make([]byte, len(ct))
    copy(tmp_ct, ct)
    iv := tmp_ct[:aes.BlockSize]
    if len(iv) != aes.BlockSize {
      err = errors.New("Invalid IV on Decrypt\n")
      return
    }
    msg = tmp_ct[aes.BlockSize:]

    cbc := cipher.NewCBCDecrypter(c, iv)
    cbc.CryptBlocks(msg, msg)
    msg, err = AESUnpadBuffer(msg)

    return
}

// Hash an array of bytes and return a base64 string
func Hash_data(data []byte) (str string,err error) {
  if len(data) == 0 {
    err = errors.New("No data to Hash\n")
    return
  }

  hash := sha256.New()
  hash.Write(data)
  sha := hash.Sum(nil)

  str = base64.StdEncoding.EncodeToString(sha[:32])

  return
}

// Create Public RSA key from Base64 string
func PubKey_fromBase64(str string) (pub_key interface{},err error) {
  if str == "" {
    err = errors.New("Base64 String cannot be Empty\n")
    return
  }

  bytes,err := base64.StdEncoding.DecodeString(str)
  if err != nil {
    return
  }

  pub_blk, _ := pem.Decode(bytes)
  if pub_blk == nil {
    err = errors.New("Could not PEM Decode from Base64\n")
    return
  }

  pub_key, err = x509.ParsePKIXPublicKey(pub_blk.Bytes)
  if err != nil {
    return
  }

  return
}

// Create Base64 string from Public Key
func PubKey_toBase64(pub interface{}) (str string,err error) {
  if pub == nil {
    err = errors.New("Public Key Cannot Be Empty\n")
    return
  }

  pub_der, err := x509.MarshalPKIXPublicKey(pub)
  if err != nil {
    return
  }

  pub_blk := pem.Block {Type: "PUBLIC KEY", Headers: nil, Bytes: pub_der,}
  pub_pem := pem.EncodeToMemory(&pub_blk)

  str = base64.StdEncoding.EncodeToString(pub_pem)

  return
}
