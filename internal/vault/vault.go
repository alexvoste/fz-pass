package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

const (
	magic          = "FZPASSV1"
	saltSize       = 16
	nonceSize      = 12
	keySize        = 32
	iter           = 200000
	EncryptionType = "AES-256-GCM"
)

var (
	jsonPool        = sync.Pool{New: func() any { return new(bytes.Buffer) }}
	errInvalidVault = errors.New("invalid vault file")
)

type Entry struct {
	Service        string            `json:"service"`
	Data           map[string]string `json:"data,omitempty"`
	CreatedAt      string            `json:"created_at"`
	EncryptionType string            `json:"encryption_type"`
}

type Record struct {
	Service  string
	Username string
	Password string
}

func Init(path string, password []byte) error {
	if len(password) == 0 {
		return errors.New("password required")
	}
	if _, err := os.Stat(path); err == nil {
		return errors.New("vault already exists")
	}
	if err := ensureDir(path); err != nil {
		return err
	}
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	key, cleanup := deriveKey(password, salt)
	defer cleanup()
	payload, err := marshalJSON([]Entry{})
	if err != nil {
		return err
	}
	defer zeroBytes(payload)
	return writeEncrypted(path, salt, key[:], payload)
}

func Add(path string, password []byte, service string, data map[string]string) error {
	if len(password) == 0 || len(service) == 0 || len(data) == 0 {
		return errors.New("missing required values")
	}
	if data["password"] == "" {
		return errors.New("password required")
	}
	entries, salt, key, err := loadEntries(path, password)
	if err != nil {
		return err
	}
	entry := Entry{
		Service:        service,
		Data:           data,
		CreatedAt:      time.Now().UTC().Format(time.RFC3339),
		EncryptionType: EncryptionType,
	}
	entries = append(entries, entry)
	return writeEntries(path, salt, key[:], entries)
}

func Get(path string, password []byte, query string) ([]Entry, error) {
	if len(password) == 0 || len(query) == 0 {
		return nil, errors.New("missing required values")
	}
	entries, _, _, err := loadEntries(path, password)
	if err != nil {
		return nil, err
	}
	query = strings.ToLower(query)
	matches := make([]Entry, 0, len(entries))
	for _, entry := range entries {
		if strings.HasPrefix(strings.ToLower(entry.Service), query) {
			matches = append(matches, entry)
		}
	}
	if len(matches) == 0 {
		return nil, errors.New("no matching services")
	}
	return matches, nil
}

func List(path string, password []byte) ([]string, error) {
	entries, _, _, err := loadEntries(path, password)
	if err != nil {
		return nil, err
	}
	services := make([]string, 0, len(entries))
	for _, entry := range entries {
		services = append(services, entry.Service)
	}
	return services, nil
}

func Verify(path string, password []byte) error {
	_, _, _, err := loadEntries(path, password)
	return err
}

func Import(path string, password []byte, sourcePath string) error {
	entries, salt, key, err := loadEntries(path, password)
	if err != nil {
		return err
	}
	sourceData, err := os.ReadFile(sourcePath)
	if err != nil {
		return err
	}
	var incoming []Entry
	if err := json.Unmarshal(sourceData, &incoming); err != nil {
		return err
	}
	existing := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		login := entry.Data["login"]
		existing[entry.Service+"|"+login] = struct{}{}
	}
	for _, entry := range incoming {
		login := entry.Data["login"]
		if _, ok := existing[entry.Service+"|"+login]; ok {
			continue
		}
		if entry.EncryptionType == "" {
			entry.EncryptionType = EncryptionType
		}
		entries = append(entries, entry)
	}
	return writeEntries(path, salt, key[:], entries)
}

func ensureDir(path string) error {
	dir := filepath.Dir(path)
	return os.MkdirAll(dir, 0o700)
}

func deriveKey(password, salt []byte) ([keySize]byte, func()) {
	var key [keySize]byte
	tmp := pbkdf2.Key(password, salt, iter, keySize, sha256.New)
	copy(key[:], tmp)
	cleanup := func() {
		for i := range tmp {
			tmp[i] = 0
		}
	}
	return key, cleanup
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func marshalJSON(entries []Entry) ([]byte, error) {
	buf := jsonPool.Get().(*bytes.Buffer)
	buf.Reset()
	encoder := json.NewEncoder(buf)
	if err := encoder.Encode(entries); err != nil {
		buf.Reset()
		jsonPool.Put(buf)
		return nil, err
	}
	out := make([]byte, buf.Len())
	copy(out, buf.Bytes())
	buf.Reset()
	jsonPool.Put(buf)
	return out, nil
}

func loadEntries(path string, password []byte) ([]Entry, []byte, [keySize]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, [keySize]byte{}, err
	}
	salt, nonce, ciphertext, err := parseVaultFile(data)
	if err != nil {
		return nil, nil, [keySize]byte{}, err
	}
	key, cleanup := deriveKey(password, salt)
	defer cleanup()
	plaintext, err := decrypt(nonce, ciphertext, key[:])
	if err != nil {
		return nil, nil, [keySize]byte{}, err
	}
	defer zeroBytes(plaintext)
	var entries []Entry
	if err := json.Unmarshal(plaintext, &entries); err != nil {
		legacy, legacyErr := parseRecords(plaintext)
		if legacyErr != nil {
			return nil, nil, [keySize]byte{}, err
		}
		entries = legacyToEntries(legacy)
		if writeErr := writeEntries(path, salt, key[:], entries); writeErr != nil {
			return nil, nil, [keySize]byte{}, writeErr
		}
		return entries, salt, key, nil
	}
	return entries, salt, key, nil
}

func legacyToEntries(records []Record) []Entry {
	entries := make([]Entry, 0, len(records))
	for _, record := range records {
		entries = append(entries, Entry{
			Service: record.Service,
			Data: map[string]string{
				"login":    record.Username,
				"password": record.Password,
			},
			CreatedAt:      time.Now().UTC().Format(time.RFC3339),
			EncryptionType: EncryptionType,
		})
	}
	return entries
}

func parseRecords(data []byte) ([]Record, error) {
	if len(data) < 2 {
		return nil, errInvalidVault
	}
	count := int(binary.LittleEndian.Uint16(data[:2]))
	i := 2
	recs := make([]Record, 0, count)
	for j := 0; j < count; j++ {
		if i+2 > len(data) {
			return nil, errInvalidVault
		}
		sLen := int(binary.LittleEndian.Uint16(data[i : i+2]))
		i += 2
		if i+sLen > len(data) {
			return nil, errInvalidVault
		}
		service := string(data[i : i+sLen])
		i += sLen
		if i+2 > len(data) {
			return nil, errInvalidVault
		}
		uLen := int(binary.LittleEndian.Uint16(data[i : i+2]))
		i += 2
		if i+uLen > len(data) {
			return nil, errInvalidVault
		}
		username := string(data[i : i+uLen])
		i += uLen
		if i+2 > len(data) {
			return nil, errInvalidVault
		}
		pLen := int(binary.LittleEndian.Uint16(data[i : i+2]))
		i += 2
		if i+pLen > len(data) {
			return nil, errInvalidVault
		}
		password := string(data[i : i+pLen])
		i += pLen
		recs = append(recs, Record{Service: service, Username: username, Password: password})
	}
	return recs, nil
}

func writeEntries(path string, salt, key []byte, entries []Entry) error {
	payload, err := marshalJSON(entries)
	if err != nil {
		return err
	}
	defer zeroBytes(payload)
	return writeEncrypted(path, salt, key, payload)
}

func parseVaultFile(data []byte) ([]byte, []byte, []byte, error) {
	if len(data) < len(magic)+saltSize+nonceSize {
		return nil, nil, nil, errInvalidVault
	}
	if string(data[:len(magic)]) != magic {
		return nil, nil, nil, errInvalidVault
	}
	salt := make([]byte, saltSize)
	copy(salt, data[len(magic):len(magic)+saltSize])
	nonceStart := len(magic) + saltSize
	nonce := make([]byte, nonceSize)
	copy(nonce, data[nonceStart:nonceStart+nonceSize])
	ciphertext := data[nonceStart+nonceSize:]
	return salt, nonce, ciphertext, nil
}

func encrypt(plaintext, key []byte) ([]byte, []byte, error) {
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return nonce, ciphertext, nil
}

func decrypt(nonce, ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func writeEncrypted(path string, salt, key, plaintext []byte) error {
	nonce, ciphertext, err := encrypt(plaintext, key)
	if err != nil {
		return err
	}
	payload := make([]byte, 0, len(magic)+len(salt)+len(nonce)+len(ciphertext))
	payload = append(payload, magic...)
	payload = append(payload, salt...)
	payload = append(payload, nonce...)
	payload = append(payload, ciphertext...)
	return os.WriteFile(path, payload, 0o600)
}
