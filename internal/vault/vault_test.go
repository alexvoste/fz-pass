package vault

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestInitAddGetList(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.db")
	master := []byte("correcthorsebatterystaple")
	if err := Init(path, master); err != nil {
		t.Fatal(err)
	}
	if err := Add(path, master, "telegram", map[string]string{"password": "hunter2", "login": "user1", "email": "user@example.com"}); err != nil {
		t.Fatal(err)
	}
	entries, err := Get(path, master, "tel")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Service != "telegram" {
		t.Fatalf("unexpected entries %v", entries)
	}
	services, err := List(path, master)
	if err != nil {
		t.Fatal(err)
	}
	if len(services) != 1 || services[0] != "telegram" {
		t.Fatalf("unexpected services %v", services)
	}
}

func TestMultipleMatches(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.db")
	master := []byte("masterpass")
	if err := Init(path, master); err != nil {
		t.Fatal(err)
	}
	if err := Add(path, master, "google", map[string]string{"password": "pass1", "login": "user1"}); err != nil {
		t.Fatal(err)
	}
	if err := Add(path, master, "gopher", map[string]string{"password": "pass2", "login": "user2"}); err != nil {
		t.Fatal(err)
	}
	matches, err := Get(path, master, "go")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 2 {
		t.Fatalf("expected 2 matches got %d", len(matches))
	}
}

func TestVerify(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.db")
	master := []byte("masterpass")
	if err := Init(path, master); err != nil {
		t.Fatal(err)
	}
	if err := Verify(path, master); err != nil {
		t.Fatal(err)
	}
}

func TestImport(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.db")
	source := filepath.Join(dir, "source.json")
	master := []byte("masterpass")
	if err := Init(path, master); err != nil {
		t.Fatal(err)
	}
	payload := []Entry{{Service: "slack", Data: map[string]string{"login": "slackuser", "password": "secret"}, CreatedAt: "2023-10-27T15:04:05Z", EncryptionType: "AES-256-GCM"}}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := Import(path, master, source); err != nil {
		t.Fatal(err)
	}
	services, err := List(path, master)
	if err != nil {
		t.Fatal(err)
	}
	if len(services) != 1 || services[0] != "slack" {
		t.Fatalf("unexpected services %v", services)
	}
}

func TestLegacyMigration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.db")
	master := []byte("masterpass")
	if err := ensureDir(path); err != nil {
		t.Fatal(err)
	}
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err)
	}
	key, cleanup := deriveKey(master, salt)
	defer cleanup()
	tmp := make([]byte, 2)
	legacy := make([]byte, 0, 1024)
	binary.LittleEndian.PutUint16(tmp, 1)
	legacy = append(legacy, tmp...)
	binary.LittleEndian.PutUint16(tmp, uint16(len("telegram")))
	legacy = append(legacy, tmp...)
	legacy = append(legacy, "telegram"...)
	binary.LittleEndian.PutUint16(tmp, uint16(len("user")))
	legacy = append(legacy, tmp...)
	legacy = append(legacy, "user"...)
	binary.LittleEndian.PutUint16(tmp, uint16(len("hunter2")))
	legacy = append(legacy, tmp...)
	legacy = append(legacy, "hunter2"...)
	if err := writeEncrypted(path, salt, key[:], legacy); err != nil {
		t.Fatal(err)
	}
	entries, err := Get(path, master, "tel")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Service != "telegram" {
		t.Fatalf("unexpected entries after migration %v", entries)
	}
}

func TestInitCreatesEncryptedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vault.db")
	master := []byte("masterpass")
	if err := Init(path, master); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("masterpass")) {
		t.Fatal("vault file contains plaintext password")
	}
	if bytes.Contains(data, []byte("[]")) {
		t.Fatal("vault file contains plaintext JSON")
	}
}
