# fz-pass

Password manager. CLI. Written in Go.

(c) AlexVoste. All rights reserved.

---

## Description

fz-pass stores credentials in an encrypted local vault. Encryption is AES-256-GCM. The master key is derived via Argon2id. The vault lives at `~/.config/fz-pass/vault.db` and is not readable without the master password.

---

## Directory Structure

```
fz-pass/
├── cmd/
│   └── fz-pass/
│       └── main.go
├── internal/
│   └── vault/
│       ├── vault.go
│       └── vault_test.go
├── go.mod
└── README.md
```

`main.go` — CLI entry point, argument parsing, user interaction.  
`vault.go` — crypto, JSON serialization, I/O.  
`vault_test.go` — encryption and allocation benchmarks.

---

## Database Record (Decrypted)

```json
{
  "service": "telegram",
  "data": {
    "login": "alex_voste",
    "password": "super_secure_password",
    "email": "alex@example.com"
  },
  "created_at": "2023-10-27T15:04:05Z",
  "encryption_type": "AES-256-GCM"
}
```

The `email` field is optional and omitted if empty.

---

## Requirements

Go 1.20 or later.

---

## Installation

```
git clone https://github.com/alexvoste/fz-pass.git
cd fz-pass
go build -o fz-pass ./cmd/fz-pass/
mv fz-pass /usr/local/bin/
```

---

## Usage

### init

Initialize the vault. Generates cryptographic salt, creates empty database.

```
fz-pass init
```

Fails if vault already exists.

### add

Add a credential entry. Prompts for master password, entry password, and optionally email.

```
fz-pass add <service> <login>
```

Example:

```
fz-pass add telegram alex_voste
```

### get

Retrieve credentials by service name. Accepts a prefix or substring. If multiple entries match, an interactive selection menu is shown.

```
fz-pass get <query>
```

Example:

```
fz-pass get tel
```

### list

Print names of all stored services. No credentials are shown.

```
fz-pass list
```

### pwd

Print the physical path of the vault file. Requires master password authentication.

```
fz-pass pwd
```

### import

Import a plaintext JSON file into the active vault. Entries are merged and re-encrypted.

```
fz-pass import <path>
```

Example:

```
fz-pass import /path/to/backup.json
```

Input file must follow the database record schema described above.

---

## Security Notes

- Master key derived with Argon2id (configurable parameters).  
- Each vault operation requires master password re-entry or a live session key held in memory.  
- No plaintext is written to disk at any point.  
- `fz-pass pwd` requires authentication to prevent trivial path disclosure.

---

## License

Copyright (c) AlexVoste. All rights reserved.
