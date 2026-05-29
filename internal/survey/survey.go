package survey

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"

	"fz-pass/internal/vault"

	"golang.org/x/term"
)

var stdin = bufio.NewReader(os.Stdin)

func PromptPassword(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stdout, prompt)
	fmt.Fprint(os.Stdout, ": ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stdout)
	return pw, err
}

func PromptLine(prompt string) (string, error) {
	fmt.Fprint(os.Stdout, prompt)
	fmt.Fprint(os.Stdout, ": ")
	line, err := stdin.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func PromptYesNo(prompt string) (bool, error) {
	for {
		answer, err := PromptLine(prompt)
		if err != nil {
			return false, err
		}
		switch strings.ToLower(answer) {
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		}
	}
}

func CollectEntry(service string) (map[string]string, []byte, error) {
	master, err := PromptPassword("master password")
	if err != nil {
		return nil, nil, err
	}
	secret, err := PromptPassword("password for " + service)
	if err != nil {
		ZeroBytes(master)
		return nil, nil, err
	}
	data := make(map[string]string, 6)
	data["password"] = string(secret)
	fields := []string{"login", "email", "phone", "address", "custom_notes"}
	for _, field := range fields {
		add, err := PromptYesNo("Add " + field + "? (y/n)")
		if err != nil {
			ZeroBytes(master)
			ZeroBytes(secret)
			return nil, nil, err
		}
		if !add {
			continue
		}
		value, err := PromptLine(field)
		if err != nil {
			ZeroBytes(master)
			ZeroBytes(secret)
			return nil, nil, err
		}
		if value != "" {
			data[field] = value
		}
	}
	ZeroBytes(secret)
	return data, master, nil
}

func ChooseEntry(matches []vault.Entry) (vault.Entry, error) {
	fmt.Fprintln(os.Stdout, "matches:")
	for i, entry := range matches {
		fmt.Fprintf(os.Stdout, "%d. %s\n", i+1, entry.Service)
	}
	choice, err := PromptLine("select number")
	if err != nil {
		return vault.Entry{}, err
	}
	n, err := parsePositive(choice)
	if err != nil || n < 1 || n > len(matches) {
		return vault.Entry{}, fmt.Errorf("invalid selection")
	}
	return matches[n-1], nil
}

func PrintEntry(entry vault.Entry) {
	fmt.Fprintf(os.Stdout, "Service: %s\n", entry.Service)
	keys := []string{"login", "password", "email", "phone", "address", "custom_notes"}
	for _, key := range keys {
		if value, ok := entry.Data[key]; ok && value != "" {
			fmt.Fprintf(os.Stdout, "%s: %s\n", formatKey(key), value)
		}
	}
	other := make([]string, 0, len(entry.Data))
	for key := range entry.Data {
		if key != "login" && key != "password" && key != "email" && key != "phone" && key != "address" && key != "custom_notes" {
			other = append(other, key)
		}
	}
	sort.Strings(other)
	for _, key := range other {
		fmt.Fprintf(os.Stdout, "%s: %s\n", formatKey(key), entry.Data[key])
	}
	fmt.Fprintf(os.Stdout, "Created At: %s\n", entry.CreatedAt)
	fmt.Fprintf(os.Stdout, "Encryption: %s\n", entry.EncryptionType)
}

func formatKey(key string) string {
	switch key {
	case "custom_notes":
		return "Custom Notes"
	case "password":
		return "Password"
	case "login":
		return "Login"
	case "email":
		return "Email"
	case "phone":
		return "Phone"
	case "address":
		return "Address"
	}
	return strings.Title(strings.ReplaceAll(key, "_", " "))
}

func parsePositive(value string) (int, error) {
	var n int
	for _, r := range value {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("invalid selection")
		}
		n = n*10 + int(r-'0')
	}
	return n, nil
}

func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func Same(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
