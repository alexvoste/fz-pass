package main

import (
	"fmt"
	"os"
	"path/filepath"

	"fz-pass/internal/survey"
	"fz-pass/internal/vault"
)

func configPath() string {
	dir, err := os.UserConfigDir()
	if err != nil {
		dir, _ = os.UserHomeDir()
	}
	return filepath.Join(dir, "fz-pass", "vault.db")
}

func printHelp() {
	fmt.Fprintln(os.Stdout, "fz-pass - Minimalist, high-security terminal password manager.")
	fmt.Fprintln(os.Stdout, "(c) AlexVoste")
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, "Usage:")
	fmt.Fprintln(os.Stdout, "  fz-pass <command> [arguments]")
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, "Commands:")
	fmt.Fprintln(os.Stdout, "  init                     Initialize a new secure cryptographic vault database.")
	fmt.Fprintln(os.Stdout, "  add <service>            Start an interactive survey to securely add a service with dynamic fields.")
	fmt.Fprintln(os.Stdout, "  get <query>              Retrieve decrypted credentials using prefix-based search.")
	fmt.Fprintln(os.Stdout, "  list                     List all registered service names stored in the vault.")
	fmt.Fprintln(os.Stdout, "  pwd                      Verify master password and print the absolute path to the database.")
	fmt.Fprintln(os.Stdout, "  import <file>            Merge decrypted external JSON records into the active vault.")
	fmt.Fprintln(os.Stdout, "  help                     Show this detailed reference screen.")
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, "Core Engine Details:")
	fmt.Fprintln(os.Stdout, "  - Cryptography: Hardened key derivation via PBKDF2 (SHA-256) / Argon2id, file encryption using AES-256-GCM.")
	fmt.Fprintln(os.Stdout, "  - Dynamic Survey: Commands dynamically query for password (masked), login, email, phone, address, and notes.")
	fmt.Fprintln(os.Stdout, "  - Prefix Search: Typing a short query (e.g., 'tel') automatically scans and matches entries.")
	fmt.Fprintln(os.Stdout, "  - Zero-Overhead: Built with optimal memory layouts to ensure near-zero runtime allocations.")
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, "fz-pass (c) AlexVoste")
}

func printFooter() {
	fmt.Fprintln(os.Stdout, "fz-pass (c) AlexVoste")
}

func printError(err error) {
	fmt.Fprintln(os.Stderr, err)
	fmt.Fprintln(os.Stderr, "fz-pass (c) AlexVoste")
}

func printSuccess(message string) {
	fmt.Fprintln(os.Stdout, message)
	fmt.Fprintln(os.Stdout, "fz-pass (c) AlexVoste")
}

func main() {
	if len(os.Args) < 2 {
		printHelp()
		os.Exit(2)
	}
	path := configPath()
	switch os.Args[1] {
	case "help":
		printHelp()
	case "init":
		password, err := survey.PromptPassword("master password")
		if err != nil {
			printError(err)
			os.Exit(1)
		}
		confirm, err := survey.PromptPassword("confirm password")
		if err != nil {
			survey.ZeroBytes(password)
			printError(err)
			os.Exit(1)
		}
		if !survey.Same(password, confirm) || len(password) == 0 {
			survey.ZeroBytes(password)
			survey.ZeroBytes(confirm)
			printError(fmt.Errorf("passwords do not match"))
			os.Exit(1)
		}
		err = vault.Init(path, password)
		survey.ZeroBytes(password)
		survey.ZeroBytes(confirm)
		if err != nil {
			printError(err)
			os.Exit(1)
		}
		printSuccess("Vault initialized successfully.")
	case "add":
		if len(os.Args) != 3 {
			printHelp()
			os.Exit(2)
		}
		data, master, err := survey.CollectEntry(os.Args[2])
		if err != nil {
			printError(err)
			os.Exit(1)
		}
		err = vault.Add(path, master, os.Args[2], data)
		survey.ZeroBytes(master)
		if err != nil {
			printError(err)
			os.Exit(1)
		}
		printSuccess(fmt.Sprintf("Entry added for service: %s", os.Args[2]))
	case "get":
		if len(os.Args) != 3 {
			printHelp()
			os.Exit(2)
		}
		master, err := survey.PromptPassword("master password")
		if err != nil {
			printError(err)
			os.Exit(1)
		}
		matches, err := vault.Get(path, master, os.Args[2])
		survey.ZeroBytes(master)
		if err != nil {
			printError(err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stdout, "Retrieved entry:")
		if len(matches) == 1 {
			survey.PrintEntry(matches[0])
			printFooter()
			return
		}
		chosen, err := survey.ChooseEntry(matches)
		if err != nil {
			printError(err)
			os.Exit(1)
		}
		survey.PrintEntry(chosen)
		printFooter()
	case "list":
		master, err := survey.PromptPassword("master password")
		if err != nil {
			printError(err)
			os.Exit(1)
		}
		services, err := vault.List(path, master)
		survey.ZeroBytes(master)
		if err != nil {
			printError(err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stdout, "Stored services:")
		for i, service := range services {
			fmt.Fprintf(os.Stdout, "  %d. %s\n", i+1, service)
		}
		printFooter()
	case "pwd":
		master, err := survey.PromptPassword("master password")
		if err != nil {
			printError(err)
			os.Exit(1)
		}
		err = vault.Verify(path, master)
		survey.ZeroBytes(master)
		if err != nil {
			printError(err)
			os.Exit(1)
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			printError(err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stdout, "Vault path:")
		fmt.Fprintln(os.Stdout, abs)
		printFooter()
	case "import":
		if len(os.Args) != 3 {
			printHelp()
			os.Exit(2)
		}
		master, err := survey.PromptPassword("master password")
		if err != nil {
			printError(err)
			os.Exit(1)
		}
		err = vault.Import(path, master, os.Args[2])
		survey.ZeroBytes(master)
		if err != nil {
			printError(err)
			os.Exit(1)
		}
		printSuccess("Import completed successfully.")
	default:
		printHelp()
		os.Exit(2)
	}
}
