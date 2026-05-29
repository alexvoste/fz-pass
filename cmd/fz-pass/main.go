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

func usage() {
	fmt.Fprintln(os.Stdout, "usage: fz-pass <command> [args]")
	fmt.Fprintln(os.Stdout, "commands:")
	fmt.Fprintln(os.Stdout, "  init")
	fmt.Fprintln(os.Stdout, "  add <service>")
	fmt.Fprintln(os.Stdout, "  get <query>")
	fmt.Fprintln(os.Stdout, "  list")
	fmt.Fprintln(os.Stdout, "  pwd")
	fmt.Fprintln(os.Stdout, "  import <source_path>")
	fmt.Fprintln(os.Stdout, "  help")
	fmt.Fprintln(os.Stdout, "(c) AlexVoste")
}

func printFooter() {
	fmt.Fprintln(os.Stdout, "(c) AlexVoste")
}

func printError(err error) {
	fmt.Fprintln(os.Stderr, err)
	fmt.Fprintln(os.Stderr, "(c) AlexVoste")
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	path := configPath()
	switch os.Args[1] {
	case "help":
		usage()
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
		fmt.Fprintln(os.Stdout, "vault initialized")
		printFooter()
	case "add":
		if len(os.Args) != 3 {
			usage()
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
		fmt.Fprintf(os.Stdout, "entry added for %s\n", os.Args[2])
		printFooter()
	case "get":
		if len(os.Args) != 3 {
			usage()
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
		fmt.Fprintln(os.Stdout, "Services:")
		for i, service := range services {
			fmt.Fprintf(os.Stdout, "%d. %s\n", i+1, service)
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
		fmt.Fprintln(os.Stdout, abs)
		printFooter()
	case "import":
		if len(os.Args) != 3 {
			usage()
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
		fmt.Fprintln(os.Stdout, "import complete")
		printFooter()
	default:
		usage()
		os.Exit(2)
	}
}
