package main

import (
	"flag"
	"fmt"
	"os"

	"filippo.io/age"
	"filippo.io/age/plugin"
	"filippo.io/typage/fido2prf"
	"golang.org/x/term"
)

// TODO: -list, to list resident credentials as identity strings.
// TODO: maybe support non-UV hmac-secret?

func main() {
	p, err := plugin.New("fido2prf")
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		os.Exit(1)
	}

	generate := flag.String("generate", "", "Generate a new credential for the given relying party ID.")
	transport := flag.String("transport", "auto", "Transport to use when generating a credential: auto, usb, nfc, or smart-card.")
	reader := flag.String("reader", "", "PC/SC reader name to use when generating a credential.")
	p.RegisterFlags(nil)
	flag.Parse()

	if *generate != "" {
		if *transport != "auto" && *transport != "usb" && *transport != "nfc" && *transport != "smart-card" {
			fmt.Printf("Error: unsupported transport %q\n", *transport)
			os.Exit(1)
		}
		if *reader != "" && *transport == "usb" {
			fmt.Println("Error: -reader can't be used with -transport usb")
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Enter the security key PIN: ")
		pin, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			fmt.Printf("Error reading the PIN: %s\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "\r\033[K") // Clear the line.

		identity, err := fido2prf.NewCredentialOnReader(*generate, string(pin), *reader, *transport)
		if err != nil {
			fmt.Printf("Error: %s\n", err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "This is a symmetric identity; using it also requires the hardware key.")
		fmt.Fprintln(os.Stderr, "Encrypt with: age -e -i identity.txt")
		fmt.Fprintln(os.Stderr, "Decrypt with: age -d -i identity.txt")
		fmt.Println(identity)
		return
	}

	p.HandleIdentity(func(data []byte) (age.Identity, error) {
		return fido2prf.NewIdentityFromData(data, func() (string, error) {
			return p.RequestValue("Enter the security key PIN:", true)
		})
	})
	p.HandleIdentityAsRecipient(func(data []byte) (age.Recipient, error) {
		return fido2prf.NewIdentityFromData(data, func() (string, error) {
			return p.RequestValue("Enter the security key PIN:", true)
		})
	})
	os.Exit(p.Main())
}
