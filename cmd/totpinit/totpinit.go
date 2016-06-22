// totpinit initializes a shared secret for time-based one-time password authentication
// usage:
// ./totpinit
// or
// ./totpinit -account ix@clive -issuer lsub.org # or change account, issuer as you see fit, they are not checked
// then point your browser to http://clivemachine:8181/secret to view shared secret as QR code
// then point your totp app (e.g. google authenticator app on your phone) at the QR code picture in your browser
// then enter 6 digit passcode on the command line for totpinit
// TODO: functionality should probably be moved to cmd/auth/auth.go, ask nemo
package main

import (
	"clive/x/github.com/pquerna/otp/totp"
	"clive/net/auth"

	"bytes"
	"flag"
	"fmt"
	"image/png"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

const introduction=`
(Account name and issuer are only shown by the totp app on the phone (e.g. google authenticator) and fully ignored by all other programs. To change account name or issuer, stop totpinit anytime and see -h for details.)
`

var account string
var issuer string
var port string

var buf bytes.Buffer

var accessed chan bool
var once sync.Once

// read 6 digit passcode from console
func getPasscode(a, i string) string {
	var code string
	fmt.Printf("Please enter 6 digit passcode for account: %#v by issuer: %#v: ", a, i)

	fmt.Scan(&code)
	return code
}

// imageHandler() serves the QR code picture for totp initialization
// TODO: could be modified, to only allow 1 picture download for increased security
func imageHandler(w http.ResponseWriter, r *http.Request) {
	once.Do(func() {
		accessed <- true
	})
	io.Copy(w, bytes.NewReader(buf.Bytes()))
}

// startImage() tries to start the http server for 1 second
// returns no error, for successfull start, otherwise the reason for error
func startImage() error {
	started := make(chan error)
	go func (e chan error) {
			http.HandleFunc("/", imageHandler)
			e <- http.ListenAndServe(port, nil)
		} (started)

	select {
	case err := <-started:
		return err
	case <-time.After(1 * time.Second):
		return nil
	}
}

func init() {
	flag.StringVar(&account, "account", "ix@clive", "A nice totp account name (shown only by totp app on the phone and fully ignored by all other programs.)")
	flag.StringVar(&issuer, "issuer", "lsub.org", "Neither the issuer nor the totp account name matter for authentication.")
	flag.StringVar(&port, "port", ":8181", "Port number where totpinit should be accessible.")
}

func main() {
	flag.Parse()

	account = strings.TrimSpace(account)
	if len(account) == 0 {
		log.Fatalf("Error: totp account name should really not be empty! Please see -h for details.")
	}

	fmt.Printf("Initializing shared secret for totp (time-based one-time password) authentication for account name %#v by issuer %#v\n", account, issuer)
	fmt.Println(introduction)

	// generate shared secret
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: account,
	})
	if err != nil {
		log.Fatalf("Error while initializing shared secret. Error details='%v'\n", err)
	}

	// convert shared secret and account+issuer information into a QR code encoded as a PNG image.
	img, err := key.Image(200, 200)
	if err != nil {
		log.Fatalf("Error while generating QR code image, err='%v'\n", err)
	}
	err = png.Encode(&buf, img)
	if err != nil {
		log.Fatalf("Error while encoding QR code image, err='%v'\n", err)
	}

	// display QR code picture

	// start image serving http server
	err = startImage()
	if err != nil {
		log.Fatalf("Error while showing QR code image, probably port %v is not available, use -port to change it. Error details: '%v'", port, err)
	}

	// ask user to access QR code picture
	fmt.Printf("Please visit http://localhost%v to view shared secret as QR code. (Prefix is http NOT https!)\n", port)
	fmt.Println("Now waiting for QR code picture to be accessed...\n")

	// ask user to set up totp app (e.g. google authenticator app on phone)
	accessed = make(chan bool)
	<-accessed // browser accessing
	fmt.Println("Excellent! Your browser should be displaying a QR code picture.")
	fmt.Println("Now point your phone's camera at the QR code picture when your totp app asks for it (e.g. use google authenticator app on your phone -> 'Set up account')\n")

	// validate that the user successfully added the shared secret from the QR code in the totp app
	passcode := getPasscode(account, issuer)
	for valid := totp.Validate(passcode, key.Secret()); !valid; {
		fmt.Println("This passcode is NOT valid. (You probably just mistyped your passcode from your totp app.)")
		fmt.Println("Please verify your account name (%v) and issuer (%v) on the totp app on your phone and try again.\n", account, issuer)
		passcode := getPasscode(account, issuer)
		valid = totp.Validate(passcode, key.Secret())
	}
	fmt.Println("Validation successfull.")

	err = ioutil.WriteFile(auth.KeyDir() + "/clive.totp", []byte(key.Secret()), 0600)
	if err != nil {
		log.Fatalf("Could not write shared secret to " + auth.KeyDir() + "/clive.totp error details: '%v'\n", err)
	}

	fmt.Println("Shared secret stored in " + auth.KeyDir() + "/clive.totp")
	fmt.Println("Time-based one-time password (totp) authentication initialization is finished. You can start ix.")
}
