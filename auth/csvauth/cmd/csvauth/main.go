package main

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/therootcompany/golib/auth/csvauth"
)

const (
	defaultAESKeyENVName  = "CSVAUTH_AES_128_KEY"
	defaultCSVFileENVName = "CSVAUTH_CSV_FILE"
	defaultCSVPath        = "credentials.tsv"
	passwordEntropy       = 12 // 96-bit
)

var (
	keyRelPath = filepath.Join(".config", "csvauth", "aes-128.key")
)

func showHelp() {
	fmt.Fprintf(os.Stderr, `csvauth - create, update, and verify users, passwords, and tokens

EXAMPLES
   csvauth store --token 'my-new-token'
   csvauth store --ask-password 'my-new-user'
   csvauth verify 'my-new-user'

USAGE
   csvauth help
   csvauth store [--help] [FLAGS] <username>
   csvauth verify [--help] [FLAGS] <username>

`)

	handleSet([]string{"--help"}, nil, nil)
	fmt.Fprintf(os.Stderr, "\n")

	handleCheck([]string{"--help"}, nil, nil)
	fmt.Fprintf(os.Stderr, "\n")
}

func main() {
	var subcmd string
	if len(os.Args) > 1 {
		subcmd = os.Args[1]
	}
	switch len(os.Args) {
	case 0:
		panic(errors.New("it's impossible to have 0 arguments"))
	case 1:
		fallthrough
	case 2:
		os.Args = append(os.Args, "--help")
	default:
		switch os.Args[2] {
		case "", "help":
			os.Args[2] = "--help"
		}
	}

	homedir, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		return
	}
	filename := filepath.Join(homedir, keyRelPath)
	csvPath := getCSVPath()

	var aesKey []byte
	var csvFile csvauth.NamedReadCloser
	switch subcmd {
	case "store", "check":
		var keyErr error
		aesKey, keyErr = getAESKey(defaultAESKeyENVName, filename)
		if keyErr != nil {
			if os.IsNotExist(keyErr) {
				fmt.Fprintf(os.Stderr, "no AES key found, run 'csvauth init' to create it, or provide %s or ~/%s\n", defaultAESKeyENVName, keyRelPath)
			} else {
				fmt.Fprintf(os.Stderr, "%v\n", keyErr)
			}
		}

		var csvErr error
		csvFile, csvErr = getCSVFile(csvPath)
		if csvErr != nil {
			if os.IsNotExist(csvErr) {
				fmt.Fprintf(os.Stderr, "no credentials file found, run 'csvauth init' to create it, or provide %s or %s\n", defaultCSVFileENVName, csvPath)
			} else {
				fmt.Fprintf(os.Stderr, "%v\n", csvErr)
			}
		}

		if keyErr != nil || csvErr != nil {
			os.Exit(1)
		}

		fmt.Fprintf(os.Stderr, "\n")
	}

	switch subcmd {
	case "init":
		if err := handleInit(defaultAESKeyENVName, filename, csvPath); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
	case "store":
		handleSet(os.Args[2:], aesKey, csvFile)
	case "check":
		handleCheck(os.Args[2:], aesKey, csvFile)
	case "--help", "-help", "help", "":
		showHelp()
		return
	default:
		if len(subcmd) > 0 {
			fmt.Fprintf(os.Stderr, "unknown subcommand %q\n", subcmd)
			os.Exit(1)
			return
		}

		showHelp()

		switch subcmd {
		case "--help", "-help", "help":
			return
		default:
			os.Exit(1)
		}
	}
}

func getCSVPath() string {
	path := os.Getenv(defaultCSVFileENVName)
	if len(path) == 0 {
		path = defaultCSVPath
	}
	return path
}

func getOrCreateAESKey(envname, filename string) ([]byte, error) {
	aesKey, err := getAESKey(envname, filename)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}
	}
	if aesKey != nil {
		return aesKey, nil
	}

	if err := os.MkdirAll(filepath.Dir(filename), 0750); err != nil {
		return nil, fmt.Errorf("failed to create directory for %s: %v", filename, err)
	}

	fmt.Fprintf(os.Stderr, "Creating new AES-128 key at %s\n", filename)
	key := make([]byte, 16)
	if _, err = io.ReadFull(rand.Reader, key); err != nil {
		panic(err) // the universe has run out of entropy
	}
	hexKey := hex.EncodeToString(key) + "\n"

	if err := os.WriteFile(filename, []byte(hexKey), 0640); err != nil {
		return nil, fmt.Errorf("failed to write %s: %v", filename, err)
	}
	return aesKey, nil
}

func getAESKey(envname, filename string) ([]byte, error) {
	envKey := os.Getenv(envname)
	if envKey != "" {
		key, err := hex.DecodeString(strings.TrimSpace(envKey))
		if err != nil || len(key) != 16 {
			return nil, fmt.Errorf("invalid %s: must be 32-char hex string", envname)
		}
		fmt.Fprintf(os.Stderr, "Found AES Key in %s\n", envname)
		return key, nil
	}

	if _, err := os.Stat(filename); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %v", filename, err)
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(key) != 16 {
		return nil, fmt.Errorf("invalid key in %s: must be 32-char hex string", filename)
	}
	// relpath := strings.Replace(filename, homedir, "~", 1)
	fmt.Fprintf(os.Stderr, "Found AES Key at %s\n", filename)
	return key, nil
}

func getOrCreateCSVFile(csvPath string) (csvauth.NamedReadCloser, error) {
	r, err := getCSVFile(csvPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, err
		}

		csvAbs, err := filepath.Abs(csvPath)
		if err != nil {
			panic(err)
		}
		fmt.Fprintf(os.Stderr, "Creating new credentials csv at %s\n", csvAbs)
		r, err = os.OpenFile(csvPath, os.O_RDWR|os.O_CREATE, 0640)
		if err != nil {
			return nil, err
		}
	}

	return r, nil
}

func getCSVFile(csvPath string) (csvauth.NamedReadCloser, error) {
	f, csvErr := os.Open(csvPath)
	if csvErr != nil {
		return nil, csvErr
	}

	csvAbs, err := filepath.Abs(csvPath)
	if err != nil {
		panic(err)
	}
	fmt.Fprintf(os.Stderr, "Found credentials db at %s\n", csvAbs)
	return f, nil
}

func handleInit(keyenv, keypath, csvpath string) error {
	_, keyErr := getOrCreateAESKey(keyenv, keypath)
	_, csvErr := getOrCreateCSVFile(csvpath)

	if keyErr != nil {
		return keyErr
	}

	if csvErr != nil {
		return csvErr
	}

	return nil
}

func handleSet(args []string, aesKey []byte, csvFile csvauth.NamedReadCloser) {
	storeFlags := flag.NewFlagSet("csvauth-store", flag.ContinueOnError)
	purpose := storeFlags.String("purpose", "login", "'login' for users, 'token' for tokens, or a service account name, such as 'basecamp_api_key'")
	roleList := storeFlags.String("roles", "", "a comma- or space-separated list of roles (defined by you), such as 'triage audit'")
	extra := storeFlags.String("extra", "", "free form data to retrieve with the user (hint: JSON might be nice)")
	algorithm := storeFlags.String("algorithm", "", "Hash algorithm: aes, plain, pbkdf2[,iters[,size[,hash]]], or bcrypt[,cost]")
	askPassword := storeFlags.Bool("ask-password", false, "Read password or token from stdin")
	useToken := storeFlags.Bool("token", false, "generate token")
	passwordFile := storeFlags.String("password-file", "", "Read password or token from file")
	// storeFlags.StringVar(&tsvPath, "tsv", tsvPath, "Credentials file to use")
	if err := storeFlags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			flag.PrintDefaults()
		}
		return
	}
	if len(storeFlags.Args()) > 1 {
		fmt.Fprintf(os.Stderr, "too many arguments: %q\n", strings.Join(storeFlags.Args(), " "))
		fmt.Fprintf(os.Stderr, "note: flags should come before arguments\n")
		os.Exit(1)
	}

	name := storeFlags.Arg(0)
	switch name {
	case "", "id", "name", "purpose":
		if *useToken {
			fmt.Fprintf(os.Stderr, "invalid token name %q\n", name)
		} else {
			fmt.Fprintf(os.Stderr, "invalid username %q\n", name)
		}
		os.Exit(1)
	}

	if *useToken {
		if *purpose != csvauth.PurposeDefault && *purpose != csvauth.PurposeToken {
			fmt.Fprintf(os.Stderr, "token purpose must be 'token', not %q\n", *purpose)
			os.Exit(1)
		}
		*purpose = csvauth.PurposeToken
	}

	if len(*algorithm) == 0 {
		switch *purpose {
		case csvauth.PurposeDefault:
			*algorithm = "pbkdf2"
		case csvauth.PurposeToken:
			fallthrough
			// *algorithm = "plain"
		default:
			*algorithm = "aes-128-gcm"
		}
	}
	switch *purpose {
	case csvauth.PurposeDefault, csvauth.PurposeToken:
		// no change
	default:
		*askPassword = true
	}

	var pass string
	if len(*passwordFile) > 0 {
		data, err := os.ReadFile(*passwordFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading password file: %v\n", err)
			os.Exit(1)
		}
		pass = strings.TrimSpace(string(data))
	} else if *askPassword {
		fmt.Fprintf(os.Stderr, "New Password: ")
		reader := bufio.NewReader(os.Stdin)
		data, err := reader.ReadString('\n')
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading password from stdin: %v\n", err)
			os.Exit(1)
		}
		pass = strings.TrimSpace(data)
	} else {
		pass = generatePassword()
		fmt.Println(pass)
	}

	*algorithm = strings.ReplaceAll(*algorithm, ",", " ")
	params := strings.Split(*algorithm, " ")
	switch params[0] {
	case "aes", "aes128", "aes-128":
		params[0] = "aes-128-gcm"
	}

	var roles []string
	if len(*roleList) > 0 {
		*roleList = strings.ReplaceAll(*roleList, ",", " ")
		roles = strings.Split(*roleList, " ")
	}

	defer func() { _ = csvFile.Close() }()
	auth := csvauth.New(aesKey)
	c := auth.NewCredential(*purpose, name, pass, params, roles, *extra)

	if err := auth.LoadCSV(csvFile, '\t'); err != nil {
		fmt.Fprintf(os.Stderr, "Error loading CSV: %v\n", err)
		os.Exit(1)
	}
	_ = csvFile.Close()

	var exists bool
	if len(*purpose) > 0 && *purpose != csvauth.PurposeDefault && *purpose != csvauth.PurposeToken {
		if _, err := auth.LoadServiceAccount(*purpose); err != nil {
			if !errors.Is(err, csvauth.ErrNotFound) {
				fmt.Fprintf(os.Stderr, "could not load %s: %v\n", *purpose, err)
			}
		} else {
			exists = true
		}
		c.Purpose = *purpose
		_ = auth.CacheServiceAccount(*c)
	} else {
		if _, err := auth.LoadCredential(name); err != nil {
			if !errors.Is(err, csvauth.ErrNotFound) {
				fmt.Fprintf(os.Stderr, "could not load %s: %v\n", name, err)
			}
		} else {
			exists = true
		}
		_ = auth.CacheCredential(*c)
	}

	var records [][]string
	for _, purpose := range slices.Sorted(auth.ServiceAccountKeys()) {
		c, _ := auth.LoadServiceAccount(purpose)
		record := c.ToRecord()
		records = append(records, record)
	}
	for _, u := range slices.Sorted(auth.CredentialKeys()) {
		c, _ := auth.LoadCredential(u)
		record := c.ToRecord()
		records = append(records, record)
	}

	writeCSV(csvFile.Name(), records)
	if exists {
		fmt.Fprintf(os.Stderr, "Wrote %q with new password for %q\n", csvFile.Name(), name)
	} else {
		fmt.Fprintf(os.Stderr, "Added password for %q to %q\n", name, csvFile.Name())
	}
}

func handleCheck(args []string, aesKey []byte, csvFile csvauth.NamedReadCloser) {
	checkFlags := flag.NewFlagSet("csvauth-check", flag.ContinueOnError)
	purpose := checkFlags.String("purpose", "login", "'login' for users, 'token' for tokens, or a service account name, such as 'basecamp_api_key'")
	_ = checkFlags.Bool("ask-password", true, "Read password or token from stdin")
	useToken := checkFlags.Bool("token", false, "generate token")
	passwordFile := checkFlags.String("password-file", "", "Read password or token from file")
	// storeFlags.StringVar(&tsvPath, "tsv", tsvPath, "Credentials file to use")
	if err := checkFlags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			flag.PrintDefaults()
		}
		return
	}
	if len(checkFlags.Args()) > 1 {
		fmt.Fprintf(os.Stderr, "too many arguments: %q\n", strings.Join(checkFlags.Args(), " "))
		fmt.Fprintf(os.Stderr, "note: flags should come before arguments\n")
		os.Exit(1)
	}

	name := checkFlags.Arg(0)
	switch name {
	case "", "id", "name", "purpose":
		if !*useToken {
			fmt.Fprintf(os.Stderr, "invalid username %q\n", name)
			os.Exit(1)
		}
		if name != "" {
			fmt.Fprintf(os.Stderr, "invalid token name %q\n", name)
			os.Exit(1)
		}
	}

	if *useToken {
		if *purpose != csvauth.PurposeDefault && *purpose != csvauth.PurposeToken {
			fmt.Fprintf(os.Stderr, "token purpose must be 'token', not %q\n", *purpose)
			os.Exit(1)
		}
		*purpose = csvauth.PurposeToken
	}

	var pass string
	if len(*passwordFile) > 0 {
		data, err := os.ReadFile(*passwordFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading password file: %v\n", err)
			os.Exit(1)
		}
		pass = strings.TrimSpace(string(data))
	} else {
		fmt.Fprintf(os.Stderr, "Current Password: ")
		reader := bufio.NewReader(os.Stdin)
		data, err := reader.ReadString('\n')
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading password from stdin: %v\n", err)
			os.Exit(1)
		}
		pass = strings.TrimSpace(data)
	}

	defer func() { _ = csvFile.Close() }()
	auth := csvauth.New(aesKey)

	if err := auth.LoadCSV(csvFile, '\t'); err != nil {
		fmt.Fprintf(os.Stderr, "Error loading CSV: %v\n", err)
		os.Exit(1)
	}

	var v csvauth.BasicAuthVerifier
	var err error
	if *purpose != csvauth.PurposeDefault && *purpose != csvauth.PurposeToken {
		v, err = auth.LoadServiceAccount(*purpose)
		if err != nil {
			fmt.Fprintf(os.Stderr, "couldn't load %s: %v", *purpose, err)
			os.Exit(1)
		}
	} else {
		v = auth
	}

	if *purpose == csvauth.PurposeToken {
		if err := auth.VerifyToken(pass); err != nil {
			fmt.Fprintf(os.Stderr, "token not verified: %v\n", err)
			os.Exit(1)
			return
		}
	} else if err := v.Verify(name, pass); err != nil {
		fmt.Fprintf(os.Stderr, "user '%s' not found or incorrect secret\n", name)
		os.Exit(1)
		return
	}

	fmt.Println("verified")
}

func writeCSV(csvPath string, records [][]string) {
	f, err := os.Create(csvPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating CSV: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = f.Close() }()

	writer := csv.NewWriter(f)
	writer.Comma = '\t'

	_ = writer.Write([]string{"purpose", "name", "algo", "salt", "derived", "roles", "extra"})
	for _, record := range records {
		_ = writer.Write(record)
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing CSV: %v\n", err)
		os.Exit(1)
	}
}

func generatePassword() string {
	bytes := make([]byte, passwordEntropy)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		panic(err) // the universe has run out of entropy
	}
	encoded := base64.RawURLEncoding.EncodeToString(bytes)
	parts := make([]string, 4)
	start := 0
	for i := range 4 {
		parts[i] = encoded[start : start+4]
		start += 4
	}
	return strings.Join(parts, "-")
}
