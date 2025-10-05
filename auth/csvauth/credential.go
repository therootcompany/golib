package csvauth

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
)

type BasicAuthVerifier interface {
	Verify(string, string) error
}

const DefaultPurpose = "login"

type Purpose = string
type Name = string

// Credential represents a row in the CSV file
type Credential struct {
	Purpose Purpose
	Name    Name
	plain   string
	Params  []string
	Salt    []byte
	Derived []byte
	Roles   []string
	Extra   string
}

func (c Credential) Secret() string {
	return c.plain
}

func FromRecord(record []string) (Credential, error) {
	var roleList, extra string
	purpose, name, paramList, salt64, derived := record[0], record[1], record[2], record[3], record[4]
	if len(record) >= 6 {
		roleList = record[5]
	}
	if len(record) >= 7 {
		extra = record[6]
	}

	return FromFields(purpose, name, paramList, salt64, derived, roleList, extra)
}

func FromFields(purpose, name, paramList, saltBase64, derived, roleList, extra string) (Credential, error) {
	var credential Credential
	credential.Name = name

	if len(purpose) == 0 {
		purpose = DefaultPurpose
	}
	credential.Purpose = purpose

	var roles []string
	if len(roleList) > 0 {
		roleList = strings.ReplaceAll(roleList, ",", " ")
		roles = strings.Split(roleList, " ")
	}
	credential.Roles = roles

	credential.Extra = extra

	paramList = strings.ReplaceAll(paramList, ",", " ")
	credential.Params = strings.Split(paramList, " ")
	if len(credential.Params) == 0 {
		fmt.Fprintf(os.Stderr, "no algorithm parameters for %q\n", name)
	}

	switch credential.Params[0] {
	case "aes-128-gcm":
		if len(credential.Params) > 1 {
			return credential, fmt.Errorf("invalid plain parameters %#v", credential.Params)
		}

		salt, err := base64.RawURLEncoding.DecodeString(saltBase64)
		if err != nil {
			return credential, err
		}
		credential.Salt = salt

		bytes, err := base64.RawURLEncoding.DecodeString(derived)
		if err != nil {
			return credential, err
		}
		credential.Derived = bytes
	case "plain":
		if len(credential.Params) > 1 {
			return credential, fmt.Errorf("invalid plain parameters %#v", credential.Params)
		}

		credential.plain = derived
		h := sha256.Sum256([]byte(derived))
		credential.Derived = h[:]
	case "pbkdf2":
		var err error

		credential.Salt, err = base64.RawURLEncoding.DecodeString(saltBase64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not decode salt %q for %q\n", saltBase64, name)
		}

		credential.Derived, err = base64.RawURLEncoding.DecodeString(derived)
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not decode derived data %q for %q\n", derived, name)
		}

		iters, err := strconv.Atoi(credential.Params[1])
		if err != nil {
			return credential, err
		}
		if iters <= 0 {
			return credential, fmt.Errorf("invalid iterations %s", credential.Params[1])
		}

		size, err := strconv.Atoi(credential.Params[2])
		if err != nil {
			return credential, err
		}
		if size < 8 || size > 32 {
			return credential, fmt.Errorf("invalid size %s", credential.Params[2])
		}

		if !slices.Contains([]string{"SHA-256", "SHA-1"}, credential.Params[3]) {
			return credential, fmt.Errorf("invalid hash %s", credential.Params[3])
		}
	case "bcrypt":
		if len(credential.Params) > 1 {
			return credential, fmt.Errorf("invalid bcrypt parameters %#v", credential.Params)
		}

		credential.Derived = []byte(derived)
	default:
		return credential, fmt.Errorf("invalid algorithm %s", credential.Params[0])
	}

	return credential, nil
}

func (c Credential) ToRecord() []string {
	var paramList, salt, derived string

	paramList = strings.Join(c.Params, " ")
	switch c.Params[0] {
	case "aes-128-gcm":
		salt = base64.RawURLEncoding.EncodeToString(c.Salt)
		derived = base64.RawURLEncoding.EncodeToString(c.Derived)
	case "plain":
		salt = ""
		derived = c.plain
	case "pbkdf2":
		salt = base64.RawURLEncoding.EncodeToString(c.Salt)
		derived = base64.RawURLEncoding.EncodeToString(c.Derived)
	case "bcrypt":
		derived = string(c.Derived)
	default:
		panic(fmt.Errorf("unknown algorithm %q", c.Params[0]))
	}

	purpose := c.Purpose
	if len(purpose) == 0 {
		purpose = DefaultPurpose
	}

	record := []string{purpose, c.Name, paramList, salt, derived, strings.Join(c.Roles, " "), c.Extra}
	return record
}
