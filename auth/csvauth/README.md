# csvauth

[![Go Reference](https://pkg.go.dev/badge/github.com/therootcompany/golib/auth/csvauth.svg)](https://pkg.go.dev/github.com/therootcompany/golib/auth/csvauth)

Simple, non-scalable credentials stored in a tab-separated file. \
(logical successor to [envauth](https://github.com/therootcompany/golib/tree/main/auth/envauth))

1. Login Credentials
    - Save recoverable (aes or plain) or salted hashed passwords (pbkdf2 or bcrypt)
    - Great in http middleware, authorizing login or api requests
    - Stored by _username_
2. Service Accounts
    - Store API keys for services like SMTP and S3
    - Great for contacting other services
    - Stored by _purpose_

Also useful for generating pbkdf2 or bcrypt hashes for manual entry in a _real_ database.

Can be adapted to pull from a Google Sheets URL (CSV format).

```sh
# create login credentials
csvauth store 'bot@example.com'

# store service account
csvauth store --purpose 'postmark_smtp_notifier' 'admin@example.com'
```

`credentials.tsv`:

```tsv
purpose	name	algo	salt	derived	roles	extra
ntfy_sh	mytopic-1234	plain		mytopic-1234
s3_files	account1	aes	xxxxxxxxxxxx	xxxxxxxxxxxxxxxx
login	johndoe	pbkdf2 1000 16 SHA-256	5cLjzprCHP3WmMbzfqVaew	k-elXFa4B_P4-iZ-Rr9GnA	admin
login	janedoe	bcrypt		$2a$12$Xbe3OnIapGXUv9eF3k3cSu7sazeZSJquUwGzaovJxb9XQcN54/rte		{"foo": "bar"}
```

```go
f, err := os.Open("./credentials.tsv")
defer func() { _ = f.Close() }()

auth, err := csvauth.Load(f)

// ...

if err := auth.Verify(username, password); err != nil {
   return err
}

// ...

account := auth.LoadServiceAccount("account-mailer")
req.SetBasicAuth(account.Name, account.Secret())
```

## Login Credentials

1. Use `csvauth store [options] <username>` to create new login credentials.

    ```sh
    go run ./cmd/csvauth/ store --help
    ```

    ```sh
    go run ./cmd/csvauth/ store 'john.doe@example.com'

    go run ./cmd/csvauth/ store --algorithm aes-128-gcm 'johndoe'
    go run ./cmd/csvauth/ store --algorithm plain 'johndoe'
    go run ./cmd/csvauth/ store --algorithm 'pbkdf2 1000 16 SHA-256' 'johndoe'
    go run ./cmd/csvauth/ store --algorithm 'bcrypt 12' 'john.doe@example.com'

    go run ./cmd/csvauth/ store --ask-password 'john.doe@example.com'
    go run ./cmd/csvauth/ store --password-file ./password.txt  'johndoe'

    go run ./cmd/csvauth/ store --roles 'admin' --extra '{"foo":"bar"}' 'jimbob'
    ```

2. Use `github.com/therootcompany/golib/auth/csvauth` to verify credentials

    ```go
    package main

    import (
       "net/http"
       "os"

       "github.com/therootcompany/golib/auth/csvauth"
    )

    var auth csvauth.Auth

    func main() {
       f, _ := os.Open("./credentials.tsv")
       defer func() { _ = f.Close() }()
       auth, _ = csvauth.Load(f)

       // ...
    }

    func handleRequest(w http.ResponseWriter, r *http.Request) {
       username, password, ok := r.BasicAuth()
       if !ok || !auth.Verify(username, password) {
          http.Error(w, "Unauthorized", http.StatusUnauthorized)
          return
       }

       credential, err := auth.LoadCredential(username)
       // ...
    }
    ```

## Service Account

1. Use `csvauth store --purpose <account> [options] <username>` to store API credentials

    ```sh
    go run ./cmd/csvauth/ store --help
    ```

    ```sh
    go run ./cmd/csvauth/ store --purpose ntfy_sh_admins 'acme-admins-1234abcd'
    ```

2. Use `github.com/therootcompany/golib/auth/csvauth` to verify credentials

    ```go
    package main

    import (
       "bytes"
       "net/http"
       "os"

       "github.com/therootcompany/golib/auth/csvauth"
    )

    func main() {
       f, _ := os.Open("./credentials.tsv")
       defer func() { _ = f.Close() }()
       auth, _ := csvauth.Load(f)

       // ...

       credential := auth.LoadServiceAccount("ntfy_sh_admins")
       req, _ := http.NewRequest("POST", "https://ntfy.sh/"+credential.Secret(), bytes.NewBuffer(message))

       // ...
    }
    ```
