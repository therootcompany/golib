package auth

type BasicVerifier interface {
	Verify(string, string) error
}

type BasicAuthenticator interface {
	Authenticate(string, string) (BasicPrinciple, error)
}

type BasicPrinciple interface {
	ID() string
	Permissions() []string
}
