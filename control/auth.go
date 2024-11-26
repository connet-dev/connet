package control

type Authentication interface {
	AllowDestination(name string) bool
	AllowSource(name string) bool
}

type Authenticator interface {
	Authenticate(token string) (Authentication, error)
}
