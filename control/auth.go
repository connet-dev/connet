package control

type Authenticator interface {
	Authenticate(token string) (Authentication, error)
}

type Authentication interface {
	AllowDestination(name string) bool
	AllowSource(name string) bool
}
