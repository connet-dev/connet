package control

import "github.com/keihaya-com/connet/model"

type Authenticator interface {
	Authenticate(token string) (Authentication, error)
}

type Authentication interface {
	ValidateDestination(dst model.Forward) (model.Forward, error)
	ValidateSource(src model.Forward) (model.Forward, error)
}
