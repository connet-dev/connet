package control

import "github.com/keihaya-com/connet/model"

type Authenticator interface {
	Authenticate(token string) (Authentication, error)
}

type Authentication interface {
	AllowDestination(dst model.Forward) (bool, model.Forward)
	AllowSource(src model.Forward) (bool, model.Forward)
}
