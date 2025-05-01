package proto

import (
	"errors"
	"fmt"

	"github.com/quic-go/quic-go"
)

func NewError(code Error_Code, msg string, args ...any) *Error {
	return &Error{
		Code:    code,
		Message: fmt.Sprintf(msg, args...),
	}
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s (%d)", e.Message, e.Code)
}

func GetError(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return nil
}

func GetAppError(err error) *quic.ApplicationError {
	var e *quic.ApplicationError
	if errors.As(err, &e) {
		return e
	}
	return nil
}
