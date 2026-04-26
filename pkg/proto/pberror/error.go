package pberror

import (
	"errors"
	"fmt"

	"github.com/quic-go/quic-go"
)

func NewError(code Code, msg string, args ...any) *Error {
	return &Error{
		Code:    code,
		Message: fmt.Sprintf(msg, args...),
	}
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s (%d)", e.Message, e.Code)
}

func GetError(err error) *Error {
	if e, ok := errors.AsType[*Error](err); ok {
		return e
	}
	return nil
}

func GetAppError(err error) *quic.ApplicationError {
	if e, ok := errors.AsType[*quic.ApplicationError](err); ok {
		return e
	}
	return nil
}
