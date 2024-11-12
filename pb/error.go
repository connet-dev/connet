package pb

import "fmt"

func NewError(code Error_Code, msg string, args ...any) *Error {
	return &Error{
		Code:    code,
		Message: fmt.Sprintf(msg, args...),
	}
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s (%d)", e.Message, e.Code)
}
