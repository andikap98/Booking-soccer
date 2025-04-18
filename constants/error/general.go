package error

import "errors"


var (
	ErrInternalServerError = errors.New("internal server error")
	ErrSQLError = errors.New("database server failed to execute query")
	ErrTooManyRequest = errors.New("too many requests")
	ErrUnauthorized = errors.New("unauthorized")
	ErrInvalidToken = errors.New("invalid token")
	ErrForbidden = errors.New("forbidden")
)

var GeneralErrors = []error{
	ErrInternalServerError,
	ErrSQLError,
	ErrTooManyRequest,
	ErrUnauthorized,
	ErrInvalidToken,
	ErrForbidden,
}