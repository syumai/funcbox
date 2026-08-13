// Package service implements funcbox's management-API use cases (deploy,
// function/version lookup, rollback, deletion) on top of the internal/store,
// internal/blob, bundle, manifest, and runtime
//
// This package is server-only (not shared with the funcbox CLI binary), so
// it is free to depend on internal/store, internal/blob, and
// runtime alongside the shared packages.
package service

import (
	"errors"
	"fmt"
	"net/http"
)

// Error is a service-layer error that carries the HTTP status and
// machine-readable code the API layer should surface, matching the unified
// Handlers translate any error returned by this package into an HTTP
// response by extracting an *Error via AsError (falling back to a generic
// 500 for anything that isn't one, e.g. a bug that leaked a raw driver
// error).
type Error struct {
	Status  int
	Code    string
	Message string
	Err     error // underlying cause, if any; not exposed in the HTTP body
}

func (e *Error) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *Error) Unwrap() error { return e.Err }

func newError(status int, code, message string, err error) *Error {
	return &Error{Status: status, Code: code, Message: message, Err: err}
}

// BadRequest builds a 400 service Error with the given machine-readable
// code.
func BadRequest(code, message string, err error) *Error {
	return newError(http.StatusBadRequest, code, message, err)
}

// TooLarge builds a 413 service Error (oversized bundle, per
func TooLarge(message string, err error) *Error {
	return newError(http.StatusRequestEntityTooLarge, "too_large", message, err)
}

// NotFoundErr builds a 404 service Error.
func NotFoundErr(message string, err error) *Error {
	return newError(http.StatusNotFound, "not_found", message, err)
}

// Forbidden builds a 403 service Error (an authenticated actor lacking
// the rights an operation requires; see internal/authz).
func Forbidden(message string) *Error {
	return newError(http.StatusForbidden, "forbidden", message, nil)
}

// Unauthorized builds a 401 service Error.
func Unauthorized(message string) *Error {
	return newError(http.StatusUnauthorized, "unauthorized", message, nil)
}

// ConflictErr builds a 409 service Error.
func ConflictErr(message string, err error) *Error {
	return newError(http.StatusConflict, "conflict", message, err)
}

// FunctionNameTaken reports a failed installation-global function-name claim
// without revealing which user or workspace currently owns it.
func FunctionNameTaken(err error) *Error {
	return newError(http.StatusConflict, "function_name_taken", "function name is already taken", err)
}

// Internal builds a 500 service Error for unexpected backend failures.
func Internal(message string, err error) *Error {
	return newError(http.StatusInternalServerError, "internal", message, err)
}

// AsError extracts a *Error from err, if any is present in its chain.
func AsError(err error) (*Error, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}
