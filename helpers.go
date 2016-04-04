package jwt

import (
	"time"

	"github.com/niktheblak/jwt/errors"
)

func (token JSONWebToken) Validate() error {
	alg, ok := token.header["alg"]
	if !ok {
		return errors.ErrInvalidHeader
	}
	if alg != "HS256" {
		return errors.ErrInvalidAlgorithm
	}
	typ, ok := token.header["typ"]
	if !ok {
		return errors.ErrInvalidHeader
	}
	if typ != "JWT" {
		return errors.ErrInvalidType
	}
	if token.Expired() {
		return errors.ErrExpiredToken
	}
	return nil
}

func (token JSONWebToken) Expired() bool {
	ts, ok := token.Claims["exp"]
	if ok {
		tsint := ts.(int64)
		exp := time.Unix(tsint, 0)
		return exp.Before(time.Now())
	}
	return false
}

func (token JSONWebToken) Expiration() (time.Time, bool) {
	ts, ok := token.Claims["exp"]
	if ok {
		tsint := ts.(int64)
		exp := time.Unix(tsint, 0)
		return exp, true
	}
	return time.Time{}, false
}

func (token JSONWebToken) SetExpiration(exp time.Time) {
	token.Claims["exp"] = exp.Unix()
}
