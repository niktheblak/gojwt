package jwt

import "time"

func (token JSONWebToken) Validate() error {
	alg, ok := token.header["alg"]
	if !ok {
		return ErrInvalidHeader
	}
	if alg != "HS256" {
		return ErrInvalidAlgorithm
	}
	typ, ok := token.header["typ"]
	if !ok {
		return ErrInvalidHeader
	}
	if typ != "JWT" {
		return ErrInvalidType
	}
	if token.Expired() {
		return ErrExpiredToken
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
