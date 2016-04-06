package jwt

import (
	"time"

	"github.com/niktheblak/jwt/sign/algorithm"
)

type JSONWebToken struct {
	Claims map[string]interface{}
	Header map[string]interface{}
}

func New() JSONWebToken {
	return JSONWebToken{
		Claims: make(map[string]interface{}),
		Header: nil,
	}
}

func (token JSONWebToken) Algorithm() (algo algorithm.Algorithm) {
	if token.Header == nil {
		return
	}
	name, ok := token.Header["alg"]
	if !ok {
		return
	}
	algo = algorithm.Algorithms[name.(string)]
	return
}

func (token JSONWebToken) Type() (typ string) {
	if token.Header == nil {
		return
	}
	t, ok := token.Header["typ"]
	if ok {
		typ = t.(string)
	}
	return
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

func (token *JSONWebToken) SetExpiration(exp time.Time) {
	token.Claims["exp"] = exp.Unix()
}
