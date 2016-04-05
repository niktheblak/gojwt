package jwt

import (
	"time"

	"github.com/niktheblak/jwt/sign"
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

func (token JSONWebToken) Algorithm() sign.Algorithm {
	name, ok := token.Header["alg"]
	if !ok {
		return sign.Algorithm{}
	}
	algo, ok := sign.Algorithms[name.(string)]
	if !ok {
		return sign.Algorithm{}
	}
	return algo
}

func (token JSONWebToken) Type() string {
	return token.Header["typ"].(string)
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
