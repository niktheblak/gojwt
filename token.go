package jwt

import (
	"time"

	"github.com/niktheblak/jwt/sign/algorithm"
)

type Token struct {
	Claims map[string]interface{}
	Header map[string]interface{}
}

func New() Token {
	return Token{
		Claims: make(map[string]interface{}),
		Header: nil,
	}
}

func (token Token) Algorithm() (algo algorithm.Algorithm) {
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

func (token Token) Type() (typ string) {
	if token.Header == nil {
		return
	}
	t, ok := token.Header["typ"]
	if ok {
		typ = t.(string)
	}
	return
}

func (token Token) Expired() bool {
	ts, ok := token.Claims["exp"]
	if ok {
		tsint := ts.(int64)
		exp := time.Unix(tsint, 0)
		return exp.Before(time.Now())
	}
	return false
}

func (token Token) Expiration() (time.Time, bool) {
	ts, ok := token.Claims["exp"]
	if ok {
		tsint := ts.(int64)
		exp := time.Unix(tsint, 0)
		return exp, true
	}
	return time.Time{}, false
}

func (token *Token) SetExpiration(exp time.Time) {
	token.Claims["exp"] = exp.Unix()
}
