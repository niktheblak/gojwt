package jwt

import (
	"time"

	"github.com/niktheblak/jwt/errors"
)

var DefaultHeader = map[string]interface{}{
	"alg": "HS256",
	"typ": "JWT",
}

type JSONWebToken struct {
	header map[string]interface{}
	Claims map[string]interface{}
}

func New() JSONWebToken {
	return JSONWebToken{
		header: DefaultHeader,
		Claims: make(map[string]interface{}),
	}
}

func (t JSONWebToken) Algorithm() string {
	return t.Header("alg").(string)
}

func (t JSONWebToken) Type() string {
	return t.Header("typ").(string)
}

func (t JSONWebToken) Headers() []string {
	var keys []string
	for k := range t.header {
		keys = append(keys, k)
	}
	return keys
}

func (t JSONWebToken) Header(key string) interface{} {
	return t.header[key]
}

func (t JSONWebToken) SetHeader(key, value string) {
	if &t.header == &DefaultHeader {
		hdr := make(map[string]interface{})
		for k, v := range t.header {
			hdr[k] = v
		}
		t.header = hdr
	}
	t.header[key] = value
}

func (token JSONWebToken) Validate() error {
	if token.Algorithm() != "HS256" {
		return errors.ErrInvalidAlgorithm
	}
	if token.Type() != "JWT" {
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
