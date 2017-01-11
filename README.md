# gojwt
Proof of concept JWT encoding and decoding library for Go.
This project is an experimental API for securely decoding
JWT tokens where token signing algorithms and token validity is
very strictly enforced with the aim of avoiding the security
pitfalls described in
https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/.

If you're looking for a stable and production ready JWT library for Go,
you should look at https://github.com/dgrijalva/jwt-go or
https://github.com/SermoDigital/jose.

# License

[Apache License 2.0](http://choosealicense.com/licenses/apache-2.0/)
