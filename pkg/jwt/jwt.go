package jwt

import (
	"errors"
	"github.com/dgrijalva/jwt-go"
	"time"
)

const TokenExpireDuration = time.Hour * 2

var Sercet = []byte("LMP is the best, bite me.")

type Claims struct {
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
	jwt.StandardClaims
}

func GenToken(userID int64, username string) (string, error) {
	c := &Claims{
		userID,
		username,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(TokenExpireDuration).Unix(),
			Issuer:    "bluebell",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, c)

	return token.SignedString(Sercet)
}

func ParseToken(tokenString string) (*Claims, error) {
	var mc = new(Claims)

	token, err := jwt.ParseWithClaims(tokenString, mc, func(token *jwt.Token) (i interface{}, err error) {
		return Sercet, nil
	})
	if err != nil {
		return nil, err
	}

	if token.Valid {
		return mc, nil
	}
	return nil, errors.New("invalid token")
}
