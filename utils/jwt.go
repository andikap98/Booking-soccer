package utils

import (
	"time"
	"user-service/config"
	"user-service/domain/dto"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	User *dto.UserResponse
	jwt.RegisteredClaims
}

func GeneratedToken(User *dto.UserResponse)(string, error){
	expirationTime := time.Now().Add(time.Duration(config.Config.JwtExpirationTime)*time.Minute).Unix()
	claims := &Claims{
		User: User,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Unix(expirationTime,0)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(config.Config.JwtSecretKey))
}