package user

import (
	"context"
	"strings"
	"time"
	"user-service/config"
	"user-service/domain/dto"
	"user-service/repositories"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type UserService struct {
	repository repositories.IRepositoryRegistry
}

type IUserService interface {
	Login(context.Context, *dto.LoginRequest)(*dto.LoginResponse,error)
	Register(context.Context, *dto.RegisterRequest)(*dto.RegisterRequest, error)
	Update(context.Context, *dto.UpdateRequest, string)(*dto.UserResponse, error)
	GetUserLogin(context.Context)(*dto.UserResponse, error)
	GetUserByUUID(context.Context, string)(*dto.UserResponse,error)
}

type Claims struct{
	User *dto.UserResponse
	jwt.RegisteredClaims
}

func NewUserService(repository repositories.IRepositoryRegistry)IUserService{
	return &UserService{repository: repository}
}

func (s *UserService) Login(ctx context.Context, req *dto.LoginRequest)(*dto.LoginResponse, error){
	user, err := s.repository.GetUser().FindByUsername(ctx, req.Username)
	if err != nil{
		return nil, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password))
	if err != nil{
		return nil, err
	}
	
	expirationTime := time.Now().Add(time.Duration(config.Config.JwtExpirationTime)*time.Minute).Unix()
	data := &dto.UserResponse{
		UUID: user.UUID,
		Username: user.Username,
		Name: user.Name,
		Email: user.Email,
		PhoneNumber: user.PhoneNumber,
		Role: strings.ToLower(user.Role.Code),

	}
	
	claims:= &Claims{
		User: data,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Unix(expirationTime, 0)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256,claims)
	tokenString, err := token.SignedString([]byte(config.Config.JwtSecretKey))
	if err != nil{
		return nil, err
	}

	response := &dto.LoginResponse{
		User: *data,
		Token: tokenString,
	}

	return response, nil
}

