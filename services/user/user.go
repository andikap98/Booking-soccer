package user

import (
	"context"
	"strings"

	"user-service/constants"
	errConstants "user-service/constants/error"
	"user-service/domain/dto"
	"user-service/repositories"
	"user-service/utils"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

type UserService struct {
	repository repositories.IRepositoryRegistry
}

type IUserService interface {
	Login(context.Context, *dto.LoginRequest)(*dto.LoginResponse,error)
	Register(context.Context, *dto.RegisterRequest)(*dto.RegisterResponse, error)
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
		return nil, errConstants.ErrUnauthorized
	}
	
	data := &dto.UserResponse{
		UUID: user.UUID,
		Username: user.Username,
		Name: user.Name,
		Email: user.Email,
		PhoneNumber: user.PhoneNumber,
		Role: strings.ToLower(user.Role.Code),
	}
	
	tokenString, err := utils.GeneratedToken(data)
	if err != nil{
		return nil, err
	}

	response := &dto.LoginResponse{
		User: *data,
		Token: tokenString,
	}

	return response, nil
}

func (s *UserService) isUserNameExist(ctx context.Context, username string)(bool, error){
	_, err := s.repository.GetUser().FindByUsername(ctx, username)
	if err !=nil{
		if err == errConstants.ErrUserNotFound {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (s *UserService) isEmailExist(ctx context.Context, email string)(bool, error){
	_, err := s.repository.GetUser().FindByEmail(ctx, email)
	if err !=nil{
		if err == errConstants.ErrUserNotFound {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (s *UserService) Register(ctx context.Context, req *dto.RegisterRequest)(*dto.RegisterResponse, error){
	hashPassword,err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	UsernameExist, err :=s.isUserNameExist(ctx, req.Username)
	if err != nil{
		return nil, err
	}

	if UsernameExist {
		return nil, errConstants.ErrUsernameExists
	}

	EmailExist, err := s.isEmailExist(ctx, req.Email)
	if err != nil {
		return nil, err
	}

	if EmailExist {
		return nil, errConstants.ErrEmailExists
	}

	if req.Password != req.ConfirmPassword{
		return nil, errConstants.ErrPasswordDoesNotMatch
	}

	user, err := s.repository.GetUser().Register(ctx, &dto.RegisterRequest{
		Name: req.Name,
		Username: req.Username,
		Password: string(hashPassword),
		Email: req.Email,
		RoleID: constants.Customer,
	})
	if err != nil {
		return nil, err
	}

	response := &dto.RegisterResponse{
		User: dto.UserResponse{
			UUID: user.UUID,
			Name: user.Name,
			Username: user.Username,
			PhoneNumber: user.PhoneNumber,
			Email: user.Email,
		},
	}

	return response, nil
}
