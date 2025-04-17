package user

import (
	"context"
	"strings"

	"user-service/constants"
	errConstants "user-service/constants/error"
	"user-service/domain/dto"
	"user-service/domain/models"
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

func (s *UserService) Update(ctx context.Context, request *dto.UpdateRequest, uuid string)(*dto.UserResponse, error){
	var (
		password string
		checkUsername, checkEmail *models.User
		hashedPassword []byte
		user, userResult *models.User
		err error
		data dto.UserResponse
	)

	user, err = s.repository.GetUser().FindByUUID(ctx, uuid)
	if err != nil {
		return nil, err
	}

	userNameExist,err := s.isUserNameExist(ctx, request.Username)
	if userNameExist && user.Username != request.Username{
		checkUsername, err = s.repository.GetUser().FindByUsername(ctx, request.Username)
		if err != nil {
			return nil, err
		}

		if checkUsername != nil {
			return nil, errConstants.ErrUsernameExists
		}
	}

	EmailExist, err := s.isEmailExist(ctx, request.Email)
	if EmailExist && user.Email != request.Email {
		checkEmail, err = s.repository.GetUser().FindByEmail(ctx, request.Email)
		if err !=nil {
			return nil, err
		}
		if checkEmail !=nil{
			return nil, errConstants.ErrEmailExists
		}
	}

	if request.Password != nil {
		if &request.Password != &request.ConfirmPassword{
			return nil, errConstants.ErrPasswordDoesNotMatch
		}
		hashedPassword, err = bcrypt.GenerateFromPassword([]byte(*request.Password), bcrypt.DefaultCost)
		if err != nil {
			return nil, err
		}
		password = string(hashedPassword)
	}
	userResult, err = s.repository.GetUser().Update(ctx, &dto.UpdateRequest{
		Name: request.Name,
		Email: request.Email,
		Password: &password,
		PhoneNumber: request.PhoneNumber,
	}, uuid)
	if err !=nil {
		return nil, err
	}

	data = dto.UserResponse{
		UUID: userResult.UUID,
		Name: userResult.Name,
		Username: userResult.Username,
		Email: userResult.Email,
		PhoneNumber: userResult.PhoneNumber,
	}

	return &data, nil
}

func (s *UserService) GetUserLogin(ctx context.Context) (*dto.UserResponse, error){
	var(
		userLogin = ctx.Value(constants.UserLogin).(*dto.UserResponse)
		data dto.UserResponse
	)

	data = dto.UserResponse{
		UUID: userLogin.UUID,
		Name: userLogin.Name,
		Username: userLogin.Username,
		Email: userLogin.Email,
		PhoneNumber: userLogin.PhoneNumber,
		Role: userLogin.Role,
	}

	return &data, nil
}

func (s *UserService) GetUserByUUID(ctx context.Context, uuid string)(*dto.UserResponse, error){
	user, err := s.repository.GetUser().FindByUUID(ctx, uuid)
	if err !=nil {
		return nil, err
	}

	data := dto.UserResponse{
		UUID: user.UUID,
		Name: user.Name,
		Username: user.Username,
		Email: user.Email,
		PhoneNumber: user.PhoneNumber,
	}

	return &data, nil
}