package user

import (
	"net/http"
	errWrap "user-service/common/error"
	"user-service/common/response"
	"user-service/domain/dto"
	"user-service/services"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

type UserController struct {
	service services.IServiceRegistry
}

type IUserController interface{
	Login(ctx *gin.Context)
	Register(ctx *gin.Context)
	Update(ctx *gin.Context)
	GetUserLogin(ctx *gin.Context)
	GetUserByUUID(ctx *gin.Context)
}

func NewUserController(service services.IServiceRegistry) IUserController{
	return &UserController{service: service}
}

func (c *UserController)Login(ctx *gin.Context){
	request := &dto.LoginRequest{}

	err := ctx.ShouldBindJSON(request)
	if err != nil {
		response.HttpResponse(response.ParamHTTPResp{
			Code: http.StatusBadRequest,
			Err: err,
			Gin: ctx,
		})
		return
	}
	validate := validator.New()
	err = validate.Struct(request)
	if err !=nil {
		errMessage :=http.StatusText(http.StatusUnprocessableEntity)
		errResponse := errWrap.ErrValidationResponse(err)
		response.HttpResponse(response.ParamHTTPResp{
			Code: http.StatusUnprocessableEntity,
			Message: &errMessage,
			Data: errResponse,
			Err: err,
			Gin: ctx,
		})
		return
	}
	authResult, err:=c.service.GetUser().Login(ctx, request)
	if err != nil{
		response.HttpResponse(response.ParamHTTPResp{
			Code: http.StatusBadRequest,
			Err: err,
			Gin: ctx,
		})
		return
	}
	
	response.HttpResponse(response.ParamHTTPResp{
		Code: http.StatusOK,
		Data: authResult.User,
		Token: &authResult.Token,
		Gin: ctx,
	})
}

func (c *UserController)Register(ctx *gin.Context){
	request := &dto.RegisterRequest{}

	err := ctx.ShouldBindJSON(request)
	if err != nil{
		response.HttpResponse(response.ParamHTTPResp{
			Code: http.StatusBadRequest,
			Err: err,
			Gin: ctx,
		})
		return
	}

	validate := validator.New()
	err = validate.Struct(request)
	if err !=nil {
		errMesagge := http.StatusText(http.StatusUnprocessableEntity)
		errResponse := errWrap.ErrValidationResponse(err)
		response.HttpResponse(response.ParamHTTPResp{
			Code: http.StatusUnprocessableEntity,
			Message: &errMesagge,
			Data: errResponse,
			Err: err,
			Gin: ctx,
		})
		return
	}

	authResult, err := c.service.GetUser().Register(ctx, request)
	if err !=nil {
		response.HttpResponse(response.ParamHTTPResp{
			Code: http.StatusBadRequest,
			Err: err,
			Gin: ctx,
		})
		return
	}

	response.HttpResponse(response.ParamHTTPResp{
		Code: http.StatusOK,
		Data: authResult.User,
		Gin: ctx,
	})
}

func (c *UserController)Update(ctx *gin.Context){
	request := &dto.UpdateRequest{}
	uuid := ctx.Param("uuid")

	err := ctx.ShouldBindJSON(request)
	if err != nil{
		response.HttpResponse(response.ParamHTTPResp{
			Code: http.StatusBadRequest,
			Err: err,
			Gin: ctx,
		})
		return
	}

	validate := validator.New()
	err = validate.Struct(request)
	if err !=nil {
	errMessage := http.StatusText(http.StatusUnprocessableEntity)
		errResponse := errWrap.ErrValidationResponse(err)
		response.HttpResponse(response.ParamHTTPResp{
			Code: http.StatusUnprocessableEntity,
			Message: &errMessage,
			Data: errResponse,
			Err: err,
			Gin: ctx,
		})
		return
	}

	authResult, err := c.service.GetUser().Update(ctx, request, uuid)
	if err !=nil {
		response.HttpResponse(response.ParamHTTPResp{
			Code: http.StatusBadRequest,
			Err: err,
			Gin: ctx,
		})
		return
	}

	response.HttpResponse(response.ParamHTTPResp{
		Code: http.StatusOK,
		Data: authResult,
		Gin: ctx,
	})
}

func (c *UserController) GetUserLogin(ctx *gin.Context){
	user,err := c.service.GetUser().GetUserLogin(ctx.Request.Context())
	if err != nil {
		response.HttpResponse(response.ParamHTTPResp{
			Code: http.StatusBadRequest,
			Err: err,
			Gin: ctx,
		})
		return
	}

	response.HttpResponse(response.ParamHTTPResp{
		Code: http.StatusOK,
		Data: user,
		Gin: ctx,
	})
}

func (c *UserController) GetUserByUUID(ctx *gin.Context){
	user,err := c.service.GetUser().GetUserByUUID(ctx.Request.Context(), ctx.Param("uuid"))
	if err != nil {
		response.HttpResponse(response.ParamHTTPResp{
			Code: http.StatusBadRequest,
			Err: err,
			Gin: ctx,
		})
		return
	}

	response.HttpResponse(response.ParamHTTPResp{
		Code: http.StatusOK,
		Data: user,
		Gin: ctx,
	})
}