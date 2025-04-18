package middlewares

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"user-service/common/response"
	"user-service/config"
	"user-service/constants"
	errConstants "user-service/constants/error"
	"user-service/utils"

	"github.com/didip/tollbooth"
	"github.com/didip/tollbooth/limiter"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
)

func HandlePanic() gin.HandlerFunc{
	return func(c *gin.Context) {
		defer func ()  {
			if r := recover(); r!=nil{
				logrus.Errorf("Recovered from panic : %v", r)
				c.JSON(http.StatusInternalServerError,response.Response{
					Status: constants.Error,
					Message: errConstants.ErrInternalServerError.Error(),
				})
				c.Abort()
			}
		}()
		c.Next()
	}
}

func RateLimiter(lmt *limiter.Limiter) gin.HandlerFunc{
	return func(c *gin.Context) {
		err := tollbooth.LimitByRequest(lmt, c.Writer, c.Request)
		if err != nil {
			c.JSON(http.StatusTooManyRequests, response.Response{
				Status: constants.Error,
				Message: errConstants.ErrTooManyRequest.Error(),
			})
			c.Abort()
		}
		c.Next()
	}
}

func extractBearerToken(token string) string{
	arrayToken := strings.Split(token, " ")//pisah berdasarkan spasi
	if len(arrayToken) == 2 && strings.ToLower(arrayToken[0]) == "bearer" {
		return arrayToken[1]
	}
	return "" //format salah
}

func responseUnathorized(c *gin.Context, message string) {
	c.JSON(http.StatusUnauthorized, response.Response{
		Status: constants.Error,
		Message: message,
	})
	c.Abort()
}

func validateAPIKey(c *gin.Context) error{
	apiKey:= c.GetHeader(constants.XApiKey)
	requestaAt := c.GetHeader(constants.XRequestAt)
	serviceName := c.GetHeader(constants.XServiceName)
	signatureKey := config.Config.SignatureKey

	if apiKey == "" || requestaAt== "" || serviceName == "" {
		return errConstants.ErrUnauthorized
	}
	validateKey := fmt.Sprintf("%s:%s:%s" , serviceName, signatureKey, requestaAt)
	hash := sha256.New()
	hash.Write([]byte(validateKey))
	resultHash := hex.EncodeToString(hash.Sum(nil))

	if apiKey != resultHash{
		return errConstants.ErrUnauthorized
	}
	return nil
}

func validateBearerToken(c *gin.Context, token string)error{
	if !strings.Contains(token, "Bearer"){
		return errConstants.ErrUnauthorized
	}

	tokenString := extractBearerToken(token)
	if tokenString == ""{
		return errConstants.ErrUnauthorized
	}

	claims := &utils.Claims{}
	tokenJwt, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok{
			return nil, errConstants.ErrInvalidToken
		}
		

		jwtSecret := []byte(config.Config.JwtSecretKey)
		return jwtSecret, nil
	})
	if err != nil || !tokenJwt.Valid{
		return errConstants.ErrUnauthorized
	}

	userLogin := c.Request.WithContext(context.WithValue(c.Request.Context(), constants.UserLogin, claims.User))
	c.Request = userLogin
	c.Set(constants.Token, token)

	return nil
}

func Authenticate() gin.HandlerFunc{
	return func(c *gin.Context) {
		var err error
		token:=c.GetHeader(constants.Authorization)
		if err != nil{
			responseUnathorized(c, errConstants.ErrUnauthorized.Error())
			return
		}
		err = validateBearerToken(c, token)
		if err != nil {
			responseUnathorized(c, err.Error())
			return
		}
		err = validateAPIKey(c)
		if err != nil {
			responseUnathorized(c, err.Error())
			return
		}

		c.Next()
	}
}