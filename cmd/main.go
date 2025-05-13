package cmd

import (
	"fmt"
	"net/http"
	"time"
	"user-service/common/response"
	"user-service/config"
	"user-service/constants"
	"user-service/controllers"
	"user-service/database/seeders"
	"user-service/domain/models"
	"user-service/middlewares"
	"user-service/repositories"
	"user-service/routes"
	"user-service/services"

	"github.com/didip/tollbooth"
	"github.com/didip/tollbooth/limiter"
	"github.com/gin-gonic/gin"
	"github.com/spf13/cobra"
	"github.com/subosito/gotenv"
)

var command = &cobra.Command{
	Use: "server",
	Short: "Start the server",
	Run: func (cmd * cobra.Command, args []string)  {
		_ =gotenv.Load()
		config.Init()
		db, err := config.InitDatabase()
		if err != nil {
			panic(err)
		}

		loc, err := time.LoadLocation("Asia/Jakarta")
		if err != nil {
			panic(err)
		}
		time.Local = loc

		err = db.AutoMigrate(
			&models.Role{},
			&models.User{},
		)
		if err != nil {
			panic(err)
		}

		seeders.NewSeederRegistry(db).Run()
		repository := repositories.NewRepositoryRegistry(db)
		service := services.NewUserServiceRegistry(repository)
		controller := controllers.NewUserControllerRegistry(service)

		router := *gin.Default()
		router.Use(middlewares.HandlePanic())
		router.NoRoute(func(c *gin.Context) {
			c.JSON(http.StatusNotFound, response.Response{
				Status: constants.Error,
				Message: fmt.Sprintf("Path %s", http.StatusText(http.StatusNotFound)),
			})
		})

		router.GET("/", func(c *gin.Context) {
			c.JSON(http.StatusOK, response.Response{
				Status: constants.Success,
				Message: "Welcome to user service",
			})
		})

		router.Use(func(c *gin.Context) {
			c.Writer.Header().Set("Access-Controll-Allow-Origin", "*")
			c.Writer.Header().Set("Access-Controll-Allow-Methods", "GET, POST PUT")
			c.Writer.Header().Set("Access-Controll-Allow-Headers", "Content-Type, Authorization, x-service-name, x-api-key, x-request-at")
			c.Next()
		})

		lmt := tollbooth.NewLimiter(
			float64(config.Config.RateLimiterMaxRequests),
			&limiter.ExpirableOptions{
				DefaultExpirationTTL: time.Duration(config.Config.RateLimiterMaxRequests) * time.Second,
			})
		router.Use(middlewares.RateLimiter(lmt))

		group := router.Group("/api/v1")
		route := routes.NewRouteRegistry(controller, group)
		route.Serve()

		port := fmt.Sprintf(":%d", config.Config.Port)
		router.Run(port)
	},
}

func Run()  {
	err := command.Execute()
	if err != nil {
		panic(err)
	}
}