package config

import (
	"os"
	"user-service/common/util"

	"github.com/sirupsen/logrus"
)

var Config AppConfig

type AppConfig struct {
	Port                   int      `json:"port"`
	AppName                string   `json:"appName"`
	AppEnv                 string   `json:"appEnv"`
	SignatureKey           string   `json:"signatureKey"`
	Database               Database `json:"database"`
	RateLimiterMaxRequests int      `json:"rateLimiterMaxRequests"`
	RateLimiterTimeSecond  int      `json:"rateLimiterTimeSecond"`
	JwtSecretKey           string   `json:"jwtSecretKey"`
	JwtExpirationTime      int      `json:"jwtExpiretionTime"`
}

type Database struct {
	Host                  string `json:"host"`
	Password              string `json:"password"`
	Port                  int    `json:"port"`
	Username              string `json:"username"`
	Name                  string `json:"name"`
	MaxOpenConnections    int    `json:"maxOpenConnection"`
	MaxLifeTimeConnection int    `json:"maxLifeTimeConnection"`
	MaxIdleConnection     int    `json:"maxIdleConnection"`
	MaxIdleTime           int    `json:"maxIdleTime"`
}

func init() {
	err := util.BindFormJSON(&Config, "config.json", ".")
	if err != nil{
		logrus.Errorf("failed to bind config: %v", err)
		err = util.BindFromConsul(&Config, os.Getenv("CONSUL_HTTP_URL"), os.Getenv("CONSUL_HTTP_KEY"))
		if err != nil {
			panic(err)
		}
	}
}