package seeders

import (
	"user-service/domain/models"

	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

func RunRoleSeeder(db *gorm.DB){
	roles := []models.Role{
		{
			Code: "ADMIN",
			Name: "Administrator",

		},
		{
			Code: "CUSTOMER",
			Name: "Customer",
		},
	}

	for _,r:= range roles {
		role := models.Role{
			Code: r.Code,
			Name: r.Name,
		}
		err:= db.FirstOrCreate(&role, models.Role{Code: r.Code}).Error
		if err != nil{
			logrus.Errorf("failed to seed role: %v", err)
			panic(err)
		}
		logrus.Infof("successfully seeded role :%s", r.Code)
	}
}