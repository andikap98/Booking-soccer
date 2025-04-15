package seeders

import (
	"user-service/constants"
	"user-service/domain/models"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// RunUserSeeder adalah fungsi untuk melakukan seeding data user ke dalam database
func RunUserSeeder(db *gorm.DB){
	password, err :=bcrypt.GenerateFromPassword([]byte("admin123"), bcrypt.DefaultCost)
	if err != nil {
		logrus.Errorf("failed to hash password: %v", err)
		panic(err)
	}

	// buat user adminsitrator
	user := models.User{ //objek tunggal
			UUID: uuid.New(),
			Name: "Administrator",
			Username: "admin",
			Password: string(password),
			PhoneNumber: "08123456789",
			Email: "example@gmail.com",
			RoleID: constants.Admin,
	}

	// cek user sudah ada atau belum, jika belum ada maka buat user baru
	err = db.FirstOrCreate(&user, models.User{Username: user.Username}).Error
	if err != nil {
		logrus.Errorf("failed to seed user: %v", err)
		panic(err)
	}
	logrus.Infof("successfully seeded user: %s",user.Username)
}