package models

import (
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID   			int 		`gorm:"primaryKey;autoIncrement"`
	UUID 			uuid.UUID 	`gorm:"type:uuid;not null"`
	Name 			string 		`gorm:"type:varchar(100);not null"`
	Password 		string 		`gorm:"type:varchar(255);not null"`
	Email 			string 		`gorm:"type:varchar(100);not null"`
	PhoneNumber 	string 		`gorm:"type:varchar(20);not null"`
	RoleID 			uint 		`gorm:"type:uint;not null"`
	CreatedAt 		*time.Time
	UpdatedAt 		*time.Time
	Role 			Role 		`gorm:"foreignkey:role_id:references:id;constraint:onDelete:CASCADE"`
}