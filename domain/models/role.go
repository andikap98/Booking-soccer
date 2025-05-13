package models

import "time"

type Role struct {
	ID        int    `gorm:"primaryKey"`
	Code      string `gorm:"type:varchar(15);not null"`
	Name      string `gorm:"type:varchar(20);not null"`
	CreatedAt *time.Time
	UpdatedAt *time.Time
}