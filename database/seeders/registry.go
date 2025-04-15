package seeders

import "gorm.io/gorm"

type Registry struct {
	db *gorm.DB
}

type IseederRegistry interface{
	Run()
}

func NewSeederRegistry(db *gorm.DB) IseederRegistry{
	return &Registry{db: db}
}

func (r *Registry) Run(){
	RunRoleSeeder(r.db)
	RunUserSeeder(r.db)
}