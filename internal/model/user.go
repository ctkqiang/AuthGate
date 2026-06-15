package model

import (
	"time"

	"gorm.io/gorm"
)

type (
	Gender int
	Locale string
)

type User struct {
	gorm.Model

	Username string `gorm:"type:varchar(50);unique;not null;index"`
	Email    string `gorm:"type:varchar(100);unique;not null"`
	Password string `gorm:"type:varchar(255);not null"`

	Gender Gender `gorm:"type:tinyint(1);not null;default:0"`
	Locale Locale `gorm:"type:varchar(10);not null;default:en"`

	AccessToken  string `gorm:"type:varchar(255)"`
	RefreshToken string `gorm:"type:varchar(255)"`

	CreatedAt time.Time `gorm:"autoCreateTime"`
}

const (
	Unknown Gender = iota
	Male
	Female
)
