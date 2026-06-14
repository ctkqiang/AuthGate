package model

import (
	"crypto/rsa"
	"sync"
)

var (
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
	once       sync.Once
)
