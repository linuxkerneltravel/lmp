package controllers

import (
	"errors"

	"github.com/gin-gonic/gin"
)

const (
	CtxtUserIDKey   = "userID"
	CtxtUsernameKey = "username"
)

var ErrorUserNotLogin = errors.New("Not Login")

func getCurrentUserID(c *gin.Context) (userID int64, err error) {
	uid, ok := c.Get(CtxtUserIDKey)
	if !ok {
		err = ErrorUserNotLogin
		return
	}
	userID, ok = uid.(int64)
	if !ok {
		err = ErrorUserNotLogin
		return
	}
	return
}

func getCurrentUsername(c *gin.Context) (username string, err error) {
	name, ok := c.Get(CtxtUsernameKey)
	if !ok {
		err = ErrorUserNotLogin
		return
	}
	username, ok = name.(string)
	if !ok {
		err = ErrorUserNotLogin
		return
	}
	return
}
