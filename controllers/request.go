package controllers

import (
	"errors"
	"github.com/gin-gonic/gin"
)

const CtxtUserIDKey = "userID"

var ErrorUserNotLogin = errors.New("Not Login")

func getCurrentUser(c *gin.Context) (userID int64, err error) {
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
