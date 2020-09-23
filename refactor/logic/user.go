package logic

import (
	"refactor/dao/mysql"
	"refactor/models"
	"refactor/pkg/snowflake"
)

func SignUp(p *models.ParamSignUp) (err error) {
	if err = mysql.CheckUserExist(p.Username); err != nil {
		return err
	}

	userID := snowflake.GenID()

	user := models.User{
		UserID:   userID,
		Username: p.Username,
		Password: p.Password,
	}


	return mysql.InsertUser(&user)
}

func Login(p *models.ParamLogin) (err error) {
	user := &models.User{
		Username: p.Username,
		Password: p.Password,
	}
	return mysql.Login(user)
}
