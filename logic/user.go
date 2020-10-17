package logic

import (
	"lmp/dao/mysql"
	"lmp/models"
	"lmp/pkg/jwt"
	"lmp/pkg/snowflake"
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

	return mysql.Register(&user)
}

func Login(p *models.ParamLogin) (token string, err error) {
	user := &models.User{
		Username: p.Username,
		Password: p.Password,
	}

	if err := mysql.Login(user); err != nil {
		return "", err
	}

	return jwt.GenToken(user.UserID, user.Username)
	//return jwt.GenTokenAR(user.UserID, user.Username)
}
