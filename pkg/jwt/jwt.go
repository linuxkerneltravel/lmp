package jwt

import (
	"errors"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// jwt的过期时间
const TokenExpireDuration = time.Hour * 2

// sercet签名
var secret = []byte("LMP is the best, bite me.")

/*
	定义自己的数据，自定义声明结构体并内嵌jwt.StandardClaims
	jwt包自带的jwt.StandardClaims只包含了官方字段
	如果我们需要记录一个username字段，就需要自己定义结构体
	如果想要保存更多的信息，都可以添加到这个结构体里面
*/
type Claims struct {
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
	jwt.StandardClaims
}

// 生成token
func GenToken(userID int64, username string) (string, error) {
	// 创建一个自己声明的字段
	c := &Claims{
		userID,
		username,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(TokenExpireDuration).Unix(), // 过期时间
			Issuer:    "lmp",                                      // 签发人
		},
	}
	// 使用指定的签名方法创建签名对象
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	// 使用指定的secret签名并获得完整的编码后的字符串token
	return token.SignedString(secret)
}

func GenTokenAR(userID int64, username string) (aToken, rToken string, err error) {
	// 创建一个自己声明的字段
	c := &Claims{
		userID,
		username,
		jwt.StandardClaims{
			ExpiresAt: time.Now().Add(TokenExpireDuration).Unix(), // 过期时间
			Issuer:    "lmp",                                      // 签发人
		},
	}
	// 使用指定的签名方法创建签名对象
	aToken, err = jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString(secret)

	// refresh token 不需要存储任何自定义的数据
	rToken, err = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		ExpiresAt: time.Now().Add(time.Second * 30).Unix(), // 过期时间
		Issuer:    "lmp",                                   // 签发人
	}).SignedString(secret)
	return
}

// 验证token
func ParseToken(tokenString string) (*Claims, error) {
	var mc = new(Claims)

	token, err := jwt.ParseWithClaims(tokenString, mc, func(token *jwt.Token) (i interface{}, err error) {
		return secret, nil
	})
	if err != nil {
		return nil, err
	}

	if token.Valid {
		return mc, nil
	}
	return nil, errors.New("invalid token")
}

func RefreshToken(aToken, rToken string) (newAToken, newRToken string, err error) {
	return
}
