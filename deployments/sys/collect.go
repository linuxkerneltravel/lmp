package sys

import (
	"fmt"
	"github.com/gin-gonic/gin"
	_ "net/http"
)


type Data struct{}

func (d *Data)Collect(c *gin.Context) {
	name := c.PostForm("dispatchingdelay")

	//c.JSON(http.StatusOK,name)
	fmt.Println(name)
}
