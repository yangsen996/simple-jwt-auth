package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis"
	"github.com/yangsen996/simple-jwt-auth/auth"
	"github.com/yangsen996/simple-jwt-auth/models"
	"github.com/yangsen996/simple-jwt-auth/servers"
)

func Login(c *gin.Context) {
	var u models.User
	if err := c.ShouldBindJSON(&u); err != nil {
		c.JSON(http.StatusUnprocessableEntity, "invalid json provided")
		return
	}
	id, _ := strconv.Atoi(u.ID)
	user, err := models.UserRepo.FindByID(id)
	if err != nil {
		return
	}
	if user.UserName != u.UserName || user.Password != u.Password {
		c.JSON(http.StatusNotFound, "失败")
		return
	}
	ts, err := servers.NewTokenService().CreateToken(u.ID, u.UserName)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, err.Error())
		return
	}
	// save redis
	saveErr := auth.NewAuthService(&redis.Client{}).CreateAuth(u.ID, ts)
	if saveErr != nil {
		c.JSON(http.StatusUnprocessableEntity, saveErr.Error())
	}
	tokens := map[string]string{
		"access_token":  ts.AccessToken,
		"refresh_toekn": ts.RefreshToken,
	}
	c.JSON(http.StatusOK, tokens)

}

func Logout(c *gin.Context) {
	c.JSON(http.StatusOK, "success")
}
