package middleware

import (
	"net/http"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/persist"
	"github.com/gin-gonic/gin"
	"github.com/yangsen996/simple-jwt-auth/servers"
)

func TokenAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		err := servers.TokenValid(c.Request)
		if err != nil {
			c.JSON(http.StatusUnauthorized, "unauthorizaed")
			c.Abort()
			return
		}
		c.Next()
	}
}

func Authorize(obj string, act string, adapter persist.Adapter) gin.HandlerFunc {
	return func(c *gin.Context) {
		err := servers.TokenValid(c.Request)
		if err != nil {
			c.JSON(http.StatusUnauthorized, "unauthorizaed")
			c.Abort()
			return
		}
		metadata, err := servers.NewTokenService().ExtracTokenMetadata(c.Request)
		if err != nil {
			c.JSON(http.StatusUnauthorized, "unauthorizaed")
			return
		}
		ok, err := enforce(metadata.UserName, obj, act, adapter)
		if err != nil {
			c.AbortWithStatusJSON(500, "")
			return
		}
		if !ok {
			c.AbortWithStatusJSON(500, "forbidden")
			return
		}
		c.Next()
	}
}

func enforce(sub string, obj string, act string, adapter persist.Adapter) (bool, error) {
	enforcer, _ := casbin.NewEnforcer("config/rbac_model.conf", adapter)
	err := enforcer.LoadPolicy()
	if err != nil {
		return false, nil
	}
	ok, _ := enforcer.Enforce(sub, obj, act)
	return ok, nil
}
