package servers

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/form3tech-oss/jwt-go"
	uuid "github.com/satori/go.uuid"
	"github.com/yangsen996/simple-jwt-auth/auth"
)

type TokenManager struct{}

func NewTokenService() *TokenManager {
	return &TokenManager{}
}

type TokenInterface interface {
	CreateToken(userId, userName string) (*auth.TokenDetails, error)
	ExtracTokenMetadata(r *http.Request) (*auth.AccessDetails, error)
}

var _ TokenInterface = &TokenManager{}

func (t *TokenManager) CreateToken(userId, userName string) (*auth.TokenDetails, error) {
	td := &auth.TokenDetails{}

	td.AtExpires = time.Now().Add(time.Minute * 30).Unix()
	td.TokenUuid = uuid.NewV4().String()

	td.RtExpires = time.Now().Add(time.Hour * 24 * 7).Unix()
	td.RefreshUuid = td.TokenUuid + "++" + userId

	var err error

	atClaims := jwt.MapClaims{}
	atClaims["access_uuid"] = td.TokenUuid
	atClaims["user_name"] = userName
	atClaims["exp"] = td.AtExpires

	at := jwt.NewWithClaims(jwt.SigningMethodES256, atClaims)
	td.AccessToken, err = at.SignedString([]byte(os.Getenv("ACCESS_SECRET")))

	if err != nil {
		return nil, err
	}

	td.RtExpires = time.Now().Add(time.Hour * 24 * 7).Unix()
	td.RefreshUuid = td.TokenUuid + "++" + userId

	rtClaims := jwt.MapClaims{}
	rtClaims["access_uuid"] = td.TokenUuid
	rtClaims["user_name"] = userName
	rtClaims["exp"] = td.AtExpires
	rt := jwt.NewWithClaims(jwt.SigningMethodES256, rtClaims)
	td.RefreshToken, err = rt.SignedString([]byte(os.Getenv("REFRESH_SECRET")))

	if err != nil {
		return nil, err
	}
	return td, nil
}

func (t *TokenManager) ExtracTokenMetadata(r *http.Request) (*auth.AccessDetails, error) {
	token, err := VerifyToken(r)
	if err != nil {
		return nil, err
	}
	acc, err := Extract(token)
	if err != nil {
		return nil, err
	}
	return acc, nil

}

func TokenValid(r *http.Request) error {
	token, err := VerifyToken(r)
	if err != nil {
		return err
	}
	if _, ok := token.Claims.(jwt.MapClaims); !ok && !token.Valid {
		return err
	}
	return nil

}

func VerifyToken(r *http.Request) (*jwt.Token, error) {
	tokenSting := ExtractToken(r)
	token, err := jwt.Parse(tokenSting, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(os.Getenv("ACCESS_SECRET")), nil
	})
	if err != nil {
		return nil, err
	}
	return token, nil

}

func ExtractToken(r *http.Request) string {
	bearToken := r.Header.Get("Authorization")
	strArr := strings.Split(bearToken, " ")
	if len(strArr) == 2 {
		return strArr[1]
	}
	return ""
}

func Extract(token *jwt.Token) (*auth.AccessDetails, error) {
	claims, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		accessUuid, ok := claims["access_uuid"].(string)
		userId, userOk := claims["user_id"].(string)
		userName, userNameOk := claims["user_name"].(string)
		if ok == false || userOk == false || userNameOk == false {
			return nil, errors.New("unauthorized")
		} else {
			return &auth.AccessDetails{
				TokenUuid: accessUuid,
				UserId:    userId,
				UserName:  userName,
			}, nil
		}
	}
	return nil, errors.New("something went worng")
}
