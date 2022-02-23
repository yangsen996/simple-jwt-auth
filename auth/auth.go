package auth

import (
	"errors"
	"fmt"
	"time"

	"github.com/go-redis/redis"
)

type AccessDetails struct {
	TokenUuid string
	UserId    string
	UserName  string
}

type TokenDetails struct {
	AccessToken  string
	RefreshToken string
	TokenUuid    string
	RefreshUuid  string
	AtExpires    int64
	RtExpires    int64
}

type AuthInterface interface {
	CreateAuth(string, *TokenDetails) error
	FetchAuth(string) (string, error)
	DeleteRefresh(string) error
	DeleteTokens(*AccessDetails) error
}
type RedisAuthService struct {
	client *redis.Client
}

var _ AuthInterface = &RedisAuthService{}

func NewAuthService(client *redis.Client) *RedisAuthService {
	return &RedisAuthService{client: client}
}

func (tx *RedisAuthService) CreateAuth(userId string, td *TokenDetails) error {
	at := time.Unix(td.AtExpires, 0)
	rt := time.Unix(td.RtExpires, 0)
	now := time.Now()

	atCreated, err := tx.client.Set(td.TokenUuid, userId, at.Sub(now)).Result()
	if err != nil {
		return err
	}
	rtCreated, err := tx.client.Set(td.RefreshUuid, userId, rt.Sub(now)).Result()
	if err != nil {
		return err
	}
	if atCreated == "0" || rtCreated == "0" {
		return errors.New("no record inserted")
	}
	return nil
}

func (tx *RedisAuthService) FetchAuth(uuid string) (string, error) {
	userId, err := tx.client.Get(uuid).Result()
	if err != nil {
		return "", err
	}
	return userId, nil
}

func (tx *RedisAuthService) DeleteRefresh(refuuid string) error {
	deleted, err := tx.client.Del(refuuid).Result()
	if err != nil || deleted == 0 {
		return err
	}
	return nil
}

func (tx *RedisAuthService) DeleteTokens(acc *AccessDetails) error {
	refUuid := fmt.Sprintf("%s++%s", acc.TokenUuid, acc.UserId)
	deletedAt, err := tx.client.Del(acc.TokenUuid).Result()
	if err != nil {
		return err
	}
	deletedRt, err := tx.client.Del(refUuid).Result()
	if err != nil {
		return err
	}
	if deletedAt != 1 || deletedRt != 1 {
		return errors.New("something")
	}
	return nil
}
