package jwtkuy

import (
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"openlib/constants"
	"openlib/logger"
	"openlib/timekuy"
	"reflect"
	"strings"
	"time"
)

type JwtAbstract interface {
	GenerateToken(interface{}) (token string, err error)
	ParseToken(token string) (data map[string]interface{}, err error)
	GenerateAccessRefreshToken(interface{}) (accessToken string, refreshToken string, err error)
}

type JwtMaster struct {
	SecretKey             string
	refreshTokenExpiredIn time.Duration
	accessTokenExpiredIn  time.Duration
	expiredLength         string
	UserAgent             string
	zapLog                logger.Logger
	timeNow               time.Time
}

func NewJwtMaster(SecretKey string, refreshTokenExpired, accessTokenExpired int, ExpiredLength, UserAgent string) JwtMaster {
	var accessTokenDuration, refreshTokenDuration time.Duration
	switch ExpiredLength {
	case "day":
		refreshTokenDuration = time.Duration(24 * refreshTokenExpired)
		accessTokenDuration = time.Duration(accessTokenExpired)
	case "hour":
		refreshTokenDuration = time.Duration(60 * refreshTokenExpired)
		accessTokenDuration = time.Duration(accessTokenExpired)
	case "minute":
		refreshTokenDuration = time.Duration(60 * refreshTokenExpired)
		accessTokenDuration = time.Duration(accessTokenExpired)
	default:
		refreshTokenDuration = time.Duration(60 * refreshTokenExpired)
		accessTokenDuration = time.Duration(accessTokenExpired)
	}
	return JwtMaster{
		SecretKey:             SecretKey,
		refreshTokenExpiredIn: refreshTokenDuration,
		accessTokenExpiredIn:  accessTokenDuration,
		UserAgent:             UserAgent,
		timeNow:               timekuy.TimeNow(),
	}
}

func (j *JwtMaster) GenerateAccessRefreshToken(i interface{}) (accessToken string, refreshToken string, err error) {
	accessToken, err = j.GenerateToken(i)
	refreshToken, err = j.generateRefreshToken(i)
	return
}
func (j *JwtMaster) getExpiredIntRefreshToken() int64 {
	duration := j.refreshTokenExpiredIn * 1000
	return j.timeNow.Add(time.Hour * duration).Unix()
}
func (j *JwtMaster) getExpiredInAccessToken() int64 {
	duration := j.accessTokenExpiredIn * 60
	return j.timeNow.Add(time.Hour * duration).Unix()
}
func (j *JwtMaster) SetDefaultSecretKey() {
	j.SecretKey = "uhuy"
}
func marshalUnmarshalIt(i interface{}) (data map[string]interface{}, err error) {
	marshaled, err := json.Marshal(i)
	err = json.Unmarshal(marshaled, &data)
	return data, err
}
func (j *JwtMaster) GenerateToken(i interface{}) (token string, err error) {
	data, err := marshalUnmarshalIt(i)
	claims := jwt.New(jwt.SigningMethodHS256)
	myClaim := claims.Claims.(jwt.MapClaims)
	for k, v := range data {
		myClaim[k] = v
	}
	myClaim["exp"] = j.getExpiredInAccessToken()

	myClaim["user_agent"] = j.UserAgent
	token, err = claims.SignedString([]byte(j.SecretKey))
	return token, err
}

func (j *JwtMaster) generateRefreshToken(i interface{}) (token string, err error) {
	data, err := marshalUnmarshalIt(i)
	claims := jwt.New(jwt.SigningMethodHS256)
	myClaim := claims.Claims.(jwt.MapClaims)
	myClaim["id"] = data["id"]
	myClaim["exp"] = j.getExpiredIntRefreshToken()
	myClaim["user_agent"] = j.UserAgent
	myClaim["rt"] = true
	token, err = claims.SignedString([]byte(j.SecretKey))
	return token, err
}

func (j *JwtMaster) ParseToken(tokenString string) (claims map[string]interface{}, err error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if method, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return false, fmt.Errorf("%v", "Signing method invalid")
		} else if method != jwt.SigningMethodHS256 {
			return false, fmt.Errorf("%v", "Signing method invalid")
		}
		return []byte(j.SecretKey), nil
	})
	claims, ok := token.Claims.(jwt.MapClaims)
	if claims != nil {
		_, isUserAgent := claims["user_agent"]
		if !isUserAgent {
			return nil, fmt.Errorf("%s", constants.MsgTokenIsNotValid)
		}
		if !reflect.DeepEqual(claims["user_agent"].(string), j.UserAgent) {
			j.zapLog.Zap.Info("User Agent Claims ", claims["user_agent"])
			j.zapLog.Zap.Info("User Agent Browser ", j.UserAgent)
			j.zapLog.Zap.Error("User agent is not valid")
			return nil, fmt.Errorf("%s", constants.MsgTokenIsNotValid)
		}
	}
	if err != nil {
		if strings.Contains(err.Error(), "expired") {
			return nil, fmt.Errorf("%v", constants.MsgTokenIsExpired)
		}
		return nil, err
	}
	if !ok || !token.Valid {
		return nil, fmt.Errorf("%v", constants.MsgTokenIsNotValid)
	}
	return claims, nil
}

var _ JwtAbstract = &JwtMaster{}
