package jwtkuy

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestJwtMaster_GenerateToken(t *testing.T) {
	secretKey, refreshTokenExpired, accessTokenExpired, expiredLength, userAgent := "abc", 1, 60, "hour", "Cli"
	jwtMaster := NewJwtMaster(secretKey, refreshTokenExpired, accessTokenExpired, expiredLength, userAgent)
	data := map[string]interface{}{
		"id":   1,
		"nama": "aulia illahi",
	}
	token, err := jwtMaster.GenerateToken(data)

	assert.NoError(t, err)
	parseToken, err := jwtMaster.ParseToken(token)
	assert.NoError(t, err)
	assert.NotEmpty(t, parseToken)
	assert.Equal(t, int(parseToken["id"].(float64)), data["id"].(int))
	assert.Equal(t, parseToken["nama"].(string), data["nama"].(string))
}

func TestJwtMaster_GenerateAccessRefreshToken(t *testing.T) {
	secretKey, refreshTokenExpired, accessTokenExpired, expiredLength, userAgent := "abc", 1, 60, "hour", "Cli"
	jwtMaster := NewJwtMaster(secretKey, refreshTokenExpired, accessTokenExpired, expiredLength, userAgent)
	data := map[string]interface{}{
		"id":   1,
		"nama": "aulia illahi",
	}
	accessToken, refreshToken, err := jwtMaster.GenerateAccessRefreshToken(data)

	assert.NoError(t, err)
	parseToken, err := jwtMaster.ParseToken(accessToken)
	assert.NoError(t, err)
	assert.NotEmpty(t, parseToken)
	assert.Equal(t, int(parseToken["id"].(float64)), data["id"].(int))
	assert.Equal(t, parseToken["nama"].(string), data["nama"].(string))
	parseToken, err = jwtMaster.ParseToken(refreshToken)
	assert.NoError(t, err)
	assert.NotEmpty(t, parseToken)
	assert.Equal(t, int(parseToken["id"].(float64)), data["id"].(int))
	assert.Equal(t, parseToken["rt"], true)
}
