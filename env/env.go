package env

import "os"

// Env has environment stored
type Env struct {
	ServerPort      string
	Environment     string
	LogOutput       string
	DBUsername      string
	DBPassword      string
	DBHost          string
	DBPort          string
	DBName          string
	JWTSecret       string
	DBEUsername     string
	DBEPassword     string
	DBEHost         string
	Endpoint        string
	AcessKeyID      string
	SecretAccessKey string
	UseSsl          string
	DBEIndex        string
	BucketName      string
	IsRedis         string
	ExpiredToken    string
	RefreshToken    string
	BlockTime       string
	RedisConfig     RedisConfig
	RabbitUsername  string
	RabbitPassword  string
	RabbitHost      string
	RabbitPort      string
	RabbitTopic     string
	RabbitExchange  string
}
type RedisConfig struct {
	Addr     string
	Username string
	Password string
}

// NewEnv creates a new environment
func NewEnv() Env {
	env := Env{}
	env.LoadEnv()
	return env
}

// LoadEnv loads environment
func (env *Env) LoadEnv() {
	env.ServerPort = os.Getenv("ServerPort")
	env.Environment = os.Getenv("Environment")
	env.LogOutput = os.Getenv("LogOutput")

	env.DBUsername = os.Getenv("DBUsername")
	env.DBPassword = os.Getenv("DBPassword")
	env.DBHost = os.Getenv("DBHost")
	env.DBPort = os.Getenv("DBPort")
	env.DBName = os.Getenv("DBName")

	env.JWTSecret = os.Getenv("JWTSecret")

	env.DBEUsername = os.Getenv("DBEUsername")
	env.DBEPassword = os.Getenv("DBEPassword")
	env.DBEHost = os.Getenv("DBEHost")
	env.DBEIndex = os.Getenv("DBEIndex")

	env.Endpoint = os.Getenv("ENDPOINT")
	env.AcessKeyID = os.Getenv("ACCESS_KEY_ID")
	env.SecretAccessKey = os.Getenv("SECRET_ACCESS_KEY")
	env.UseSsl = os.Getenv("USE_SSL")
	env.BucketName = os.Getenv("BUCKET_NAME")
	env.IsRedis = os.Getenv("IS_REDIS")
	env.ExpiredToken = os.Getenv("EXPIRED_TOKEN")
	env.RefreshToken = os.Getenv("REFRESH_TOKEN")
	env.BlockTime = os.Getenv("BLOCK_TIME")
	env.RedisConfig.Addr = os.Getenv("REDIS_HOST")
	env.RedisConfig.Username = os.Getenv("REDIS_USERNAME")
	env.RedisConfig.Password = os.Getenv("REDIS_PASSWORD")
	env.RabbitUsername = os.Getenv("RABBIT_USERNAME")
	env.RabbitPassword = os.Getenv("RABBIT_PASSWORD")
	env.RabbitHost = os.Getenv("RABBIT_HOST")
	env.RabbitPort = os.Getenv("RABBIT_PORT")
	env.RabbitTopic = os.Getenv("RABBIT_TOPIC")
	env.RabbitExchange = os.Getenv("RABBIT_EXCHANGE")
}
