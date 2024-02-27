package timekuy

import (
	"fmt"
	"strings"
	"time"
)

func GetTimeNow(param string) string {

	currentTime := time.Now()
	time.LoadLocation("Asia/Jakarta")

	switch param {
	case "timestime":
		return currentTime.Format("2006-01-02 15:04:05")
	case "date":
		return currentTime.Format("2006-01-02")
	case "year":
		return fmt.Sprint(currentTime.Year())
	case "month":
		return fmt.Sprint(int(currentTime.Month()))
	case "month-name":
		return fmt.Sprint(currentTime.Month())
	case "day":
		return fmt.Sprint(currentTime.Day())
	case "hour":
		return fmt.Sprint(currentTime.Hour())
	case "minutes":
		return fmt.Sprint(currentTime.Minute())
	case "second":
		return fmt.Sprint(currentTime.Second())
	case "unixmicro":
		return fmt.Sprint(currentTime.UnixMicro())
	default:
		fmt.Println("masukan parameter")
		return ""
	}
}

func AddTime(year int, month int, days int) *string {
	currentTime := time.Now()
	time.LoadLocation("Asia/Jakarta")

	addtime := fmt.Sprint(currentTime.AddDate(year, month, days).Format("2006-01-02 15:04:05"))
	return &addtime
}

func TimeNow() time.Time {
	loc, _ := time.LoadLocation("Asia/Jakarta")
	return time.Now().In(loc)
}

func ConvertMs(millis int64) string {
	minutesValue := millis / (1000 * 60)
	secondsValue := (millis / 1000) % 60
	return fmt.Sprintf(" %d menit dan %d detik", minutesValue, secondsValue)
}
func ConvertMsDur(ms time.Duration) string {
	str := fmt.Sprintf("%v", ms)
	str = strings.ReplaceAll(str, "h", " jam ")
	str = strings.ReplaceAll(str, "m", " menit ")
	str = strings.ReplaceAll(str, "s", " detik")
	return str
}
func ConvertMsMinute(millis int64) string {
	//minutesValue := millis / (1000 * 60)
	//secondsValue := (millis / 1000) % 60
	//fmt.Println(minutesValue)
	//fmt.Println(secondsValue)
	//if minutesValue >= 0 && secondsValue > 0 {
	//	minutesValue = 1
	//}
	//return fmt.Sprintf("%d", minutesValue)
	minutesValue := millis / (1000 * 60)
	secondsValue := (millis / 1000) % 60
	return fmt.Sprintf(" %d menit dan %d detik", minutesValue, secondsValue)
}
