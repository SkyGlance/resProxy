package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"log"
	"net/url"
	resProxy "secretProxy/resProxy"
	"strings"
)

var (
	downLoadBytes  uint64
	downLoadFailed uint64
)

type loginterface struct {
}

func (lf *loginterface) OnError(code string, reason string) {
	log.Printf("ON_ERROR:%s %s", code, reason)

}
func (lf *loginterface) OnLog(code string, reason string) {
	log.Printf("ON_LOG:%s %s", code, reason)
}

func main() {
	user := "ztu001"
	pass := "53d14095434c509364277e93c81ece06d07c07b3-1603270407316-eyJpZCI6IjIyMDY4MDczMzk2ZTQzYTJiMGEwMTUxMzdiMTk1MGRlIiwibG9naW5OYW1lIjoienR1MDAxIiwiY29kZSI6bnVsbCwic3RhcnREYXRlIjoiMjAxOS0xMC0yNSAxMDoxMDozOSIsImVuZERhdGUiOiIyMDIwLTExLTIwIDExOjI0OjI1IiwibW9udGhOdW0iOjE4LCJzdGF0dXMiOjEsInRpbWUiOjAsInB3ZCI6IjEyMzQiLCJ4dHJlYW0iOnsidXJsIjpudWxsLCJzdGFuZGJ5dXJsIjpudWxsLCJyb3V0ZUFjY291bnQiOm51bGwsInJvdXRlUGFzc3dvcmQiOm51bGwsImxpdmVSb3V0ZUFjY291bnQiOm51bGwsImxpdmVSb3V0ZVBhc3N3b3JkIjpudWxsLCJsaXZlRXhwaXJlZCI6bnVsbCwidm9kRXhwaXJlZCI6bnVsbH0sImlwIjpudWxsLCJzZXJ2aWNlIjp7InN0YXRlIjowLCJtZXNzYWdlIjoiIn0sImN1c3RUeXBlIjoxLCJsb2dpbkZsYWciOm51bGwsImFjY291bnRTZXEiOiJ6dHUwMDExNjAzMjcwNDA3MzA2IiwidG9rZW4iOiIxNjAzMjcwNDA3MzA2IiwiYWRkcmVzc1VybCI6eyJ1cmwiOiJodHRwOi8vMTk1LjE4MS4xNjIuMTExOjcyODMifSwiYWRkcmVzc1N0YXR1cyI6IjkifQ%3D%3D"
	llog := loginterface{}
	dt, err := url.QueryUnescape(pass)
	if err != nil {
		return
	}
	parts := strings.Split(dt, "-")
	if len(parts) != 3 {
		return
	}
	mac := hmac.New(sha1.New, []byte("1234567890"))
	mac.Write([]byte(parts[1] + parts[2]))
	sign := fmt.Sprintf("%x", mac.Sum(nil))
	if len(parts[0]) != len(sign) {
		return
	}
	if !strings.EqualFold(parts[0], sign) {
		return
	}
	jdata, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return
	}
	fmt.Printf("%s\n", jdata)
	//	resProxy.PostLogData(`https://vip.magistv.net/api/streamLog/save`,
	//		`{"applicationId":"com.android.mgandroid","brand":"Android","carrier":"amlogic","country":"CN","hardware":"","lauguage":"zh","loginName":"yang","model":"Aboxx","osversion":"5.1.1","platform":"2","playMsg":"media play state is ready !","playUrl":"http://123.com/EL-CANAL-DE-FUTBOL-ECUADOR-HD/index.m3u8?token=cNyJnqtM9ZmRSqf9grBhx4YdvCCZFEBi8k1qxeJUtx6KvX5Li9AtJWchaMaADaLwiUOI5GAMIMXsKXTv82GEfdA/n3pKM7VDwvHmc765pJbeKYS7mDXC9k3EOHZDOY-yang-yang1591116724364-1591167869556-0.0.0.0","sdk":"22","serial":"7eec2f90576c42a0848fc22b9e0bd9f9","timeZone":"America/Chicago","versionCode":"20600","versionName":"2.6.0_debug"}`)
	resProxy.StartProxy(user, pass, 19230, 19231, &llog)
	select {}
}
