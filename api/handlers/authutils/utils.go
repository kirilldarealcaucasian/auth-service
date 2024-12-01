package utils

import (
	"net/http"
	"strings"
)

func GetUserIp(r *http.Request) string {
	ip := r.RemoteAddr
  return strings.Split(ip, ":")[0]
}