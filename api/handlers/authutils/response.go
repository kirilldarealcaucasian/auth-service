package utils

import (
	"encoding/json"
	"net/http"
)

type Response struct {
	Msg string `json:"msg"`
	Status int `json:"status"`
}

func WriteJson(w http.ResponseWriter, status int, data any) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	err := json.NewEncoder(w).Encode(&data)
	return err
}

func WriteResponse(w http.ResponseWriter, status int, msg string) error {
	resp := Response{
				Msg: msg,
				Status: status,
			}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	err := json.NewEncoder(w).Encode(&resp)
	return err
}