package routes

import (
	"net/http"
	"testovoe_medods/api/handlers"
)


func RegisterAuthRoutes(mux *http.ServeMux, h *handlers.AuthHandler) {
	mux.HandleFunc("/api/authenticate/{guid}", h.Authenticate)
	mux.HandleFunc("/api/refresh", h.Refresh)
}