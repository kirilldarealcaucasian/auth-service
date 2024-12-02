package handlers

import (
	"context"
	"errors"
	"net/http"
	"strings"
	utils "testovoe_medods/api/handlers/authutils"
	"testovoe_medods/config"
	"testovoe_medods/entities"
	"testovoe_medods/service"
)

type AuthHandler struct {
	cfg *config.Config
	authService service.AuthService
}

func NewAuthHandler(cfg *config.Config, authService service.AuthService) *AuthHandler {
	return &AuthHandler{
		cfg: cfg,
		authService: authService,
	}
}

func (h *AuthHandler) Authenticate(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), h.cfg.Database.Timeout)
	defer cancel()
	url := strings.Split(r.URL.String(), "/")
	guid := url[len(url) - 1]
	ipAddr := utils.GetUserIp(r)

	authReq := entities.AuthenticateRequest{Guid: guid, IpAddr: ipAddr}
	tokenPair, err := h.authService.ReleaseTokens(ctx, &authReq)

	if err != nil {
		if errors.Is(err, service.ErrNoUserFound) {
			utils.WriteResponse(w, 403, err.Error())
		}
		utils.WriteResponse(w, 500, "something went wrong")
	}

	utils.WriteJson(w, 200, tokenPair)
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	bearerT := r.Header.Get("Authorization")

	if bearerT == "" || !strings.HasPrefix(bearerT, "Bearer ") {
		utils.WriteResponse(w, 403, "no token in the header")
		return

	}
}
