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

	"github.com/golang-jwt/jwt/v5"
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
			return
		}
		utils.WriteResponse(w, 500, "something went wrong")
		return
	}

	utils.WriteJson(w, 200, tokenPair)
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), h.cfg.Database.Timeout)
	defer cancel()
	bearerT := r.Header.Get("Authorization")

	bearerSlc := strings.Split(bearerT, " ")

	if len(bearerSlc) != 2 {
		utils.WriteResponse(w, 403, "incorrect token format")
		return
	}

	token := bearerSlc[1]
	
	tokenPair, err := h.authService.RefreshToken(ctx, token)

	if err != nil {
		if errors.Is(err, jwt.ErrTokenMalformed) ||  errors.Is(err, service.ErrInvalidTokenClaims) {
			utils.WriteResponse(w, 403, err.Error())
			return
		}
		utils.WriteResponse(w, 500, "something went wrong")
		return
	}
	utils.WriteJson(w, 200, tokenPair)
}
