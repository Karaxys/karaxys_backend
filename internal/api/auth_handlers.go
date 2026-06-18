package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"karaxys_backend/internal/config"
	"karaxys_backend/internal/core"
	"karaxys_backend/internal/db"
	"karaxys_backend/internal/security/password"
	"karaxys_backend/internal/security/securetoken"

	"go.mongodb.org/mongo-driver/mongo"
)

const (
	refreshCookieName = "karaxys_refresh_token"
	accessTokenTTL    = 15 * time.Minute
	refreshTokenTTL   = 30 * 24 * time.Hour
)

type SignupRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	Name        string `json:"name"`
	AccountName string `json:"account_name"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type AuthResponse struct {
	AccessToken      string          `json:"access_token"`
	TokenType        string          `json:"token_type"`
	AccessExpiresAt  time.Time       `json:"access_expires_at"`
	RefreshExpiresAt time.Time       `json:"refresh_expires_at"`
	User             UserResponse    `json:"user"`
	Account          AccountResponse `json:"account"`
}

type UserResponse struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Name      string    `json:"name,omitempty"`
	AccountID string    `json:"account_id"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

type AccountResponse struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

func (s *Server) handleSignup(w http.ResponseWriter, r *http.Request) {
	var req SignupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	email, err := normalizeAuthEmail(req.Email)
	if err != nil {
		s.auditAuth(r, core.AuditActionSignup, core.AuditStatusFailure, "", "", "invalid email")
		http.Error(w, "Invalid email", http.StatusBadRequest)
		return
	}
	passwordHash, err := password.Hash(req.Password)
	if err != nil {
		status := http.StatusInternalServerError
		message := "Password setup failed"
		if errors.Is(err, password.ErrWeakPassword) {
			status = http.StatusBadRequest
			message = err.Error()
		}
		s.auditAuth(r, core.AuditActionSignup, core.AuditStatusFailure, "", "", message)
		http.Error(w, message, status)
		return
	}

	account, user, err := s.DB.CreateAccountWithAdminUser(email, req.Name, req.AccountName, passwordHash)
	if err != nil {
		if errors.Is(err, db.ErrDuplicateUser) {
			s.auditAuth(r, core.AuditActionSignup, core.AuditStatusFailure, "", "", "duplicate user")
			http.Error(w, "User already exists", http.StatusConflict)
			return
		}
		s.auditAuth(r, core.AuditActionSignup, core.AuditStatusFailure, "", "", "user creation failed")
		http.Error(w, "User creation failed", http.StatusInternalServerError)
		return
	}

	resp, err := s.createSessionResponse(w, r, user, account)
	if err != nil {
		s.auditAuth(r, core.AuditActionSignup, core.AuditStatusFailure, user.ID.Hex(), account.ID.Hex(), "session creation failed")
		http.Error(w, "Session creation failed", http.StatusInternalServerError)
		return
	}
	s.auditAuth(r, core.AuditActionSignup, core.AuditStatusSuccess, user.ID.Hex(), account.ID.Hex(), "")
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	email, err := normalizeAuthEmail(req.Email)
	if err != nil {
		s.auditAuth(r, core.AuditActionLogin, core.AuditStatusFailure, "", "", "invalid email")
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}
	user, err := s.DB.FindUserByEmail(email)
	if err != nil {
		s.auditAuth(r, core.AuditActionLogin, core.AuditStatusFailure, "", "", "unknown user")
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}
	if !password.Verify(user.PasswordHash, req.Password) {
		s.auditAuth(r, core.AuditActionLogin, core.AuditStatusFailure, user.ID.Hex(), user.AccountID.Hex(), "invalid password")
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}
	account, err := s.DB.GetAccount(user.AccountID)
	if err != nil {
		s.auditAuth(r, core.AuditActionLogin, core.AuditStatusFailure, user.ID.Hex(), user.AccountID.Hex(), "account missing")
		http.Error(w, "Account not found", http.StatusInternalServerError)
		return
	}
	resp, err := s.createSessionResponse(w, r, user, account)
	if err != nil {
		s.auditAuth(r, core.AuditActionLogin, core.AuditStatusFailure, user.ID.Hex(), user.AccountID.Hex(), "session creation failed")
		http.Error(w, "Session creation failed", http.StatusInternalServerError)
		return
	}
	_ = s.DB.MarkUserLogin(user.ID)
	s.auditAuth(r, core.AuditActionLogin, core.AuditStatusSuccess, user.ID.Hex(), user.AccountID.Hex(), "")
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	refreshToken := refreshTokenFromRequest(r)
	if refreshToken == "" {
		http.Error(w, "Refresh token missing", http.StatusUnauthorized)
		return
	}
	identity, err := s.DB.FindSessionByRefreshTokenHash(securetoken.Hash(refreshToken))
	if err != nil {
		s.auditAuth(r, core.AuditActionSessionRefresh, core.AuditStatusFailure, "", "", "invalid refresh token")
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}
	accessToken, refreshToken, accessExpiresAt, refreshExpiresAt, err := newSessionTokens()
	if err != nil {
		http.Error(w, "Token generation failed", http.StatusInternalServerError)
		return
	}
	if err := s.DB.RotateSessionTokens(identity.Session.ID, securetoken.Hash(accessToken), securetoken.Hash(refreshToken), accessExpiresAt, refreshExpiresAt); err != nil {
		http.Error(w, "Refresh failed", http.StatusUnauthorized)
		return
	}
	setRefreshCookie(w, refreshToken, refreshExpiresAt)
	s.auditAuth(r, core.AuditActionSessionRefresh, core.AuditStatusSuccess, identity.User.ID.Hex(), identity.Account.ID.Hex(), "")
	writeJSON(w, http.StatusOK, AuthResponse{
		AccessToken:      accessToken,
		TokenType:        "Bearer",
		AccessExpiresAt:  accessExpiresAt,
		RefreshExpiresAt: refreshExpiresAt,
		User:             userResponse(identity.User),
		Account:          accountResponse(identity.Account),
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	refreshToken := refreshTokenFromRequest(r)
	if refreshToken != "" {
		_ = s.DB.RevokeSessionByRefreshTokenHash(securetoken.Hash(refreshToken))
	}
	clearRefreshCookie(w)
	principal, _ := PrincipalFromContext(r.Context())
	s.auditAuth(r, core.AuditActionLogout, core.AuditStatusSuccess, principal.UserID, principal.AccountID, "")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	principal, ok := PrincipalFromContext(r.Context())
	if !ok || principal.UserID == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"subject":    principal.Subject,
		"actor_type": principal.ActorType,
		"user_id":    principal.UserID,
		"account_id": principal.AccountID,
		"role":       principal.Role,
	})
}

func (s *Server) createSessionResponse(w http.ResponseWriter, r *http.Request, user core.User, account core.Account) (AuthResponse, error) {
	accessToken, refreshToken, accessExpiresAt, refreshExpiresAt, err := newSessionTokens()
	if err != nil {
		return AuthResponse{}, err
	}
	_, err = s.DB.CreateSession(core.Session{
		UserID:           user.ID,
		AccountID:        account.ID,
		AccessTokenHash:  securetoken.Hash(accessToken),
		RefreshTokenHash: securetoken.Hash(refreshToken),
		UserAgent:        r.UserAgent(),
		RemoteAddr:       clientID(r),
		AccessExpiresAt:  accessExpiresAt,
		RefreshExpiresAt: refreshExpiresAt,
	})
	if err != nil {
		return AuthResponse{}, err
	}
	_ = s.DB.RevokeOldUserSessions(user.ID, 10)
	setRefreshCookie(w, refreshToken, refreshExpiresAt)
	return AuthResponse{
		AccessToken:      accessToken,
		TokenType:        "Bearer",
		AccessExpiresAt:  accessExpiresAt,
		RefreshExpiresAt: refreshExpiresAt,
		User:             userResponse(user),
		Account:          accountResponse(account),
	}, nil
}

func (s *Server) authenticateSessionToken(token string) (*Principal, bool) {
	if token == "" {
		return nil, false
	}
	identity, err := s.DB.FindSessionByAccessTokenHash(securetoken.Hash(token))
	if err != nil {
		if !errors.Is(err, mongo.ErrNoDocuments) {
			// Avoid failing closed with implementation detail leakage; the request is simply unauthenticated.
		}
		return nil, false
	}
	return &Principal{
		Subject:   "user:" + identity.User.ID.Hex(),
		ActorType: core.AuditActorUser,
		UserID:    identity.User.ID.Hex(),
		AccountID: identity.Account.ID.Hex(),
		Role:      identity.User.Role,
	}, true
}

func newSessionTokens() (string, string, time.Time, time.Time, error) {
	accessToken, err := securetoken.Generate("kx_access")
	if err != nil {
		return "", "", time.Time{}, time.Time{}, err
	}
	refreshToken, err := securetoken.Generate("kx_refresh")
	if err != nil {
		return "", "", time.Time{}, time.Time{}, err
	}
	now := time.Now().UTC()
	return accessToken, refreshToken, now.Add(accessTokenTTL), now.Add(refreshTokenTTL), nil
}

func setRefreshCookie(w http.ResponseWriter, refreshToken string, expiresAt time.Time) {
	cookie := &http.Cookie{
		Name:     refreshCookieName,
		Value:    refreshToken,
		Path:     "/",
		Expires:  expiresAt,
		MaxAge:   int(time.Until(expiresAt).Seconds()),
		HttpOnly: true,
		Secure:   config.IsProduction(),
		SameSite: http.SameSiteLaxMode,
	}
	http.SetCookie(w, cookie)
}

func clearRefreshCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     refreshCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   config.IsProduction(),
		SameSite: http.SameSiteLaxMode,
	})
}

func refreshTokenFromRequest(r *http.Request) string {
	if cookie, err := r.Cookie(refreshCookieName); err == nil {
		return cookie.Value
	}
	return ""
}

func normalizeAuthEmail(email string) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return "", errors.New("email is required")
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return "", err
	}
	return email, nil
}

func userResponse(user core.User) UserResponse {
	return UserResponse{
		ID:        user.ID.Hex(),
		Email:     user.Email,
		Name:      user.Name,
		AccountID: user.AccountID.Hex(),
		Role:      user.Role,
		CreatedAt: user.CreatedAt,
	}
}

func accountResponse(account core.Account) AccountResponse {
	return AccountResponse{
		ID:   account.ID.Hex(),
		Name: account.Name,
		Slug: account.Slug,
	}
}

func (s *Server) auditAuth(r *http.Request, action string, status string, userID string, accountID string, message string) {
	if s == nil || s.DB == nil {
		return
	}
	_ = s.DB.SaveAuditLog(core.AuditLog{
		ActorType:    core.AuditActorUser,
		ActorID:      userID,
		Action:       action,
		ResourceType: "session",
		ResourceID:   accountID,
		Status:       status,
		RemoteAddr:   clientID(r),
		Message:      message,
	})
}
