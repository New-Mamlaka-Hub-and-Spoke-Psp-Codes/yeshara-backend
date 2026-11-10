package api

import (
	"errors"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"yeshara.network/marketplace/internal/admins"
)

// adminLogin exchanges the configured admin email + password for an admin
// session token (sent back as X-Admin-Token). The password is the stored one
// after a reset, else ADMIN_PASSWORD_HASH.
func (s *Server) adminLogin(c *gin.Context) {
	var req struct {
		Email    string `json:"email" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email != strings.ToLower(strings.TrimSpace(s.cfg.AdminEmail)) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid email or password"})
		return
	}
	token, err := admins.Login(c.Request.Context(), req.Password, s.cfg.AdminPasswordHash)
	if errors.Is(err, admins.ErrInvalidCredentials) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid email or password"})
		return
	}
	if err != nil {
		log.Printf("admin login: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "couldn't sign in, please try again"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": token})
}

// adminLogout ends the caller's admin session (a no-op for ADMIN_TOKEN).
func (s *Server) adminLogout(c *gin.Context) {
	_ = admins.Logout(c.Request.Context(), c.GetHeader("X-Admin-Token"))
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
