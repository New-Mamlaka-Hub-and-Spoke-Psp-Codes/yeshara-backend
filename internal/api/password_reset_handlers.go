package api

import (
	"context"
	"errors"
	"fmt"
	"html"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"

	"yeshara.network/marketplace/internal/investors"
	"yeshara.network/marketplace/internal/owners"
	"yeshara.network/marketplace/internal/passwordreset"
	"yeshara.network/marketplace/internal/staff"
)

const forgotPasswordReply = "If an account exists for that email, we've sent a link to reset its password. It expires in 30 minutes."

// forgotPassword handles POST /api/v1/auth/password/forgot {email, accountType}.
// It always answers the same way, whether or not the account exists, so the
// endpoint can't be used to find out who is registered.
func (s *Server) forgotPassword(c *gin.Context) {
	var req struct {
		Email       string `json:"email" binding:"required,email"`
		AccountType string `json:"accountType"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Enter a valid email address."})
		return
	}
	accountType, ok := passwordreset.ParseAccountType(req.AccountType)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "accountType must be investor, owner or staff"})
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))

	// Looked up and sent off the request path, so response time doesn't
	// reveal whether the account exists either.
	go s.sendResetEmail(accountType, email)
	c.JSON(http.StatusOK, gin.H{"status": "ok", "message": forgotPasswordReply})
}

func (s *Server) sendResetEmail(accountType passwordreset.AccountType, email string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	id, name, err := lookupAccount(ctx, accountType, email)
	if err != nil {
		return // unknown email: nothing to send
	}
	token, err := passwordreset.Issue(ctx, accountType, id)
	if err != nil {
		log.Printf("password reset: issue token for %s %s: %v", accountType, id.Hex(), err)
		return
	}
	link := fmt.Sprintf("%s/reset-password?type=%s&token=%s", s.cfg.AppPublicURL, accountType, url.QueryEscape(token))

	if !s.mail.Configured() {
		if s.cfg.AppEnv == "production" {
			log.Printf("password reset: SMTP is not configured, so no email was sent to %s account %s", accountType, id.Hex())
		} else {
			log.Printf("password reset (dev, no SMTP): %s %s → %s", accountType, email, link)
		}
		return
	}
	text, body := resetEmail(name, link)
	if err := s.mail.Send(email, "Reset your Yeshara password", text, body); err != nil {
		log.Printf("password reset: send to %s account %s: %v", accountType, id.Hex(), err)
	}
}

func lookupAccount(ctx context.Context, t passwordreset.AccountType, email string) (primitive.ObjectID, string, error) {
	switch t {
	case passwordreset.Owner:
		o, err := owners.GetByEmail(ctx, email)
		if err != nil {
			return primitive.NilObjectID, "", err
		}
		return o.ID, o.FullName, nil
	case passwordreset.Staff:
		st, err := staff.GetByEmail(ctx, email)
		if err != nil {
			return primitive.NilObjectID, "", err
		}
		return st.ID, st.FullName, nil
	default:
		inv, err := investors.GetByEmail(ctx, email)
		if err != nil {
			return primitive.NilObjectID, "", err
		}
		return inv.ID, inv.FullName, nil
	}
}

// resetPassword handles POST /api/v1/auth/password/reset {token, password}.
func (s *Server) resetPassword(c *gin.Context) {
	var req struct {
		Token    string `json:"token" binding:"required"`
		Password string `json:"password" binding:"required,min=8,max=72"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Choose a password between 8 and 72 characters."})
		return
	}
	ctx := c.Request.Context()
	accountType, id, err := passwordreset.Redeem(ctx, req.Token)
	if errors.Is(err, passwordreset.ErrInvalidToken) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "This reset link is invalid or has expired. Request a new one."})
		return
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Couldn't reset the password. Please try again."})
		return
	}
	switch accountType {
	case passwordreset.Owner:
		err = owners.SetPassword(ctx, id, req.Password)
	case passwordreset.Staff:
		err = staff.SetPassword(ctx, id, req.Password)
	default:
		err = investors.SetPassword(ctx, id, req.Password)
	}
	if err != nil {
		log.Printf("password reset: set password for %s %s: %v", accountType, id.Hex(), err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Couldn't reset the password. Please try again."})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok", "accountType": accountType})
}

func resetEmail(name, link string) (text, body string) {
	greeting := "Hi"
	if n := strings.TrimSpace(name); n != "" {
		greeting = "Hi " + strings.Fields(n)[0]
	}
	text = fmt.Sprintf("%s,\n\nWe received a request to reset your Yeshara password. Open this link to choose a new one:\n\n%s\n\nThe link expires in 30 minutes and works once. If you didn't ask for this, ignore this email; your password stays the same.\n\nYeshara", greeting, link)
	l := html.EscapeString(link)
	body = fmt.Sprintf(`<div style="background:#04090a;padding:32px 16px;font-family:Arial,sans-serif">
<div style="max-width:480px;margin:0 auto;background:#0a1615;border:1px solid #16302d;border-radius:16px;padding:32px;color:#f4fbfb">
<p style="margin:0 0 24px;font-weight:bold;font-size:18px">Yeshara</p>
<p style="margin:0 0 12px">%s,</p>
<p style="margin:0 0 24px;color:#8ba7a5;line-height:1.6">We received a request to reset your Yeshara password. Choose a new one with the button below.</p>
<a href="%s" style="display:inline-block;background:#8fd0d2;color:#04090a;text-decoration:none;font-weight:bold;padding:12px 22px;border-radius:12px">Reset password</a>
<p style="margin:24px 0 0;color:#567270;font-size:13px;line-height:1.6">The link expires in 30 minutes and works once. If you didn't ask for this, ignore this email; your password stays the same.</p>
</div></div>`, html.EscapeString(greeting), l)
	return text, body
}
