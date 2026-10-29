// Package mailer sends Yeshara's transactional email (password resets) over
// SMTP. It is configured from SMTP_HOST, SMTP_PORT, SMTP_USERNAME,
// SMTP_PASSWORD and MAIL_FROM; with no SMTP_HOST it is unconfigured and the
// caller decides what to do instead.
package mailer

import (
	"crypto/tls"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"os"
	"strings"
	"time"
)

type Mailer struct {
	host, port, username, password, from string
}

func FromEnv() *Mailer {
	port := strings.TrimSpace(os.Getenv("SMTP_PORT"))
	if port == "" {
		port = "587"
	}
	return &Mailer{
		host:     strings.TrimSpace(os.Getenv("SMTP_HOST")),
		port:     port,
		username: os.Getenv("SMTP_USERNAME"),
		password: os.Getenv("SMTP_PASSWORD"),
		from:     strings.TrimSpace(os.Getenv("MAIL_FROM")),
	}
}

func (m *Mailer) Configured() bool { return m != nil && m.host != "" && m.from != "" }

// Send delivers a multipart text + HTML message. Port 465 uses implicit TLS;
// any other port uses STARTTLS when the server offers it.
func (m *Mailer) Send(to, subject, text, html string) error {
	if !m.Configured() {
		return fmt.Errorf("mailer: SMTP_HOST and MAIL_FROM are not set")
	}
	if strings.ContainsAny(to, "\r\n") {
		return fmt.Errorf("mailer: invalid recipient")
	}
	msg := buildMessage(m.from, to, subject, text, html)
	addr := net.JoinHostPort(m.host, m.port)
	var auth smtp.Auth
	if m.username != "" {
		auth = smtp.PlainAuth("", m.username, m.password, m.host)
	}
	if m.port != "465" {
		return smtp.SendMail(addr, auth, envelopeAddress(m.from), []string{to}, msg)
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 15 * time.Second}, "tcp", addr, &tls.Config{ServerName: m.host})
	if err != nil {
		return fmt.Errorf("mailer: dial %s: %w", addr, err)
	}
	c, err := smtp.NewClient(conn, m.host)
	if err != nil {
		return err
	}
	defer c.Close()
	if auth != nil {
		if err := c.Auth(auth); err != nil {
			return err
		}
	}
	if err := c.Mail(envelopeAddress(m.from)); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// envelopeAddress takes "Yeshara <no-reply@yeshara.network>" to the bare address.
func envelopeAddress(from string) string {
	if i, j := strings.LastIndex(from, "<"), strings.LastIndex(from, ">"); i >= 0 && j > i {
		return from[i+1 : j]
	}
	return from
}

func buildMessage(from, to, subject, text, html string) []byte {
	const boundary = "yeshara-alt-boundary"
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\n", from, to, mime.QEncoding.Encode("utf-8", subject))
	fmt.Fprintf(&b, "Date: %s\r\nContent-Type: multipart/alternative; boundary=%q\r\n\r\n", time.Now().UTC().Format(time.RFC1123Z), boundary)
	fmt.Fprintf(&b, "--%s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n", boundary, text)
	fmt.Fprintf(&b, "--%s\r\nContent-Type: text/html; charset=utf-8\r\n\r\n%s\r\n", boundary, html)
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return []byte(b.String())
}
