package passwordreset_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"yeshara.network/marketplace/internal/config"
	"yeshara.network/marketplace/internal/database"
	"yeshara.network/marketplace/internal/investors"
	"yeshara.network/marketplace/internal/passwordreset"
)

// Needs a real MongoDB; skipped unless TEST_MONGO_URI is set. Uses its own
// yeshara_passwordreset_test database, dropped before and after.
func TestResetFlow(t *testing.T) {
	uri := os.Getenv("TEST_MONGO_URI")
	if uri == "" {
		t.Skip("set TEST_MONGO_URI to run the Mongo-backed password reset test")
	}
	ctx := context.Background()
	if err := database.Init(&config.Config{MongoURI: uri, MongoDB: "yeshara_passwordreset_test"}); err != nil {
		t.Fatal(err)
	}
	_ = database.GetDB().Drop(ctx)
	t.Cleanup(func() { _ = database.GetDB().Drop(ctx) })
	if err := passwordreset.EnsureIndexes(ctx); err != nil {
		t.Fatal(err)
	}
	if err := investors.EnsureIndexes(ctx); err != nil {
		t.Fatal(err)
	}

	inv, err := investors.Register(ctx, "reset@example.com", "old-password", "Reset Tester")
	if err != nil {
		t.Fatal(err)
	}
	_, session, err := investors.Login(ctx, "reset@example.com", "old-password")
	if err != nil {
		t.Fatal(err)
	}

	first, _ := passwordreset.Issue(ctx, passwordreset.Investor, inv.ID)
	token, err := passwordreset.Issue(ctx, passwordreset.Investor, inv.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := passwordreset.Redeem(ctx, first); !errors.Is(err, passwordreset.ErrInvalidToken) {
		t.Fatalf("an older link must stop working once a new one is sent, got %v", err)
	}
	gotType, gotID, err := passwordreset.Redeem(ctx, token)
	if err != nil || gotType != passwordreset.Investor || gotID != inv.ID {
		t.Fatalf("redeem = %v %v %v", gotType, gotID, err)
	}
	if _, _, err := passwordreset.Redeem(ctx, token); !errors.Is(err, passwordreset.ErrInvalidToken) {
		t.Fatalf("a link must work only once, got %v", err)
	}

	if err := investors.SetPassword(ctx, inv.ID, "new-password"); err != nil {
		t.Fatal(err)
	}
	if _, err := investors.ValidateSession(ctx, session); err == nil {
		t.Fatal("resetting the password must sign out existing sessions")
	}
	if _, _, err := investors.Login(ctx, "reset@example.com", "old-password"); err == nil {
		t.Fatal("old password still works")
	}
	if _, _, err := investors.Login(ctx, "reset@example.com", "new-password"); err != nil {
		t.Fatalf("new password: %v", err)
	}
}
