package admins_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"yeshara.network/marketplace/internal/admins"
	"yeshara.network/marketplace/internal/config"
	"yeshara.network/marketplace/internal/database"
	"yeshara.network/marketplace/internal/passwordreset"
)

// Needs a real MongoDB; skipped unless TEST_MONGO_URI is set.
func TestAdminResetFlow(t *testing.T) {
	uri := os.Getenv("TEST_MONGO_URI")
	if uri == "" {
		t.Skip("set TEST_MONGO_URI to run the Mongo-backed admin test")
	}
	ctx := context.Background()
	if err := database.Init(&config.Config{MongoURI: uri, MongoDB: "yeshara_admins_test"}); err != nil {
		t.Fatal(err)
	}
	_ = database.GetDB().Drop(ctx)
	t.Cleanup(func() { _ = database.GetDB().Drop(ctx) })
	if err := admins.EnsureIndexes(ctx); err != nil {
		t.Fatal(err)
	}
	if err := passwordreset.EnsureIndexes(ctx); err != nil {
		t.Fatal(err)
	}
	envHash, _ := bcrypt.GenerateFromPassword([]byte("env-password"), bcrypt.MinCost)

	// Before any reset the env hash is the password.
	session, err := admins.Login(ctx, "env-password", string(envHash))
	if err != nil {
		t.Fatalf("env password login: %v", err)
	}
	if ok, _ := admins.ValidSession(ctx, session); !ok {
		t.Fatal("fresh session should be valid")
	}
	if _, err := admins.Login(ctx, "wrong", string(envHash)); !errors.Is(err, admins.ErrInvalidCredentials) {
		t.Fatalf("wrong password = %v", err)
	}

	token, err := passwordreset.Issue(ctx, passwordreset.Admin, admins.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	typ, id, err := passwordreset.Redeem(ctx, token)
	if err != nil || typ != passwordreset.Admin || id != admins.AccountID {
		t.Fatalf("redeem = %v %v %v", typ, id, err)
	}
	if err := admins.SetPassword(ctx, "new-admin-password"); err != nil {
		t.Fatal(err)
	}

	if ok, _ := admins.ValidSession(ctx, session); ok {
		t.Fatal("a reset must sign the admin out everywhere")
	}
	if _, err := admins.Login(ctx, "env-password", string(envHash)); !errors.Is(err, admins.ErrInvalidCredentials) {
		t.Fatalf("old env password must stop working after a reset, got %v", err)
	}
	s2, err := admins.Login(ctx, "new-admin-password", string(envHash))
	if err != nil {
		t.Fatalf("new password login: %v", err)
	}
	if err := admins.Logout(ctx, s2); err != nil {
		t.Fatal(err)
	}
	if ok, _ := admins.ValidSession(ctx, s2); ok {
		t.Fatal("logout must end the session")
	}
}
