// Package admins backs Yeshara's single issuer admin login with a stored
// password and revocable sessions, so the admin can reset a forgotten
// password like every other account type.
//
// The admin's email still comes from ADMIN_EMAIL. Until the first reset the
// password is checked against ADMIN_PASSWORD_HASH; once a reset stores a
// hash in admin_credentials, that hash wins. ADMIN_TOKEN stays valid as a
// static operator/script credential; sign-ins get their own session tokens,
// which a reset revokes.
package admins

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"

	"yeshara.network/marketplace/internal/database"
)

// AccountID identifies the single admin in password_resets, which keys
// tokens by ObjectID.
var AccountID = primitive.NilObjectID

const (
	credentialsID = "admin"
	sessionTTL    = 12 * time.Hour
)

var (
	ErrInvalidCredentials = errors.New("admins: invalid email or password")
	ErrSessionExpired     = errors.New("admins: session expired or invalid")
)

func credentials() *mongo.Collection { return database.GetDB().Collection("admin_credentials") }
func sessions() *mongo.Collection    { return database.GetDB().Collection("admin_sessions") }

func EnsureIndexes(ctx context.Context) error {
	_, err := sessions().Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "expires_at", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0),
	})
	return err
}

// hashFor returns the stored hash, or envHash when no reset has happened yet.
func hashFor(ctx context.Context, envHash string) (string, error) {
	var doc struct {
		PasswordHash string `bson:"password_hash"`
	}
	err := credentials().FindOne(ctx, bson.M{"_id": credentialsID}).Decode(&doc)
	if errors.Is(err, mongo.ErrNoDocuments) || (err == nil && doc.PasswordHash == "") {
		return envHash, nil
	}
	return doc.PasswordHash, err
}

// Login checks the password and opens a session, returning its token.
func Login(ctx context.Context, password, envHash string) (string, error) {
	hash, err := hashFor(ctx, envHash)
	if err != nil {
		return "", err
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		return "", ErrInvalidCredentials
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)
	now := time.Now().UTC()
	_, err = sessions().InsertOne(ctx, bson.M{"_id": hashToken(token), "expires_at": now.Add(sessionTTL), "created_at": now})
	return token, err
}

// ValidSession reports whether token is a live admin session.
func ValidSession(ctx context.Context, token string) (bool, error) {
	if token == "" {
		return false, nil
	}
	n, err := sessions().CountDocuments(ctx, bson.M{"_id": hashToken(token), "expires_at": bson.M{"$gt": time.Now().UTC()}})
	return n > 0, err
}

func Logout(ctx context.Context, token string) error {
	_, err := sessions().DeleteOne(ctx, bson.M{"_id": hashToken(token)})
	return err
}

// SetPassword stores a new admin password and signs every admin session out.
func SetPassword(ctx context.Context, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = credentials().UpdateOne(ctx, bson.M{"_id": credentialsID},
		bson.M{"$set": bson.M{"password_hash": string(hash), "updated_at": time.Now().UTC()}},
		options.Update().SetUpsert(true))
	if err != nil {
		return err
	}
	_, err = sessions().DeleteMany(ctx, bson.M{})
	return err
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
