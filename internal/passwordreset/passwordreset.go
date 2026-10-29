// Package passwordreset issues and redeems single-use password-reset tokens
// for investor, owner and staff accounts. Only a SHA-256 of each token is
// stored, a token lives for TokenTTL, and redeeming it is atomic, so a
// leaked database row can't be replayed and a link works exactly once.
package passwordreset

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"

	"yeshara.network/marketplace/internal/database"
)

const TokenTTL = 30 * time.Minute

type AccountType string

const (
	Investor AccountType = "investor"
	Owner    AccountType = "owner"
	Staff    AccountType = "staff"
)

func ParseAccountType(s string) (AccountType, bool) {
	switch AccountType(s) {
	case "", Investor:
		return Investor, true
	case Owner, Staff:
		return AccountType(s), true
	}
	return "", false
}

var ErrInvalidToken = errors.New("this reset link is invalid or has expired")

type record struct {
	TokenHash   string             `bson:"_id"`
	AccountType AccountType        `bson:"account_type"`
	AccountID   primitive.ObjectID `bson:"account_id"`
	ExpiresAt   time.Time          `bson:"expires_at"`
	CreatedAt   time.Time          `bson:"created_at"`
	UsedAt      *time.Time         `bson:"used_at,omitempty"`
}

func collection() *mongo.Collection { return database.GetDB().Collection("password_resets") }

// EnsureIndexes lets Mongo drop expired tokens and keeps per-account lookups cheap.
func EnsureIndexes(ctx context.Context) error {
	_, err := collection().Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "expires_at", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0)},
		{Keys: bson.D{{Key: "account_type", Value: 1}, {Key: "account_id", Value: 1}}},
	})
	return err
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Issue returns a fresh token for the account and voids any earlier unused
// ones, so only the most recent email's link works.
func Issue(ctx context.Context, t AccountType, accountID primitive.ObjectID) (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	if _, err := collection().DeleteMany(ctx, bson.M{"account_type": t, "account_id": accountID, "used_at": bson.M{"$exists": false}}); err != nil {
		return "", err
	}
	now := time.Now().UTC()
	_, err := collection().InsertOne(ctx, record{TokenHash: hashToken(token), AccountType: t, AccountID: accountID, ExpiresAt: now.Add(TokenTTL), CreatedAt: now})
	if err != nil {
		return "", err
	}
	return token, nil
}

// Redeem consumes a token and returns the account it was issued for.
func Redeem(ctx context.Context, token string) (AccountType, primitive.ObjectID, error) {
	if token == "" {
		return "", primitive.NilObjectID, ErrInvalidToken
	}
	now := time.Now().UTC()
	var rec record
	err := collection().FindOneAndUpdate(ctx,
		bson.M{"_id": hashToken(token), "used_at": bson.M{"$exists": false}, "expires_at": bson.M{"$gt": now}},
		bson.M{"$set": bson.M{"used_at": now}},
	).Decode(&rec)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return "", primitive.NilObjectID, ErrInvalidToken
	}
	if err != nil {
		return "", primitive.NilObjectID, err
	}
	return rec.AccountType, rec.AccountID, nil
}
