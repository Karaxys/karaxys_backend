package db

import (
	"context"
	"errors"
	"time"

	"karaxys_backend/internal/core"
	"karaxys_backend/internal/security/scansecrets"
	"karaxys_backend/internal/security/securetoken"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const ingestTokenPrefix = "kar"

var ErrIngestTokenNotFound = errors.New("account ingest token not found")

// GetOrCreateAccountIngestToken returns the existing ingest token for an account,
// creating one if none exists. Returns the model and the decrypted raw token.
func (db *DB) GetOrCreateAccountIngestToken(ctx context.Context, accountID primitive.ObjectID, protector *scansecrets.Protector) (*core.AccountIngestToken, string, error) {
	existing, rawToken, err := db.GetAccountIngestToken(ctx, accountID, protector)
	if err == nil {
		return existing, rawToken, nil
	}
	if !errors.Is(err, ErrIngestTokenNotFound) {
		return nil, "", err
	}
	return db.createAccountIngestToken(ctx, accountID, protector)
}

// GetAccountIngestToken retrieves and decrypts the ingest token for an account.
func (db *DB) GetAccountIngestToken(ctx context.Context, accountID primitive.ObjectID, protector *scansecrets.Protector) (*core.AccountIngestToken, string, error) {
	var tok core.AccountIngestToken
	err := db.AccountIngestTokens.FindOne(ctx, bson.M{"account_id": accountID}).Decode(&tok)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, "", ErrIngestTokenNotFound
	}
	if err != nil {
		return nil, "", err
	}
	rawToken, err := decryptIngestToken(tok.TokenNonce, tok.TokenCipher, protector)
	if err != nil {
		return nil, "", err
	}
	return &tok, rawToken, nil
}

// RotateAccountIngestToken replaces the existing token with a new one.
// Returns the new model and new raw token.
func (db *DB) RotateAccountIngestToken(ctx context.Context, accountID primitive.ObjectID, protector *scansecrets.Protector) (*core.AccountIngestToken, string, error) {
	rawToken, err := securetoken.Generate(ingestTokenPrefix)
	if err != nil {
		return nil, "", err
	}
	tokenHash := securetoken.Hash(rawToken)
	nonce, cipher, err := encryptIngestToken(rawToken, protector)
	if err != nil {
		return nil, "", err
	}
	now := time.Now()
	tok := core.AccountIngestToken{
		AccountID:   accountID,
		TokenHash:   tokenHash,
		TokenNonce:  nonce,
		TokenCipher: cipher,
		TokenPrefix: tokenPrefix(rawToken),
		CreatedAt:   now,
		UpdatedAt:   now,
		RotatedAt:   now,
	}
	filter := bson.M{"account_id": accountID}
	update := bson.M{"$set": tok}
	opts := options.FindOneAndUpdate().SetUpsert(true).SetReturnDocument(options.After)
	var result core.AccountIngestToken
	err = db.AccountIngestTokens.FindOneAndUpdate(ctx, filter, update, opts).Decode(&result)
	if err != nil {
		return nil, "", err
	}
	return &result, rawToken, nil
}

// FindAccountByIngestToken looks up the token record by the SHA-256 hash of the raw token.
// Used at the hot path of POST /ingest — O(1) indexed lookup, no decryption.
func (db *DB) FindAccountByIngestToken(ctx context.Context, tokenHash string) (*core.AccountIngestToken, error) {
	var tok core.AccountIngestToken
	err := db.AccountIngestTokens.FindOne(ctx, bson.M{"token_hash": tokenHash}).Decode(&tok)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, ErrIngestTokenNotFound
	}
	return &tok, err
}

// TouchIngestToken updates last_used_at asynchronously (fire-and-forget pattern).
func (db *DB) TouchIngestToken(ctx context.Context, accountID primitive.ObjectID) {
	_, _ = db.AccountIngestTokens.UpdateOne(
		ctx,
		bson.M{"account_id": accountID},
		bson.M{"$set": bson.M{"last_used_at": time.Now()}},
	)
}

// createAccountIngestToken generates and persists a fresh ingest token.
func (db *DB) createAccountIngestToken(ctx context.Context, accountID primitive.ObjectID, protector *scansecrets.Protector) (*core.AccountIngestToken, string, error) {
	rawToken, err := securetoken.Generate(ingestTokenPrefix)
	if err != nil {
		return nil, "", err
	}
	tokenHash := securetoken.Hash(rawToken)
	nonce, cipher, err := encryptIngestToken(rawToken, protector)
	if err != nil {
		return nil, "", err
	}
	now := time.Now()
	tok := core.AccountIngestToken{
		AccountID:   accountID,
		TokenHash:   tokenHash,
		TokenNonce:  nonce,
		TokenCipher: cipher,
		TokenPrefix: tokenPrefix(rawToken),
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	res, err := db.AccountIngestTokens.InsertOne(ctx, tok)
	if err != nil {
		return nil, "", err
	}
	tok.ID = res.InsertedID.(primitive.ObjectID)
	return &tok, rawToken, nil
}

// encryptIngestToken encrypts the raw token. When protector is nil (dev mode),
// stores the plaintext in cipher with a sentinel nonce so it can be read back.
func encryptIngestToken(rawToken string, protector *scansecrets.Protector) (nonce, cipher string, err error) {
	if protector == nil {
		return "dev", rawToken, nil
	}
	n, c, err := protector.Encrypt(rawToken)
	return n, c, err
}

// decryptIngestToken reverses encryptIngestToken.
func decryptIngestToken(nonce, cipher string, protector *scansecrets.Protector) (string, error) {
	if nonce == "dev" {
		return cipher, nil
	}
	if protector == nil {
		return "", errors.New("encryption key required to decrypt token")
	}
	return protector.Decrypt(nonce, cipher)
}

func tokenPrefix(rawToken string) string {
	if len(rawToken) <= 8 {
		return rawToken
	}
	return rawToken[:8]
}
