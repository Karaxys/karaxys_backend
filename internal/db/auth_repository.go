package db

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"karaxys_backend/internal/core"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var (
	ErrDuplicateUser  = errors.New("user already exists")
	ErrSessionInvalid = errors.New("session invalid")
)

type SessionIdentity struct {
	Session core.Session
	User    core.User
	Account core.Account
}

func (db *DB) CreateAccountWithAdminUser(email string, name string, accountName string, passwordHash string) (core.Account, core.User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	email = normalizeEmail(email)
	if email == "" {
		return core.Account{}, core.User{}, errors.New("email is required")
	}
	accountName = strings.TrimSpace(accountName)
	if accountName == "" {
		accountName = defaultAccountName(email)
	}
	now := time.Now().UTC()

	if existing, err := db.FindUserByEmail(email); err == nil && !existing.ID.IsZero() {
		return core.Account{}, core.User{}, ErrDuplicateUser
	} else if err != nil && !errors.Is(err, mongo.ErrNoDocuments) {
		return core.Account{}, core.User{}, err
	}

	account := core.Account{
		ID:        primitive.NewObjectID(),
		Name:      accountName,
		Slug:      uniqueSlug(accountName),
		CreatedAt: now,
		UpdatedAt: now,
	}
	user := core.User{
		ID:           primitive.NewObjectID(),
		Email:        email,
		Name:         strings.TrimSpace(name),
		PasswordHash: passwordHash,
		AccountID:    account.ID,
		Role:         core.UserRoleAdmin,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	account.CreatedBy = user.ID

	if _, err := db.Accounts.InsertOne(ctx, account); err != nil {
		return core.Account{}, core.User{}, err
	}
	if _, err := db.Users.InsertOne(ctx, user); err != nil {
		if mongo.IsDuplicateKeyError(err) {
			_, _ = db.Accounts.DeleteOne(ctx, bson.M{"_id": account.ID})
			return core.Account{}, core.User{}, ErrDuplicateUser
		}
		_, _ = db.Accounts.DeleteOne(ctx, bson.M{"_id": account.ID})
		return core.Account{}, core.User{}, err
	}
	return account, user, nil
}

func (db *DB) FindUserByEmail(email string) (core.User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var user core.User
	err := db.Users.FindOne(ctx, bson.M{"email": normalizeEmail(email)}).Decode(&user)
	return user, err
}

func (db *DB) GetAccount(id primitive.ObjectID) (core.Account, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var account core.Account
	err := db.Accounts.FindOne(ctx, bson.M{"_id": id}).Decode(&account)
	return account, err
}

func (db *DB) MarkUserLogin(userID primitive.ObjectID) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now := time.Now().UTC()
	_, err := db.Users.UpdateByID(ctx, userID, bson.M{"$set": bson.M{
		"last_login_at": now,
		"updated_at":    now,
	}})
	return err
}

func (db *DB) CreateSession(session core.Session) (core.Session, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now := time.Now().UTC()
	if session.ID.IsZero() {
		session.ID = primitive.NewObjectID()
	}
	if session.CreatedAt.IsZero() {
		session.CreatedAt = now
	}
	session.UpdatedAt = now
	if _, err := db.Sessions.InsertOne(ctx, session); err != nil {
		return core.Session{}, err
	}
	return session, nil
}

func (db *DB) FindSessionByAccessTokenHash(tokenHash string) (*SessionIdentity, error) {
	return db.findSessionIdentity(bson.M{
		"access_token_hash": tokenHash,
		"access_expires_at": bson.M{"$gt": time.Now().UTC()},
		"revoked_at":        zeroOrMissingTimeFilter(),
	})
}

func (db *DB) FindSessionByRefreshTokenHash(tokenHash string) (*SessionIdentity, error) {
	return db.findSessionIdentity(bson.M{
		"refresh_token_hash": tokenHash,
		"refresh_expires_at": bson.M{"$gt": time.Now().UTC()},
		"revoked_at":         zeroOrMissingTimeFilter(),
	})
}

func (db *DB) RotateSessionTokens(sessionID primitive.ObjectID, accessHash string, refreshHash string, accessExpiresAt time.Time, refreshExpiresAt time.Time) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now := time.Now().UTC()
	res, err := db.Sessions.UpdateOne(ctx, bson.M{
		"_id":        sessionID,
		"revoked_at": zeroOrMissingTimeFilter(),
	}, bson.M{"$set": bson.M{
		"access_token_hash":  accessHash,
		"refresh_token_hash": refreshHash,
		"access_expires_at":  accessExpiresAt,
		"refresh_expires_at": refreshExpiresAt,
		"updated_at":         now,
	}})
	if err != nil {
		return err
	}
	if res.MatchedCount == 0 {
		return ErrSessionInvalid
	}
	return nil
}

func (db *DB) RevokeSessionByRefreshTokenHash(refreshHash string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now := time.Now().UTC()
	res, err := db.Sessions.UpdateOne(ctx, bson.M{
		"refresh_token_hash": refreshHash,
		"revoked_at":         zeroOrMissingTimeFilter(),
	}, bson.M{"$set": bson.M{
		"revoked_at": now,
		"updated_at": now,
	}})
	if err != nil {
		return err
	}
	if res.MatchedCount == 0 {
		return ErrSessionInvalid
	}
	return nil
}

func (db *DB) findSessionIdentity(filter bson.M) (*SessionIdentity, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var session core.Session
	if err := db.Sessions.FindOne(ctx, filter).Decode(&session); err != nil {
		return nil, err
	}
	var user core.User
	if err := db.Users.FindOne(ctx, bson.M{"_id": session.UserID}).Decode(&user); err != nil {
		return nil, err
	}
	var account core.Account
	if err := db.Accounts.FindOne(ctx, bson.M{"_id": session.AccountID}).Decode(&account); err != nil {
		return nil, err
	}
	return &SessionIdentity{Session: session, User: user, Account: account}, nil
}

func (db *DB) CountInventoryForAccount(accountID primitive.ObjectID) (int64, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	filter := bson.M{}
	if !accountID.IsZero() {
		filter = bson.M{"$or": []bson.M{
			{"tenant_id": accountID.Hex()},
			{"tenant_id": bson.M{"$exists": false}},
			{"tenant_id": ""},
		}}
	}
	return db.Client.Database(db.Name).Collection("api_inventory").CountDocuments(ctx, filter)
}

func zeroOrMissingTimeFilter() bson.M {
	return bson.M{"$in": []interface{}{time.Time{}, nil}}
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func defaultAccountName(email string) string {
	email = normalizeEmail(email)
	if idx := strings.Index(email, "@"); idx > 0 {
		return email[:idx] + "'s organization"
	}
	return "Karaxys organization"
}

func uniqueSlug(accountName string) string {
	base := slugify(accountName)
	if base == "" {
		base = "karaxys"
	}
	return fmt.Sprintf("%s-%s", base, primitive.NewObjectID().Hex()[18:])
}

var nonSlugChars = regexp.MustCompile(`[^a-z0-9]+`)

func slugify(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = nonSlugChars.ReplaceAllString(value, "-")
	value = strings.Trim(value, "-")
	if len(value) > 48 {
		value = strings.Trim(value[:48], "-")
	}
	return value
}

func (db *DB) PruneExpiredSessions() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := db.Sessions.DeleteMany(ctx, bson.M{"refresh_expires_at": bson.M{"$lte": time.Now().UTC()}})
	return err
}

func (db *DB) RevokeOldUserSessions(userID primitive.ObjectID, keep int64) error {
	if keep <= 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	opts := options.Find().
		SetSort(bson.D{{Key: "created_at", Value: -1}}).
		SetSkip(keep).
		SetProjection(bson.M{"_id": 1})
	cursor, err := db.Sessions.Find(ctx, bson.M{
		"user_id":    userID,
		"revoked_at": zeroOrMissingTimeFilter(),
	}, opts)
	if err != nil {
		return err
	}
	defer cursor.Close(ctx)
	var ids []primitive.ObjectID
	for cursor.Next(ctx) {
		var item struct {
			ID primitive.ObjectID `bson:"_id"`
		}
		if err := cursor.Decode(&item); err != nil {
			return err
		}
		ids = append(ids, item.ID)
	}
	if err := cursor.Err(); err != nil {
		return err
	}
	if len(ids) == 0 {
		return nil
	}
	now := time.Now().UTC()
	_, err = db.Sessions.UpdateMany(ctx, bson.M{"_id": bson.M{"$in": ids}}, bson.M{"$set": bson.M{
		"revoked_at": now,
		"updated_at": now,
	}})
	return err
}
