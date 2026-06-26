package db

import (
	"context"
	"errors"
	"strings"
	"time"

	"karaxys_backend/internal/core"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// ErrOAuthEmailUnverified is returned when an OAuth login would link to an
// existing local account but the provider has not verified the email, which
// would otherwise enable account takeover.
var ErrOAuthEmailUnverified = errors.New("oauth email is not verified")

// OAuthProfile is the normalized identity a provider returns after exchange.
type OAuthProfile struct {
	Provider       string
	ProviderUserID string
	Email          string
	EmailVerified  bool
	Name           string
}

// oauthAction is the decision for how to resolve an OAuth profile to a user.
type oauthAction int

const (
	oauthActionUseIdentity oauthAction = iota // identity already exists -> log that user in
	oauthActionLinkByEmail                    // link new identity to an existing local user
	oauthActionCreateNew                      // provision a new account + user
)

// decideOAuthAction applies the linking policy. Linking a provider identity to
// an existing local user is refused unless the provider verified the email,
// which prevents account takeover via an attacker-controlled unverified email.
func decideOAuthAction(identityExists, userByEmailExists, emailVerified bool) (oauthAction, error) {
	switch {
	case identityExists:
		return oauthActionUseIdentity, nil
	case userByEmailExists && emailVerified:
		return oauthActionLinkByEmail, nil
	case userByEmailExists && !emailVerified:
		return 0, ErrOAuthEmailUnverified
	default:
		return oauthActionCreateNew, nil
	}
}

// ResolveOAuthLogin finds or provisions the user for an OAuth profile, applying
// the linking policy in decideOAuthAction.
func (db *DB) ResolveOAuthLogin(profile OAuthProfile) (core.Account, core.User, error) {
	if strings.TrimSpace(profile.Provider) == "" || strings.TrimSpace(profile.ProviderUserID) == "" {
		return core.Account{}, core.User{}, errors.New("provider and provider user id are required")
	}
	email := normalizeEmail(profile.Email)

	identity, identityErr := db.findOAuthIdentity(profile.Provider, profile.ProviderUserID)
	if identityErr != nil && !errors.Is(identityErr, mongo.ErrNoDocuments) {
		return core.Account{}, core.User{}, identityErr
	}
	identityExists := identityErr == nil

	var emailUser core.User
	userByEmailExists := false
	if email != "" && !identityExists {
		user, err := db.FindUserByEmail(email)
		if err == nil && !user.ID.IsZero() {
			emailUser = user
			userByEmailExists = true
		} else if err != nil && !errors.Is(err, mongo.ErrNoDocuments) {
			return core.Account{}, core.User{}, err
		}
	}

	action, err := decideOAuthAction(identityExists, userByEmailExists, profile.EmailVerified)
	if err != nil {
		return core.Account{}, core.User{}, err
	}

	switch action {
	case oauthActionUseIdentity:
		user, err := db.findUserByID(identity.UserID)
		if err != nil {
			return core.Account{}, core.User{}, err
		}
		account, err := db.GetAccount(user.AccountID)
		if err != nil {
			return core.Account{}, core.User{}, err
		}
		return account, user, nil
	case oauthActionLinkByEmail:
		if err := db.linkOAuthIdentity(emailUser, profile); err != nil {
			return core.Account{}, core.User{}, err
		}
		account, err := db.GetAccount(emailUser.AccountID)
		if err != nil {
			return core.Account{}, core.User{}, err
		}
		return account, emailUser, nil
	default:
		return db.createAccountWithOAuthUser(profile)
	}
}

func (db *DB) findOAuthIdentity(provider string, providerUserID string) (core.OAuthIdentity, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var identity core.OAuthIdentity
	err := db.OAuthIdentities.FindOne(ctx, bson.M{
		"provider":         provider,
		"provider_user_id": providerUserID,
	}).Decode(&identity)
	return identity, err
}

func (db *DB) findUserByID(id primitive.ObjectID) (core.User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var user core.User
	err := db.Users.FindOne(ctx, bson.M{"_id": id}).Decode(&user)
	return user, err
}

func (db *DB) linkOAuthIdentity(user core.User, profile OAuthProfile) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now := time.Now().UTC()
	identity := core.OAuthIdentity{
		ID:             primitive.NewObjectID(),
		UserID:         user.ID,
		AccountID:      user.AccountID,
		Provider:       profile.Provider,
		ProviderUserID: profile.ProviderUserID,
		Email:          normalizeEmail(profile.Email),
		EmailVerified:  profile.EmailVerified,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if _, err := db.OAuthIdentities.InsertOne(ctx, identity); err != nil {
		if mongo.IsDuplicateKeyError(err) {
			// Identity was created concurrently; treat as linked.
			return nil
		}
		return err
	}
	return nil
}

func (db *DB) createAccountWithOAuthUser(profile OAuthProfile) (core.Account, core.User, error) {
	email := normalizeEmail(profile.Email)
	now := time.Now().UTC()

	accountName := defaultAccountName(email)
	if email == "" {
		accountName = "Karaxys organization"
	}
	account := core.Account{
		ID:        primitive.NewObjectID(),
		Name:      accountName,
		Slug:      uniqueSlug(accountName),
		CreatedAt: now,
		UpdatedAt: now,
	}
	user := core.User{
		ID:          primitive.NewObjectID(),
		Email:       email,
		Name:        strings.TrimSpace(profile.Name),
		AccountID:   account.ID,
		Role:        core.UserRoleAdmin,
		CreatedAt:   now,
		UpdatedAt:   now,
		LastLoginAt: now,
	}
	account.CreatedBy = user.ID

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if email != "" {
		if existing, err := db.FindUserByEmail(email); err == nil && !existing.ID.IsZero() {
			return core.Account{}, core.User{}, ErrDuplicateUser
		} else if err != nil && !errors.Is(err, mongo.ErrNoDocuments) {
			return core.Account{}, core.User{}, err
		}
	}

	if _, err := db.Accounts.InsertOne(ctx, account); err != nil {
		return core.Account{}, core.User{}, err
	}
	if _, err := db.Users.InsertOne(ctx, user); err != nil {
		_, _ = db.Accounts.DeleteOne(ctx, bson.M{"_id": account.ID})
		if mongo.IsDuplicateKeyError(err) {
			return core.Account{}, core.User{}, ErrDuplicateUser
		}
		return core.Account{}, core.User{}, err
	}
	if err := db.linkOAuthIdentity(user, profile); err != nil {
		_, _ = db.Users.DeleteOne(ctx, bson.M{"_id": user.ID})
		_, _ = db.Accounts.DeleteOne(ctx, bson.M{"_id": account.ID})
		return core.Account{}, core.User{}, err
	}
	return account, user, nil
}
