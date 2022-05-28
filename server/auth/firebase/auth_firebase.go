// Package firebase is an authenticator by firebase access token.
package firebase

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	firebase "firebase.google.com/go"
	firebaseAuth "firebase.google.com/go/auth"

	"google.golang.org/api/option"

	"github.com/tinode/chat/server/auth"
	"github.com/tinode/chat/server/logs"
	"github.com/tinode/chat/server/store"
	"github.com/tinode/chat/server/store/types"
)

type authenticator struct {
	name            string
	projectId       string
	credentialsFile string
	firebaseApp     *firebase.App
	firebaseAuth    *firebaseAuth.Client
	ctx             context.Context
	addToTags       bool
}

// Init initializes the firebase authenticator.
func (a *authenticator) Init(jsonconf json.RawMessage, name string) error {
	if name == "" {
		return errors.New("auth_firebase: authenticator name cannot be blank")
	}

	if a.name != "" {
		return errors.New("auth_firebase: already initialized as " + a.name + "; " + name)
	}

	type configType struct {
		// CredentialsFilePath reveals the private key file used in firebase.
		CredentialsFilePath string `json:"credentials_file_path"`
		// AddToTags indicates that the user name should be used as a searchable tag.
		AddToTags bool `json:"add_to_tags"`
	}
	var config configType
	if err := json.Unmarshal(jsonconf, &config); err != nil {
		return errors.New("auth_firebase: failed to parse config: " + err.Error() + "(" + string(jsonconf) + ")")
	}

	opt := option.WithCredentialsFile(config.CredentialsFilePath)
	ctx := context.Background()
	app, err := firebase.NewApp(ctx, nil, opt)
	if err != nil {
		errString := fmt.Sprintf("auth_firebase: error initializing app: %v", err)
		return errors.New(errString)
	}
	client, err := app.Auth(ctx)
	if err != nil {
		errString := fmt.Sprintf("error getting Auth client: %v\n", err)
		return errors.New(errString)
	}

	a.name = name
	a.addToTags = config.AddToTags
	a.firebaseApp = app
	a.firebaseAuth = client
	a.ctx = ctx

	return nil
}

// IsInitialized returns true if the handler is initialized.
func (a *authenticator) IsInitialized() bool {
	return a.name != ""
}

// AddRecord is not supprted, will produce an error.
func (authenticator) AddRecord(rec *auth.Rec, secret []byte, remoteAddr string) (*auth.Rec, error) {
	return nil, types.ErrUnsupported
}

// UpdateRecord is not supported, will produce an error.
func (authenticator) UpdateRecord(rec *auth.Rec, secret []byte, remoteAddr string) (*auth.Rec, error) {
	return nil, types.ErrUnsupported
}

// Authenticate checks login and password.
func (a *authenticator) Authenticate(idToken []byte, remoteAddr string) (*auth.Rec, []byte, error) {
	token, err := a.firebaseAuth.VerifyIDToken(a.ctx, string(idToken))
	if err != nil {
		return nil, nil, types.ErrFailed
	}
	logs.Info.Printf("successful decrypt token: " + token.UID)

	// Check token expiration time.
	expires := time.Unix(int64(token.Expires), 0).UTC()
	if expires.Before(time.Now().Add(1 * time.Second)) {
		return nil, nil, types.ErrExpired
	}
	logs.Info.Printf("not Expired")

	newUid := store.Store.GetUid()
	logs.Info.Printf("new Uid: " + newUid.String())
	logs.Info.Printf("new Uid: " + newUid.String32())

	// Get UID from db
	uid, authLvl, _, _, err := store.Users.GetAuthUniqueRecord(a.name, token.UID)
	if err != nil {
		return nil, nil, err
	}

	logs.Info.Printf("Got uid success " + uid.String())

	return &auth.Rec{
		Uid:       uid,
		AuthLevel: authLvl,
		Lifetime:  auth.Duration(time.Until(expires)),
		Features:  0,
		State:     types.StateUndefined}, nil, nil
}

// AsTag is not supported, will produce an empty string.
func (authenticator) AsTag(token string) string {
	return ""
}

// IsUnique checks the uniqueness (if the secrets allows a new user to be created).
func (a *authenticator) IsUnique(idToken []byte, remoteAddr string) (bool, error) {
	token, err := a.firebaseAuth.VerifyIDToken(a.ctx, string(idToken))
	if err != nil {
		return false, err
	}

	// Check token expiration time.
	expires := time.Unix(int64(token.Expires), 0).UTC()
	if expires.Before(time.Now().Add(1 * time.Second)) {
		return false, types.ErrExpired
	}

	// Get UID from db
	uid, _, _, _, err := store.Users.GetAuthUniqueRecord(a.name, token.UID)
	if err != nil {
		return false, err
	}

	if uid.IsZero() {
		return true, nil
	}
	return false, nil
}

// GenSecret is not supported, generates an error.
func (authenticator) GenSecret(rec *auth.Rec) ([]byte, time.Time, error) {
	return nil, time.Time{}, types.ErrUnsupported
}

// DelRecords deletes saved authentication records of the given user.
func (a *authenticator) DelRecords(uid types.Uid) error {
	return store.Users.DelAuthRecords(uid, a.name)
}

// RestrictedTags returns tag namespaces (prefixes) restricted by this adapter.
func (a *authenticator) RestrictedTags() ([]string, error) {
	var prefix []string
	if a.addToTags {
		prefix = []string{a.name}
	}
	return prefix, nil
}

// GetResetParams returns authenticator parameters passed to password reset handler. Unsupported
func (a *authenticator) GetResetParams(uid types.Uid) (map[string]interface{}, error) {
	return nil, types.ErrUnsupported
}

const realName = "firebase"

// GetRealName returns the hardcoded name of the authenticator.
func (authenticator) GetRealName() string {
	return realName
}

func init() {
	store.RegisterAuthScheme(realName, &authenticator{})
}
