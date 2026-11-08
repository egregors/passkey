package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/egregors/passkey"
)

// -- User storage methods --

type UserStore struct {
	users map[string]*User
	mu    sync.RWMutex
}

func NewUserStore() *UserStore {
	return &UserStore{
		users: make(map[string]*User),
		mu:    sync.RWMutex{},
	}
}

func (s *UserStore) UpdateCredential(userID []byte, credential webauthn.Credential) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, user := range s.users {
		if !bytes.Equal(user.ID, userID) {
			continue
		}
		for i := range user.creds {
			stored := &user.creds[i]
			if bytes.Equal(stored.ID, credential.ID) {
				stored.Authenticator.CloneWarning = stored.Authenticator.CloneWarning || credential.Authenticator.CloneWarning
				if credential.Authenticator.SignCount >= stored.Authenticator.SignCount {
					stored.Authenticator.SignCount = credential.Authenticator.SignCount
					stored.Flags = credential.Flags
				}
				return nil
			}
		}
		return passkey.ErrCredentialNotFound
	}
	return passkey.ErrUserNotFound
}

func (s *UserStore) Get(userID []byte) (passkey.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, u := range s.users {
		if bytes.Equal(u.WebAuthnID(), userID) {
			return u.snapshot(), nil
		}
	}

	return nil, passkey.ErrUserNotFound
}

func (s *UserStore) GetByName(username string) (passkey.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if u, ok := s.users[username]; ok {
		return u.snapshot(), nil
	}

	return nil, passkey.ErrUserNotFound
}

func (s *UserStore) Create(user passkey.NewUser) (passkey.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.users[user.Username]; ok {
		return nil, fmt.Errorf("%w: user %s already exists", passkey.ErrUserAlreadyExists, user.Username)
	}
	for _, existing := range s.users {
		if bytes.Equal(existing.ID, user.UserID) {
			return nil, passkey.ErrUserAlreadyExists
		}
	}

	u := &User{
		ID:    user.UserID,
		Name:  user.Username,
		creds: []webauthn.Credential{user.Credential},
	}
	s.users[user.Username] = u.snapshot()
	return u, nil
}

// -- Session storage methods --

type SessionStore[T any] struct {
	sessions map[string]T
	mu       sync.Mutex
}

const sessionStoreCapacity = 1024

func NewSessionStore[T any]() *SessionStore[T] {
	return &SessionStore[T]{
		sessions: make(map[string]T),
	}
}

func genSessionID() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(b), nil
}

func (s *SessionStore[T]) Create(data T) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for token, session := range s.sessions {
		if !now.Before(sessionExpiration(session)) {
			delete(s.sessions, token)
		}
	}
	if !now.Before(sessionExpiration(data)) {
		return "", fmt.Errorf("session has expired")
	}
	if len(s.sessions) >= sessionStoreCapacity {
		return "", passkey.ErrSessionStoreFull
	}
	for {
		token, err := genSessionID()
		if err != nil {
			return "", err
		}
		if _, exists := s.sessions[token]; !exists {
			s.sessions[token] = data
			return token, nil
		}
	}
}

func (s *SessionStore[T]) Get(token string) (*T, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	val, ok := s.sessions[token]
	if !ok || !time.Now().Before(sessionExpiration(val)) {
		delete(s.sessions, token)
		return nil, false
	}
	return &val, true
}

func (s *SessionStore[T]) Consume(token string) (*T, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	val, ok := s.sessions[token]
	delete(s.sessions, token)
	if !ok || !time.Now().Before(sessionExpiration(val)) {
		return nil, false
	}
	return &val, true
}

func (s *SessionStore[T]) Delete(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.sessions, token)
}

func sessionExpiration(data any) time.Time {
	switch v := data.(type) {
	case webauthn.SessionData:
		return v.Expires
	case passkey.RegistrationSessionData:
		return v.Expires
	case passkey.UserSessionData:
		return v.Expires
	default:
		return time.Time{}
	}
}
