package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"

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
	mu       sync.RWMutex
}

func NewSessionStore[T any]() *SessionStore[T] {
	return &SessionStore[T]{
		sessions: make(map[string]T),
		mu:       sync.RWMutex{},
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

	sID, err := genSessionID()
	if err != nil {
		return "", err
	}

	// FIXME: there could be collisions, but in purpose of example we don't care
	s.sessions[sID] = data

	return sID, nil
}

func (s *SessionStore[T]) Get(token string) (*T, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	val, ok := s.sessions[token]
	if !ok {
		return nil, false
	}
	return &val, true
}

func (s *SessionStore[T]) Consume(token string) (*T, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	val, ok := s.sessions[token]
	if !ok {
		return nil, false
	}
	delete(s.sessions, token)

	return &val, true
}

func (s *SessionStore[T]) Delete(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.sessions, token)
}
