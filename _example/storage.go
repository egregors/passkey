package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/egregors/passkey"
)

type Storage struct {
	users    map[string]passkey.User
	sessions map[string]webauthn.SessionData

	uMu, sMu sync.RWMutex
}

func NewStorage() *Storage {
	return &Storage{
		users:    make(map[string]passkey.User),
		sessions: make(map[string]webauthn.SessionData),
		uMu:      sync.RWMutex{},
		sMu:      sync.RWMutex{},
	}
}

// -- User storage methods --

func (s *Storage) Update(user passkey.User) error {
	s.uMu.Lock()
	defer s.uMu.Unlock()

	s.users[user.WebAuthnName()] = user

	return nil
}

func (s *Storage) Get(userID []byte) (passkey.User, error) {
	s.uMu.RLock()
	defer s.uMu.RUnlock()

	// TODO: full scan, optimize eventually
	for _, u := range s.users {
		if bytes.Equal(u.WebAuthnID(), userID) {
			return u, nil
		}
	}

	return nil, fmt.Errorf("user not found")
}

func (s *Storage) GetByName(username string) (passkey.User, error) {
	s.uMu.RLock()
	defer s.uMu.RUnlock()

	if u, ok := s.users[username]; ok {
		return u, nil
	}

	return nil, fmt.Errorf("user not found")
}

func (s *Storage) Create(username string) (passkey.User, error) {
	s.uMu.Lock()
	defer s.uMu.Unlock()

	if _, ok := s.users[username]; ok {
		return nil, fmt.Errorf("user %s already exists", username)
	}

	u := &User{
		ID:   []byte(uuid.NewString()),
		Name: username,
	}
	s.users[username] = u

	return u, nil
}

func (s *Storage) GetOrCreateUser(userName string) passkey.User {
	s.uMu.Lock()
	defer s.uMu.Unlock()

	if user, ok := s.users[userName]; ok {
		return user
	}

	u := User{
		ID:          []byte(userName),
		DisplayName: userName,
		Name:        userName,
	}

	s.users[userName] = &u

	return &u
}

// -- Session storage methods --

func (s *Storage) GenSessionID() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(b), nil
}

func (s *Storage) GetSession(token string) (*webauthn.SessionData, bool) {
	s.sMu.RLock()
	defer s.sMu.RUnlock()

	if val, ok := s.sessions[token]; !ok {
		return nil, false
	} else {
		return &val, true
	}
}

func (s *Storage) SaveSession(token string, data *webauthn.SessionData) {
	s.sMu.Lock()
	defer s.sMu.Unlock()

	s.sessions[token] = *data
}

func (s *Storage) DeleteSession(token string) {
	s.sMu.Lock()
	defer s.sMu.Unlock()

	delete(s.sessions, token)
}
