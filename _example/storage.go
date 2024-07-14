package main

import (
	"crypto/rand"
	"encoding/base64"
	"sync"

	"github.com/egregors/passkey"
	"github.com/go-webauthn/webauthn/webauthn"
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

func (s *Storage) SaveUser(user passkey.User) {
	s.uMu.Lock()
	defer s.uMu.Unlock()

	s.users[user.WebAuthnName()] = user
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
