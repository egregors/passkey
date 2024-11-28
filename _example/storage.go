package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"

	"github.com/google/uuid"

	"github.com/egregors/passkey"
)

// -- User storage methods --

type UserStore struct {
	users map[string]passkey.User
	mu    sync.RWMutex
}

func NewUserStore() *UserStore {
	return &UserStore{
		users: make(map[string]passkey.User),
		mu:    sync.RWMutex{},
	}
}

func (s *UserStore) Update(user passkey.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.users[user.WebAuthnName()] = user

	return nil
}

func (s *UserStore) Get(userID []byte) (passkey.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// TODO: full scan, optimize eventually
	for _, u := range s.users {
		if bytes.Equal(u.WebAuthnID(), userID) {
			return u, nil
		}
	}

	return nil, fmt.Errorf("user not found")
}

func (s *UserStore) GetByName(username string) (passkey.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if u, ok := s.users[username]; ok {
		return u, nil
	}

	return nil, fmt.Errorf("user not found")
}

func (s *UserStore) Create(username string) (passkey.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

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

func (s *UserStore) GetOrCreateUser(userName string) passkey.User {
	s.mu.Lock()
	defer s.mu.Unlock()

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
		return "", nil
	}

	// FIXME: there could be collisions, but in prepuce of example we don't care
	s.sessions[sID] = data

	return sID, nil
}

func (s *SessionStore[T]) Get(token string) (*T, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if val, ok := s.sessions[token]; !ok {
		return nil, false
	} else {
		return &val, true
	}
}

func (s *SessionStore[T]) Delete(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.sessions, token)
}
