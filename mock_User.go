// Code generated by mockery v2.47.0. DO NOT EDIT.

package passkey

import (
	webauthn "github.com/go-webauthn/webauthn/webauthn"
	mock "github.com/stretchr/testify/mock"
)

// MockUser is an autogenerated mock type for the User type
type MockUser struct {
	mock.Mock
}

type MockUser_Expecter struct {
	mock *mock.Mock
}

func (_m *MockUser) EXPECT() *MockUser_Expecter {
	return &MockUser_Expecter{mock: &_m.Mock}
}

// PutCredential provides a mock function with given fields: _a0
func (_m *MockUser) PutCredential(_a0 webauthn.Credential) {
	_m.Called(_a0)
}

// MockUser_PutCredential_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'PutCredential'
type MockUser_PutCredential_Call struct {
	*mock.Call
}

// PutCredential is a helper method to define mock.On call
//   - _a0 webauthn.Credential
func (_e *MockUser_Expecter) PutCredential(_a0 interface{}) *MockUser_PutCredential_Call {
	return &MockUser_PutCredential_Call{Call: _e.mock.On("PutCredential", _a0)}
}

func (_c *MockUser_PutCredential_Call) Run(run func(_a0 webauthn.Credential)) *MockUser_PutCredential_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(webauthn.Credential))
	})
	return _c
}

func (_c *MockUser_PutCredential_Call) Return() *MockUser_PutCredential_Call {
	_c.Call.Return()
	return _c
}

func (_c *MockUser_PutCredential_Call) RunAndReturn(run func(webauthn.Credential)) *MockUser_PutCredential_Call {
	_c.Call.Return(run)
	return _c
}

// WebAuthnCredentials provides a mock function with given fields:
func (_m *MockUser) WebAuthnCredentials() []webauthn.Credential {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for WebAuthnCredentials")
	}

	var r0 []webauthn.Credential
	if rf, ok := ret.Get(0).(func() []webauthn.Credential); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]webauthn.Credential)
		}
	}

	return r0
}

// MockUser_WebAuthnCredentials_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'WebAuthnCredentials'
type MockUser_WebAuthnCredentials_Call struct {
	*mock.Call
}

// WebAuthnCredentials is a helper method to define mock.On call
func (_e *MockUser_Expecter) WebAuthnCredentials() *MockUser_WebAuthnCredentials_Call {
	return &MockUser_WebAuthnCredentials_Call{Call: _e.mock.On("WebAuthnCredentials")}
}

func (_c *MockUser_WebAuthnCredentials_Call) Run(run func()) *MockUser_WebAuthnCredentials_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockUser_WebAuthnCredentials_Call) Return(_a0 []webauthn.Credential) *MockUser_WebAuthnCredentials_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockUser_WebAuthnCredentials_Call) RunAndReturn(run func() []webauthn.Credential) *MockUser_WebAuthnCredentials_Call {
	_c.Call.Return(run)
	return _c
}

// WebAuthnDisplayName provides a mock function with given fields:
func (_m *MockUser) WebAuthnDisplayName() string {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for WebAuthnDisplayName")
	}

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// MockUser_WebAuthnDisplayName_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'WebAuthnDisplayName'
type MockUser_WebAuthnDisplayName_Call struct {
	*mock.Call
}

// WebAuthnDisplayName is a helper method to define mock.On call
func (_e *MockUser_Expecter) WebAuthnDisplayName() *MockUser_WebAuthnDisplayName_Call {
	return &MockUser_WebAuthnDisplayName_Call{Call: _e.mock.On("WebAuthnDisplayName")}
}

func (_c *MockUser_WebAuthnDisplayName_Call) Run(run func()) *MockUser_WebAuthnDisplayName_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockUser_WebAuthnDisplayName_Call) Return(_a0 string) *MockUser_WebAuthnDisplayName_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockUser_WebAuthnDisplayName_Call) RunAndReturn(run func() string) *MockUser_WebAuthnDisplayName_Call {
	_c.Call.Return(run)
	return _c
}

// WebAuthnID provides a mock function with given fields:
func (_m *MockUser) WebAuthnID() []byte {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for WebAuthnID")
	}

	var r0 []byte
	if rf, ok := ret.Get(0).(func() []byte); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]byte)
		}
	}

	return r0
}

// MockUser_WebAuthnID_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'WebAuthnID'
type MockUser_WebAuthnID_Call struct {
	*mock.Call
}

// WebAuthnID is a helper method to define mock.On call
func (_e *MockUser_Expecter) WebAuthnID() *MockUser_WebAuthnID_Call {
	return &MockUser_WebAuthnID_Call{Call: _e.mock.On("WebAuthnID")}
}

func (_c *MockUser_WebAuthnID_Call) Run(run func()) *MockUser_WebAuthnID_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockUser_WebAuthnID_Call) Return(_a0 []byte) *MockUser_WebAuthnID_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockUser_WebAuthnID_Call) RunAndReturn(run func() []byte) *MockUser_WebAuthnID_Call {
	_c.Call.Return(run)
	return _c
}

// WebAuthnName provides a mock function with given fields:
func (_m *MockUser) WebAuthnName() string {
	ret := _m.Called()

	if len(ret) == 0 {
		panic("no return value specified for WebAuthnName")
	}

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// MockUser_WebAuthnName_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'WebAuthnName'
type MockUser_WebAuthnName_Call struct {
	*mock.Call
}

// WebAuthnName is a helper method to define mock.On call
func (_e *MockUser_Expecter) WebAuthnName() *MockUser_WebAuthnName_Call {
	return &MockUser_WebAuthnName_Call{Call: _e.mock.On("WebAuthnName")}
}

func (_c *MockUser_WebAuthnName_Call) Run(run func()) *MockUser_WebAuthnName_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run()
	})
	return _c
}

func (_c *MockUser_WebAuthnName_Call) Return(_a0 string) *MockUser_WebAuthnName_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockUser_WebAuthnName_Call) RunAndReturn(run func() string) *MockUser_WebAuthnName_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockUser creates a new instance of MockUser. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockUser(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockUser {
	mock := &MockUser{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
