// Code generated by mockery v2.47.0. DO NOT EDIT.

package passkey

import mock "github.com/stretchr/testify/mock"

// MockUserStore is an autogenerated mock type for the UserStore type
type MockUserStore struct {
	mock.Mock
}

type MockUserStore_Expecter struct {
	mock *mock.Mock
}

func (_m *MockUserStore) EXPECT() *MockUserStore_Expecter {
	return &MockUserStore_Expecter{mock: &_m.Mock}
}

// Create provides a mock function with given fields: username
func (_m *MockUserStore) Create(username string) (User, error) {
	ret := _m.Called(username)

	if len(ret) == 0 {
		panic("no return value specified for Create")
	}

	var r0 User
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (User, error)); ok {
		return rf(username)
	}
	if rf, ok := ret.Get(0).(func(string) User); ok {
		r0 = rf(username)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(User)
		}
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(username)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockUserStore_Create_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Create'
type MockUserStore_Create_Call struct {
	*mock.Call
}

// Create is a helper method to define mock.On call
//   - username string
func (_e *MockUserStore_Expecter) Create(username interface{}) *MockUserStore_Create_Call {
	return &MockUserStore_Create_Call{Call: _e.mock.On("Create", username)}
}

func (_c *MockUserStore_Create_Call) Run(run func(username string)) *MockUserStore_Create_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *MockUserStore_Create_Call) Return(_a0 User, _a1 error) *MockUserStore_Create_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockUserStore_Create_Call) RunAndReturn(run func(string) (User, error)) *MockUserStore_Create_Call {
	_c.Call.Return(run)
	return _c
}

// Get provides a mock function with given fields: userID
func (_m *MockUserStore) Get(userID []byte) (User, error) {
	ret := _m.Called(userID)

	if len(ret) == 0 {
		panic("no return value specified for Get")
	}

	var r0 User
	var r1 error
	if rf, ok := ret.Get(0).(func([]byte) (User, error)); ok {
		return rf(userID)
	}
	if rf, ok := ret.Get(0).(func([]byte) User); ok {
		r0 = rf(userID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(User)
		}
	}

	if rf, ok := ret.Get(1).(func([]byte) error); ok {
		r1 = rf(userID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockUserStore_Get_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Get'
type MockUserStore_Get_Call struct {
	*mock.Call
}

// Get is a helper method to define mock.On call
//   - userID []byte
func (_e *MockUserStore_Expecter) Get(userID interface{}) *MockUserStore_Get_Call {
	return &MockUserStore_Get_Call{Call: _e.mock.On("Get", userID)}
}

func (_c *MockUserStore_Get_Call) Run(run func(userID []byte)) *MockUserStore_Get_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].([]byte))
	})
	return _c
}

func (_c *MockUserStore_Get_Call) Return(_a0 User, _a1 error) *MockUserStore_Get_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockUserStore_Get_Call) RunAndReturn(run func([]byte) (User, error)) *MockUserStore_Get_Call {
	_c.Call.Return(run)
	return _c
}

// GetByName provides a mock function with given fields: username
func (_m *MockUserStore) GetByName(username string) (User, error) {
	ret := _m.Called(username)

	if len(ret) == 0 {
		panic("no return value specified for GetByName")
	}

	var r0 User
	var r1 error
	if rf, ok := ret.Get(0).(func(string) (User, error)); ok {
		return rf(username)
	}
	if rf, ok := ret.Get(0).(func(string) User); ok {
		r0 = rf(username)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(User)
		}
	}

	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(username)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// MockUserStore_GetByName_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'GetByName'
type MockUserStore_GetByName_Call struct {
	*mock.Call
}

// GetByName is a helper method to define mock.On call
//   - username string
func (_e *MockUserStore_Expecter) GetByName(username interface{}) *MockUserStore_GetByName_Call {
	return &MockUserStore_GetByName_Call{Call: _e.mock.On("GetByName", username)}
}

func (_c *MockUserStore_GetByName_Call) Run(run func(username string)) *MockUserStore_GetByName_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(string))
	})
	return _c
}

func (_c *MockUserStore_GetByName_Call) Return(_a0 User, _a1 error) *MockUserStore_GetByName_Call {
	_c.Call.Return(_a0, _a1)
	return _c
}

func (_c *MockUserStore_GetByName_Call) RunAndReturn(run func(string) (User, error)) *MockUserStore_GetByName_Call {
	_c.Call.Return(run)
	return _c
}

// Update provides a mock function with given fields: _a0
func (_m *MockUserStore) Update(_a0 User) error {
	ret := _m.Called(_a0)

	if len(ret) == 0 {
		panic("no return value specified for Update")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(User) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// MockUserStore_Update_Call is a *mock.Call that shadows Run/Return methods with type explicit version for method 'Update'
type MockUserStore_Update_Call struct {
	*mock.Call
}

// Update is a helper method to define mock.On call
//   - _a0 User
func (_e *MockUserStore_Expecter) Update(_a0 interface{}) *MockUserStore_Update_Call {
	return &MockUserStore_Update_Call{Call: _e.mock.On("Update", _a0)}
}

func (_c *MockUserStore_Update_Call) Run(run func(_a0 User)) *MockUserStore_Update_Call {
	_c.Call.Run(func(args mock.Arguments) {
		run(args[0].(User))
	})
	return _c
}

func (_c *MockUserStore_Update_Call) Return(_a0 error) *MockUserStore_Update_Call {
	_c.Call.Return(_a0)
	return _c
}

func (_c *MockUserStore_Update_Call) RunAndReturn(run func(User) error) *MockUserStore_Update_Call {
	_c.Call.Return(run)
	return _c
}

// NewMockUserStore creates a new instance of MockUserStore. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewMockUserStore(t interface {
	mock.TestingT
	Cleanup(func())
}) *MockUserStore {
	mock := &MockUserStore{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
