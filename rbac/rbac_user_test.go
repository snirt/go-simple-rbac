package rbac

import (
	"reflect"
	"testing"

	"github.com/snirt/simple-rbac/rbac/errors"
	"github.com/snirt/simple-rbac/rbac/models"
)

func TestCreateUser(t *testing.T) {
	r := &RBACImpl{
		Users: make(map[string]*models.User),
	}

	// Test case 1: Creating a new user
	user1 := &models.User{ID: "1", Name: "John Doe"}
	r.CreateUser(user1)
	if r.Users["1"] != user1 {
		t.Errorf("Expected user1 to be created, got: %v", r.Users["1"])
	}

	// Test case 2: Creating another user
	user2 := &models.User{ID: "2", Name: "Jane Smith"}
	r.CreateUser(user2)
	if r.Users["2"] != user2 {
		t.Errorf("Expected user2 to be created, got: %v", r.Users["2"])
	}
}

func TestRBACImpl_GetUser(t *testing.T) {
	rbac := &RBACImpl{
		Users: map[string]*models.User{
			"1": {
				ID:   "1",
				Name: "John Doe",
			},
		},
	}

	t.Run("ExistingUser", func(t *testing.T) {
		user, err := rbac.GetUser("1")
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		expectedUser := &models.User{
			ID:   "1",
			Name: "John Doe",
		}
		if !reflect.DeepEqual(user, expectedUser) {
			t.Errorf("expected user: %v, got: %v", expectedUser, user)
		}
	})

	t.Run("NonExistingUser", func(t *testing.T) {
		_, err := rbac.GetUser("2")
		if err == nil {
			t.Error("expected error, got nil")
		}

		_, ok := err.(*errors.ErrUserNotExists)
		if !ok {
			t.Errorf("expected error of type ErrUserNotExists, got: %T", err)
		}
	})
}

func TestModifyUserRole(t *testing.T) {
	var rbac RBAC = NewRBACModule()
	user1 := &models.User{
		ID: "user1",
	}
	rbac.CreateUser(user1)
	org1 := &models.Organization{
		ID: "org1",
	}
	rbac.CreateOrganization(org1)
	rbac.AddUserToOrganization(user1.ID, org1.ID)
	binding, err := models.NewRoleBinding(rbac.GetRoles(), user1.ID, org1, models.RoleAdmin)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	rbac.AddRoleBinding(binding)
	roleName := models.RoleAdmin

	t.Run("Valid user", func(t *testing.T) {
		err := rbac.ModifyUserRole(user1.ID, org1, roleName)
		if err != nil {
			t.Errorf("Expected no error, got: %v", err)
		}
	})

	errUserNotFound := errors.ErrUserNotExists{}
	errRoleNotExists := errors.ErrRoleNotExists{}
	t.Run("Invalid user", func(t *testing.T) {
		err := rbac.ModifyUserRole("invalidUser", org1, roleName)
		if err.Error() != errUserNotFound.Error() {
			t.Errorf("Expected ErrUserNotFound, got: %v", err)
		}
	})

	t.Run("Invalid role", func(t *testing.T) {
		err := rbac.ModifyUserRole(user1.ID, org1, "invalidRole")
		if err.Error() != errRoleNotExists.Error() {
			t.Errorf("Expected ErrRoleNotExists, got: %v", err)
		}
	})
}

func TestGetUsersPermissionsForResource(t *testing.T) {
	var rbacModule RBAC = NewRBACModule()

	org1 := &models.Organization{
		ID: "org1",
	}
	rbacModule.CreateOrganization(org1)
	// Test case 1: User does not exist
	_, err := rbacModule.GetUsersPermissionsForResource("nonexistent_user", org1)
	if err == nil {
		t.Error("Expected error, got nil")
	}

	// Test case 2: User exists but has no role binding
	user1 := &models.User{
		ID: "user1",
	}
	rbacModule.CreateUser(user1)
	_, err = rbacModule.GetUsersPermissionsForResource("user1", org1)
	if err == nil {
		t.Error("Expected error, got nil")
	}

	// Test case 3: User exists and has a role binding
	user2 := &models.User{
		ID: "user2",
	}
	rbacModule.CreateUser(user2)
	rbacModule.AddUserToOrganization(user1.ID, org1.ID)
	binding, err := models.NewRoleBinding(rbacModule.GetRoles(), user1.ID, org1, models.RoleAdmin)
	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}
	rbacModule.AddRoleBinding(binding)
	rbacModule.AddUserToOrganization(user2.ID, org1.ID)
	binding, err = models.NewRoleBinding(rbacModule.GetRoles(), user2.ID, org1, models.RoleMember)
	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}
	rbacModule.AddRoleBinding(binding)
	user1CanPerform, err := rbacModule.CanUserPerformAction(user1.ID, org1, models.PermissionOrgCreateProject)
	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}
	if !user1CanPerform {
		t.Error("Expected true, got false")
	}

	user2CanPerform, err := rbacModule.CanUserPerformAction(user2.ID, org1, models.PermissionOrgCreateProject)
	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}
	if user2CanPerform {
		t.Error("Expected false, got true")
	}
}
