package rbac

import (
	"testing"

	"github.com/snirt/simple-rbac/rbac/models"
)

func TestOrganizationCRUD(t *testing.T) {
	var rbacModule RBAC = NewRBACModule()

	org1 := &models.Organization{
		ID: "org1",
	}

	user1 := &models.User{
		ID: "user1",
	}

	user2 := &models.User{
		ID: "user2",
	}

	rbacModule.CreateOrganization(org1)
	rbacModule.CreateUser(user1)
	rbacModule.CreateUser(user2)

	rbacModule.AddUserToOrganization(user1.ID, org1.ID)
	rbacModule.AddUserToOrganization(user2.ID, org1.ID)

	org1Get, err := rbacModule.GetOrganization(org1.ID)
	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	if org1Get.ID != org1.ID {
		t.Errorf("Expected %s, got %s", org1.ID, org1Get.ID)
	}

	orgUsersSet, err := rbacModule.ListOrgUsers(org1.ID)
	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	if len(orgUsersSet) != 2 {
		t.Errorf("Expected %d, got %d", 2, len(orgUsersSet))
	}

	err = rbacModule.RemoveUserFromOrganization(user2.ID, org1.ID)
	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	orgUsersSet, err = rbacModule.ListOrgUsers(org1.ID)
	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	if len(orgUsersSet) != 1 {
		t.Errorf("Expected %d, got %d", 1, len(orgUsersSet))
	}

}

func TestAuthorizedUserChangeOrganization(t *testing.T) {
	var rbacModule RBAC = NewRBACModule()

	org1 := &models.Organization{
		ID: "org1",
	}

	user1 := &models.User{
		ID: "user1",
	}

	rbacModule.CreateOrganization(org1)
	rbacModule.CreateUser(user1)

	rbacModule.AddUserToOrganization(user1.ID, org1.ID)

	// user with no permissions in org1
	ok, err := rbacModule.CanUserPerformAction(user1.ID, org1, models.PermissionOrgCreateProject)
	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	if ok {
		t.Error("Expected false, got true")
	}

	// chagning user permissions in org1 to admin
	binding, err := models.NewRoleBinding(rbacModule.GetRoles(), user1.ID, org1, models.RoleAdmin)
	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	rbacModule.AddRoleBinding(binding)

	// user with admin permissions in org1
	ok, err = rbacModule.CanUserPerformAction(user1.ID, org1, models.PermissionOrgCreateProject)
	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	if !ok {
		t.Error("Expected true, got false")
	}

}
