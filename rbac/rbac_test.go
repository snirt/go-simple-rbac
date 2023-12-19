package rbac

import (
	"testing"

	"github.com/snirt/simple-rbac/rbac/models"
)

func TestAddRemoveUserFromOrganizarion(t *testing.T) {
	// add user to organization
	// create module
	var rbacModule RBAC = NewRBACModule()

	// create admin user
	org1Admin := &models.User{
		ID: "org1Admin",
	}
	user1 := &models.User{
		ID: "user1",
	}
	rbacModule.CreateUser(org1Admin)
	rbacModule.CreateUser(user1)

	// create organization
	org1 := &models.Organization{
		ID: "org1",
	}
	rbacModule.CreateOrganization(org1)

	// add user to organization
	err := rbacModule.AddUserToOrganization(user1.ID, org1.ID)
	if err != nil {
		t.Error("Failed to add user to organization:", err)
	}

	// remove user from organization
	err = rbacModule.RemoveUserFromOrganization(user1.ID, org1.ID)
	if err != nil {
		t.Error("Failed to remove user from organization:", err)
	}

	_ = rbacModule
}
