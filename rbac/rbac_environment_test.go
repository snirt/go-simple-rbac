package rbac

import (
	"testing"

	"github.com/snirt/simple-rbac/rbac/models"
)

func TestNewEnvInProj(t *testing.T) {
	var rbacModule RBAC = NewRBACModule()

	org1 := &models.Organization{
		ID: "org1",
	}

	proj1 := &models.Project{
		ID: "proj1",
	}

	env1 := &models.Environment{
		ID: "env1",
	}

	env2 := &models.Environment{
		ID: "env2",
	}

	rbacModule.CreateOrganization(org1)
	rbacModule.CreateProjInOrg(proj1, org1.ID)
	rbacModule.CreateEnvInProj(env1, proj1.ID)
	rbacModule.CreateEnvInProj(env2, proj1.ID)

	env1_get, err := rbacModule.GetEnvironment(env1.ID)
	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	if env1_get.ID != env1.ID {
		t.Errorf("Expected %s, got %s", env1.ID, env1_get.ID)
	}

}
