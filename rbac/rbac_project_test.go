package rbac

import (
	"testing"

	"github.com/snirt/simple-rbac/rbac/models"
)

// test create project
func TestCreateProjInOrg(t *testing.T) {
	var rbacModule RBAC = NewRBACModule()

	org1 := &models.Organization{
		ID: "org1",
	}

	proj1 := &models.Project{
		ID: "proj1",
	}

	rbacModule.CreateOrganization(org1)
	rbacModule.CreateProjInOrg(proj1, org1.ID)

	orgProjs, err := rbacModule.ListOrgProjects(org1.ID)
	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	ok := orgProjs[proj1.ID]
	if !ok {
		t.Error("Expected true, got false")
	}
}

func TestDeleteProjFromOrg(t *testing.T) {
	var rbacModule RBAC = NewRBACModule()

	org1 := &models.Organization{
		ID: "org1",
	}

	proj1 := &models.Project{
		ID: "proj1",
	}

	rbacModule.CreateOrganization(org1)
	rbacModule.CreateProjInOrg(proj1, org1.ID)

	orgProjs, err := rbacModule.ListOrgProjects(org1.ID)
	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	ok := orgProjs[proj1.ID]
	if !ok {
		t.Error("Expected true, got false")
	}

	rbacModule.DeleteProjFromOrg(org1.ID, proj1.ID)
	orgProjs, err = rbacModule.ListOrgProjects(org1.ID)
	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	ok = orgProjs[proj1.ID]
	if ok {
		t.Error("Expected false, got true")
	}

}

func TestGetProject(t *testing.T) {
	var rbacModule RBAC = NewRBACModule()

	org1 := &models.Organization{
		ID: "org1",
	}

	proj1 := &models.Project{
		ID: "proj1",
	}

	proj2 := &models.Project{
		ID: "proj2",
	}

	rbacModule.CreateOrganization(org1)
	rbacModule.CreateProjInOrg(proj1, org1.ID)
	rbacModule.CreateProjInOrg(proj2, org1.ID)

	proj1FromGet, err := rbacModule.GetProject(proj1.ID)
	if err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	if proj1FromGet.ID != proj1.ID {
		t.Errorf("Expected %v, got %v", proj1.ID, proj1FromGet.ID)
	}

	if err := rbacModule.DeleteProjFromOrg(org1.ID, proj1.ID); err != nil {
		t.Errorf("Expected nil error, got %v", err)
	}

	_, err = rbacModule.GetProject(proj1.ID)
	if err == nil {
		t.Error("Expected error, got nil")
	}
}
