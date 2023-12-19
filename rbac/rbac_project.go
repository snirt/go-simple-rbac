package rbac

import (
	"github.com/snirt/simple-rbac/rbac/errors"
	"github.com/snirt/simple-rbac/rbac/internal"
	"github.com/snirt/simple-rbac/rbac/models"
)

func (r *RBACImpl) CreateProjInOrg(project *models.Project, orgID string) error {
	if err := r.validateOrganization(orgID); err != nil {
		return err
	}
	r.Projects[project.ID] = project
	internal.LinkResources(r.orgToProjs, orgID, project.ID)
	return nil
}

func (r *RBACImpl) GetProject(projID string) (*models.Project, error) {
	proj, ok := r.Projects[projID]
	if !ok {
		return nil, &errors.ErrProjNotExists{}
	}
	return proj, nil
}

func (r *RBACImpl) ListOrgProjects(orgID string) (map[string]bool, error) {
	if err := r.validateOrganization(orgID); err != nil {
		return nil, err
	}

	return r.orgToProjs[orgID], nil

}

func (r *RBACImpl) DeleteProjFromOrg(orgID string, projID string) error {
	if err := r.validateOrganization(orgID); err != nil {
		return err
	}

	if err := r.validateProject(projID); err != nil {
		return err
	}
	internal.UnlinkResources(r.orgToProjs, orgID, projID)
	delete(r.Projects, projID)
	return nil
}
