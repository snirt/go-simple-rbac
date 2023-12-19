package rbac

import (
	"github.com/snirt/simple-rbac/rbac/errors"
	"github.com/snirt/simple-rbac/rbac/internal"
	"github.com/snirt/simple-rbac/rbac/models"
)

func (r *RBACImpl) CreateOrganization(organization *models.Organization) error {
	if err := r.validateOrganization(organization.ID); err == nil {
		return &errors.ErrOrgAlreadyExists{}
	}

	r.Organizations[organization.ID] = organization
	return nil
}

func (r *RBACImpl) AddUserToOrganization(userID, orgID string) error {
	if err := r.validateUser(userID); err != nil {
		return err
	}
	if err := r.validateOrganization(orgID); err != nil {
		return err
	}

	if err := internal.LinkResources(r.orgToUsers, orgID, userID); err != nil {
		return err
	}

	return nil
}

func (r *RBACImpl) GetOrganization(orgID string) (*models.Organization, error) {
	org, ok := r.Organizations[orgID]
	if !ok {
		return nil, &errors.ErrOrgNotExists{}
	}
	return org, nil
}

func (r *RBACImpl) ListOrgUsers(orgID string) (map[string]bool, error) {
	if err := r.validateOrganization(orgID); err != nil {
		return nil, err
	}
	return r.orgToUsers[orgID], nil
}

func (r *RBACImpl) RemoveUserFromOrganization(userID string, orgID string) error {
	if err := r.validateUser(userID); err != nil {
		return err
	}

	if err := r.validateOrganization(orgID); err != nil {
		return err
	}
	if err := internal.UnlinkResources(r.orgToUsers, orgID, userID); err != nil {
		return err
	}
	return nil
}
