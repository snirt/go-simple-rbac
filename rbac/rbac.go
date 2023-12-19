package rbac

import (
	"github.com/snirt/simple-rbac/rbac/errors"
	"github.com/snirt/simple-rbac/rbac/models"
)

type RBAC interface {
	// basic functions
	CreateRole(role *models.Role)
	GetRole(name models.RoleName) (*models.Role, error)
	GetRoles() map[models.RoleName]*models.Role
	AddRoleBinding(binding *models.RoleBinding)
	ModifyUserRole(userId string, resource models.Resource, role models.RoleName) error
	GetRoleBinding(id string) (*models.RoleBinding, error)
	RemoveRoleBinding(id string)

	// access control
	CanUserPerformAction(userID string, resource models.Resource, permission models.Permission) (bool, error)

	// user
	CreateUser(user *models.User) error
	GetUser(id string) (*models.User, error)
	GetUsersPermissionsForResource(userID string, resource models.Resource) (map[models.Permission]struct{}, error)

	// organization
	CreateOrganization(organization *models.Organization) error
	GetOrganization(id string) (*models.Organization, error)
	ListOrgUsers(orgID string) (map[string]bool, error)
	AddUserToOrganization(userID string, orgID string) error
	RemoveUserFromOrganization(userID string, orgID string) error

	// project
	CreateProjInOrg(project *models.Project, orgID string) error
	GetProject(projID string) (*models.Project, error)
	ListOrgProjects(orgID string) (map[string]bool, error)
	DeleteProjFromOrg(orgID string, projID string) error

	// environment
	CreateEnvInProj(env *models.Environment, projID string) error
	GetEnvironment(envID string) (*models.Environment, error)
	ListProjEnvironments(projID string) (map[string]bool, error)
	UpdateEnvironment(env *models.Environment) error
}

type RBACImpl struct {
	// resources
	Users         map[string]*models.User
	Organizations map[string]*models.Organization
	Projects      map[string]*models.Project
	Environments  map[string]*models.Environment
	// roles
	Roles        map[models.RoleName]*models.Role
	roleBindings map[string]*models.RoleBinding
	// connections
	orgToUsers map[string]map[string]bool
	orgToProjs map[string]map[string]bool
	projToEnvs map[string]map[string]bool
}

func NewRBACModule() RBAC {
	userAdmin := &models.User{
		ID: "admin",
	}

	// roles definition
	roleAdmin := &models.Role{
		Name: "admin",
		Permissions: map[models.Permission]struct{}{
			models.PermissionOrgAddRemoveUsers:          {},
			models.PermissionOrgModifyUsers:             {},
			models.PermissionOrgCreateProject:           {},
			models.PermissionOrgRemoveProject:           {},
			models.PermissionProjDeployProjToEnv:        {},
			models.PermissionModifyEnvDefinitionForProj: {},
		},
	}
	roleMember := &models.Role{
		Name: "member",
		Permissions: map[models.Permission]struct{}{
			models.PermissionProjDeployProjToEnv: {},
		},
	}

	return &RBACImpl{
		Users: map[string]*models.User{
			userAdmin.ID: userAdmin,
		},
		Roles: map[models.RoleName]*models.Role{
			roleAdmin.Name:  roleAdmin,
			roleMember.Name: roleMember,
		},
		roleBindings:  make(map[string]*models.RoleBinding),
		// entities
		Organizations: make(map[string]*models.Organization),
		Projects:      make(map[string]*models.Project),
		Environments:  make(map[string]*models.Environment),
		// relations
		orgToUsers:    make(map[string]map[string]bool),
		orgToProjs:    make(map[string]map[string]bool),
		projToEnvs:    make(map[string]map[string]bool),
	}
}

func (r *RBACImpl) CreateRole(role *models.Role) {
	r.Roles[role.Name] = role
}

func (r *RBACImpl) GetRole(name models.RoleName) (*models.Role, error) {
	role, ok := r.Roles[name]
	if !ok {
		return nil, &errors.ErrRoleNotExists{}
	}
	return role, nil
}

func (r *RBACImpl) GetRoles() map[models.RoleName]*models.Role {
	return r.Roles
}

func (r *RBACImpl) AddRoleBinding(binding *models.RoleBinding) {
	r.roleBindings[binding.Key()] = binding
}

func (r *RBACImpl) GetRoleBinding(key string) (*models.RoleBinding, error) {
	binding, ok := r.roleBindings[key]
	if !ok {
		return nil, &errors.ErrRoleNotExists{}
	}
	return binding, nil
}

func (r *RBACImpl) RemoveRoleBinding(key string) {
	delete(r.roleBindings, key)
}

func (r *RBACImpl) CanUserPerformAction(userID string, resource models.Resource, permission models.Permission) (bool, error) {
	if err := r.validateUser(userID); err != nil {
		return false, err
	}

	var err error
	switch resource.GetType() {
	case models.ResourceUser:
		err = r.validateUser(resource.GetID())
	case models.ResourceOrganization:
		err = r.validateOrganization(resource.GetID())
	case models.ResourceProject:
		err = r.validateProject(resource.GetID())
	case models.ResourceEnvironment:
		err = r.validateEnvironment(resource.GetID())
	default:
		return false, &errors.ErrResourceNotExists{}
	}
	if err != nil {
		return false, err
	}

	user := r.Users[userID]
	return r.hasPermission(user, resource, permission), nil
}

func (r *RBACImpl) hasPermission(user *models.User, resource models.Resource, permission models.Permission) bool {
	roleBinding, ok := r.roleBindings[models.BindingKey(user, resource)]
	if !ok {
		return false
	}
	role := roleBinding.Role
	_, ok = role.Permissions[permission]
	return ok
}

func (r *RBACImpl) validateUser(userID string) error {
	_, ok := r.Users[userID]
	if !ok {
		return &errors.ErrUserNotExists{}
	}
	return nil
}

func (r *RBACImpl) validateOrganization(orgID string) error {
	_, ok := r.Organizations[orgID]
	if !ok {
		return &errors.ErrOrgNotExists{}
	}
	return nil
}

func (r *RBACImpl) validateProject(projID string) error {
	_, ok := r.Projects[projID]
	if !ok {
		return &errors.ErrProjNotExists{}
	}
	return nil
}

func (r *RBACImpl) validateEnvironment(envID string) error {
	_, ok := r.Environments[envID]
	if !ok {
		return &errors.ErrEnvNotExists{}
	}
	return nil
}
