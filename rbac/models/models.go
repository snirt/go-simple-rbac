package models

import "github.com/snirt/simple-rbac/rbac/errors"

type RoleName string

const (
	RoleAdmin  RoleName = "admin"
	RoleMember RoleName = "member"
)

type Role struct {
	Name        RoleName
	Permissions map[Permission]struct{}
}

type ResourceType string

const (
	ResourceUser         ResourceType = "user"
	ResourceOrganization ResourceType = "organization"
	ResourceProject      ResourceType = "project"
	ResourceEnvironment  ResourceType = "environment"
)

// --- resources
type Resource interface {
	GetID() string
	GetType() ResourceType
}

// ---
type User struct {
	ID   string
	Name string
}

func (u *User) GetID() string {
	return u.ID
}
func (u *User) GetType() string {
	return "user"
}

// ---
type Organization struct {
	ID       string
	Projects map[string]*Project
}

func (o *Organization) GetID() string {
	return o.ID
}

func (o *Organization) GetType() ResourceType {
	return ResourceOrganization
}

//---

type Project struct {
	ID          string
	Environment []*Environment
}

func (p *Project) GetID() string {
	return p.ID
}

func (p *Project) GetType() ResourceType {
	return ResourceProject
}

// ---
type Environment struct {
	ID string
}

func (e *Environment) GetID() string {
	return e.ID
}
func (e *Environment) GetType() ResourceType {
	return ResourceEnvironment
}

type Permission string

const (
	PermissionOrgAddRemoveUsers          Permission = "org_add_remove_users"
	PermissionOrgModifyUsers             Permission = "org_modify_users"
	PermissionOrgCreateProject           Permission = "org_create_project"
	PermissionOrgRemoveProject           Permission = "org_remove_project"
	PermissionProjDeployProjToEnv        Permission = "proj_deploy_proj_to_env"
	PermissionModifyEnvDefinitionForProj Permission = "modify_env_definition_for_proj"
	// TODO ...
)

func BindingKey(user *User, resource Resource) string {
	return user.ID + ":" + string(resource.GetType()) + ":" + resource.GetID()
}

type RoleBinding struct {
	UserID       string
	ResourceType ResourceType
	ResourceID   string
	Role         *Role
}

func NewRoleBinding(roles map[RoleName]*Role, userID string, resource Resource, roleName RoleName) (*RoleBinding, error) {
	role, ok := roles[roleName]
	if !ok {
		return nil, &errors.ErrRoleNotExists{}
	}
	return &RoleBinding{
		UserID:       userID,
		ResourceType: resource.GetType(),
		ResourceID:   resource.GetID(),
		Role:         role,
	}, nil
}

func (rb *RoleBinding) Key() string {
	return rb.UserID + ":" + string(rb.ResourceType) + ":" + rb.ResourceID
}
