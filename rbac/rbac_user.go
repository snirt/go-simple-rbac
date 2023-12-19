package rbac

import (
	"github.com/snirt/simple-rbac/rbac/errors"
	"github.com/snirt/simple-rbac/rbac/models"
)

func (r *RBACImpl) CreateUser(user *models.User) error {
	if err := r.validateUser(user.ID); err == nil {
		return &errors.ErrUserAlreadyExists{}
	}
	r.Users[user.ID] = user
	return nil
}

func (r *RBACImpl) GetUser(id string) (*models.User, error) {
	user, ok := r.Users[id]
	if !ok {
		return nil, &errors.ErrUserNotExists{}
	}
	return user, nil
}

func (r *RBACImpl) ModifyUserRole(userID string, resource models.Resource, roleName models.RoleName) error {
	if err := r.validateUser(userID); err != nil {
		return err
	}
	user := r.Users[userID]

	// modify user role
	binding, err := models.NewRoleBinding(r.Roles, userID, resource, roleName)
	if err != nil {
		return err
	}
	r.roleBindings[models.BindingKey(user, resource)] = binding

	return nil
}

func (r *RBACImpl) GetUsersPermissionsForResource(userID string, resource models.Resource) (map[models.Permission]struct{}, error) {
	if err := r.validateUser(userID); err != nil {
		return nil, err
	}
	user, ok := r.Users[userID]
	if !ok {
		return nil, &errors.ErrUserNotExists{}
	}

	binding := r.roleBindings[models.BindingKey(user, resource)]
	if binding == nil {
		return nil, &errors.ErrRoleNotExists{}
	}
	return binding.Role.Permissions, nil
}
