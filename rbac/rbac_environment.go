package rbac

import (
	"github.com/snirt/simple-rbac/rbac/errors"
	"github.com/snirt/simple-rbac/rbac/internal"
	"github.com/snirt/simple-rbac/rbac/models"
)

func (r *RBACImpl) CreateEnvInProj(env *models.Environment, projID string) error {
	if err := r.validateProject(projID); err != nil {
		return err
	}
	r.Environments[env.ID] = env
	internal.LinkResources(r.projToEnvs, projID, env.ID)
	return nil
}

func (r *RBACImpl) GetEnvironment(envID string) (*models.Environment, error) {
	if err := r.validateEnvironment(envID); err != nil {
		return nil, err
	}
	env, ok := r.Environments[envID]
	if !ok {
		return nil, &errors.ErrEnvNotExists{}
	}
	return env, nil
}

func (r *RBACImpl) ListProjEnvironments(projID string) (map[string]bool, error) {
	if err := r.validateProject(projID); err != nil {
		return nil, err
	}
	return r.projToEnvs[projID], nil
}

func (r *RBACImpl) UpdateEnvironment(env *models.Environment) error {
	if err := r.validateEnvironment(env.ID); err != nil {
		return err
	}

	// assume there are more fields except the id which we want to update
	r.Environments[env.ID] = env
	return nil
}

func (r *RBACImpl) DeleteEnvFromProj(projID string, envID string) error {
	if err := r.validateProject(projID); err != nil {
		return err
	}

	if err := r.validateEnvironment(envID); err != nil {
		return err
	}

	internal.UnlinkResources(r.projToEnvs, projID, envID)
	delete(r.Environments, envID)

	return nil
}
