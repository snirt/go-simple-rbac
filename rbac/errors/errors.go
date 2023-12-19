package errors

type ErrUserNotPermitted struct{}

func (e *ErrUserNotPermitted) Error() string {
	return "user not permitted"
}

type ErrUserNotExists struct{}

func (e *ErrUserNotExists) Error() string {
	return "user not exists"
}

type ErrUserAlreadyExists struct{}

func (e *ErrUserAlreadyExists) Error() string {
	return "user already exists"
}

type ErrRoleNotExists struct{}

func (e *ErrRoleNotExists) Error() string {
	return "role not exists"
}

type ErrOrgNotExists struct{}

func (e *ErrOrgNotExists) Error() string {
	return "organization not exists"
}

type ErrOrgAlreadyExists struct{}

func (e *ErrOrgAlreadyExists) Error() string {
	return "organization already exists"
}

type ErrResourceNotExists struct{}

func (e *ErrResourceNotExists) Error() string {
	return "resource not exists"
}

type ErrProjNotExists struct{}

func (e *ErrProjNotExists) Error() string {
	return "project not exists"
}

type ErrEnvNotExists struct{}

func (e *ErrEnvNotExists) Error() string {
	return "environment not exists"
}
