package internal

import "github.com/snirt/simple-rbac/rbac/errors"

func LinkResources(r2r map[string]map[string]bool, parent string, child string) error {
	p, ok := r2r[parent]
	if !ok {
		p = map[string]bool{child: true}
	} else {
		p[child] = true
	}
	r2r[parent] = p
	return nil
}

func UnlinkResources(r2r map[string]map[string]bool, parent string, child string) error {
	p, ok := r2r[parent]
	if !ok {
		return &errors.ErrResourceNotExists{}
	}
	ok = p[child]
	if !ok {
		return &errors.ErrResourceNotExists{}
	}
	delete(p, child)
	return nil
}
