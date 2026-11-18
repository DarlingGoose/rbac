package rbac

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/google/uuid"
)

// MockRepo is an in-memory implementation of all RBAC repository interfaces.
// It stores permissions, roles, users, user‐role, role‐permission, user‐group,
// and group‐role relationships in maps. This allows unit testing of Manager logic
// without a real database.
type MockRepo struct {
	perms       map[string]*Permission
	roles       map[string]*Role
	users       map[string]*User
	rolePerms   map[string]map[string]struct{}   // roleID -> set of permIDs
	userRoles   map[string]map[string]struct{}   // userID -> set of roleIDs
	userGroups  map[string]map[string]*UserGroup // userID -> groupID -> *UserGroup
	groupUsers  map[string]map[string]*UserGroup // groupID -> userID -> *UserGroup
	groupRoles  map[string]map[string]struct{}   // groupID -> set of roleIDs
	assignments map[string]*RoleAssignment
}

func (f *MockRepo) ListAllRoles(ctx context.Context) ([]*Role, error) {
	out := make([]*Role, 0, len(f.roles))
	for _, role := range f.roles {
		out = append(out, role)
	}
	return out, nil
}

func (f *MockRepo) GetPermissionByResource(ctx context.Context, resource string, action Action) (*Permission, error) {
	for _, permission := range f.perms {
		if permission.Resource == resource && permission.Action == action {
			return permission, nil
		}
	}
	return nil, nil
}

func (f *MockRepo) GetUserByMeta(ctx context.Context, meta map[string]interface{}) (*User, error) {
	for _, user := range f.users {
		matched := true
		for key, value := range meta {
			switch key {
			case "id":
				matched = reflect.DeepEqual(user.ID, value)
			case "username":
				matched = reflect.DeepEqual(user.Username, value)
			case "email":
				matched = reflect.DeepEqual(user.Email, value)
			default:
				return nil, fmt.Errorf("GetUserByMeta: unsupported field %q", key)
			}
			if !matched {
				break
			}
		}
		if matched {
			return user, nil
		}
	}
	return nil, nil
}

func (f *MockRepo) GetRoleByName(ctx context.Context, name string) (*Role, error) {
	//TODO implement me
	for _, role := range f.roles {
		if role.Name == name {
			return role, nil
		}
	}
	return nil, nil
}

// NewMockRepo initializes a new MockRepo with empty data structures.
func NewMockRepo() *MockRepo {
	return &MockRepo{
		perms:       make(map[string]*Permission),
		roles:       make(map[string]*Role),
		users:       make(map[string]*User),
		rolePerms:   make(map[string]map[string]struct{}),
		userRoles:   make(map[string]map[string]struct{}),
		userGroups:  make(map[string]map[string]*UserGroup),
		groupUsers:  make(map[string]map[string]*UserGroup),
		groupRoles:  make(map[string]map[string]struct{}),
		assignments: make(map[string]*RoleAssignment),
	}
}

func NewMockRepoManager(m *MockRepo) *Manager {
	return &Manager{
		Perms:           m,
		Roles:           m,
		Users:           m,
		RP:              m,
		UR:              m,
		UG:              m,
		GR:              m,
		Assignments:     m,
		DefaultRoleName: "default",
	}
}

func assignmentKey(userID, roleID string, scope Scope) string {
	return userID + "\x00" + roleID + "\x00" + scope.Type + "\x00" + scope.ID
}

// RoleAssignmentRepo implementation
func (f *MockRepo) CreateRoleAssignment(_ context.Context, assignment *RoleAssignment) error {
	key := assignmentKey(assignment.UserID, assignment.RoleID, assignment.Scope)
	if existing, ok := f.assignments[key]; ok {
		*assignment = *existing
		return nil
	}
	if assignment.ID == "" {
		assignment.ID = uuid.NewString()
	}
	if assignment.CreatedAt.IsZero() {
		assignment.CreatedAt = time.Now().UTC()
	}
	copy := *assignment
	f.assignments[key] = &copy
	return nil
}

func (f *MockRepo) DeleteRoleAssignment(_ context.Context, userID, roleID string, scope Scope) error {
	delete(f.assignments, assignmentKey(userID, roleID, scope))
	return nil
}

func (f *MockRepo) ListRoleAssignments(_ context.Context, userID string, scopes []Scope) ([]*RoleAssignment, error) {
	filter := make(map[Scope]struct{}, len(scopes))
	for _, scope := range scopes {
		filter[scope] = struct{}{}
	}
	var out []*RoleAssignment
	for _, assignment := range f.assignments {
		if assignment.UserID != userID {
			continue
		}
		if len(filter) > 0 {
			if _, ok := filter[assignment.Scope]; !ok {
				continue
			}
		}
		copy := *assignment
		out = append(out, &copy)
	}
	return out, nil
}

// PermissionRepo implementation
func (f *MockRepo) CreatePermission(ctx context.Context, p *Permission) error {
	f.perms[p.ID] = p
	return nil
}
func (f *MockRepo) DeletePermission(ctx context.Context, id string) error {
	delete(f.perms, id)
	return nil
}
func (f *MockRepo) GetPermissionByID(ctx context.Context, id string) (*Permission, error) {
	if p, ok := f.perms[id]; ok {
		return p, nil
	}
	return nil, nil
}

// RoleRepo implementation
func (f *MockRepo) CreateRole(ctx context.Context, r *Role) error {
	f.roles[r.ID] = r
	return nil
}
func (f *MockRepo) DeleteRole(ctx context.Context, id string) error {
	delete(f.roles, id)
	return nil
}
func (f *MockRepo) GetRoleByID(ctx context.Context, id string) (*Role, error) {
	if r, ok := f.roles[id]; ok {
		return r, nil
	}
	return nil, nil
}

// UserRepo implementation
func (f *MockRepo) CreateUser(ctx context.Context, u *User) error {
	f.users[u.ID] = u
	return nil
}
func (f *MockRepo) DeleteUser(ctx context.Context, id string) error {
	delete(f.users, id)
	return nil
}
func (f *MockRepo) GetUserByID(ctx context.Context, id string) (*User, error) {
	if u, ok := f.users[id]; ok {
		return u, nil
	}
	return nil, nil
}

// RolePermissionRepo implementation
func (f *MockRepo) AddRP(ctx context.Context, roleID, permID string) error {
	if f.rolePerms[roleID] == nil {
		f.rolePerms[roleID] = make(map[string]struct{})
	}
	f.rolePerms[roleID][permID] = struct{}{}
	return nil
}
func (f *MockRepo) Remove(ctx context.Context, roleID, permID string) error {
	if m, ok := f.rolePerms[roleID]; ok {
		delete(m, permID)
	}
	return nil
}
func (f *MockRepo) ListPermissions(ctx context.Context, roleID string) ([]string, error) {
	var out []string
	if m, ok := f.rolePerms[roleID]; ok {
		for pid := range m {
			out = append(out, pid)
		}
	}
	return out, nil
}

// UserRoleRepo implementation
func (f *MockRepo) AddUR(ctx context.Context, userID, roleID string) error {
	if f.userRoles[userID] == nil {
		f.userRoles[userID] = make(map[string]struct{})
	}
	f.userRoles[userID][roleID] = struct{}{}
	return nil
}
func (f *MockRepo) RemoveUR(ctx context.Context, userID, roleID string) error {
	if m, ok := f.userRoles[userID]; ok {
		delete(m, roleID)
	}
	return nil
}
func (f *MockRepo) ListRoles(ctx context.Context, userID string) ([]string, error) {
	var out []string
	if m, ok := f.userRoles[userID]; ok {
		for rid := range m {
			out = append(out, rid)
		}
	}
	return out, nil
}

// UserGroupRepo implementation
func (f *MockRepo) AddUserToGroup(ctx context.Context, ug *UserGroup) error {
	// by user
	if f.userGroups[ug.UserID] == nil {
		f.userGroups[ug.UserID] = make(map[string]*UserGroup)
	}
	f.userGroups[ug.UserID][ug.GroupName] = ug
	// by group
	if f.groupUsers[ug.GroupName] == nil {
		f.groupUsers[ug.GroupName] = make(map[string]*UserGroup)
	}
	f.groupUsers[ug.GroupName][ug.UserID] = ug
	return nil
}
func (f *MockRepo) RemoveUserFromGroup(ctx context.Context, groupID string, ug *UserGroup) error {
	if m, ok := f.userGroups[ug.UserID]; ok {
		delete(m, groupID)
	}
	if m, ok := f.groupUsers[groupID]; ok {
		delete(m, ug.UserID)
	}
	return nil
}
func (f *MockRepo) GetUsersByGroupID(ctx context.Context, groupID string) ([]*UserGroup, error) {
	var out []*UserGroup
	if m, ok := f.groupUsers[groupID]; ok {
		for _, ug := range m {
			out = append(out, ug)
		}
	}
	return out, nil
}
func (f *MockRepo) GetGroupsByUserID(ctx context.Context, userID string) ([]*UserGroup, error) {
	var out []*UserGroup
	if m, ok := f.userGroups[userID]; ok {
		for _, ug := range m {
			out = append(out, ug)
		}
	}
	return out, nil
}

// GroupRoleRepo implementation
func (f *MockRepo) AddRoleToGroup(ctx context.Context, groupID, roleID string) error {
	if f.groupRoles[groupID] == nil {
		f.groupRoles[groupID] = make(map[string]struct{})
	}
	f.groupRoles[groupID][roleID] = struct{}{}
	return nil
}
func (f *MockRepo) RemoveRoleFromGroup(ctx context.Context, groupID, roleID string) error {
	if m, ok := f.groupRoles[groupID]; ok {
		delete(m, roleID)
	}
	return nil
}
func (f *MockRepo) ListRolesForGroup(ctx context.Context, groupID string) ([]string, error) {
	var out []string
	if m, ok := f.groupRoles[groupID]; ok {
		for rid := range m {
			out = append(out, rid)
		}
	}
	return out, nil
}
