package rbac

import (
	"context"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var (
	meter           = otel.Meter("rbac/manager")
	requestCounter  metric.Int64Counter
	errorCounter    metric.Int64Counter
	latencyRecorder metric.Float64Histogram
)

func init() {
	// Total number of calls to any Manager method
	requestCounter, _ = meter.Int64Counter(
		"rbac_manager_requests_total",
		metric.WithDescription("Total number of RBAC manager method invocations"),
	)
	// Total number of errors returned by Manager methods
	errorCounter, _ = meter.Int64Counter(
		"rbac_manager_errors_total",
		metric.WithDescription("Total number of errors in RBAC manager methods"),
	)
	// Distribution of method latencies (seconds)
	latencyRecorder, _ = meter.Float64Histogram(
		"rbac_manager_request_duration_seconds",
		metric.WithDescription("Latency of RBAC manager methods"),
	)
}

type Manager struct {
	Perms       PermissionRepo
	Roles       RoleRepo
	Users       UserRepo
	RP          RolePermissionRepo
	UR          UserRoleRepo
	UG          UserGroupRepo
	GR          GroupRoleRepo
	Assignments RoleAssignmentRepo
	Resolver    ResourceResolver
	Inheritance InheritancePolicy
	// MaxInheritanceDepth bounds resolver calls. Values <= 0 use 32.
	MaxInheritanceDepth int
	DefaultRoleName     string
}

var (
	ErrInvalidCheckRequest = errors.New("rbac: invalid check request")
	ErrResolverCycle       = errors.New("rbac: resource ancestry cycle")
	ErrResolverDepth       = errors.New("rbac: resource ancestry exceeds maximum depth")
	ErrAssignmentsDisabled = errors.New("rbac: role assignment repository is not configured")
)

func (m *Manager) AssignRoleToGroup(ctx context.Context, groupID, roleID string) error {
	start := time.Now()
	err := m.GR.AddRoleToGroup(ctx, groupID, roleID)
	m.record(ctx, start, "AssignRoleToGroup", err)
	return err
}

func (m *Manager) UnassignRoleFromGroup(ctx context.Context, groupID, roleID string) error {
	start := time.Now()
	err := m.GR.RemoveRoleFromGroup(ctx, groupID, roleID)
	m.record(ctx, start, "UnassignRoleFromGroup", err)
	return err
}

func (m *Manager) ListRolesForGroup(ctx context.Context, groupID string) ([]string, error) {
	start := time.Now()
	roles, err := m.GR.ListRolesForGroup(ctx, groupID)
	m.record(ctx, start, "ListRolesForGroup", err)
	return roles, err
}

// CreateRole instruments the CreateRole call.
func (m *Manager) CreateRole(ctx context.Context, r *Role) error {
	start := time.Now()
	err := m.Roles.CreateRole(ctx, r)
	m.record(ctx, start, "CreateRole", err)
	return err
}

func (m *Manager) DeleteRole(ctx context.Context, id string) error {
	start := time.Now()
	err := m.Roles.DeleteRole(ctx, id)
	m.record(ctx, start, "DeleteRole", err)
	return err
}

func (m *Manager) GetRole(ctx context.Context, id string) (*Role, error) {
	start := time.Now()
	role, err := m.Roles.GetRoleByID(ctx, id)
	m.record(ctx, start, "GetRole", err)
	return role, err
}

func (m *Manager) CreateUser(ctx context.Context, u *User) error {
	start := time.Now()
	err := m.Users.CreateUser(ctx, u)
	m.record(ctx, start, "CreateUser", err)
	return err
}

func (m *Manager) DeleteUser(ctx context.Context, id string) error {
	start := time.Now()
	err := m.Users.DeleteUser(ctx, id)
	m.record(ctx, start, "DeleteUser", err)
	return err
}

func (m *Manager) GetUser(ctx context.Context, id string) (*User, error) {
	start := time.Now()
	user, err := m.Users.GetUserByID(ctx, id)
	m.record(ctx, start, "GetUser", err)
	return user, err
}

func (m *Manager) AssignPermissionToRole(ctx context.Context, roleID, permID string) error {
	start := time.Now()
	err := m.RP.AddRP(ctx, roleID, permID)
	m.record(ctx, start, "AssignPermissionToRole", err)
	return err
}

func (m *Manager) RemovePermissionFromRole(ctx context.Context, roleID, permID string) error {
	start := time.Now()
	err := m.RP.Remove(ctx, roleID, permID)
	m.record(ctx, start, "RemovePermissionFromRole", err)
	return err
}

func (m *Manager) ListPermissionsForRole(ctx context.Context, roleID string) ([]string, error) {
	start := time.Now()
	perms, err := m.RP.ListPermissions(ctx, roleID)
	m.record(ctx, start, "ListPermissionsForRole", err)
	return perms, err
}

func (m *Manager) AssignRoleToUser(ctx context.Context, userID, roleID string) error {
	start := time.Now()
	err := m.UR.AddUR(ctx, userID, roleID)
	m.record(ctx, start, "AssignRoleToUser", err)
	return err
}

func (m *Manager) UnassignRoleFromUser(ctx context.Context, userID, roleID string) error {
	start := time.Now()
	err := m.UR.RemoveUR(ctx, userID, roleID)
	m.record(ctx, start, "UnassignRoleFromUser", err)
	return err
}

func (m *Manager) ListRolesForUser(ctx context.Context, userID string) ([]string, error) {
	start := time.Now()
	roles, err := m.UR.ListRoles(ctx, userID)
	m.record(ctx, start, "ListRolesForUser", err)
	return roles, err
}

func (m *Manager) AddUserToGroup(ctx context.Context, ug *UserGroup) error {
	start := time.Now()
	err := m.UG.AddUserToGroup(ctx, ug)
	m.record(ctx, start, "AddUserToGroup", err)
	return err
}

func (m *Manager) RemoveUserFromGroup(ctx context.Context, groupID string, ug *UserGroup) error {
	start := time.Now()
	err := m.UG.RemoveUserFromGroup(ctx, groupID, ug)
	m.record(ctx, start, "RemoveUserFromGroup", err)
	return err
}

func (m *Manager) GetUsersByGroupID(ctx context.Context, groupID string) ([]*UserGroup, error) {
	start := time.Now()
	list, err := m.UG.GetUsersByGroupID(ctx, groupID)
	m.record(ctx, start, "GetUsersByGroupID", err)
	return list, err
}

// CreatePermission instruments the underlying repo call.
func (m *Manager) CreatePermission(ctx context.Context, p *Permission) error {
	start := time.Now()
	err := m.Perms.CreatePermission(ctx, p)

	// common attributes
	attrs := []attribute.KeyValue{
		attribute.String("method", "CreatePermission"),
	}
	requestCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
	latencyRecorder.Record(ctx, time.Since(start).Seconds(), metric.WithAttributes(attrs...))
	if err != nil {
		errorCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
	}
	return err
}

func (m *Manager) record(ctx context.Context, start time.Time, method string, err error) {
	attrs := []attribute.KeyValue{
		attribute.String("method", method),
	}
	requestCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
	latencyRecorder.Record(ctx, time.Since(start).Seconds(), metric.WithAttributes(attrs...))
	if err != nil {
		errorCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
	}
}

func (m *Manager) DeletePermission(ctx context.Context, id string) error {
	start := time.Now()
	err := m.Perms.DeletePermission(ctx, id)
	attrs := []attribute.KeyValue{attribute.String("method", "DeletePermission")}
	requestCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
	latencyRecorder.Record(ctx, time.Since(start).Seconds(), metric.WithAttributes(attrs...))
	if err != nil {
		errorCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
	}
	return err
}

func (m *Manager) GetPermission(ctx context.Context, id string) (*Permission, error) {
	start := time.Now()
	perm, err := m.Perms.GetPermissionByID(ctx, id)
	attrs := []attribute.KeyValue{attribute.String("method", "GetPermission")}
	requestCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
	latencyRecorder.Record(ctx, time.Since(start).Seconds(), metric.WithAttributes(attrs...))
	if err != nil {
		errorCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
	}
	return perm, err
}

// ... repeat the same wrapping for CreateRole, DeleteRole, GetRole, etc. ...

func (m *Manager) HasPermission(ctx context.Context, userID, permID string) (bool, error) {
	start := time.Now()
	ok, err := func() (bool, error) {
		roles, err := m.UR.ListRoles(ctx, userID)
		if err != nil {
			return false, err
		}
		for _, r := range roles {
			perms, err := m.RP.ListPermissions(ctx, r)
			if err != nil {
				return false, err
			}
			for _, p := range perms {
				if p == permID {
					return true, nil
				}
			}
		}
		return false, nil
	}()

	attrs := []attribute.KeyValue{attribute.String("method", "HasPermission")}
	requestCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
	latencyRecorder.Record(ctx, time.Since(start).Seconds(), metric.WithAttributes(attrs...))
	if err != nil {
		errorCounter.Add(ctx, 1, metric.WithAttributes(attrs...))
	}
	return ok, err
}

func (m *Manager) GetGroupsByUserID(ctx context.Context, userID string) ([]*UserGroup, error) {
	start := time.Now()
	groups, err := m.UG.GetGroupsByUserID(ctx, userID)
	m.record(ctx, start, "GetGroupsByUserID", err)
	return groups, err
}

func (m *Manager) Can(ctx context.Context, userID, resource string, action Action) (bool, error) {
	start := time.Now()
	roles, err := m.globalRoleIDs(ctx, userID)
	if err == nil {
		var allowed bool
		allowed, err = m.rolesAllow(ctx, roles, resource, action)
		if err == nil {
			m.record(ctx, start, "Can", nil)
			return allowed, nil
		}
	}
	m.record(ctx, start, "Can", err)
	return false, err
}

// AssignRole creates a scoped user role assignment.
func (m *Manager) AssignRole(ctx context.Context, assignment RoleAssignment) error {
	start := time.Now()
	err := validateAssignment(assignment)
	if err == nil {
		if m.Assignments == nil {
			err = ErrAssignmentsDisabled
		} else {
			err = m.Assignments.CreateRoleAssignment(ctx, &assignment)
		}
	}
	m.record(ctx, start, "AssignRole", err)
	return err
}

// UnassignRole revokes one role from one user in one scope.
func (m *Manager) UnassignRole(ctx context.Context, userID, roleID string, scope Scope) error {
	start := time.Now()
	err := validateAssignment(RoleAssignment{UserID: userID, RoleID: roleID, Scope: scope})
	if err == nil {
		if m.Assignments == nil {
			err = ErrAssignmentsDisabled
		} else {
			err = m.Assignments.DeleteRoleAssignment(ctx, userID, roleID, scope)
		}
	}
	m.record(ctx, start, "UnassignRole", err)
	return err
}

func (m *Manager) ListRoleAssignments(ctx context.Context, userID string, scopes ...Scope) ([]*RoleAssignment, error) {
	start := time.Now()
	if m.Assignments == nil {
		m.record(ctx, start, "ListRoleAssignments", ErrAssignmentsDisabled)
		return nil, ErrAssignmentsDisabled
	}
	assignments, err := m.Assignments.ListRoleAssignments(ctx, userID, scopes)
	m.record(ctx, start, "ListRoleAssignments", err)
	return assignments, err
}

// Check evaluates global legacy roles plus role assignments at the requested
// scope, explicitly allowed ancestors, and the normalized platform scope.
func (m *Manager) Check(ctx context.Context, request CheckRequest) (bool, error) {
	start := time.Now()
	allowed, err := m.check(ctx, request)
	m.record(ctx, start, "Check", err)
	if err != nil {
		return false, err
	}
	return allowed, nil
}

func (m *Manager) check(ctx context.Context, request CheckRequest) (bool, error) {
	if request.UserID == "" || request.ResourceType == "" || request.ResourceID == "" || request.Action == ActionUnknown {
		return false, ErrInvalidCheckRequest
	}
	roles, err := m.globalRoleIDs(ctx, request.UserID)
	if err != nil {
		return false, err
	}
	if m.Assignments != nil {
		scopes, err := m.applicableScopes(ctx, request)
		if err != nil {
			return false, err
		}
		assignments, err := m.Assignments.ListRoleAssignments(ctx, request.UserID, scopes)
		if err != nil {
			return false, err
		}
		for _, assignment := range assignments {
			if assignment != nil {
				roles = append(roles, assignment.RoleID)
			}
		}
	}
	return m.rolesAllow(ctx, dedupe(roles), request.ResourceType, request.Action)
}

func (m *Manager) globalRoleIDs(ctx context.Context, userID string) ([]string, error) {
	if m.UR == nil && m.UG == nil && m.GR == nil {
		return nil, nil
	}
	if m.UR == nil || m.UG == nil || m.GR == nil {
		return nil, errors.New("rbac: incomplete legacy role repositories")
	}
	roles, err := m.UR.ListRoles(ctx, userID)
	if err != nil {
		return nil, err
	}
	groups, err := m.UG.GetGroupsByUserID(ctx, userID)
	if err != nil {
		return nil, err
	}
	for _, membership := range groups {
		if membership == nil {
			continue
		}
		groupRoles, err := m.GR.ListRolesForGroup(ctx, membership.GroupName)
		if err != nil {
			return nil, err
		}
		roles = append(roles, groupRoles...)
	}
	return dedupe(roles), nil
}

func (m *Manager) rolesAllow(ctx context.Context, roles []string, resource string, action Action) (bool, error) {
	if action == ActionUnknown {
		return false, nil
	}
	if m.RP == nil || m.Perms == nil {
		return false, errors.New("rbac: permission repositories are not configured")
	}
	for _, roleID := range dedupe(roles) {
		permissionIDs, err := m.RP.ListPermissions(ctx, roleID)
		if err != nil {
			return false, err
		}
		for _, permissionID := range permissionIDs {
			permission, err := m.Perms.GetPermissionByID(ctx, permissionID)
			if err != nil {
				return false, err
			}
			if permission == nil {
				continue
			}
			resourceMatches, err := matchResource(permission.Resource, resource)
			if err != nil {
				return false, err
			}
			actionMatches, err := path.Match(string(permission.Action), string(action))
			if err != nil {
				return false, err
			}
			if resourceMatches && actionMatches {
				return true, nil
			}
		}
	}
	return false, nil
}

func (m *Manager) applicableScopes(ctx context.Context, request CheckRequest) ([]Scope, error) {
	requested := ResourceRef{Type: request.ResourceType, ID: request.ResourceID}
	scopes := []Scope{{Type: requested.Type, ID: requested.ID}, PlatformScope()}
	if m.Resolver == nil || m.Inheritance == nil {
		return scopes, nil
	}
	limit := m.MaxInheritanceDepth
	if limit <= 0 {
		limit = 32
	}
	seen := map[ResourceRef]struct{}{requested: {}}
	current := requested
	for depth := 0; depth < limit; depth++ {
		parent, err := m.Resolver.Parent(ctx, current)
		if err != nil {
			return nil, err
		}
		if parent == nil {
			return dedupeScopes(scopes), nil
		}
		if parent.Type == "" || parent.ID == "" {
			return nil, fmt.Errorf("%w: resolver returned an empty resource", ErrInvalidCheckRequest)
		}
		if _, exists := seen[*parent]; exists {
			return nil, ErrResolverCycle
		}
		seen[*parent] = struct{}{}
		allowed, err := m.Inheritance.AllowInherited(ctx, request, *parent)
		if err != nil {
			return nil, err
		}
		if allowed {
			scopes = append(scopes, Scope{Type: parent.Type, ID: parent.ID})
		}
		current = *parent
	}
	return nil, ErrResolverDepth
}

func validateAssignment(assignment RoleAssignment) error {
	if assignment.UserID == "" || assignment.RoleID == "" || assignment.Scope.Type == "" || assignment.Scope.ID == "" {
		return errors.New("rbac: role assignment requires user, role, scope type, and scope id")
	}
	if assignment.Scope.Type == ScopeTypePlatform && assignment.Scope.ID != PlatformScopeID {
		return errors.New("rbac: platform assignments must use PlatformScope")
	}
	return nil
}

func dedupe(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func dedupeScopes(scopes []Scope) []Scope {
	seen := make(map[Scope]struct{}, len(scopes))
	out := make([]Scope, 0, len(scopes))
	for _, scope := range scopes {
		if _, exists := seen[scope]; exists {
			continue
		}
		seen[scope] = struct{}{}
		out = append(out, scope)
	}
	return out
}

// matchResource implements segment-aware globbing. A double star must occupy
// an entire segment and matches zero or more segments; a single star stays
// within one segment.
func matchResource(pattern, resource string) (bool, error) {
	if pattern == "*" || pattern == "**" {
		return true, nil
	}
	separator := "."
	if strings.Contains(pattern, "/") || strings.Contains(resource, "/") {
		separator = "/"
	}
	patternSegments := strings.Split(pattern, separator)
	resourceSegments := strings.Split(resource, separator)
	for _, segment := range patternSegments {
		if strings.Contains(segment, "**") && segment != "**" {
			return false, path.ErrBadPattern
		}
	}
	var match func(int, int) (bool, error)
	match = func(patternIndex, resourceIndex int) (bool, error) {
		if patternIndex == len(patternSegments) {
			return resourceIndex == len(resourceSegments), nil
		}
		if patternSegments[patternIndex] == "**" {
			for next := resourceIndex; next <= len(resourceSegments); next++ {
				ok, err := match(patternIndex+1, next)
				if err != nil || ok {
					return ok, err
				}
			}
			return false, nil
		}
		if resourceIndex == len(resourceSegments) {
			return false, nil
		}
		ok, err := path.Match(patternSegments[patternIndex], resourceSegments[resourceIndex])
		if err != nil || !ok {
			return false, err
		}
		return match(patternIndex+1, resourceIndex+1)
	}
	return match(0, 0)
}
