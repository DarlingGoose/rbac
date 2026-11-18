package rbac

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

type mapResolver map[ResourceRef]*ResourceRef

func (r mapResolver) Parent(_ context.Context, resource ResourceRef) (*ResourceRef, error) {
	return r[resource], nil
}

type failingUserRoles struct{ err error }

func (f failingUserRoles) AddUR(context.Context, string, string) error    { return f.err }
func (f failingUserRoles) RemoveUR(context.Context, string, string) error { return f.err }
func (f failingUserRoles) ListRoles(context.Context, string) ([]string, error) {
	return nil, f.err
}

func addRolePermission(t *testing.T, repo *MockRepo, roleID, permissionID, resource string, action Action) {
	t.Helper()
	ctx := context.Background()
	if err := repo.CreateRole(ctx, &Role{ID: roleID, Name: roleID}); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreatePermission(ctx, &Permission{ID: permissionID, Resource: resource, Action: action}); err != nil {
		t.Fatal(err)
	}
	if err := repo.AddRP(ctx, roleID, permissionID); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPMethodToAction(t *testing.T) {
	tests := map[string]Action{
		http.MethodGet:     ActionRead,
		http.MethodHead:    ActionRead,
		http.MethodPost:    ActionCreate,
		http.MethodPut:     ActionUpdate,
		http.MethodPatch:   ActionUpdate,
		http.MethodDelete:  ActionDelete,
		http.MethodOptions: ActionUnknown,
	}
	for method, want := range tests {
		if got := HTTPMethodToAction(method); got != want {
			t.Errorf("HTTPMethodToAction(%q) = %q, want %q", method, got, want)
		}
	}
}

func TestCanFailsClosedOnRepositoryError(t *testing.T) {
	repo := NewMockRepo()
	wantErr := errors.New("storage unavailable")
	manager := NewMockRepoManager(repo)
	manager.UR = failingUserRoles{err: wantErr}
	allowed, err := manager.Can(context.Background(), "user", "guide", ActionRead)
	if allowed || !errors.Is(err, wantErr) {
		t.Fatalf("Can() = (%v, %v), want (false, %v)", allowed, err, wantErr)
	}
}

func TestMatchResourceSegmentBoundaries(t *testing.T) {
	tests := []struct {
		pattern  string
		resource string
		want     bool
		wantErr  bool
	}{
		{"guide.*.lesson", "guide.one.lesson", true, false},
		{"guide.*.lesson", "guide.one.extra.lesson", false, false},
		{"guide.**.lesson", "guide.lesson", true, false},
		{"guide.**.lesson", "guide.one.extra.lesson", true, false},
		{"guide.**", "guidebook.lesson", false, false},
		{"guide/**/lesson", "guide/a/b/lesson", true, false},
		{"guide**lesson", "guide.one.lesson", false, true},
	}
	for _, test := range tests {
		got, err := matchResource(test.pattern, test.resource)
		if (err != nil) != test.wantErr || got != test.want {
			t.Errorf("matchResource(%q, %q) = (%v, %v), want (%v, error=%v)", test.pattern, test.resource, got, err, test.want, test.wantErr)
		}
	}
}

func TestScopedChecksIsolationInheritanceAndRevocation(t *testing.T) {
	ctx := context.Background()
	repo := NewMockRepo()
	manager := NewMockRepoManager(repo)
	manager.Resolver = mapResolver{
		{Type: "lesson", ID: "lesson-a"}: {Type: "guide", ID: "guide-a"},
		{Type: "lesson", ID: "lesson-b"}: {Type: "guide", ID: "guide-b"},
	}
	manager.Inheritance = ActionInheritancePolicy{ActionUpdate: true}
	addRolePermission(t, repo, "editor", "edit-guide", "guide", ActionUpdate)
	addRolePermission(t, repo, "editor", "edit-lesson", "lesson", ActionUpdate)
	addRolePermission(t, repo, "viewer", "read-guide", "guide", ActionRead)

	if err := manager.AssignRole(ctx, RoleAssignment{
		UserID: "user-1", RoleID: "editor", Scope: Scope{Type: "guide", ID: "guide-a"},
	}); err != nil {
		t.Fatal(err)
	}
	if err := manager.AssignRole(ctx, RoleAssignment{
		UserID: "user-1", RoleID: "viewer", Scope: Scope{Type: "guide", ID: "guide-b"},
	}); err != nil {
		t.Fatal(err)
	}

	checks := []struct {
		request CheckRequest
		want    bool
	}{
		{CheckRequest{UserID: "user-1", ResourceType: "guide", ResourceID: "guide-a", Action: ActionUpdate}, true},
		{CheckRequest{UserID: "user-1", ResourceType: "guide", ResourceID: "guide-b", Action: ActionUpdate}, false},
		{CheckRequest{UserID: "user-1", ResourceType: "guide", ResourceID: "guide-b", Action: ActionRead}, true},
		{CheckRequest{UserID: "user-1", ResourceType: "lesson", ResourceID: "lesson-a", Action: ActionUpdate}, true},
		{CheckRequest{UserID: "user-1", ResourceType: "lesson", ResourceID: "lesson-b", Action: ActionUpdate}, false},
	}
	for _, check := range checks {
		got, err := manager.Check(ctx, check.request)
		if err != nil || got != check.want {
			t.Errorf("Check(%+v) = (%v, %v), want %v", check.request, got, err, check.want)
		}
	}

	if err := manager.UnassignRole(ctx, "user-1", "editor", Scope{Type: "guide", ID: "guide-a"}); err != nil {
		t.Fatal(err)
	}
	allowed, err := manager.Check(ctx, CheckRequest{
		UserID: "user-1", ResourceType: "lesson", ResourceID: "lesson-a", Action: ActionUpdate,
	})
	if err != nil || allowed {
		t.Fatalf("revoked role Check() = (%v, %v), want false", allowed, err)
	}
}

func TestScopedPoliciesProtectPrivateResourcesAndEscalation(t *testing.T) {
	ctx := context.Background()
	repo := NewMockRepo()
	manager := NewMockRepoManager(repo)
	manager.Resolver = mapResolver{
		{Type: "submission", ID: "submission-1"}: {Type: "class", ID: "class-a"},
	}
	manager.Inheritance = ActionInheritancePolicy{Action("grade"): true}
	addRolePermission(t, repo, "teacher", "grade-submission", "submission", Action("grade"))
	addRolePermission(t, repo, "editor", "read-submission", "submission", ActionRead)
	addRolePermission(t, repo, "owner", "manage-permissions", "workspace", Action("manage_permissions"))

	for _, assignment := range []RoleAssignment{
		{UserID: "teacher-1", RoleID: "teacher", Scope: Scope{Type: "class", ID: "class-a"}},
		{UserID: "editor-1", RoleID: "editor", Scope: Scope{Type: "class", ID: "class-a"}},
		{UserID: "owner-1", RoleID: "owner", Scope: Scope{Type: "workspace", ID: "workspace-a"}},
	} {
		if err := manager.AssignRole(ctx, assignment); err != nil {
			t.Fatal(err)
		}
	}

	allowed, err := manager.Check(ctx, CheckRequest{UserID: "teacher-1", ResourceType: "submission", ResourceID: "submission-1", Action: Action("grade")})
	if err != nil || !allowed {
		t.Fatalf("teacher grade Check() = (%v, %v), want true", allowed, err)
	}
	allowed, err = manager.Check(ctx, CheckRequest{UserID: "editor-1", ResourceType: "submission", ResourceID: "submission-1", Action: ActionRead})
	if err != nil || allowed {
		t.Fatalf("editor private submission Check() = (%v, %v), want false", allowed, err)
	}
	allowed, err = manager.Check(ctx, CheckRequest{UserID: "owner-1", ResourceType: "workspace", ResourceID: "workspace-b", Action: Action("manage_permissions")})
	if err != nil || allowed {
		t.Fatalf("cross-workspace escalation Check() = (%v, %v), want false", allowed, err)
	}
}

func TestSameUserCanBeTeacherAndStudentInDifferentClasses(t *testing.T) {
	ctx := context.Background()
	repo := NewMockRepo()
	manager := NewMockRepoManager(repo)
	addRolePermission(t, repo, "teacher", "grade-class", "class", Action("grade"))
	addRolePermission(t, repo, "student", "read-class", "class", ActionRead)
	for _, assignment := range []RoleAssignment{
		{UserID: "user-1", RoleID: "teacher", Scope: Scope{Type: "class", ID: "class-a"}},
		{UserID: "user-1", RoleID: "student", Scope: Scope{Type: "class", ID: "class-b"}},
	} {
		if err := manager.AssignRole(ctx, assignment); err != nil {
			t.Fatal(err)
		}
	}
	checks := []struct {
		class  string
		action Action
		want   bool
	}{
		{"class-a", Action("grade"), true},
		{"class-b", Action("grade"), false},
		{"class-b", ActionRead, true},
		{"class-a", ActionRead, false},
	}
	for _, check := range checks {
		allowed, err := manager.Check(ctx, CheckRequest{UserID: "user-1", ResourceType: "class", ResourceID: check.class, Action: check.action})
		if err != nil || allowed != check.want {
			t.Errorf("Check(class=%s, action=%s) = (%v, %v), want %v", check.class, check.action, allowed, err, check.want)
		}
	}
}

func TestPlatformAssignmentsAndLegacyRolesRemainCompatible(t *testing.T) {
	ctx := context.Background()
	repo := NewMockRepo()
	manager := NewMockRepoManager(repo)
	addRolePermission(t, repo, "moderator", "moderate", "community", Action("moderate"))
	addRolePermission(t, repo, "legacy", "legacy-read", "guide", ActionRead)
	if err := manager.AssignRole(ctx, RoleAssignment{UserID: "user-1", RoleID: "moderator", Scope: PlatformScope()}); err != nil {
		t.Fatal(err)
	}
	if err := manager.AssignRoleToUser(ctx, "user-1", "legacy"); err != nil {
		t.Fatal(err)
	}
	allowed, err := manager.Check(ctx, CheckRequest{UserID: "user-1", ResourceType: "community", ResourceID: "post-1", Action: Action("moderate")})
	if err != nil || !allowed {
		t.Fatalf("platform Check() = (%v, %v), want true", allowed, err)
	}
	allowed, err = manager.Check(ctx, CheckRequest{UserID: "user-1", ResourceType: "guide", ResourceID: "any-guide", Action: ActionRead})
	if err != nil || !allowed {
		t.Fatalf("legacy Check() = (%v, %v), want true", allowed, err)
	}
}

func TestCheckRejectsResolverCyclesAndDepthOverflow(t *testing.T) {
	ctx := context.Background()
	repo := NewMockRepo()
	manager := NewMockRepoManager(repo)
	manager.Inheritance = ActionInheritancePolicy{ActionRead: true}
	manager.Resolver = mapResolver{
		{Type: "lesson", ID: "one"}: {Type: "module", ID: "two"},
		{Type: "module", ID: "two"}: {Type: "lesson", ID: "one"},
	}
	_, err := manager.Check(ctx, CheckRequest{UserID: "user", ResourceType: "lesson", ResourceID: "one", Action: ActionRead})
	if !errors.Is(err, ErrResolverCycle) {
		t.Fatalf("cycle Check() error = %v, want %v", err, ErrResolverCycle)
	}

	manager.MaxInheritanceDepth = 1
	manager.Resolver = mapResolver{
		{Type: "lesson", ID: "one"}: {Type: "module", ID: "two"},
	}
	_, err = manager.Check(ctx, CheckRequest{UserID: "user", ResourceType: "lesson", ResourceID: "one", Action: ActionRead})
	if !errors.Is(err, ErrResolverDepth) {
		t.Fatalf("depth Check() error = %v, want %v", err, ErrResolverDepth)
	}
}
