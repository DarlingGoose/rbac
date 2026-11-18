# RBAC Go Package

A flexible, storage-agnostic Role-Based Access Control (RBAC) library for Go. Defines core domain types, repository interfaces, and a high-level `Manager` to handle permission and role checks. Includes a MongoDB implementation, in-memory testing stub, wildcard and fuzzy matching, benchmarks, and unit tests.

## Features

* **Storage-agnostic**: Define `PermissionRepo`, `RoleRepo`, `UserRepo`, `RolePermissionRepo`, and `UserRoleRepo` interfaces to plug in any backend (MongoDB, SQL, in-memory, etc.).
* **High-level Manager**: `Manager` struct orchestrates CRUD and business logic: creating/deleting users, roles, permissions; assigning roles and permissions; checking access via `Can`.
* **Wildcard support**:

    * **Action wildcard** (`*`) grants all actions on a resource (e.g. `survey,*`).
    * **Resource single-segment wildcard** (`*`) matches exactly one segment between dots (e.g. `survey.*.test` matches `survey.foo.test`).
    * **Resource multi-segment wildcard** (`**`) matches zero or more segments (e.g. `survey.**.test` matches `survey.test`, `survey.foo.test`, or `survey.foo.bar.test`).
    * **Global wildcard** (`*`) on resource matches any resource name (e.g. `*`).

## Installation

```bash
go get github.com/DarlingGoose/rbac
```

## Quick Start

```go
package main

import (
  "context"
  "fmt"
  "log/slog"

  "github.com/DarlingGoose/rbac"
  "go.mongodb.org/mongo-driver/mongo"
  "go.mongodb.org/mongo-driver/mongo/options"
)

func main() {
  // MongoDB setup
  client, _ := mongo.Connect(context.Background(), options.Client().ApplyURI("mongodb://localhost:27017"))
  db := client.Database("mydb")

  // Create store and manager
  mgr,err := rbac.NewMongoStoreManager(context.Background(),db)
  if err != nil {
    slog.Error("failed setting up manager","err",err)
    return
  }
  ctx := context.Background()

  // Create a permission and a role
  perm := &rbac.Permission{Resource: "survey.*", Action: rbac.ActionAll}
  err = mgr.CreatePermission(ctx, perm)
  if err != nil {
    slog.Error("failed creating permission","err",err)
	return
  }
  role := &rbac.Role{Name: "admin"}
  err = mgr.CreateRole(ctx, role)
  if err != nil {
    slog.Error("failed creating permission","err",err)
    return
  }
  err = mgr.AssignPermissionToRole(ctx, role.ID, perm.ID)
  if err != nil {
    slog.Error("failed assigning permission to role","err",err)
    return
  }

  // Assign role to user
  user := &rbac.User{Username: "alice", Email: "alice@example.com"}
  err = mgr.CreateUser(ctx, user)
  if err != nil {
    slog.Error("failed creating user","err",err)
    return
  }
  
  err = mgr.AssignRoleToUser(ctx, user.ID, role.ID)
  if err != nil {
    slog.Error("failed assigning user to role","err",err)
    return
  }

  // Check access
  ok, _ := mgr.Can(ctx, user.ID, "survey.123.test", rbac.ActionRead)
  fmt.Println("Access granted?", ok)
}
```

## Scoped role assignments

Global assignments made with `AssignRoleToUser` remain supported. For resource isolation, PostgreSQL-backed and in-memory managers also expose scoped assignments:

```go
err := mgr.AssignRole(ctx, rbac.RoleAssignment{
  UserID: "user-123",
  RoleID: teacherRole.ID,
  Scope:  rbac.Scope{Type: "guide", ID: "guide-456"},
})

allowed, err := mgr.Check(ctx, rbac.CheckRequest{
  UserID:       "user-123",
  ResourceType: "guide",
  ResourceID:   "guide-456",
  Action:       rbac.ActionUpdate,
})
```

`Check` is the request-based API; the original `Can(ctx, userID, resource, action)` method remains available for global roles. Legacy user and group roles are treated as global grants by `Check`, which permits gradual migration from `user_roles`.

Use `PlatformScope()` for a deliberately global scoped assignment. Scope IDs are always non-empty; the platform scope uses a normalized sentinel ID so PostgreSQL uniqueness cannot be bypassed with `NULL` values.

### Resource inheritance

Inheritance is disabled unless both `Manager.Resolver` and `Manager.Inheritance` are configured. The application supplies ancestry without exposing its content tables to this package:

```go
type contentResolver struct { /* application repositories */ }

func (r *contentResolver) Parent(ctx context.Context, ref rbac.ResourceRef) (*rbac.ResourceRef, error) {
  // For example, resolve lesson -> module -> guide -> workspace.
  return nil, nil
}

mgr.Resolver = &contentResolver{}
mgr.Inheritance = rbac.ActionInheritancePolicy{
  rbac.ActionRead:   true,
  rbac.ActionUpdate: true,
}
```

Only the listed actions inherit ancestor assignments. Resolution fails closed on repository errors, cycles, malformed parents, or more than 32 parent lookups by default. Set `MaxInheritanceDepth` to a smaller application-specific bound when appropriate.

### Application relationships

RBAC grants do not replace ownership, enrollment, publication, or privacy checks. For a private submission, first allow the submitting student based on the application's verified ownership relationship; otherwise call `Check` for a role with `grade` permission on the submission's class ancestry. A guide editor should not receive submission access unless its role has the relevant permission and that action is explicitly inheritable.

### PostgreSQL migration notes

`NewPostgresStore` creates `rbac.role_assignments`, including foreign keys, cascade behavior, a non-null normalized scope, uniqueness, and a user/scope lookup index. Existing `user_roles` data is retained. The legacy join tables also receive foreign keys with cascading deletes; upgrading a database that already contains orphaned join rows will fail schema initialization until those rows are repaired.

The existing core tables remain in their historical schema for compatibility. New applications that share a database should isolate RBAC objects at the database or schema level and decide whether the library's `users` table or application-owned user identifiers are authoritative before deployment.

## Testing

* **Unit tests**:

  ```bash
    go test ./...   # includes CRUD, wildcard, fuzzy tests
  ```




* **Benchmarks**:

    ```bash
    go test -bench=. ./...
    ```
  
    ```bash
    goos: linux
    goarch: amd64
    pkg: github.com/DarlingGoose/rbac
    cpu: AMD Ryzen 7 3700X 8-Core Processor             
    BenchmarkCan_NoRoles-16                          2158071               596.0 ns/op
    BenchmarkCan_SingleRoleSinglePerm-16              953500              1084 ns/op
    BenchmarkCan_ManyRolesManyPerms-16                169365              7284 ns/op
    BenchmarkCan_ResourceWildcard-16                  894992              1210 ns/op
    PASS
    ok      github.com/DarlingGoose/rbac     5.322s
    ```
## Contributing

1. Fork the repo
2. Create a feature branch (`git checkout -b feat/your-feature`)
3. Write code and tests
4. Update this README
5. Submit a pull request

## License

MIT © Seann Moser
