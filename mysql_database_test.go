package rbac

import (
	"database/sql"
	"strings"
	"testing"
)

func TestMySQLDatabaseQualification(t *testing.T) {
	database, err := newMySQLDatabase(&sql.DB{}, "jpn_learning_rbac")
	if err != nil {
		t.Fatalf("newMySQLDatabase: %v", err)
	}

	got := database.sql("SELECT * FROM rbacv2.users JOIN rbacv2.roles")
	want := "SELECT * FROM `jpn_learning_rbac`.users JOIN `jpn_learning_rbac`.roles"
	if got != want {
		t.Fatalf("qualified SQL = %q, want %q", got, want)
	}
}

func TestMySQLDatabaseQualificationEscapesIdentifier(t *testing.T) {
	database, err := newMySQLDatabase(&sql.DB{}, "tenant`rbac")
	if err != nil {
		t.Fatalf("newMySQLDatabase: %v", err)
	}
	if got := database.sql("SELECT * FROM rbacv2.users"); got != "SELECT * FROM `tenant``rbac`.users" {
		t.Fatalf("qualified SQL = %q", got)
	}
}

func TestNewMySQLDatabaseRejectsInvalidInputs(t *testing.T) {
	for _, database := range []string{"", "bad\x00name", strings.Repeat("a", 65)} {
		if _, err := newMySQLDatabase(&sql.DB{}, database); err == nil {
			t.Errorf("newMySQLDatabase(%q) succeeded, want error", database)
		}
	}
	if _, err := newMySQLDatabase(nil, "rbac"); err == nil {
		t.Error("newMySQLDatabase(nil, ...) succeeded, want error")
	}
}
