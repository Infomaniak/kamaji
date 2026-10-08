// Copyright 2022 Clastix Labs
// SPDX-License-Identifier: Apache-2.0

package datastore

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	kamajiv1alpha1 "github.com/clastix/kamaji/api/v1alpha1"
)

// TestMySQLMigrateHexBlobRoundTrip is a regression test for the data-loss bug fixed by
// switching Migrate() from github.com/JamesStewy/go-mysqldump to the real mysqldump/mysql
// (or mariadb-dump/mariadb) CLI binaries with --hex-blob: go-mysqldump wrote BLOB/TEXT
// values with zero escaping, so a value containing a backslash immediately followed by a
// quote silently lost bytes on restore - exactly the shape of Kubernetes-stored objects
// (managedFields, escaped-JSON annotations). It spins up two real MariaDB containers via
// testcontainers-go, migrates a row containing that exact byte pattern, and asserts the
// restored value is byte-identical to the original.
//
// Opt-in only (needs Docker + mariadb-dump/mariadb or mysqldump/mysql on PATH):
// KAMAJI_MYSQL_MIGRATE_IT=1 go test ./internal/datastore/ -run TestMySQLMigrateHexBlobRoundTrip -v
func TestMySQLMigrateHexBlobRoundTrip(t *testing.T) {
	if os.Getenv("KAMAJI_MYSQL_MIGRATE_IT") == "" {
		t.Skip("set KAMAJI_MYSQL_MIGRATE_IT=1 to run (spins up real MariaDB containers via Docker)")
	}

	if _, err := resolveClientBinary("mariadb-dump", "mysqldump"); err != nil {
		t.Skipf("no dump client binary on PATH: %v", err)
	}

	if _, err := resolveClientBinary("mariadb", "mysql"); err != nil {
		t.Skipf("no restore client binary on PATH: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	source := startMariaDB(ctx, t)
	target := startMariaDB(ctx, t)

	const schema = "testschema"

	// Reproduces exactly the trigger described in the Migrate() fix: a BLOB value
	// containing a backslash immediately followed by a single quote. The old
	// go-mysqldump implementation wrapped BLOB values in '...' with zero escaping,
	// so this byte sequence closed the literal early and truncated the value.
	original := []byte("prefix\\'managedFields-like-payload\\'suffix\x00\xffbinary")

	setupDB, err := sql.Open("mysql", source.dsn(""))
	if err != nil {
		t.Fatalf("open source setup connection: %v", err)
	}
	defer setupDB.Close()

	mustExec(t, setupDB, fmt.Sprintf("CREATE DATABASE `%s`", schema))
	mustExec(t, setupDB, fmt.Sprintf("CREATE TABLE `%s`.kine (id BIGINT PRIMARY KEY, value MEDIUMBLOB)", schema))

	if _, err = setupDB.ExecContext(ctx, fmt.Sprintf("INSERT INTO `%s`.kine (id, value) VALUES (1, ?)", schema), original); err != nil {
		t.Fatalf("seed source row: %v", err)
	}

	sourceConn, err := NewMySQLConnection(ConnectionConfig{
		User:      "root",
		Password:  "root",
		Endpoints: []ConnectionEndpoint{{Host: source.host, Port: source.port}},
	})
	if err != nil {
		t.Fatalf("NewMySQLConnection(source): %v", err)
	}

	targetConn, err := NewMySQLConnection(ConnectionConfig{
		User:      "root",
		Password:  "root",
		Endpoints: []ConnectionEndpoint{{Host: target.host, Port: target.port}},
	})
	if err != nil {
		t.Fatalf("NewMySQLConnection(target): %v", err)
	}

	tcp := kamajiv1alpha1.TenantControlPlane{
		ObjectMeta: metav1.ObjectMeta{UID: types.UID("test-migrate-uid")},
	}
	tcp.Status.Storage.Setup.Schema = schema

	if err = sourceConn.Migrate(ctx, tcp, targetConn); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	verifyDB, err := sql.Open("mysql", target.dsn(schema))
	if err != nil {
		t.Fatalf("open target verify connection: %v", err)
	}
	defer verifyDB.Close()

	var got []byte

	if err = verifyDB.QueryRowContext(ctx, "SELECT value FROM kine WHERE id = 1").Scan(&got); err != nil {
		t.Fatalf("read back migrated row: %v", err)
	}

	if !bytes.Equal(got, original) {
		t.Fatalf("migrated value corrupted:\n got  = %q (%d bytes)\n want = %q (%d bytes)", got, len(got), original, len(original))
	}
}

func mustExec(t *testing.T, db *sql.DB, query string) {
	t.Helper()

	if _, err := db.Exec(query); err != nil {
		t.Fatalf("exec %q: %v", query, err)
	}
}

type mariadbContainer struct {
	testcontainers.Container
	host string
	port int
}

func (m mariadbContainer) dsn(dbName string) string {
	return fmt.Sprintf("root:root@tcp(%s:%d)/%s?parseTime=true", m.host, m.port, dbName)
}

func startMariaDB(ctx context.Context, t *testing.T) mariadbContainer {
	t.Helper()

	req := testcontainers.ContainerRequest{
		Image:        "mariadb:11.4",
		ExposedPorts: []string{"3306/tcp"},
		Env: map[string]string{
			"MARIADB_ROOT_PASSWORD": "root",
		},
		WaitingFor: wait.ForLog("ready for connections").WithOccurrence(2).WithStartupTimeout(90 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		t.Fatalf("start mariadb container: %v", err)
	}

	t.Cleanup(func() {
		_ = container.Terminate(context.Background())
	})

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("container host: %v", err)
	}

	mappedPort, err := container.MappedPort(ctx, "3306/tcp")
	if err != nil {
		t.Fatalf("container mapped port: %v", err)
	}

	return mariadbContainer{Container: container, host: host, port: int(mappedPort.Num())}
}
