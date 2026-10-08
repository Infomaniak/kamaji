// Copyright 2022 Clastix Labs
// SPDX-License-Identifier: Apache-2.0

package datastore

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/go-sql-driver/mysql"

	kamajiv1alpha1 "github.com/clastix/kamaji/api/v1alpha1"
	"github.com/clastix/kamaji/internal/datastore/errors"
)

const (
	defaultProtocol = "tcp"
	sqlErrorNoRows  = "sql: no rows in result set"
)

const (
	// Identifiers (database and user names) cannot be passed as bind parameters,
	// so the `%s` verbs below must only ever be fed values run through
	// quoteMySQLIdentifier; the password literal must be fed escapeMySQLString.
	mysqlFetchUserStatement        = "SELECT User FROM mysql.user WHERE User= ? LIMIT 1"
	mysqlFetchDBStatement          = "SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA WHERE SCHEMA_NAME=? LIMIT 1"
	mysqlCreateDBStatement         = "CREATE DATABASE IF NOT EXISTS %s"
	mysqlCreateUserStatement       = "CREATE USER %s@`%%` IDENTIFIED BY '%s'"
	mysqlUpdateUserStatement       = "ALTER USER %s@`%%` IDENTIFIED BY '%s'"
	mysqlGrantPrivilegesStatement  = "GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX ON %s.* TO %s@`%%`"
	mysqlDropDBStatement           = "DROP DATABASE IF EXISTS %s"
	mysqlDropUserStatement         = "DROP USER IF EXISTS %s"
	mysqlRevokePrivilegesStatement = "REVOKE ALL PRIVILEGES ON %s.* FROM %s"
	mysqlCheckGrantsStatement      = `
		SELECT 1
		FROM mysql.db
		WHERE user = ? AND db = ? AND host = '%'
		  AND Select_priv = 'Y'
		  AND Insert_priv = 'Y'
		  AND Update_priv = 'Y'
		  AND Delete_priv = 'Y'
		  AND Create_priv = 'Y'
		  AND Alter_priv = 'Y'
		  AND Index_priv = 'Y'
	`
)

type MySQLConnection struct {
	db        *sql.DB
	config    *mysql.Config
	connector ConnectionEndpoint
	caPEM     []byte
	certPEM   []byte
	keyPEM    []byte
}

// writeTLSFiles writes any configured CA/client cert/key PEM blobs to dir and
// returns the mysql-client CLI flags needed to use them (empty if no TLS is set).
func (c *MySQLConnection) writeTLSFiles(dir string) ([]string, error) {
	var args []string

	write := func(name string, content []byte) (string, error) {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, content, 0o600); err != nil {
			return "", fmt.Errorf("unable to write %s: %w", name, err)
		}

		return p, nil
	}

	if len(c.caPEM) > 0 {
		p, err := write("ca.pem", c.caPEM)
		if err != nil {
			return nil, err
		}

		args = append(args, "--ssl-ca="+p)
	}

	if len(c.certPEM) > 0 && len(c.keyPEM) > 0 {
		certPath, err := write("client-cert.pem", c.certPEM)
		if err != nil {
			return nil, err
		}

		keyPath, err := write("client-key.pem", c.keyPEM)
		if err != nil {
			return nil, err
		}

		args = append(args, "--ssl-cert="+certPath, "--ssl-key="+keyPath)
	}

	return args, nil
}

// resolveClientBinary looks up primary on PATH, falling back to secondary if it isn't
// found. Recent official MariaDB images (11.4+) only ship the mariadb/mariadb-dump
// binaries and no longer install the mysql/mysqldump compatibility symlinks, while a
// real MySQL image - or an older MariaDB tag - only has the mysql-named ones. Resolving
// at runtime keeps this working regardless of which image --migrate-image points at.
func resolveClientBinary(primary, secondary string) (string, error) {
	if path, err := exec.LookPath(primary); err == nil {
		return path, nil
	}

	if path, err := exec.LookPath(secondary); err == nil {
		return path, nil
	}

	return "", fmt.Errorf("neither %q nor %q found on PATH", primary, secondary)
}

// Migrate copies the schema's data from c (origin) to target using the official,
// actively maintained mysqldump/mysql client binaries (dump-to-file, then restore
// from that file), instead of the previous in-process github.com/JamesStewy/go-mysqldump
// based implementation. That library (unmaintained since 2018) writes BLOB/TEXT
// values with zero escaping - a bare value.String wrapped in '...' - so any value
// containing a backslash immediately followed by a quote silently loses bytes on
// restore. That pattern is routine in Kubernetes-stored objects (managedFields,
// annotations holding escaped JSON), and the resulting truncation makes
// kube-apiserver fail to decode objects on its first full watch-cache resync
// after migration, while the migrate Job itself reports success. --hex-blob makes
// BLOB/TEXT values unambiguous 0x<hex> literals, sidestepping escaping entirely.
func (c *MySQLConnection) Migrate(ctx context.Context, tcp kamajiv1alpha1.TenantControlPlane, target Connection) error {
	schema := tcp.Status.Storage.Setup.Schema

	// Ensuring the connection is working as expected
	if err := target.Check(ctx); err != nil {
		return err
	}
	// Creating the target schema if it doesn't exist
	if ok, _ := target.DBExists(ctx, schema); !ok {
		if err := target.CreateDB(ctx, schema); err != nil {
			return err
		}
	}

	targetClient := target.(*MySQLConnection) //nolint:forcetypeassert

	tlsDir, err := os.MkdirTemp("", string(tcp.GetUID())+"-tls")
	if err != nil {
		return fmt.Errorf("unable to create temp directory for MySQL migration TLS material: %w", err)
	}
	defer os.RemoveAll(tlsDir)

	originTLSDir, targetTLSDir := filepath.Join(tlsDir, "origin"), filepath.Join(tlsDir, "target")
	if err = os.MkdirAll(originTLSDir, 0o700); err != nil {
		return fmt.Errorf("unable to create origin TLS directory: %w", err)
	}
	if err = os.MkdirAll(targetTLSDir, 0o700); err != nil {
		return fmt.Errorf("unable to create target TLS directory: %w", err)
	}

	originTLSArgs, err := c.writeTLSFiles(originTLSDir)
	if err != nil {
		return fmt.Errorf("unable to prepare origin TLS material: %w", err)
	}

	targetTLSArgs, err := targetClient.writeTLSFiles(targetTLSDir)
	if err != nil {
		return fmt.Errorf("unable to prepare target TLS material: %w", err)
	}

	dumpArgs := append([]string{
		"--host=" + c.connector.Host,
		"--port=" + strconv.Itoa(c.connector.Port),
		"--user=" + c.config.User,
		"--single-transaction",
		"--hex-blob", // binary-safe: BLOB/TEXT values are emitted as 0x<hex> literals, no string-escaping ambiguity
		"--skip-add-locks",
		"--no-tablespaces",
	}, append(originTLSArgs, schema)...)

	restoreArgs := append([]string{
		"--host=" + targetClient.connector.Host,
		"--port=" + strconv.Itoa(targetClient.connector.Port),
		"--user=" + targetClient.config.User,
	}, append(targetTLSArgs, schema)...)

	// Dump to an intermediate file rather than streaming mysqldump's stdout
	// directly into mysql's stdin via an in-process io.Pipe: with a pipe, Go
	// relays the data through two independently-scheduled copy goroutines
	// (child -> OS pipe -> goroutine -> io.Pipe -> goroutine -> OS pipe -> child),
	// which was observed to interleave/misalign rows under real load. Writing to
	// a file and handing mysql an *os.File for Stdin removes that relay entirely.
	dumpPath := filepath.Join(tlsDir, "dump.sql")

	dumpFile, err := os.Create(dumpPath)
	if err != nil {
		return fmt.Errorf("unable to create MySQL dump file: %w", err)
	}

	dumpBin, err := resolveClientBinary("mariadb-dump", "mysqldump")
	if err != nil {
		return fmt.Errorf("unable to locate a dump client binary: %w", err)
	}

	dumpCmd := exec.CommandContext(ctx, dumpBin, dumpArgs...)
	dumpCmd.Env = append(os.Environ(), "MYSQL_PWD="+c.config.Passwd)
	dumpCmd.Stdout = dumpFile

	var dumpStderr, restoreStderr bytes.Buffer
	dumpCmd.Stderr = &dumpStderr

	dumpErr := dumpCmd.Run()
	closeErr := dumpFile.Close()

	if dumpErr != nil {
		return fmt.Errorf("mysqldump failed: %w (stderr: %s)", dumpErr, dumpStderr.String())
	}

	if closeErr != nil {
		return fmt.Errorf("unable to finalize MySQL dump file: %w", closeErr)
	}

	dumpFileForRestore, err := os.Open(dumpPath)
	if err != nil {
		return fmt.Errorf("unable to reopen MySQL dump file for restore: %w", err)
	}
	defer dumpFileForRestore.Close()

	restoreBin, err := resolveClientBinary("mariadb", "mysql")
	if err != nil {
		return fmt.Errorf("unable to locate a restore client binary: %w", err)
	}

	restoreCmd := exec.CommandContext(ctx, restoreBin, restoreArgs...)
	restoreCmd.Env = append(os.Environ(), "MYSQL_PWD="+targetClient.config.Passwd)
	restoreCmd.Stdin = dumpFileForRestore
	restoreCmd.Stderr = &restoreStderr

	if err = restoreCmd.Run(); err != nil {
		return fmt.Errorf("mysql restore failed: %w (stderr: %s)", err, restoreStderr.String())
	}

	return nil
}

func (c *MySQLConnection) Driver() string {
	return string(kamajiv1alpha1.KineMySQLDriver)
}

func NewMySQLConnection(config ConnectionConfig) (Connection, error) {
	nameDB := fmt.Sprintf("%s(%s)", defaultProtocol, config.Endpoints[0].String())

	var parameters string
	if len(config.Parameters) > 0 {
		parameters = url.Values(config.Parameters).Encode()
	}

	dsn := fmt.Sprintf("%s%s/%s?%s", config.getDataSourceNameUserPassword(), nameDB, config.DBName, parameters)

	mysqlConfig, err := mysql.ParseDSN(dsn)
	if err != nil {
		return nil, err
	}

	tlsKey := "mysql"

	if config.TLSConfig != nil {
		if err = mysql.RegisterTLSConfig(tlsKey, config.TLSConfig); err != nil {
			return nil, err
		}
		mysqlConfig.TLSConfig = tlsKey
	}

	mysqlConfig.DBName = config.DBName
	parsedDSN := mysqlConfig.FormatDSN()

	db, err := sql.Open("mysql", parsedDSN)
	if err != nil {
		return nil, err
	}

	return &MySQLConnection{
		db:        db,
		config:    mysqlConfig,
		connector: config.Endpoints[0],
		caPEM:     config.CACertPEM,
		certPEM:   config.ClientCertPEM,
		keyPEM:    config.ClientKeyPEM,
	}, nil
}

func (c *MySQLConnection) GetConnectionString() string {
	return c.connector.String()
}

func (c *MySQLConnection) Close() error {
	if err := c.db.Close(); err != nil {
		return errors.NewCloseConnectionError(err)
	}

	return nil
}

func (c *MySQLConnection) Check(ctx context.Context) error {
	if err := c.db.PingContext(ctx); err != nil {
		return errors.NewCheckConnectionError(err)
	}

	return nil
}

func (c *MySQLConnection) CreateUser(ctx context.Context, user, password string) error {
	if err := c.mutate(ctx, mysqlCreateUserStatement, quoteMySQLIdentifier(user), escapeMySQLString(password)); err != nil {
		return errors.NewCreateUserError(err)
	}

	return nil
}

func (c *MySQLConnection) UpdateUser(ctx context.Context, user, password string) error {
	if err := c.mutate(ctx, mysqlUpdateUserStatement, quoteMySQLIdentifier(user), escapeMySQLString(password)); err != nil {
		return errors.NewUpdateUserError(err)
	}

	return nil
}

func (c *MySQLConnection) CreateDB(ctx context.Context, dbName string) error {
	if err := c.mutate(ctx, mysqlCreateDBStatement, quoteMySQLIdentifier(dbName)); err != nil {
		return errors.NewCreateDBError(err)
	}

	return nil
}

func (c *MySQLConnection) GrantPrivileges(ctx context.Context, user, dbName string) error {
	if err := c.mutate(ctx, mysqlGrantPrivilegesStatement, quoteMySQLIdentifier(dbName), quoteMySQLIdentifier(user)); err != nil {
		return errors.NewGrantPrivilegesError(err)
	}

	return nil
}

func (c *MySQLConnection) UserExists(ctx context.Context, user string) (bool, error) {
	checker := func(row *sql.Row) (bool, error) {
		var name string
		if err := row.Scan(&name); err != nil {
			if c.checkEmptyQueryResult(err) {
				return false, nil
			}

			return false, err
		}

		return name == user, nil
	}

	ok, err := c.check(ctx, mysqlFetchUserStatement, checker, user)
	if err != nil {
		return false, errors.NewCheckUserExistsError(err)
	}

	return ok, nil
}

func (c *MySQLConnection) DBExists(ctx context.Context, dbName string) (bool, error) {
	checker := func(row *sql.Row) (bool, error) {
		var name string
		if err := row.Scan(&name); err != nil {
			if c.checkEmptyQueryResult(err) {
				return false, nil
			}

			return false, err
		}

		return name == dbName, nil
	}

	ok, err := c.check(ctx, mysqlFetchDBStatement, checker, dbName)
	if err != nil {
		return false, errors.NewCheckDatabaseExistError(err)
	}

	return ok, nil
}

func (c *MySQLConnection) GrantPrivilegesExists(ctx context.Context, user, dbName string) (bool, error) {
	var exists int

	if err := c.db.QueryRowContext(ctx, mysqlCheckGrantsStatement, user, dbName).Scan(&exists); err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}

		return false, errors.NewCheckGrantExistsError(err)
	}

	return true, nil
}

func (c *MySQLConnection) DeleteUser(ctx context.Context, user string) error {
	if err := c.mutate(ctx, mysqlDropUserStatement, quoteMySQLIdentifier(user)); err != nil {
		return errors.NewDeleteUserError(err)
	}

	return nil
}

func (c *MySQLConnection) DeleteDB(ctx context.Context, dbName string) error {
	if err := c.mutate(ctx, mysqlDropDBStatement, quoteMySQLIdentifier(dbName)); err != nil {
		return errors.NewCannotDeleteDatabaseError(err)
	}

	return nil
}

func (c *MySQLConnection) RevokePrivileges(ctx context.Context, user, dbName string) error {
	if err := c.mutate(ctx, mysqlRevokePrivilegesStatement, quoteMySQLIdentifier(dbName), quoteMySQLIdentifier(user)); err != nil {
		return errors.NewRevokePrivilegesError(err)
	}

	return nil
}

func (c *MySQLConnection) check(ctx context.Context, nonFilledStatement string, checker func(*sql.Row) (bool, error), args ...any) (bool, error) {
	statement, err := c.db.PrepareContext(ctx, nonFilledStatement)
	if err != nil {
		return false, err
	}
	defer statement.Close()

	row := statement.QueryRowContext(ctx, args...)

	return checker(row)
}

func (c *MySQLConnection) mutate(ctx context.Context, nonFilledStatement string, args ...any) error {
	statement := fmt.Sprintf(nonFilledStatement, args...)
	if _, err := c.db.ExecContext(ctx, statement); err != nil {
		return err
	}

	return nil
}

func (c *MySQLConnection) checkEmptyQueryResult(err error) bool {
	return err.Error() == sqlErrorNoRows
}

// quoteMySQLIdentifier safely quotes a MySQL identifier (such as a database or
// user name) so it can be interpolated into a statement: it wraps the value in
// backticks and doubles any embedded backtick, neutralising attempts to break
// out of the identifier. NUL bytes, which are illegal in identifiers, are
// stripped. Identifiers cannot be supplied as bind parameters, hence the manual
// quoting.
func quoteMySQLIdentifier(identifier string) string {
	identifier = strings.ReplaceAll(identifier, "\x00", "")

	return "`" + strings.ReplaceAll(identifier, "`", "``") + "`"
}

// escapeMySQLString escapes a value for safe embedding inside a single-quoted
// MySQL string literal. Both ways of breaking out of such a literal are closed
// in a manner that holds under every sql_mode: single quotes are doubled (” is
// a literal quote regardless of NO_BACKSLASH_ESCAPES) and backslashes are
// doubled (so a trailing backslash cannot escape the closing quote when
// backslash escaping is enabled). The remaining control-character escapes are
// conveniences for the default sql_mode. DDL statements such as CREATE USER
// cannot bind the password as a parameter, hence the manual escaping.
func escapeMySQLString(value string) string {
	var b strings.Builder

	for _, r := range value {
		switch r {
		case 0:
			b.WriteString(`\0`)
		case '\'':
			b.WriteString(`''`)
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case 26: // Ctrl+Z
			b.WriteString(`\Z`)
		default:
			b.WriteRune(r)
		}
	}

	return b.String()
}
