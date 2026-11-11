
package com.pritamx.thunderantialt;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

public final class DatabaseIntegrity {

    private DatabaseIntegrity() {
    }

    /**
     * Installs database security triggers and verifies
     * existing account relationships.
     *
     * Existing records are never automatically deleted.
     */
    public static void installAndVerify(Connection db)
            throws SQLException {

        if (db == null || db.isClosed()) {
            throw new SQLException(
                    "Database connection is unavailable."
            );
        }

        boolean oldAutoCommit = db.getAutoCommit();
        SQLException originalException = null;

        try {
            db.setAutoCommit(false);

            verifyExistingRelationships(db);

            try (Statement statement = db.createStatement()) {

                statement.execute("""
                    CREATE TRIGGER IF NOT EXISTS
                    trg_alt_owner_insert
                    BEFORE INSERT ON authorized_accounts
                    FOR EACH ROW
                    WHEN NOT EXISTS (
                        SELECT 1
                        FROM main_accounts
                        WHERE main_uuid = NEW.owner_uuid
                    )
                    BEGIN
                        SELECT RAISE(
                            ABORT,
                            'Alt owner is not a registered Main account.'
                        );
                    END
                    """);

                statement.execute("""
                    CREATE TRIGGER IF NOT EXISTS
                    trg_alt_owner_update
                    BEFORE UPDATE OF owner_uuid
                    ON authorized_accounts
                    FOR EACH ROW
                    WHEN NOT EXISTS (
                        SELECT 1
                        FROM main_accounts
                        WHERE main_uuid = NEW.owner_uuid
                    )
                    BEGIN
                        SELECT RAISE(
                            ABORT,
                            'Alt owner is not a registered Main account.'
                        );
                    END
                    """);

                statement.execute("""
                    CREATE TRIGGER IF NOT EXISTS
                    trg_alt_not_main_insert
                    BEFORE INSERT ON authorized_accounts
                    FOR EACH ROW
                    WHEN EXISTS (
                        SELECT 1
                        FROM main_accounts
                        WHERE main_uuid = NEW.authorized_uuid
                    )
                    BEGIN
                        SELECT RAISE(
                            ABORT,
                            'A Main account cannot be registered as an Alt.'
                        );
                    END
                    """);

                statement.execute("""
                    CREATE TRIGGER IF NOT EXISTS
                    trg_alt_not_main_update
                    BEFORE UPDATE OF authorized_uuid
                    ON authorized_accounts
                    FOR EACH ROW
                    WHEN EXISTS (
                        SELECT 1
                        FROM main_accounts
                        WHERE main_uuid = NEW.authorized_uuid
                    )
                    BEGIN
                        SELECT RAISE(
                            ABORT,
                            'A Main account cannot be registered as an Alt.'
                        );
                    END
                    """);

                statement.execute("""
                    CREATE TRIGGER IF NOT EXISTS
                    trg_main_not_alt_insert
                    BEFORE INSERT ON main_accounts
                    FOR EACH ROW
                    WHEN EXISTS (
                        SELECT 1
                        FROM authorized_accounts
                        WHERE authorized_uuid = NEW.main_uuid
                    )
                    BEGIN
                        SELECT RAISE(
                            ABORT,
                            'An authorized Alt cannot become a Main.'
                        );
                    END
                    """);

                statement.execute("""
                    CREATE TRIGGER IF NOT EXISTS
                    trg_main_not_alt_update
                    BEFORE UPDATE OF main_uuid
                    ON main_accounts
                    FOR EACH ROW
                    WHEN EXISTS (
                        SELECT 1
                        FROM authorized_accounts
                        WHERE authorized_uuid = NEW.main_uuid
                    )
                    BEGIN
                        SELECT RAISE(
                            ABORT,
                            'An authorized Alt cannot become a Main.'
                        );
                    END
                    """);

                statement.execute("""
                    CREATE TRIGGER IF NOT EXISTS
                    trg_main_protect_delete
                    BEFORE DELETE ON main_accounts
                    FOR EACH ROW
                    WHEN EXISTS (
                        SELECT 1
                        FROM authorized_accounts
                        WHERE owner_uuid = OLD.main_uuid
                    )
                    BEGIN
                        SELECT RAISE(
                            ABORT,
                            'Remove linked Alt authorizations before deleting Main.'
                        );
                    END
                    """);
            }

            verifyExistingRelationships(db);

            db.commit();

        } catch (SQLException exception) {

            originalException = exception;

            try {
                db.rollback();
            } catch (SQLException rollbackError) {
                exception.addSuppressed(rollbackError);
            }

            throw exception;

        } finally {

            try {
                db.setAutoCommit(oldAutoCommit);

            } catch (SQLException restoreError) {

                if (originalException != null) {
                    originalException.addSuppressed(restoreError);
                } else {
                    throw restoreError;
                }
            }
        }
    }

    /**
     * Checks for orphan Alt owners and conflicting
     * Main/Alt records.
     */
    private static void verifyExistingRelationships(Connection db)
            throws SQLException {

        try (PreparedStatement ps = db.prepareStatement("""
                SELECT a.authorized_uuid, a.owner_uuid
                FROM authorized_accounts a
                LEFT JOIN main_accounts m
                    ON m.main_uuid = a.owner_uuid
                WHERE m.main_uuid IS NULL
                LIMIT 1
                """);
             ResultSet rs = ps.executeQuery()) {

            if (rs.next()) {
                throw new SQLException(
                        "Orphan Alt authorization detected. Alt UUID: "
                                + rs.getString("authorized_uuid")
                                + ", Owner UUID: "
                                + rs.getString("owner_uuid")
                );
            }
        }

        try (PreparedStatement ps = db.prepareStatement("""
                SELECT a.authorized_uuid
                FROM authorized_accounts a
                INNER JOIN main_accounts m
                    ON m.main_uuid = a.authorized_uuid
                LIMIT 1
                """);
             ResultSet rs = ps.executeQuery()) {

            if (rs.next()) {
                throw new SQLException(
                        "Conflicting Main/Alt registration detected. UUID: "
                                + rs.getString("authorized_uuid")
                );
            }
        }
    }
}
