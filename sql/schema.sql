CREATE TABLE IF NOT EXISTS audit_log (
    audit_table TEXT NOT NULL,
    audit_id TEXT NOT NULL,
    audit_column TEXT NOT NULL,
    old_mtime INTEGER NOT NULL,
    new_mtime INTEGER NOT NULL,
    old_signature TEXT NOT NULL UNIQUE,
    new_signature TEXT NOT NULL UNIQUE,
    details TEXT NOT NULL, -- Stored as JSON string
    insert_order INTEGER PRIMARY KEY AUTOINCREMENT,
    ctime INTEGER DEFAULT (strftime('%s', 'now'))
);

CREATE TABLE IF NOT EXISTS org (
    id TEXT UNIQUE NOT NULL CHECK (id != '00000000-0000-0000-0000-000000000000'),
    insert_order INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL CHECK (name != ''),
    owner TEXT NOT NULL CHECK (owner != '00000000-0000-0000-0000-000000000000'),

    -- common model metadata
    ctime INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    mtime INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    -- `role` == 1 is constant `$GL::Attribute::ROLE_NORMAL`.
    -- `role` == 2 is constant `$GL::Attribute::ROLE_ADMIN`.
    -- `role` == 3 is constant `$GL::Attribute::ROLE_TEST`.
    role INTEGER NOT NULL CHECK (role > 0 AND role < 4),
    schema_version INTEGER NOT NULL DEFAULT 0 CHECK (schema_version >= 0 AND schema_version <= 99999),
    -- `uuid()` is a custom function.
    signature TEXT UNIQUE NOT NULL DEFAULT (uuid()),
    -- `status` == 1 is constant `$GL::Attribute::STATUS_UNCONFIRMED`.
    -- `status` == 2 is constant `$GL::Attribute::STATUS_ACTIVE`.
    -- `status` == 3 is constant `$GL::Attribute::STATUS_INACTIVE`.
    status INTEGER NOT NULL CHECK (status > 0 AND status < 4)
);

CREATE TRIGGER update_org_metadata BEFORE UPDATE ON org
FOR EACH ROW
BEGIN
    UPDATE org SET 
        mtime = strftime('%s', 'now'),
        signature = uuid()
    WHERE id = OLD.id;
END;

CREATE TRIGGER org_audit_update_owner AFTER UPDATE OF owner ON org
WHEN OLD.owner != NEW.owner
BEGIN
    INSERT INTO audit_log (audit_table, audit_id, audit_column, old_mtime, new_mtime, old_signature, new_signature, details)
    VALUES ('org', OLD.id, 'owner', OLD.mtime, NEW.mtime, OLD.signature, NEW.signature, 
            json_object('old', OLD.owner, 'new', NEW.owner));
END;

CREATE TRIGGER org_audit_update_status AFTER UPDATE OF status ON org
WHEN OLD.status != NEW.status
BEGIN
    INSERT INTO audit_log (audit_table, audit_id, audit_column, old_mtime, new_mtime, old_signature, new_signature, details)
    VALUES ('org', OLD.id, 'status', OLD.mtime, NEW.mtime, OLD.signature, NEW.signature, 
            json_object('old', OLD.status, 'new', NEW.status));
END;

CREATE TABLE IF NOT EXISTS repository (
    id TEXT UNIQUE NOT NULL CHECK (id != '00000000-0000-0000-0000-000000000000'),
    insert_order INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL CHECK (name != ''),
    org TEXT NOT NULL CHECK (org != '00000000-0000-0000-0000-000000000000'),
    owner TEXT NOT NULL CHECK (owner != '00000000-0000-0000-0000-000000000000'),
    path TEXT NOT NULL CHECK (path != ''),

    -- common model metadata
    ctime INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    mtime INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    -- `role` == 1 is constant `$GL::Attribute::ROLE_NORMAL`.
    -- `role` == 2 is constant `$GL::Attribute::ROLE_ADMIN`.
    -- `role` == 3 is constant `$GL::Attribute::ROLE_TEST`.
    role INTEGER NOT NULL CHECK (role > 0 AND role < 4),
    schema_version INTEGER NOT NULL DEFAULT 0 CHECK (schema_version >= 0 AND schema_version <= 99999),
    -- `uuid()` is a custom function.
    signature TEXT UNIQUE NOT NULL DEFAULT (uuid()),
    -- `status` == 1 is constant `$GL::Attribute::STATUS_UNCONFIRMED`.
    -- `status` == 2 is constant `$GL::Attribute::STATUS_ACTIVE`.
    -- `status` == 3 is constant `$GL::Attribute::STATUS_INACTIVE`.
    status INTEGER NOT NULL CHECK (status > 0 AND status < 4)
);
CREATE UNIQUE INDEX IF NOT EXISTS repository_name_owner ON repository (name, owner);

CREATE TRIGGER update_repository_metadata BEFORE UPDATE ON repository
FOR EACH ROW
BEGIN
    UPDATE repository SET 
        mtime = strftime('%s', 'now'),
        signature = uuid()
    WHERE id = OLD.id;
END;

CREATE TRIGGER repository_audit_update_owner AFTER UPDATE OF owner ON repository
WHEN OLD.owner != NEW.owner
BEGIN
    INSERT INTO audit_log (audit_table, audit_id, audit_column, old_mtime, new_mtime, old_signature, new_signature, details)
    VALUES ('repository', OLD.id, 'owner', OLD.mtime, NEW.mtime, OLD.signature, NEW.signature, 
            json_object('old', OLD.owner, 'new', NEW.owner));
END;

CREATE TRIGGER repository_audit_update_status AFTER UPDATE OF status ON repository
WHEN OLD.status != NEW.status
BEGIN
    INSERT INTO audit_log (audit_table, audit_id, audit_column, old_mtime, new_mtime, old_signature, new_signature, details)
    VALUES ('repository', OLD.id, 'status', OLD.mtime, NEW.mtime, OLD.signature, NEW.signature, 
            json_object('old', OLD.status, 'new', NEW.status));
END;

CREATE TRIGGER repository_audit_update_path AFTER UPDATE OF path ON repository
WHEN OLD.path != NEW.path
BEGIN
    INSERT INTO audit_log (audit_table, audit_id, audit_column, old_mtime, new_mtime, old_signature, new_signature, details)
    VALUES ('repository', OLD.id, 'path', OLD.mtime, NEW.mtime, OLD.signature, NEW.signature, 
            json_object('old', OLD.path, 'new', NEW.path));
END;

CREATE TABLE IF NOT EXISTS user (
    ed25519_public TEXT NOT NULL CHECK (ed25519_public != ''),
    ed25519_public_digest TEXT NOT NULL CHECK (ed25519_public_digest != ''),
    display_name TEXT NOT NULL CHECK (display_name != ''),
    display_name_digest TEXT NOT NULL CHECK (display_name_digest != ''),
    email TEXT NOT NULL CHECK (email != ''),
    email_digest TEXT NOT NULL CHECK (email_digest != ''),
    id TEXT UNIQUE NOT NULL CHECK (id != '00000000-0000-0000-0000-000000000000'),
    insert_order INTEGER PRIMARY KEY AUTOINCREMENT,
    key_version TEXT NOT NULL CHECK (key_version != '00000000-0000-0000-0000-000000000000'),
    org TEXT NOT NULL CHECK (org != '00000000-0000-0000-0000-000000000000'),
    password TEXT NOT NULL CHECK (password LIKE '$argon2%'),

    -- common model metadata
    ctime INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    mtime INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    -- `role` == 1 is constant `$GL::Attribute::ROLE_NORMAL`.
    -- `role` == 2 is constant `$GL::Attribute::ROLE_ADMIN`.
    -- `role` == 3 is constant `$GL::Attribute::ROLE_TEST`.
    role INTEGER NOT NULL CHECK (role > 0 AND role < 4),
    schema_version INTEGER NOT NULL DEFAULT 0 CHECK (schema_version >= 0 AND schema_version <= 99999),
    -- `uuid()` is a custom function.
    signature TEXT UNIQUE NOT NULL DEFAULT (uuid()),
    -- `status` == 1 is constant `$GL::Attribute::STATUS_UNCONFIRMED`.
    -- `status` == 2 is constant `$GL::Attribute::STATUS_ACTIVE`.
    -- `status` == 3 is constant `$GL::Attribute::STATUS_INACTIVE`.
    status INTEGER NOT NULL CHECK (status > 0 AND status < 4)
);
CREATE UNIQUE INDEX IF NOT EXISTS user_email_digest_org ON user (email_digest, org);
CREATE UNIQUE INDEX IF NOT EXISTS user_ed25519_public_digest_org ON user (ed25519_public_digest, org);

CREATE TRIGGER update_user_metadata BEFORE UPDATE ON user
FOR EACH ROW
BEGIN
    UPDATE user SET 
        mtime = strftime('%s', 'now'),
        signature = uuid()
    WHERE id = OLD.id;
END;

CREATE TRIGGER user_audit_update_digest AFTER UPDATE OF ed25519_public_digest ON user
WHEN OLD.ed25519_public_digest != NEW.ed25519_public_digest
BEGIN
    INSERT INTO audit_log (audit_table, audit_id, audit_column, old_mtime, new_mtime, old_signature, new_signature, details)
    VALUES ('user', OLD.id, 'ed25519_public_digest', OLD.mtime, NEW.mtime, OLD.signature, NEW.signature, 
            json_object('old', OLD.ed25519_public_digest, 'new', NEW.ed25519_public_digest));
END;

CREATE TRIGGER user_audit_update_display_name AFTER UPDATE OF display_name_digest ON user
WHEN OLD.display_name_digest != NEW.display_name_digest
BEGIN
    INSERT INTO audit_log (audit_table, audit_id, audit_column, old_mtime, new_mtime, old_signature, new_signature, details)
    VALUES ('user', OLD.id, 'display_name_digest', OLD.mtime, NEW.mtime, OLD.signature, NEW.signature, 
            json_object('old', OLD.display_name_digest, 'new', NEW.display_name_digest));
END;

CREATE TRIGGER user_audit_update_key_version AFTER UPDATE OF key_version ON user
WHEN OLD.key_version != NEW.key_version
BEGIN
    INSERT INTO audit_log (audit_table, audit_id, audit_column, old_mtime, new_mtime, old_signature, new_signature, details)
    VALUES ('user', OLD.id, 'key_version', OLD.mtime, NEW.mtime, OLD.signature, NEW.signature, 
            json_object('old', OLD.key_version, 'new', NEW.key_version));
END;

CREATE TRIGGER user_audit_update_password AFTER UPDATE OF password ON user
WHEN OLD.password != NEW.password
BEGIN
    INSERT INTO audit_log (audit_table, audit_id, audit_column, old_mtime, new_mtime, old_signature, new_signature, details)
    VALUES ('user', OLD.id, 'password', OLD.mtime, NEW.mtime, OLD.signature, NEW.signature, 
            json_object('old', OLD.password, 'new', NEW.password));
END;

CREATE TRIGGER user_audit_update_status AFTER UPDATE OF status ON user
WHEN OLD.status != NEW.status
BEGIN
    INSERT INTO audit_log (audit_table, audit_id, audit_column, old_mtime, new_mtime, old_signature, new_signature, details)
    VALUES ('user', OLD.id, 'status', OLD.mtime, NEW.mtime, OLD.signature, NEW.signature, 
            json_object('old', OLD.status, 'new', NEW.status));
END;
