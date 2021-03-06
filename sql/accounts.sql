
/* Accounts -- what you login as */
CREATE TABLE IF NOT EXISTS anthrokit_accounts (
    accountid BIGSERIAL PRIMARY KEY,
    login TEXT UNIQUE, -- username
    pwhash TEXT UNIQUE, -- encrypted argon2id hash
    twofactor TEXT, -- encrypted two factor auth shared secret
    active BOOLEAN DEFAULT FALSE,
    email TEXT,
    external_auth JSONB,
    email_activation TEXT,
    created TIMESTAMP DEFAULT NOW(),
    modified TIMESTAMP
);

/* Two Factor Auth -- 30 day remember feature */
CREATE TABLE IF NOT EXISTS anthrokit_account_known_device (
    knowndeviceid BIGSERIAL PRIMARY KEY,
    accountid BIGINT REFERENCES anthrokit_accounts(accountid),
    selector TEXT,
    validator TEXT,
    created TIMESTAMP DEFAULT NOW()
);

CREATE TABLE anthrokit_invites (
    inviteid BIGSERIAL PRIMARY KEY,
    invitefrom BIGINT REFERENCES anthrokit_accounts (accountid),
    twitter TEXT,
    email TEXT,
    invite_code TEXT,
    claimed BOOLEAN DEFAULT FALSE,
    created TIMESTAMP DEFAULT NOW(),
    newaccountid BIGINT NULL REFERENCES anthrokit_accounts (accountid)
);
