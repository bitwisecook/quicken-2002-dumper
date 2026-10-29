PRAGMA foreign_keys = ON;
PRAGMA user_version = 1;

CREATE TABLE source_files (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('qdf', 'companion')),
    byte_count INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    original_bytes BLOB NOT NULL
) STRICT;

CREATE TABLE pages (
    page_number INTEGER PRIMARY KEY,
    source_file_id INTEGER NOT NULL REFERENCES source_files(id),
    page_type INTEGER,
    stored_md5 BLOB NOT NULL CHECK(length(stored_md5) = 16),
    verified INTEGER NOT NULL CHECK(verified = 1),
    decrypted_bytes BLOB NOT NULL CHECK(length(decrypted_bytes) = 4104)
) STRICT;

CREATE TABLE record_fragments (
    id INTEGER PRIMARY KEY,
    page_number INTEGER NOT NULL REFERENCES pages(page_number),
    page_offset INTEGER NOT NULL,
    record_type INTEGER NOT NULL,
    header_flags INTEGER NOT NULL,
    is_free INTEGER NOT NULL CHECK(is_free IN (0, 1)),
    next_pointer INTEGER NOT NULL,
    payload BLOB NOT NULL,
    UNIQUE(page_number, page_offset)
) STRICT;

CREATE TABLE legacy_records (
    id INTEGER PRIMARY KEY,
    record_type INTEGER NOT NULL,
    legacy_id INTEGER NOT NULL,
    index_page INTEGER NOT NULL REFERENCES pages(page_number),
    index_slot INTEGER NOT NULL,
    payload BLOB NOT NULL,
    UNIQUE(record_type, legacy_id),
    UNIQUE(index_page, index_slot)
) STRICT;

CREATE TABLE record_parts (
    record_id INTEGER NOT NULL REFERENCES legacy_records(id),
    part_number INTEGER NOT NULL,
    fragment_id INTEGER NOT NULL REFERENCES record_fragments(id),
    PRIMARY KEY(record_id, part_number),
    UNIQUE(fragment_id)
) STRICT;

CREATE TABLE strings (
    id INTEGER PRIMARY KEY,
    record_id INTEGER NOT NULL UNIQUE REFERENCES legacy_records(id),
    legacy_hash INTEGER NOT NULL,
    legacy_flags INTEGER NOT NULL,
    text TEXT NOT NULL,
    original_text_bytes BLOB NOT NULL
) STRICT;

CREATE TABLE accounts (
    id INTEGER PRIMARY KEY,
    record_id INTEGER NOT NULL UNIQUE REFERENCES legacy_records(id),
    name TEXT NOT NULL,
    legacy_type INTEGER NOT NULL,
    currency_code TEXT,
    amount_scale INTEGER NOT NULL DEFAULT 100 CHECK(amount_scale = 100)
) STRICT;

CREATE TABLE categories (
    id INTEGER PRIMARY KEY,
    record_id INTEGER NOT NULL UNIQUE REFERENCES legacy_records(id),
    full_name TEXT NOT NULL,
    name TEXT NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('income', 'expense')),
    parent_id INTEGER REFERENCES categories(id)
) STRICT;

CREATE TABLE legacy_identifiers (
    quid INTEGER PRIMARY KEY,
    record_id INTEGER NOT NULL UNIQUE REFERENCES legacy_records(id),
    target_record_type INTEGER NOT NULL,
    target_legacy_id INTEGER NOT NULL,
    target_record_id INTEGER NOT NULL REFERENCES legacy_records(id)
) STRICT;

CREATE TABLE transactions (
    id INTEGER PRIMARY KEY,
    record_id INTEGER NOT NULL UNIQUE REFERENCES legacy_records(id),
    account_id INTEGER NOT NULL REFERENCES accounts(id),
    posted_date TEXT NOT NULL CHECK(length(posted_date) = 10),
    amount_minor INTEGER NOT NULL,
    payee_string_id INTEGER REFERENCES strings(id),
    memo_string_id INTEGER REFERENCES strings(id),
    category_id INTEGER REFERENCES categories(id),
    transfer_account_id INTEGER REFERENCES accounts(id),
    category_legacy_ref INTEGER NOT NULL,
    class_legacy_ref INTEGER NOT NULL,
    auxiliary_record_id INTEGER UNIQUE REFERENCES legacy_records(id),
    entry_kind TEXT NOT NULL CHECK(entry_kind IN ('transaction', 'opening_balance'))
) STRICT;

-- Preserve additional string references without assigning unverified meanings.
CREATE TABLE transaction_string_slots (
    transaction_id INTEGER NOT NULL REFERENCES transactions(id),
    payload_offset INTEGER NOT NULL,
    string_id INTEGER REFERENCES strings(id),
    legacy_ref INTEGER NOT NULL,
    PRIMARY KEY(transaction_id, payload_offset)
) STRICT;

CREATE TABLE recovery_issues (
    id INTEGER PRIMARY KEY,
    severity TEXT NOT NULL CHECK(severity IN ('info', 'warning')),
    code TEXT NOT NULL,
    record_id INTEGER REFERENCES legacy_records(id),
    detail TEXT NOT NULL
) STRICT;

CREATE INDEX transactions_account_date ON transactions(account_id, posted_date, id);
CREATE INDEX transactions_category_date ON transactions(category_id, posted_date);
CREATE INDEX categories_parent ON categories(parent_id);
CREATE INDEX legacy_records_type ON legacy_records(record_type, legacy_id);
CREATE INDEX record_fragments_type ON record_fragments(record_type);

CREATE VIEW ledger AS
SELECT t.id AS legacy_transaction_id, t.entry_kind, t.posted_date, a.name AS account,
       t.amount_minor, a.amount_scale, a.currency_code,
       p.text AS payee, m.text AS memo, c.full_name AS category,
       ta.name AS transfer_account, t.category_legacy_ref,
       t.entry_kind != 'opening_balance' AND t.category_legacy_ref != 0 AND t.category_id IS NULL
           AND t.transfer_account_id IS NULL AS unresolved_category,
       t.class_legacy_ref, i.quid, t.record_id
FROM transactions t
JOIN accounts a ON a.id = t.account_id
LEFT JOIN strings p ON p.id = t.payee_string_id
LEFT JOIN strings m ON m.id = t.memo_string_id
LEFT JOIN categories c ON c.id = t.category_id
LEFT JOIN accounts ta ON ta.id = t.transfer_account_id
LEFT JOIN legacy_identifiers i ON i.target_record_id = t.record_id;
