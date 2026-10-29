PRAGMA foreign_keys = ON;
PRAGMA user_version = 2;

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

CREATE TABLE hcx_files (
    source_file_id INTEGER PRIMARY KEY REFERENCES source_files(id),
    header_bytes BLOB NOT NULL CHECK(length(header_bytes) = 1024),
    node_size INTEGER NOT NULL,
    root_node INTEGER NOT NULL,
    declared_record_count INTEGER NOT NULL
) STRICT;

CREATE TABLE hcx_nodes (
    source_file_id INTEGER NOT NULL REFERENCES hcx_files(source_file_id),
    node_number INTEGER NOT NULL,
    file_offset INTEGER NOT NULL,
    level INTEGER NOT NULL,
    left_child INTEGER NOT NULL,
    next_node INTEGER NOT NULL,
    previous_node INTEGER NOT NULL,
    entry_count INTEGER NOT NULL,
    free_bytes INTEGER NOT NULL,
    node_bytes BLOB NOT NULL,
    active INTEGER NOT NULL CHECK(active IN (0, 1)),
    PRIMARY KEY(source_file_id, node_number)
) STRICT;

CREATE TABLE hcx_index_entries (
    source_file_id INTEGER NOT NULL,
    node_number INTEGER NOT NULL,
    node_offset INTEGER NOT NULL,
    index_number INTEGER NOT NULL,
    duplicate INTEGER NOT NULL,
    record_number INTEGER NOT NULL,
    key_bytes BLOB NOT NULL,
    payload_bytes BLOB NOT NULL,
    child_node INTEGER,
    original_bytes BLOB NOT NULL,
    PRIMARY KEY(source_file_id, node_number, node_offset),
    FOREIGN KEY(source_file_id, node_number) REFERENCES hcx_nodes(source_file_id, node_number)
) STRICT;

CREATE TABLE hcx_exchange_rates (
    source_file_id INTEGER NOT NULL,
    record_number INTEGER NOT NULL,
    currency_ref INTEGER NOT NULL,
    rate_date TEXT NOT NULL CHECK(length(rate_date) = 10),
    packed_date INTEGER NOT NULL,
    exchange_rate REAL NOT NULL,
    legacy_flags INTEGER,
    node_number INTEGER NOT NULL,
    node_offset INTEGER NOT NULL,
    record_bytes BLOB NOT NULL,
    PRIMARY KEY(source_file_id, record_number),
    FOREIGN KEY(source_file_id, node_number, node_offset)
        REFERENCES hcx_index_entries(source_file_id, node_number, node_offset)
) STRICT;

CREATE INDEX hcx_exchange_rates_currency_date
    ON hcx_exchange_rates(source_file_id, currency_ref, rate_date);

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

CREATE TABLE qel_files (
    source_file_id INTEGER PRIMARY KEY REFERENCES source_files(id),
    header_bytes BLOB NOT NULL CHECK(length(header_bytes) = 1024),
    node_size INTEGER NOT NULL,
    root_node INTEGER NOT NULL,
    declared_record_count INTEGER NOT NULL
) STRICT;

CREATE TABLE qel_nodes (
    source_file_id INTEGER NOT NULL REFERENCES qel_files(source_file_id),
    node_number INTEGER NOT NULL,
    file_offset INTEGER NOT NULL,
    level INTEGER NOT NULL,
    left_child INTEGER NOT NULL,
    next_node INTEGER NOT NULL,
    previous_node INTEGER NOT NULL,
    entry_count INTEGER NOT NULL,
    free_bytes INTEGER NOT NULL,
    node_bytes BLOB NOT NULL,
    active INTEGER NOT NULL CHECK(active IN (0, 1)),
    PRIMARY KEY(source_file_id, node_number)
) STRICT;

CREATE TABLE qel_index_entries (
    source_file_id INTEGER NOT NULL,
    node_number INTEGER NOT NULL,
    node_offset INTEGER NOT NULL,
    index_number INTEGER NOT NULL,
    duplicate INTEGER NOT NULL,
    record_number INTEGER NOT NULL,
    key_bytes BLOB NOT NULL,
    payload_bytes BLOB NOT NULL,
    child_node INTEGER,
    original_bytes BLOB NOT NULL,
    PRIMARY KEY(source_file_id, node_number, node_offset),
    FOREIGN KEY(source_file_id, node_number) REFERENCES qel_nodes(source_file_id, node_number)
) STRICT;


CREATE TABLE qel_records (
    source_file_id INTEGER NOT NULL REFERENCES qel_files(source_file_id),
    record_number INTEGER NOT NULL,
    index1_key BLOB NOT NULL,
    index2_key BLOB NOT NULL,
    descriptor_signature INTEGER NOT NULL,
    stored_checksum INTEGER NOT NULL,
    record_state INTEGER NOT NULL,
    payload BLOB NOT NULL,
    PRIMARY KEY(source_file_id, record_number)
) STRICT;

CREATE TABLE qel_record_parts (
    source_file_id INTEGER NOT NULL,
    record_number INTEGER NOT NULL,
    part_number INTEGER NOT NULL,
    node_number INTEGER NOT NULL,
    node_offset INTEGER NOT NULL,
    PRIMARY KEY(source_file_id, record_number, part_number),
    FOREIGN KEY(source_file_id, record_number) REFERENCES qel_records(source_file_id, record_number),
    FOREIGN KEY(source_file_id, node_number, node_offset)
        REFERENCES qel_index_entries(source_file_id, node_number, node_offset)
) STRICT;

CREATE TABLE qsd_files (
    source_file_id INTEGER PRIMARY KEY REFERENCES source_files(id),
    identification TEXT NOT NULL,
    major_version INTEGER NOT NULL,
    minor_version INTEGER NOT NULL,
    revision INTEGER NOT NULL,
    header_bytes BLOB NOT NULL CHECK(length(header_bytes) = 128)
) STRICT;

CREATE TABLE qsd_records (
    source_file_id INTEGER NOT NULL REFERENCES qsd_files(source_file_id),
    record_number INTEGER NOT NULL,
    file_offset INTEGER NOT NULL,
    record_type INTEGER NOT NULL,
    legacy_id INTEGER NOT NULL,
    deleted INTEGER NOT NULL CHECK(deleted IN (0, 1)),
    is_eof INTEGER NOT NULL CHECK(is_eof IN (0, 1)),
    name TEXT NOT NULL,
    name_bytes BLOB NOT NULL,
    header_bytes BLOB NOT NULL CHECK(length(header_bytes) = 64),
    payload BLOB NOT NULL,
    trailer_bytes BLOB NOT NULL CHECK(length(trailer_bytes) = 2),
    PRIMARY KEY(source_file_id, record_number)
) STRICT;

CREATE VIEW qsd_current_records AS
SELECT * FROM qsd_records WHERE deleted = 0 AND is_eof = 0;

CREATE TABLE idx_files (
    source_file_id INTEGER PRIMARY KEY REFERENCES source_files(id),
    directory_bytes BLOB NOT NULL
) STRICT;

CREATE TABLE idx_segments (
    source_file_id INTEGER NOT NULL REFERENCES idx_files(source_file_id),
    segment_number INTEGER NOT NULL,
    file_offset INTEGER NOT NULL,
    original_bytes BLOB NOT NULL,
    PRIMARY KEY(source_file_id, segment_number)
) STRICT;

CREATE TABLE qph_files (
    source_file_id INTEGER PRIMARY KEY REFERENCES source_files(id),
    version INTEGER NOT NULL,
    header_bytes BLOB NOT NULL CHECK(length(header_bytes) = 32)
) STRICT;

CREATE TABLE qph_symbols (
    source_file_id INTEGER NOT NULL REFERENCES qph_files(source_file_id),
    file_offset INTEGER NOT NULL,
    next_offset INTEGER NOT NULL,
    identity_type INTEGER NOT NULL,
    symbol TEXT,
    exchange_code INTEGER,
    stored_exchange_code INTEGER,
    file_identity TEXT,
    security_ref INTEGER,
    quote_head INTEGER NOT NULL,
    original_bytes BLOB NOT NULL CHECK(length(original_bytes) = 275),
    PRIMARY KEY(source_file_id, file_offset)
) STRICT;

CREATE TABLE qph_quotes (
    source_file_id INTEGER NOT NULL,
    file_offset INTEGER NOT NULL,
    symbol_offset INTEGER NOT NULL,
    next_offset INTEGER NOT NULL,
    quote_date TEXT NOT NULL CHECK(length(quote_date) = 10),
    packed_date INTEGER NOT NULL,
    priority INTEGER NOT NULL,
    kind INTEGER NOT NULL,
    field_mask INTEGER,
    close REAL,
    high REAL,
    low REAL,
    volume INTEGER,
    volume_base INTEGER,
    volume_multiplier INTEGER,
    split_numerator REAL,
    split_denominator REAL,
    legacy_status INTEGER,
    original_bytes BLOB NOT NULL CHECK(length(original_bytes) = 54),
    PRIMARY KEY(source_file_id, file_offset),
    FOREIGN KEY(source_file_id, symbol_offset) REFERENCES qph_symbols(source_file_id, file_offset)
) STRICT;

CREATE TABLE qph_unused_regions (
    source_file_id INTEGER NOT NULL REFERENCES qph_files(source_file_id),
    file_offset INTEGER NOT NULL,
    kind TEXT NOT NULL CHECK(kind IN ('free_symbol', 'free_quote', 'unclaimed')),
    next_offset INTEGER,
    original_bytes BLOB NOT NULL,
    PRIMARY KEY(source_file_id, file_offset)
) STRICT;

CREATE VIEW share_prices AS
SELECT q.source_file_id, s.symbol, s.exchange_code, s.file_identity, s.security_ref,
       q.quote_date, q.priority, q.close, q.high, q.low, q.volume, q.legacy_status,
       q.file_offset AS quote_offset, s.file_offset AS symbol_offset
FROM qph_quotes q JOIN qph_symbols s
ON s.source_file_id = q.source_file_id AND s.file_offset = q.symbol_offset
WHERE q.kind = 0;
