"""Typed JSON export report; SQLite contains the complete recovery archive."""

from typing import TypedDict


class AccountCount(TypedDict):
    account: str
    transactions: int


class RecoveryWarning(TypedDict):
    code: str
    detail: str
    record_id: int | None


class RecoveryReport(TypedDict):
    format: str
    output: str
    source_sha256: str
    sources_unchanged: bool
    password_needed_for_block_decryption: bool
    password_hint_tested: bool
    pages_verified: int
    indexed_records: int
    physical_fragments: int
    record_type_counts: dict[int, int]
    counts: dict[str, int]
    date_range: list[str | None]
    account_transaction_counts: list[AccountCount]
    entry_kind_counts: dict[str, int]
    warnings: list[RecoveryWarning]
    sqlite_integrity: str
    foreign_key_violations: int
