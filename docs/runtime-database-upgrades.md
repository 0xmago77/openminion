# Runtime Database Upgrades

Status: active

The runtime database (sessions, messages, events and their derived tables) is
migrated by the runtime itself: the first process that opens it with a newer
package applies the pending runtime migrations. Each migration, including its
data backfill, runs in one transaction with its ledger entry, so a failure
leaves the database at the previous version with no partial upgrade.

Runtime migrations 13, 14 and 15 add data that every writer must maintain
from then on. A process from before such a migration does not maintain it, so
these upgrades need every writer to move together.

## Coordinated upgrade

1. Stop every process that writes the runtime database: gateways, API
   servers, workers, CLI sessions and scheduled jobs.
2. Keep a pre-upgrade backup of the database. For SQLite,
   `openminion storage backup --sqlite <path>` takes a snapshot; for
   PostgreSQL use `pg_dump` (`openminion storage backup --backend postgres`
   prints the guidance).
3. Upgrade every process to the same package version, then start them. The
   first one applies the migrations.
4. Never run a process from before the upgrade against the migrated database.

Rolling back means restoring the matching pre-upgrade backup with the matching
older package. Downgrading in place is not supported: an older process ignores
the derived data and leaves it wrong.

If a migration fails, it raises, and the database stays at the previous
version. Fix the cause it reports and start again.

## Runtime migration 15: session metadata string rows

Migration 15 adds `session_metadata_strings`, one row for each top-level member
of a session's stored metadata whose value is a string. The session store
writes these rows in the same transaction as every session insert, metadata
update and delete. The migration backfills existing sessions in batches of
1,000 inside its transaction. It reads each stored `metadata_json` with
`json.loads`, so documents PostgreSQL cannot parse (NaN, Infinity, an escaped
NUL or a lone surrogate) get their rows too, and it does not change any stored
metadata. A session whose `metadata_json` is not JSON stops the migration,
which rolls back and names that session.

As measured on 50,000 sessions with PostgreSQL 16, the backfill wrote 160,052
rows in 4.8 s, the table and its indexes took 33 MB next to 21 MB for
`sessions`, and a metadata write took 1.27 ms instead of 0.64 ms. The cost
grows with the number of string members per session.

A process from before migration 15 does not maintain the rows, which affects
PostgreSQL metadata filters (`list_sessions(metadata_filter=...)`, used by ACP
`session/list` and Focus directory sessions):

- **Missing match.** A session it creates has no rows, so no filter returns
  it.
- **Stale match.** A session whose metadata it changes keeps the rows of its
  earlier metadata, so a filter can return it for a value it no longer has,
  and miss it for its new value.

SQLite metadata filters do not read these rows.

## Metadata filter behavior by backend

PostgreSQL selects a session whose stored metadata, as
`SessionRecord.metadata` reads it after the JSON round trip, has a top-level
member named exactly as the filter key whose value is a string equal to the
filter value. Keys keep the existing `strip()`, and empty keys are skipped.
Every other character of a key or value is literal, including `.`, `[`, `"`,
non-ASCII text, NUL and lone surrogates. Numbers, booleans, null, objects,
arrays and missing members never match. The query returns at most `limit`
sessions in the usual `updated_at, id` order.

Before either backend reads a filter value, `list_sessions` keeps its existing
normalization: a false value (`None`, `0`, `False`, an empty container) is
sent as `""`, so `{"surface": None}` matches a session whose `surface` is the
empty string, on both backends. PostgreSQL then raises `TypeError` for any
other filter value that is not a string.

The rows store each name and value as its JSON string text (`json.dumps`,
ASCII without a NUL byte). PostgreSQL compares that text with `COLLATE "C"`,
which is a byte comparison, so the database's default collation does not
affect which sessions match. The indexed `entry_digest` only finds the
candidate rows; two different entries with one digest still compare their
full name and value.

SQLite keeps its existing `json_extract(metadata_json, '$.' || key) = value`
reader. It differs from the PostgreSQL behavior where it reads more than a
literal top-level string:

- it reads a key as a JSON path (`a.b`, `a[0]`, a leading `"`);
- it matches an object or array by its minified JSON text;
- it matches keys that `json.dumps` escapes (a quote, a backslash, control or
  non-ASCII characters), and values with a NUL, on SQLite 3.45.1, 3.46.1 and
  3.47.1 but not on 3.40.1 or 3.34.1;
- it raises `malformed JSON` on NaN and Infinity documents on SQLite 3.40.1
  and 3.34.1;
- for a member name stored twice (which the writer produces only for two
  distinct float NaN keys), it reads the first value, where PostgreSQL and
  `json.loads` read the last;
- it compares a filter value that is not a string (other than a false value,
  which becomes `""`) as an SQL value, so `1` matches a stored `1` or `true`,
  where PostgreSQL raises `TypeError`.
