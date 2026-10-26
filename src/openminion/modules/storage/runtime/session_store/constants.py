EVENT_PAGE_MAX = 2000
# Events read per query while runtime migration 13 backfills their run facts.
EVENT_RUN_FACTS_BACKFILL_BATCH_SIZE = 1000
# Sessions read per query while runtime migration 15 backfills their metadata
# string members.
SESSION_METADATA_STRINGS_BACKFILL_BATCH_SIZE = 1000

__all__ = [
    "EVENT_PAGE_MAX",
    "EVENT_RUN_FACTS_BACKFILL_BATCH_SIZE",
    "SESSION_METADATA_STRINGS_BACKFILL_BATCH_SIZE",
]
