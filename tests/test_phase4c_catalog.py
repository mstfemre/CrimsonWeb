"""The test catalog is code-defined and read-only; the model may only pick its ids."""

from crimsonweb.api.verification.catalog import (
    READ_ONLY_METHODS,
    catalog_entry,
    catalog_ids,
)


def test_first_slice_offers_the_read_only_bola_test():
    entry = catalog_entry("bola_cross_owner_read")
    assert entry is not None
    assert entry.category == "auth"
    assert entry.method == "GET"
    assert entry.requires_object_identifier is True


def test_every_catalog_entry_is_read_only():
    assert catalog_ids()  # non-empty
    for entry_id in catalog_ids():
        assert catalog_entry(entry_id).method in READ_ONLY_METHODS


def test_unknown_catalog_id_is_rejected():
    assert catalog_entry("delete_everything") is None
    assert catalog_entry("") is None
