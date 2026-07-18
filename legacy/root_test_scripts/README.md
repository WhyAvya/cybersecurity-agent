# Legacy Root Test Scripts

These files were root-level executable experiments named `test_*.py`. They were
archived here so default pytest collection only runs isolated tests from
`tests/`.

The scripts are preserved for historical reference and migration. Several of
them perform import-time work such as reading benchmark files, calling stdin,
or invoking live tools, so they should not be collected by default pytest.
