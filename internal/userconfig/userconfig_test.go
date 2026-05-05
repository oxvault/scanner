package userconfig

// TODO: tests for Load.
//   - missing file → zero Config, no error
//   - well-formed [push].auto=true → cfg.Push.Auto == true
//   - $OXVAULT_CONFIG override path is respected
//   - malformed TOML → error
