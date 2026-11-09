# Directory bindings and sessions

Directory bindings are node relationship data in `nodes.json`. Runtime settings do not contain peer mappings. UUIDs identify nodes; display names are labels and may change.

A harness supplies its local cwd when opening an IC session. IC resolves that directory against owner-approved local roots and target bindings. The target selects the corresponding approved workspace. An explicit cwd without a valid mapping fails rather than executing somewhere else.

When cwd is omitted, each target allocates a private session-specific temporary directory. The target can disable temporary workspaces through session settings. Omission does not mean the service's own current directory, and agents cannot override a target's opt-out. Persisted sessions retain their mappings and execution history.

The management commands `listLocalWorkspaces`, `bindLocalWorkspace`, `unbindLocalWorkspace`, `listWorkspaceBindings` and `bindWorkspace` manage approved mappings. Read the current revision before updating; local roots and peer bindings have separate revision counters. Local roots must be canonical owned directories, not links or aliases, and must be isolated from IC code, configuration, credentials and state.

Binding a directory does not copy files. [Local synchronization](local-sync.md) is an explicit operation with its own scope and deletion semantics. Removing a binding does not delete local or remote files.
