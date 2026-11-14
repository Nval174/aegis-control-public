# Synthetic observe-only configuration

`observe.example.toml` uses schema 1 and leaves coverage unassessed.
`coverage.example.toml` uses schema 2 and requires one exact synthetic observation identity.
Both are examples, not discovered inventory or deployment configuration.

The checker requires observe mode and every optional integration explicitly false. Unknown
fields, invalid types, enabled integrations and unresolved unsupported schemas reject.
Schema 2 requires 1-64 unique nonempty declarations over supported service/source/metric/route
identities; OTHER does not replace a known route. A config-check pass assesses no live coverage.

Use the [root commands](../README.md#run-locally). Keep real inventory, credentials, private
logs and operational settings outside the repository; examples grant no activation authority.
