# Abstract
Introduce a general asynchronous pattern for change-producing `snapctl`
subcommands and a new `snapctl is-ready <change-id>` command. For any subcommand
that creates a change, passing `--no-wait` returns immediately and prints the
change id. Without `--no-wait`, the command polls the change readiness
(internally, via `snapctl is-ready`) until completion, similar to `snap watch`.
The `/v2/snapctl` response is extended to include the change id for
change-producing subcommands.

# Rationale
This helps mitigate the effects of the fixed client-side timeout from `snapctl`.
The current timeout impedes some use cases, such as large component
installations on slow networks. Returning a change ID immediately and checking
readiness with `snapctl is-ready` allows for long-running changes. This also
improves consistency with the `snap` CLI, which already exposes similar
functionality.

# Specification

## CLI Behavior

### `snapctl <subcommand> --no-wait`

The `snapctl` subcommands that creates changes will gain a new `--no-wait` flag,
which will return the change ID of the created change to the caller. Currently,
this impacts the `install` and `remove` subcommands.

- `snapctl <subcommand> --no-wait <SUBCMD-ARGS>...`:
    - exit-code:
      - 0: created change
      - 1: failed to create change
    - stdout: contains the created change ID
    - stderr: if exit-code is 1, contains the relevant error message

When calling a change-producing subcommand without the `--no-wait` flag, the
observable behavior of `snapctl` is unchanged. Internally, we use a new polling
mechanism to enable longer-running changes.

- `snapctl <subcommand> <SUBCMD-ARGS>...`:
    - exit-code:
      - 0: change completed successfully
      - 1: failed to create change or change failed to complete
    - stdout: unchanged from existing implementation
    - stderr: unchanged from existing implementation

Internally, the `snapctl` client will  poll `snapctl is-ready <id>` until the
change is ready (`Done`, `Error`, or `Hold`). Since the `snapctl` client does
not introspect the command forwarded to `snapd`, the client must use the
response from `/v2/snapctl` to determine if polling should be done or not.

### `snapctl is-ready <change-id>`

A new subcommand, `snapctl is-ready`, faciliates waiting on the change returned
by subcommands using the `--no-wait` flag.

- `snapctl is-ready <change-id>`
  - exit-code:
    - 0: change is ready and succeeded (`Done`).
    - 1: change is not ready (`Doing`, `Waiting`, or `Undoing`).
    - 2: change is ready but finished unsuccessfully (`Error` or `Hold`).
    - 3: other failures such as malformed ID, missing change, or permission
      errors.
  - stdout: empty, readiness is conveyed by the exit code.
  - stderr: empty for exit codes 0 and 1. For exit code 2, stderr contains a
    short summary (e.g., `change <id> error: <message>`). For exit code 3,
    stderr contains the relevant validation or permission error message.

The `is-ready` subcommand may only inspect changes that `snapctl` created for the
same snap instance that `snapctl` is being invoked from. Internally, snapd will
tag changes created by `snapctl` with their associated snap instance name. This
will enable `/v2/snapctl` to implement access control.

## API: /v2/snapctl

For change-producing subcommands, the response from `/v2/snapctl` will gain an
optional `"change-id": "<id>"`. The presence of this field will instruct the
`snapctl` client to internally poll for the change's readiness via `snapctl
is-ready`.

A change-producing subcommand should not respond with the `change-id` field if
the `--no-wait` flag was provided. Instead, the change ID should be sent via the
`stdout` field in the response from `/v2/snapctl`.

Response when calling command without `--no-wait`:
```json
{
  "exit-code": 0,
  "stdout":    "...",
  "stderr":    "...",
  "change-id": "15"
}
```

Response when calling command with `--no-wait`:
```json
{
  "exit-code": 0,
  "stdout":    "15",
  "stderr":    "..."
}
```

## Examples

Example 1: install a component and manually wait in a loop
```bash
# create the change and return immediately, printing the change id
change_id=$(snapctl install --no-wait +big-component)

# poll until the change is ready (exit code 0)
until snapctl is-ready "$change_id"; do
  sleep 0.5
done
```

Example 2: install a component and let snapctl do the waiting
```bash
# spawns a change and polls internally
snapctl install +big-component
```
