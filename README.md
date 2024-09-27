# tangle

This is a library that provides some components extracted from the
`libsystemd` [systemd](https://systemd.io) API.

The following is provided:

* `sd-event`
* `sd-bus`
* `sd-id128`

It has the same API, and is provided under the same license. It is originally
derived from systemd 256.6. Certain APIs may be missing, however, particularly
those that deal with systemd itself, such as unit/slice/etc creds.

## TODO

* clean up manpages
