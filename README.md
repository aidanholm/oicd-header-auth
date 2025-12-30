# Minimal header auth OICD provider

This repo implements a minimal OICD provider that expects to sit behind a
reverse proxy and receive information about the authenticated user (if any)
from that proxy, via HTTP headers the reverse proxy adds to each incoming
request.

This is useful if:

 - your reverse proxy already implements authentication, and can be configured
   to set HTTP authentication headers, and
 - a service you'd like to run behind the reverse proxy supports authentication
   via OICD, but not via HTTP authentication headers.

Since this provider sits behind an existing authenticating reverse proxy, no
additional login pages are required.

The provider is implemented as a single binary, written in (probably not very
idiomatic) Rust.

## Usage

Some modifications to source code will be required to adapt to
your particular requirements, as some deployment details (e.g. `LISTEN_ADDR`)
are baked into the binary. OICD clients are configured in `config.json` (which
is baked into the binary at build time).

Assuming you already have an operational reverse proxy, using this requires:

 - building and running this server,
 - configuring the reverse proxy to route requests to the configured `DOMAIN`
   to that running server, 
 - and configuring other applications' authentication settings according to the
   `DOMAIN` and client configuration in `config.json`.
