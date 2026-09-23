# certcheck

A headless CLI to retrieve a domain's SSL/TLS certificate and output its status (validity and expiration). Fills the gap left by convoluted `openssl s_client` pipelines by providing a quick, native way to check certificates.

## Status

**built, untested**: the TLS connection and X.509 parsing logic is built. It has not been run against a live server in this sandbox environment.

## Installation

```sh
cargo install --path .
```

## Usage

```sh
certcheck example.com
certcheck example.com --port 443
```
