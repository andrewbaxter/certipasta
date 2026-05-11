#!/usr/bin/env bash
set -xeu -o pipefail
(
	cd infra
	RUST_BACKTRACE=1 cargo run
)
(
	cd stage/tf
	TF_VAR_google_creds="$(pw read /device/apricorn/container/dev/certipasta/googletoken)" \
	TF_VAR_dnsimple_token="$(pw read /device/apricorn/container/dev/dnsimple)" \
	TF_LOG=info terraform apply --var-file input.json
)
