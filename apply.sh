#!/usr/bin/env bash
set -xeu -o pipefail
(
	cd infra
	RUST_BACKTRACE=1 cargo run
)
(
	cd stage/tf
	TF_LOG=info terraform apply --var-file input.json
)
