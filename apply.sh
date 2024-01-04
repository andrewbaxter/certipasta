#!/usr/bin/bash -xeu
(
	cd rust/infra
	cargo run
)
(
	cd deploy/tf
	terraform apply --var-file input.json
)