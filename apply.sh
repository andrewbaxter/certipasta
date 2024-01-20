#!/usr/bin/bash -xeu
(
	cd infra
	cargo run
)
(
	cd stage/tf
	terraform apply --var-file input.json
)