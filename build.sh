#!/bin/bash

CARGO_TARGET_DIR=target/libpnet cargo build --release --features libpnet --target x86_64-unknown-linux-musl
CARGO_TARGET_DIR=target/libpcap cargo build --release --features libpcap --target x86_64-unknown-linux-musl