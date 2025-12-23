#!/bin/bash

CARGO_TARGET_DIR=target/libpnet cargo build --release --features libpnet
CARGO_TARGET_DIR=target/libpcap cargo build --release --features libpcap