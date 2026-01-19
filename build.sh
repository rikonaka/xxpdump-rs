#!/bin/bash

cargo build --release --target x86_64-unknown-linux-musl --features libpnet

cargo build --release --target x86_64-pc-windows-msvc --features libpnet