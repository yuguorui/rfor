SRC_DIR := ./src
SRC_FILES := $(wildcard $(SRC_DIR)/*.rs)
TARGET_FILE := target/x86_64-unknown-linux-musl/debug/rfor

ifeq ($(release),1)
    flag=--release
endif

rfor: TARGET_FILE

TARGET_FILE: $(SRC_FILES) Cargo.toml
	RUSTFLAGS='-C target-feature=+crt-static' cargo build $(flag) --target x86_64-unknown-linux-musl

clean:
	@cargo clean

.PHONY: rfor clean
