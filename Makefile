SRC_DIR := ./src
SRC_FILES := $(wildcard $(SRC_DIR)/*.rs)

mode=debug
ifeq ($(release),1)
    flag=--release
    mode=release
endif

arch := $(shell uname -m)
TARGET_FILE := target/$(arch)-unknown-linux-musl/$(mode)/rfor
version = $(shell grep -E ^version Cargo.toml | tr -d '"'| cut -d " " -f 3)

rfor: $(TARGET_FILE)

$(TARGET_FILE): $(SRC_FILES) Cargo.toml
	RUSTFLAGS='-C target-feature=+crt-static' cargo build $(flag) --target $(arch)-unknown-linux-musl

geoip.dat:
	wget https://cdn.jsdelivr.net/gh/Loyalsoldier/v2ray-rules-dat@release/geoip.dat

geosite.dat:
	wget https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat

release: geoip.dat geosite.dat $(TARGET_FILE)
	export temp_dir=$(shell mktemp -d); \
	export artifact_name=rfor-$(version)-linux-$(arch)-$(mode); \
	mkdir -p $$temp_dir/$$artifact_name; \
	cp -a geoip.dat geosite.dat $$temp_dir/$$artifact_name; \
	cp -a conf/* $$temp_dir/$$artifact_name; \
	cp -a $(TARGET_FILE) $$temp_dir/$$artifact_name; \
	tar czf $$artifact_name.tar.gz -C $$temp_dir $$artifact_name; \
	rm -rf $$temp_dir

clean:
	@cargo clean
	@rm -f geoip.dat
	@rm -f geosite.dat

.PHONY: rfor clean release
