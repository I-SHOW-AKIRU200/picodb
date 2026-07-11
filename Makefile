# PicoDB — thin wrappers around the ./picodb CLI.
.PHONY: setup build run test bench clean

setup:            ## Install Rust (if needed), build, generate .env token
	./picodb setup

build:            ## Compile the release binary
	cargo build --release

run: build        ## Start PicoDB (loads .env)
	./picodb run

test: build       ## Run the Python integration tests
	./picodb test

bench:            ## Compile the native load generator
	./picodb bench

clean:            ## Remove build artifacts
	cargo clean
	rm -f bench/loadgen
