# PicoDB — thin wrappers around the setup/build/run scripts.
.PHONY: setup build run test bench clean

setup:            ## Install Rust (if needed), build, generate .env token
	./setup.sh

build:            ## Compile the release binary
	cargo build --release

run: build        ## Start PicoDB (loads .env)
	./run.sh

test: build       ## Build then run the Python integration tests
	python3 tests/test_picodb.py

bench: build      ## Compile and run the native load generator
	rustc -O bench/loadgen.rs -o bench/loadgen
	@echo "Start the server (./run.sh) in another shell, then: ./bench/loadgen 4 4000000 1000"

clean:            ## Remove build artifacts
	cargo clean
	rm -f bench/loadgen
