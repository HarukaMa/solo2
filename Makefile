RUNNER := runners/lpc55

build-dev:
	make -C $(RUNNER) build-dev

bacon:
	make -C $(RUNNER) bacon

run-dev:
	make -C $(RUNNER) run-dev

jlink:
	scripts/bump-jlink
	JLinkGDBServer -strict -device LPC55S69 -if SWD -vd

mount-fs:
	scripts/fuse-bee

umount-fs:
	scripts/defuse-bee

PC_FEATURES := --features test-up-control,fast-button-timeout
PC_RUNNER := runners/pc/target/debug/main

test: test-build-pc
	@# Launch PC runner, wait for socket, run tests, kill runner
	@rm -f /tmp/solo2-sim.sock /tmp/solo2-state.bin
	@$(PC_RUNNER) & PID=$$!; \
	for i in 1 2 3 4 5 6 7 8 9 10; do [ -S /tmp/solo2-sim.sock ] && break; sleep 0.1; done; \
	cargo test --manifest-path runners/pc/Cargo.toml $(PC_FEATURES) --test fido2 -- --test-threads=1; \
	STATUS=$$?; kill $$PID 2>/dev/null; exit $$STATUS

test-build-pc:
	cargo build --manifest-path runners/pc/Cargo.toml $(PC_FEATURES)

# Build and flash firmware with test-up-control to lpcxpresso55 dev board.
CHIP := LPC55S69JBD100
PROBE_ARGS := --chip $(CHIP) --protocol swd
LPC55_CARGO := cargo +1.93.0 --config 'target.thumbv8m.main-none-eabi.rustflags=["-C","link-arg=-Tlink.x","-C","link-arg=-Tdefmt.x","-Dwarnings"]' --config 'build.target="thumbv8m.main-none-eabi"'
LPC55_ELF := runners/lpc55/target/thumbv8m.main-none-eabi/release/runner
LPC55_TEST_FEATURES := --features board-lpcxpresso55,develop,fido-authenticator,test-up-control,fast-button-timeout,no-reset-time-window

test-lpcxpresso55-build:
	$(LPC55_CARGO) build --manifest-path runners/lpc55/Cargo.toml --release $(LPC55_TEST_FEATURES)

test-lpcxpresso55-flash: test-lpcxpresso55-build
	probe-rs download $(PROBE_ARGS) $(LPC55_ELF)
	probe-rs reset $(PROBE_ARGS)

# Run the fido2 test suite against the lpcxpresso55 dev board.
# Builds test firmware, flashes it, then runs tests with probe-rs UP backchannel.
test-lpcxpresso55: test-lpcxpresso55-flash
	@addr=$$(arm-none-eabi-nm $(LPC55_ELF) | awk '/ UP_CONTROL$$/ {print "0x"$$1}'); \
	if [ -z "$$addr" ]; then echo "ERROR: UP_CONTROL symbol not found in ELF"; exit 1; fi; \
	echo "UP_CONTROL at $$addr"; \
	UP_BACKEND=probe-rs UP_CONTROL_ADDR=$$addr PROBE_RS_CHIP=$(CHIP) \
		FIDO2_TRANSPORT=device cargo test --manifest-path runners/pc/Cargo.toml --features test-up-control,fast-button-timeout --test fido2 -- --test-threads=1
