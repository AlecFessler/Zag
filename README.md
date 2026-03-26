# Zag

Bare-metal x86_64 operating system with a built-in network router.

## Prerequisites

- Zig compiler (0.14+)
- QEMU with KVM support
- OVMF UEFI firmware (`/usr/share/ovmf/x64/OVMF.4m.fd`)
- Python 3 with venv (for integration tests)

## Building

### Router

The routerOS has its own build system. Build it first, then build the kernel:

```bash
cd routerOS && zig build        # builds routerOS/bin/routerOS.elf
cd .. && zig build -Dprofile=router  # builds kernel + embeds router ELF into QEMU image
```

Both steps are required when modifying router code. The root `zig build` copies the pre-built ELF from `routerOS/bin/` into `zig-out/img/`.

### Kernel tests

```bash
zig build -Dprofile=test
```

### Running in QEMU

```bash
zig build run -Dprofile=router   # boots router in QEMU with tap networking
zig build run -Dprofile=test     # runs kernel test suite in QEMU
```

## Testing

### Integration tests (routerOS)

One-time setup (requires sudo):

```bash
sudo routerOS/tests/setup_network.sh   # creates tap0/tap1 interfaces
sudo routerOS/tests/setup_sudo.sh      # sets up namespace + capabilities
```

Create the Python venv:

```bash
cd routerOS/tests
python3 -m venv .venv
.venv/bin/pip install pytest pexpect
```

Run tests (no sudo needed after setup):

```bash
cd routerOS/tests
.venv/bin/pytest -v                  # all 111 tests
.venv/bin/pytest test_dns.py -v      # single test file
```

### Router fuzzer

The fuzzer tests the router's packet processing logic against invariants and an oracle, using AFL++-style mutations:

```bash
cd fuzzing/router
zig build run -- --seed=42 --iterations=100000
```

### Other fuzzers

```bash
cd fuzzing/vmm && zig build run
cd fuzzing/buddy_allocator && zig build run
cd fuzzing/heap_allocator && zig build run
cd fuzzing/red_black_tree && zig build run
```

### Kernel unit tests

```bash
zig test kernel/memory/buddy_allocator.zig
zig test kernel/containers/red_black_tree.zig
```
