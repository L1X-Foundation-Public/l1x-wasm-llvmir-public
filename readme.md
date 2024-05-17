# WASM to LLVM IR code transaltor

Translates a WASM file to L1X VM llvmir repesentation. Used by `cargo-l1x`

**Requirements:**
```
llvm-15
```

**Build:**
```bash
cargo build
```

**Test**
```bash
cargo test
```

**Run:**
```bash
cargo run some.wasm -o some.ll
```

**Create eBPF object file:**

*Require installed `llvm-17`*

```bash
./build_ebpf.sh some.ll
```