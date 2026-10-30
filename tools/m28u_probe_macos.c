// Native macOS identification probe. No setting, reset, ISP, or flash commands.
// Live output is restricted to allowlisted firmware/source/KVM/brightness GETs
// and readback.
// Wrapping is verified against the official rthidlib.dll (SHA-256 recorded in
// analysis/findings.json): HID_i2cread 10002ff0, HID_i2cwrite 100030d0,
// read helper 100028e0. No proprietary library is loaded or executed.
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/hid/IOHIDManager.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void show_hex(const uint8_t *b, CFIndex n) {
    for (CFIndex i = 0; i < n; i++) printf("%02x%s", b[i], i + 1 == n ? "\n" : " ");
}
static int reply_value(const uint8_t *b, size_t n, uint8_t code, uint8_t subcode) {
    if (n < 11 || b[0] != 0x6e || b[1] != 0x88 || b[2] != 2 || b[3] != 0 ||
        b[4] != code || b[5] != subcode) return -1;
    uint8_t checksum = 0x50;
    for (size_t i = 0; i < 11; i++) checksum ^= b[i];
    return checksum == 0 ? (b[8] << 8) | b[9] : -1;
}
static int status_value(const uint8_t *b, size_t n, uint8_t selector) {
    return reply_value(b, n, 0xe0, selector);
}
static int firmware_version(const uint8_t *b, size_t n) {
    int value = status_value(b, n, 0x38);
    return value >= 0 && value >> 8 == 'F' && (value & 255) <= 99 ? value & 255 : -1;
}
static int self_test(void) {
    // Independently captured FO48U F06 response to the same E0/38 GET.
    uint8_t fixture[] = {0x6e,0x88,2,0,0xe0,0x38,0xff,0xff,'F',6,0x2c};
    if (firmware_version(fixture, sizeof(fixture)) != 6) return 1;
    for (size_t i = 0; i < sizeof(fixture); i++) {
        for (unsigned bit = 0; bit < 8; bit++) {
            fixture[i] ^= 1u << bit;
            if (firmware_version(fixture, sizeof(fixture)) != -1) return 1;
            fixture[i] ^= 1u << bit;
        }
    }
    for (size_t n = 0; n < sizeof(fixture); n++)
        if (firmware_version(fixture, n) != -1) return 1;
    fixture[5] ^= 1; fixture[10] ^= 1; // Valid checksum, wrong selector.
    if (firmware_version(fixture, sizeof(fixture)) != -1) return 1;
    puts("PASS: captured reply accepted; 88 bit corruptions, 11 truncations and wrong selector rejected.");
    return 0;
}
static long number(IOHIDDeviceRef dev, CFStringRef key) {
    CFTypeRef val = IOHIDDeviceGetProperty(dev, key);
    long n = -1;
    if (val && CFGetTypeID(val) == CFNumberGetTypeID()) CFNumberGetValue(val, kCFNumberLongType, &n);
    return n;
}
int main(int argc, char **argv) {
    int query = argc == 2 && !strcmp(argv[1], "--firmware-get");
    int status_query = argc == 2 && !strcmp(argv[1], "--status");
    int brightness_query = argc == 2 && !strcmp(argv[1], "--brightness-get");
    int dry = argc == 2 && !strcmp(argv[1], "--dry-run");
    int dry_read = argc == 2 && !strcmp(argv[1], "--dry-run-read");
    int test = argc == 2 && !strcmp(argv[1], "--self-test");
    if (argc > 2 || (argc == 2 && !query && !status_query && !brightness_query && !dry && !dry_read && !test)) {
        fprintf(stderr, "Usage: %s [--dry-run|--dry-run-read|--self-test|--firmware-get|--status|--brightness-get]\n", argv[0]); return 2;
    }
    if (test) return self_test();
    uint8_t request[192] = {0};
    request[0] = 0x40; request[1] = 0xc6;
    request[6] = 36; request[8] = 0x6e; request[10] = 0x80;
    const uint8_t frame[] = {0x51, 0x83, 0x01, 0xe0, 0x38, 0x0b};
    memcpy(request + 64, frame, sizeof(frame));
    if (dry) { show_hex(request, sizeof(request)); return 0; }
    uint8_t read_request[192] = {0};
    read_request[0] = 0x40; read_request[1] = 0xd6;
    read_request[2] = 0x51; read_request[6] = 36;
    read_request[8] = 0x6e; read_request[9] = 1; read_request[10] = 0x80;
    if (dry_read) { show_hex(read_request, sizeof(read_request)); return 0; }

    IOHIDManagerRef manager = IOHIDManagerCreate(kCFAllocatorDefault, kIOHIDOptionsTypeNone);
    if (!manager) return 1;
    int vid = 0x0bda, pid = 0x1100;
    CFNumberRef v = CFNumberCreate(NULL, kCFNumberIntType, &vid);
    CFNumberRef p = CFNumberCreate(NULL, kCFNumberIntType, &pid);
    const void *keys[] = {CFSTR(kIOHIDVendorIDKey), CFSTR(kIOHIDProductIDKey)};
    const void *vals[] = {v, p};
    CFDictionaryRef match = CFDictionaryCreate(NULL, keys, vals, 2,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    IOHIDManagerSetDeviceMatching(manager, match);
    CFRelease(match); CFRelease(v); CFRelease(p);
    IOHIDManagerScheduleWithRunLoop(manager, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
    CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.05, false);
    CFSetRef devices = IOHIDManagerCopyDevices(manager);
    CFIndex count = devices ? CFSetGetCount(devices) : 0;
    printf("Realtek 0bda:1100 interfaces: %ld\n", count);
    int status = 1;
    if (count == 1) {
        IOHIDDeviceRef device;
        CFSetGetValues(devices, (const void **)&device);
        printf("Usage page=%04lx usage=%04lx input-size=%ld output-size=%ld\n",
            number(device, CFSTR(kIOHIDPrimaryUsagePageKey)),
            number(device, CFSTR(kIOHIDPrimaryUsageKey)),
            number(device, CFSTR(kIOHIDMaxInputReportSizeKey)),
            number(device, CFSTR(kIOHIDMaxOutputReportSizeKey)));
        status = 0;
        if (query || status_query || brightness_query) {
            if (number(device, CFSTR(kIOHIDPrimaryUsagePageKey)) != 0xffda ||
                number(device, CFSTR(kIOHIDPrimaryUsageKey)) != 0xda ||
                number(device, CFSTR(kIOHIDMaxOutputReportSizeKey)) != 192) {
                fprintf(stderr, "Unexpected descriptor; no request sent.\n"); status = 1;
            } else {
                IOReturn opened = IOHIDDeviceOpen(device, kIOHIDOptionsTypeNone);
                printf("Open result=0x%08x\n", opened);
                if (opened != kIOReturnSuccess) status = 1;
                else {
                  const uint8_t selectors[] = {0x38, 0x2d, 0x6b, 0x6c, 0x38};
                  const char *labels[] = {"firmware", "video-source", "USB-B-video-binding", "USB-C-video-binding", "firmware-repeat"};
                  int failed = 0;
                  for (size_t q = 0; q < (status_query ? sizeof(selectors) : 1); q++) {
                    const uint8_t selector = brightness_query ? 0x10 : selectors[q];
                    request[68] = selector;
                    request[69] = 0x51 ^ 0x83 ^ 0x01 ^ 0xe0 ^ selector;
                    if (brightness_query) {
                        // USB brightness GET matches official Sidekick:
                        // MainWindow.GetCurrentBrightness/GetOSD and its XOR
                        // helper (RVAs eed4/e648/13b5c). USB payload checksum
                        // excludes the separately supplied I2C address.
                        request[65] = 0x82; request[67] = 0x10;
                        request[68] = 0xc2; request[69] = 0;
                        puts("GET brightness (VCP/10)");
                    } else printf("GET %s (E0/%02x)\n", labels[q], selector);
                    IOReturn sent = IOHIDDeviceSetReport(device, kIOHIDReportTypeOutput, 0, request, sizeof(request));
                    printf("GET send result=0x%08x\n", sent);
                    status = 1;
                    if (sent == kIOReturnSuccess) {
                        usleep(150000); // Matches Sidekick's documented GET/read delay.
                        sent = IOHIDDeviceSetReport(device, kIOHIDReportTypeOutput, 0, read_request, sizeof(read_request));
                        printf("I2C read request result=0x%08x\n", sent);
                        if (sent == kIOReturnSuccess) {
                            uint8_t input[192] = {0}; CFIndex length = sizeof(input);
                            IOReturn got = IOHIDDeviceGetReport(device, kIOHIDReportTypeInput, 0, input, &length);
                            printf("Input report result=0x%08x length=%ld\n", got, length);
                            if (got == kIOReturnSuccess) {
                                show_hex(input, length < 36 ? length : 36);
                                int value = status_value(input, (size_t)length, selector);
                                if (brightness_query) {
                                    value = reply_value(input, (size_t)length, 0x10, 0);
                                    int maximum = (input[6] << 8) | input[7];
                                    if (value >= 0 && maximum == 100 && value <= maximum) {
                                        printf("Checksum-valid brightness reply: %d/%d (active brightness remains unconfirmed; not a luminance measurement)\n", value, maximum); status = 0;
                                    }
                                } else if (selector == 0x38) {
                                    int version = firmware_version(input, (size_t)length);
                                    if (version >= 0) {
                                        printf("Validated installed firmware: F%02d\n", version); status = 0;
                                    }
                                } else if (value >= 0) {
                                    printf("Validated %s: %d\n", labels[q], value); status = 0;
                                }
                                if (status != 0) fprintf(stderr, "Reply validation failed; value remains unconfirmed.\n");
                            }
                        }
                    }
                    if (status != 0) { failed = 1; break; }
                  }
                  IOHIDDeviceClose(device, kIOHIDOptionsTypeNone);
                  status = failed;
                }
            }
        }
    } else if (query || status_query || brightness_query) fprintf(stderr, "Expected exactly one matching interface; no request sent.\n");
    if (devices) CFRelease(devices);
    IOHIDManagerUnscheduleFromRunLoop(manager, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
    CFRelease(manager);
    return status;
}
