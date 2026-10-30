// Internal macOS register worker for read-only SPI acquisition.
// RAM/engine configuration, ISP entry and MCU reset are permitted explicitly.
// SPI program/erase/status-write opcodes and the flash write-data port are absent.
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/hid/IOHIDManager.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t stopped;
static void stop_handler(int sig) { (void)sig; stopped = 1; }
static int read_opcode(unsigned n) { return n == 3 || n == 5 || n == 0x9f; }
static int read_control(unsigned n) {
    return n == 0x42 || n == 0x43 || n == 0x46 || n == 0x47 ||
           (n >= 0x5a && n <= 0x5f);
}
static int allowed_write(unsigned reg, unsigned value, int entered, int attempted, int preflight) {
    if (reg > 255 || value > 255) return 0;
    if (reg == 0x6f) return value == 0x80 && !attempted && preflight;
    if (reg == 0xee) return value == 2 && attempted;
    if (!entered) return 0;
    if (reg == 0x60) return read_control(value);
    if (reg == 0x61) return read_opcode(value);
    if (reg >= 0x64 && reg <= 0x66) return 1;
    return reg == 0x6a && value == 3;
}
static int allowed_read(unsigned reg, unsigned n, int entered) {
    if (reg > 255) return 0;
    if (reg == 0x6f || reg == 0x60) return n == 1;
    if (!entered) return 0;
    if (reg == 0x70) return n >= 1 && n <= 128;
    return n == 1 && (reg == 0x61 || (reg >= 0x67 && reg <= 0x69));
}
static int allowed_boot_read(int mode, int attempted, int entered) {
    return mode >= 0 && !(mode & 0x80) && !attempted && !entered;
}
static void read_packet(uint8_t *p, unsigned reg, unsigned n, unsigned reg_length) {
    memset(p, 0, 192);
    p[0] = 0x40; p[1] = 0xd6; p[2] = (uint8_t)reg;
    p[6] = (uint8_t)n; p[8] = 0x94; p[9] = (uint8_t)reg_length; p[10] = 0x80;
}
static void write_packet(uint8_t *p, unsigned reg, unsigned value) {
    memset(p, 0, 192);
    p[0] = 0x40; p[1] = 0xc6; p[6] = 2; p[8] = 0x94; p[10] = 0x80;
    p[64] = (uint8_t)reg; p[65] = (uint8_t)value;
}
static int i2c_read_ex(IOHIDDeviceRef dev, unsigned reg, unsigned n, unsigned reg_length, uint8_t *output) {
    uint8_t packet[192], input[192] = {0};
    read_packet(packet, reg, n, reg_length);
    if (IOHIDDeviceSetReport(dev, kIOHIDReportTypeOutput, 0, packet, sizeof(packet))) return -1;
    CFIndex length = sizeof(input);
    if (IOHIDDeviceGetReport(dev, kIOHIDReportTypeInput, 0, input, &length) || length != 192) return -1;
    memcpy(output, input, n);
    return 0;
}
static int i2c_read(IOHIDDeviceRef dev, unsigned reg, unsigned n, uint8_t *output) {
    return i2c_read_ex(dev,reg,n,1,output);
}
static int i2c_write(IOHIDDeviceRef dev, unsigned reg, unsigned value) {
    uint8_t packet[192];
    write_packet(packet, reg, value);
    return IOHIDDeviceSetReport(dev, kIOHIDReportTypeOutput, 0, packet, sizeof(packet)) == kIOReturnSuccess ? 0 : -1;
}
static const uint8_t vendor_clock_sequence[4][2] = {{0xf4,0x9f},{0xf5,0x06},{0xf4,0xa0},{0xf5,0x74}};
static int vendor_clock(IOHIDDeviceRef dev) {
    for (unsigned i=0;i<4;i++)
        if (i2c_write(dev,vendor_clock_sequence[i][0],vendor_clock_sequence[i][1])) return -1;
    return 0;
}
static int boot_mapping(IOHIDDeviceRef dev, uint8_t output[3]) {
    static const uint8_t low[] = {0xfc,0xfd,0xff};
    for (unsigned i=0;i<3;i++) {
        if (i2c_write(dev,0xf4,0x9f) || i2c_write(dev,0xf5,0xff) ||
            i2c_write(dev,0xf4,low[i]) || i2c_read(dev,0xf5,1,&output[i])) return -1;
    }
    return 0;
}
static int ddc_value(IOHIDDeviceRef dev, uint8_t selector) {
    uint8_t packet[192] = {0}, input[192] = {0};
    packet[0] = 0x40; packet[1] = 0xc6; packet[6] = 36; packet[8] = 0x6e; packet[10] = 0x80;
    const uint8_t frame[] = {0x51,0x83,1,0xe0,selector,0x51^0x83^1^0xe0^selector};
    memcpy(packet+64, frame, sizeof(frame));
    if (IOHIDDeviceSetReport(dev,kIOHIDReportTypeOutput,0,packet,sizeof(packet))) return -1;
    usleep(150000);
    memset(packet,0,sizeof(packet));
    const uint8_t read[] = {0x40,0xd6,0x51,0,0,0,36,0,0x6e,1,0x80};
    memcpy(packet,read,sizeof(read));
    if (IOHIDDeviceSetReport(dev,kIOHIDReportTypeOutput,0,packet,sizeof(packet))) return -1;
    CFIndex n = sizeof(input);
    if (IOHIDDeviceGetReport(dev,kIOHIDReportTypeInput,0,input,&n) || n != 192) return -1;
    const uint8_t header[] = {0x6e,0x88,2,0,0xe0,selector};
    if (memcmp(input,header,sizeof(header))) return -1;
    uint8_t checksum = 0x50;
    for (int i=0;i<11;i++) checksum ^= input[i];
    return checksum ? -1 : (input[8]<<8)|input[9];
}
static int firmware(IOHIDDeviceRef dev) {
    int value=ddc_value(dev,0x38);
    return value>=0 && value>>8=='F' && (value&255)<=99 ? value&255 : -1;
}
static long number(IOHIDDeviceRef dev, CFStringRef key) {
    CFTypeRef value = IOHIDDeviceGetProperty(dev,key);
    long n = -1;
    if (value && CFGetTypeID(value) == CFNumberGetTypeID()) CFNumberGetValue(value,kCFNumberLongType,&n);
    return n;
}
static int self_test(void) {
    for (unsigned value=0;value<256;value++) {
        if (allowed_write(0x61,value,1,1,0) != read_opcode(value)) return 1;
        if (allowed_write(0x60,value,1,1,0) != read_control(value)) return 1;
        if (allowed_write(0x70,value,1,1,0)) return 1;
        if (allowed_write(0x6f,value,1,1,1)) return 1;
        if (allowed_write(0xee,value,0,0,0)) return 1;
    }
    if (!allowed_write(0x6f,0x80,0,0,1) || allowed_write(0x6f,0x80,0,0,0)) return 1;
    if (!allowed_write(0xee,2,0,1,0) || allowed_read(0x70,1,0)) return 1;
    if (!allowed_boot_read(0,0,0) || allowed_boot_read(-1,0,0) ||
        allowed_boot_read(0x80,0,0) || allowed_boot_read(0,1,0) ||
        allowed_boot_read(0,0,1) || allowed_read(0xff,1,0) ||
        allowed_write(0xff,0x20,0,0,1)) return 1;
    puts("PASS: read-only SPI policy; data-port writes and non-read opcodes refused.");
    return 0;
}
int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1],"--self-test")) return self_test();
    if (argc == 2 && !strcmp(argv[1],"--dry-run-vendor-clock")) {
        uint8_t p[192];
        for (unsigned j=0;j<4;j++) {
            write_packet(p,vendor_clock_sequence[j][0],vendor_clock_sequence[j][1]);
            for (int i=0;i<192;i++) printf("%02x%s",p[i],i==191?"\n":" ");
        }
        return 0;
    }
    if (argc == 2 && (!strcmp(argv[1],"--dry-run") || !strcmp(argv[1],"--dry-run-isp-entry") || !strcmp(argv[1],"--dry-run-reset"))) {
        uint8_t p[192];
        if (!strcmp(argv[1],"--dry-run-isp-entry")) write_packet(p,0x6f,0x80);
        else if (!strcmp(argv[1],"--dry-run-reset")) write_packet(p,0xee,2);
        else read_packet(p,0x6f,1,1);
        for (int i=0;i<192;i++) printf("%02x%s",p[i],i==191?"\n":" ");
        return 0;
    }
    int probe = argc == 2 && !strcmp(argv[1],"--probe");
    int allow_clock = argc == 3 && !strcmp(argv[1],"--stdio") && !strcmp(argv[2],"--allow-vendor-clock");
    if (!probe && !allow_clock && !(argc == 2 && !strcmp(argv[1],"--stdio"))) {
        fprintf(stderr,"Usage: %s --self-test|--dry-run|--dry-run-isp-entry|--dry-run-reset|--dry-run-vendor-clock|--probe|--stdio [--allow-vendor-clock]\n",argv[0]); return 2;
    }
    struct sigaction action;
    memset(&action,0,sizeof(action)); action.sa_handler = stop_handler;
    sigaction(SIGTERM,&action,NULL); sigaction(SIGINT,&action,NULL);
    IOHIDManagerRef manager = IOHIDManagerCreate(kCFAllocatorDefault,kIOHIDOptionsTypeNone);
    if (!manager) return 1;
    int vid=0x0bda,pid=0x1100;
    CFNumberRef v=CFNumberCreate(NULL,kCFNumberIntType,&vid), p=CFNumberCreate(NULL,kCFNumberIntType,&pid);
    const void *keys[]={CFSTR(kIOHIDVendorIDKey),CFSTR(kIOHIDProductIDKey)};
    const void *values[]={v,p};
    CFDictionaryRef match=CFDictionaryCreate(NULL,keys,values,2,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
    IOHIDManagerSetDeviceMatching(manager,match); CFRelease(match); CFRelease(v); CFRelease(p);
    IOHIDManagerScheduleWithRunLoop(manager,CFRunLoopGetCurrent(),kCFRunLoopDefaultMode);
    CFRunLoopRunInMode(kCFRunLoopDefaultMode,0.05,false);
    CFSetRef devices=IOHIDManagerCopyDevices(manager);
    IOHIDDeviceRef dev=NULL;
    int status=1, attempted=0, entered=0, mode=-1, engine=-1, stream_ready=0, clock_attempted=0;
    if (!devices || CFSetGetCount(devices)!=1) goto cleanup;
    CFSetGetValues(devices,(const void **)&dev);
    if (number(dev,CFSTR(kIOHIDPrimaryUsagePageKey))!=0xffda || number(dev,CFSTR(kIOHIDPrimaryUsageKey))!=0xda ||
        number(dev,CFSTR(kIOHIDMaxInputReportSizeKey))!=192 || number(dev,CFSTR(kIOHIDMaxOutputReportSizeKey))!=192) { dev=NULL; goto cleanup; }
    if (IOHIDDeviceOpen(dev,kIOHIDOptionsTypeNone)) { dev=NULL; goto cleanup; }
    if (probe) {
        uint8_t a,b;
        if (!i2c_read(dev,0x6f,1,&a) && !i2c_read(dev,0x60,1,&b)) {
            printf("{\"mode_raw\":%u,\"spi_control_raw\":%u,\"mode_changed\":false}\n",a,b); status=0;
        }
        goto cleanup;
    }
    printf("READY %ld\n",number(dev,CFSTR(kIOHIDLocationIDKey))); fflush(stdout);
    char line[64];
    while (!stopped && fgets(line,sizeof(line),stdin)) {
        if (!strchr(line,'\n')) { puts("ERR oversized-command"); fflush(stdout); break; }
        unsigned reg,n; char tail;
        if (!strcmp(line,"Q\n")) { status=0; break; }
        if (!strcmp(line,"C\n") && allow_clock && attempted && entered && !clock_attempted && engine>=0 && !(engine&1)) {
            clock_attempted=1; stream_ready=0;
            puts(vendor_clock(dev) ? "ERR clock-transfer" : "OK");
        } else if (!strcmp(line,"V\n") && !attempted) {
            int version=firmware(dev);
            if (version>=0) printf("OK F%02d\n",version); else puts("ERR firmware-query");
        } else if (!strcmp(line,"A\n") && !attempted) {
            int source=ddc_value(dev,0x2d);
            if (source>=0) printf("OK %d\n",source); else puts("ERR source-query");
        } else if (!strcmp(line,"B\n") && allowed_boot_read(mode,attempted,entered)) {
            uint8_t bank;
            stream_ready=0;
            if (i2c_read(dev,0xff,1,&bank)) puts("ERR boot-bank-read");
            else printf("OK %02x\n",bank);
        } else if (!strcmp(line,"I\n") && allowed_boot_read(mode,attempted,entered)) {
            uint8_t values[3];
            stream_ready=0;
            if (boot_mapping(dev,values)) puts("ERR indexed-boot-read");
            else printf("OK %02x%02x%02x\n",values[0],values[1],values[2]);
        } else if (sscanf(line,"S %u %c",&n,&tail)==1 && entered && stream_ready && n>=1 && n<=128) {
            uint8_t output[128];
            if (i2c_read_ex(dev,0,n,0,output)) { stream_ready=0; puts("ERR stream-transfer"); }
            else { printf("OK "); for (unsigned i=0;i<n;i++) printf("%02x",output[i]); puts(""); }
        } else if (sscanf(line,"R %x %u %c",&reg,&n,&tail)==2 && allowed_read(reg,n,entered)) {
            uint8_t output[128];
            stream_ready=0;
            if (i2c_read(dev,reg,n,output)) puts("ERR read-transfer");
            else {
                stream_ready=entered && reg==0x70;
                if (reg==0x6f) { mode=output[0]; if (attempted) entered=(mode&0x80)!=0; }
                if (reg==0x60) engine=output[0];
                printf("OK "); for (unsigned i=0;i<n;i++) printf("%02x",output[i]); puts("");
            }
        } else if (sscanf(line,"W %x %x %c",&reg,&n,&tail)==2 &&
                   allowed_write(reg,n,entered,attempted,mode>=0 && !(mode&0x80) && engine>=0 && !(engine&1))) {
            uint8_t opcode;
            if (reg==0x60 && (n&1) && (i2c_read(dev,0x61,1,&opcode) || !read_opcode(opcode))) {
                puts("ERR opcode-readback");
            } else {
                stream_ready=0;
                if (reg==0x6f) attempted=1; // A failed host result may still have reached the device.
                if (reg==0xee) attempted=entered=0; // USB may disappear during reset; never resend it.
                if (i2c_write(dev,reg,n)) puts("ERR write-transfer");
                else { if (reg==0xee) attempted=entered=0; puts("OK"); }
                if (reg==0xee) { fflush(stdout); status=0; break; }
            }
        } else puts("ERR command-refused");
        fflush(stdout);
    }
cleanup:
    if (dev) {
        if (attempted && i2c_write(dev,0xee,2)) {
            status=1;
            fprintf(stderr,"Reset could not be confirmed; manual monitor power cycle may be needed. No SPI program/erase commands were sent.\n");
        }
        IOHIDDeviceClose(dev,kIOHIDOptionsTypeNone);
    }
    if (devices) CFRelease(devices);
    IOHIDManagerUnscheduleFromRunLoop(manager,CFRunLoopGetCurrent(),kCFRunLoopDefaultMode);
    CFRelease(manager);
    return status;
}
