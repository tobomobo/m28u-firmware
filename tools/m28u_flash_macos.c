// Explicit writer worker. The existing read-only worker and its policy stay separate.
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/hid/IOHIDManager.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
static int replay_mode;
static IOReturn writer_set_report(IOHIDDeviceRef d,IOHIDReportType t,CFIndex id,const uint8_t *p,CFIndex n) {
    if(!replay_mode)return IOHIDDeviceSetReport(d,t,id,p,n);
    if(n!=192)return kIOReturnError;
    printf("USB-OUT ");for(CFIndex i=0;i<n;i++)printf("%02x",p[i]);puts("");fflush(stdout);
    char answer[16];return fgets(answer,sizeof(answer),stdin)&&!strcmp(answer,"ACK\n")?kIOReturnSuccess:kIOReturnError;
}
static IOReturn writer_get_report(IOHIDDeviceRef d,IOHIDReportType t,CFIndex id,uint8_t *p,CFIndex *n) {
    if(!replay_mode)return IOHIDDeviceGetReport(d,t,id,p,n);
    puts("USB-IN");fflush(stdout);char answer[400];
    if(!fgets(answer,sizeof(answer),stdin)||strlen(answer)!=390||strncmp(answer,"DATA ",5)||*n<192)return kIOReturnError;
    for(unsigned i=0;i<192;i++) {
        unsigned value;char pair[3]={answer[5+i*2],answer[6+i*2],0};
        if(strspn(pair,"0123456789abcdefABCDEF")!=2||sscanf(pair,"%x",&value)!=1)return kIOReturnError;
        p[i]=(uint8_t)value;
    }
    *n=192;return kIOReturnSuccess;
}
#define IOHIDDeviceSetReport writer_set_report
#define IOHIDDeviceGetReport writer_get_report
#define main reader_worker_main
#include "m28u_scaler_macos.c"
#undef main

static int writer_read(unsigned r, unsigned n, int entered) {
    if ((r==0x6f || r==0x60) && n==1) return 1;
    if (!entered) return 0;
    if (r==0x6f && n==10) return 1;
    if (r==0x64 && n==3) return 1;
    if (r==0x70 && n>=1 && n<=128) return 1;
    return n==1 && (r==0x61 || r==0x55 || r==0xf2 || r==0xe3 ||
        r==0xf5 || (r>=0x64 && r<=0x69) || r==0x75);
}
static int writer_opcode(unsigned value) {
    return read_opcode(value) || value==0x35 || value==0x15;
}
static int writer_control(unsigned value) {
    return read_control(value) || value==0x68 || value==0x69 || value==0xb8 || value==0xb9;
}
static int update_address(const uint8_t a[3], int erase) {
    unsigned address=((unsigned)a[0]<<16)|((unsigned)a[1]<<8)|a[2];
    return address>=0x200000 && address<0x3b0000 &&
        (erase ? (address&65535)==0 : (address&255)==0);
}
static int read_registers(IOHIDDeviceRef dev, unsigned reg, unsigned n, uint8_t *output) {
    // A burst repeats the selected register on M28U. Select each byte instead.
    for(unsigned i=0;i<n;i++)
        if(i2c_read(dev,reg+i,1,&output[i])) return -1;
    return 0;
}
static int identify_writer(IOHIDDeviceRef dev) {
    uint8_t b=1, id[3];
    if (i2c_read(dev,0x60,1,&b) || (b&1) ||
        i2c_write(dev,0x60,0x46) || i2c_write(dev,0x61,0x9f) ||
        i2c_write(dev,0x60,0x47)) return -1;
    for (unsigned i=0;i<100;i++) {
        if (i2c_read(dev,0x60,1,&b)) return -1;
        if (!(b&1)) return read_registers(dev,0x67,3,id) || memcmp(id,"\xc8\x40\x16",3) ? -1 : 0;
        usleep(2000);
    }
    return -1;
}
static int indexed_read_wp(IOHIDDeviceRef dev, uint8_t *b) {
    return i2c_write(dev,0xf4,0x9f) || i2c_write(dev,0xf5,0x10) ||
        i2c_write(dev,0xf4,0x0a) || i2c_read(dev,0xf5,1,b) ? -1 : 0;
}
static int indexed_write_wp(IOHIDDeviceRef dev, uint8_t b) {
    return i2c_write(dev,0xf4,0x9f) || i2c_write(dev,0xf5,0x10) ||
        i2c_write(dev,0xf4,0x0a) || i2c_write(dev,0xf5,b) ? -1 : 0;
}
static int writer_self_test(void) {
    uint8_t a[][3]={{0x20,0,0},{0x3a,0xff,0},{0x1f,0xff,0},{0x3b,0,0},{0x20,0,1}};
    if (!update_address(a[0],1) || !update_address(a[1],0) || update_address(a[1],1) ||
        update_address(a[2],0) || update_address(a[3],0) || update_address(a[4],0)) return 1;
    if (!writer_opcode(0x35) || !writer_opcode(0x15) || writer_opcode(0x31) ||
        writer_read(0xf5,1,0) || !writer_read(0x6f,10,1)) return 1;
    puts("PASS: writer address limits; status/OTP writes absent except SR1 command 01.");
    return 0;
}
int main(int argc, char **argv) {
    if (argc==2 && !strcmp(argv[1],"--self-test")) return writer_self_test();
    replay_mode=argc==2&&!strcmp(argv[1],"--stdio-writer-dry-run");
    if (!(argc==2 && !strcmp(argv[1],"--stdio-writer"))&&!replay_mode) return 2;
    struct sigaction action;
    memset(&action,0,sizeof(action)); action.sa_handler=stop_handler;
    sigaction(SIGINT,&action,NULL); sigaction(SIGTERM,&action,NULL);
    IOHIDManagerRef manager=NULL;CFSetRef devices=NULL;IOHIDDeviceRef dev=NULL;
    int status=1,attempted=0,entered=0,armed=0,destructive=0,committed=0,hold=0;
    int mode=-1,engine=-1,stream_ready=0,wp_saved=0,wp_changed=0,clock_changed=0,status_payload=-1;
    uint8_t intended_address[3]={0};unsigned address_staged=0;
    unsigned staged=0; int page_address_checked=0; uint8_t wp=0,e3=0;
    if(replay_mode) {dev=(IOHIDDeviceRef)(uintptr_t)1;goto connected;}
    manager=IOHIDManagerCreate(NULL,kIOHIDOptionsTypeNone);
    if (!manager) return 1;
    int vid=0x0bda,pid=0x1100;
    CFNumberRef v=CFNumberCreate(NULL,kCFNumberIntType,&vid),p=CFNumberCreate(NULL,kCFNumberIntType,&pid);
    const void *keys[]={CFSTR(kIOHIDVendorIDKey),CFSTR(kIOHIDProductIDKey)};
    const void *values[]={v,p};
    CFDictionaryRef match=CFDictionaryCreate(NULL,keys,values,2,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
    IOHIDManagerSetDeviceMatching(manager,match); CFRelease(match); CFRelease(v); CFRelease(p);
    IOHIDManagerScheduleWithRunLoop(manager,CFRunLoopGetCurrent(),kCFRunLoopDefaultMode);
    CFRunLoopRunInMode(kCFRunLoopDefaultMode,0.05,false);
    devices=IOHIDManagerCopyDevices(manager);
    if (!devices || CFSetGetCount(devices)!=1) goto done;
    CFSetGetValues(devices,(const void **)&dev);
    if (number(dev,CFSTR(kIOHIDPrimaryUsagePageKey))!=0xffda || number(dev,CFSTR(kIOHIDPrimaryUsageKey))!=0xda ||
        number(dev,CFSTR(kIOHIDMaxInputReportSizeKey))!=192 || number(dev,CFSTR(kIOHIDMaxOutputReportSizeKey))!=192) {dev=NULL;goto done;}
    if (IOHIDDeviceOpen(dev,kIOHIDOptionsTypeNone)) {dev=NULL;goto done;}
connected:
    printf("READY %ld\n",replay_mode?0:number(dev,CFSTR(kIOHIDLocationIDKey)));fflush(stdout);
    char line[192];
    while (!stopped && fgets(line,sizeof(line),stdin)) {
        unsigned reg,n; char tail; uint8_t output[128];
        if (!strchr(line,'\n')) {puts("ERR oversized-command");fflush(stdout);break;}
        if (!strcmp(line,"Q\n")) {hold=wp_changed;status=(destructive&&!committed)||hold?1:0;break;}
        if (!strcmp(line,"V\n") && !attempted) {
            int ver=firmware(dev); if(ver>=0) printf("OK F%02d\n",ver);else puts("ERR firmware");
        } else if (!strcmp(line,"A\n") && !attempted) {
            int source=ddc_value(dev,0x2d);if(source>=0)printf("OK %d\n",source);else puts("ERR source");
        } else if (!strcmp(line,"X\n") && entered && !armed && !destructive && !identify_writer(dev)) {
            armed=1;puts("OK");
        } else if (!strcmp(line,"C\n") && entered && !clock_changed) {
            clock_changed=1;puts(vendor_clock(dev)?"ERR clock":"OK");
        } else if (!strcmp(line,"U\n") && armed && entered && !wp_saved) {
            if (indexed_read_wp(dev,&wp) || i2c_read(dev,0xe3,1,&e3)) puts("ERR wp-read");
            else {
                wp_saved=wp_changed=1;
                uint8_t a,b;
                if(indexed_write_wp(dev,(uint8_t)((wp&0xf9)|1)) || i2c_write(dev,0xe3,e3|4) ||
                    indexed_read_wp(dev,&a) || i2c_read(dev,0xe3,1,&b) || a!=((wp&0xf9)|1) || b!=(e3|4)) puts("ERR wp-write");
                else printf("OK %02x%02x\n",wp,e3);
            }
        } else if (!strcmp(line,"L\n") && entered && wp_saved && wp_changed) {
            uint8_t a,b;
            if (indexed_write_wp(dev,wp) || i2c_write(dev,0xe3,e3) ||
                indexed_read_wp(dev,&a) || i2c_read(dev,0xe3,1,&b) || a!=wp || b!=e3) puts("ERR wp-restore");
            else {wp_changed=0;puts("OK");}
        } else if (!strcmp(line,"K\n") && entered && destructive && !wp_changed && !staged) {
            committed=1;armed=0;puts("OK");
        } else if (!strncmp(line,"D ",2) && strlen(line)==131 && armed && entered && wp_changed && staged<=192) {
            uint8_t packet[192]={0},address[3];int valid=1;
            packet[0]=0x40;packet[1]=0xc6;packet[6]=65;packet[8]=0x94;packet[10]=0x80;packet[64]=0x70;
            for (unsigned i=0;i<64;i++) {
                unsigned value; char pair[3]={line[2+i*2],line[3+i*2],0};
                if (strspn(pair,"0123456789abcdefABCDEF")!=2 || sscanf(pair,"%x",&value)!=1) {valid=0;break;}
                packet[65+i]=(uint8_t)value;
            }
            if(valid && staged==0) {
                page_address_checked=address_staged==7 && !read_registers(dev,0x64,3,address) &&
                    !memcmp(address,intended_address,3) && update_address(address,0);
            }
            if (!valid) puts("ERR data-format");
            else if(!page_address_checked) puts("ERR page-address");
            else if (IOHIDDeviceSetReport(dev,kIOHIDReportTypeOutput,0,packet,sizeof(packet))) puts("ERR data-transfer");
            else {staged+=64;puts("OK");}
        } else if (sscanf(line,"S %u %c",&n,&tail)==1 && entered && stream_ready && n>=1 && n<=128) {
            if(i2c_read_ex(dev,0,n,0,output)) {stream_ready=0;puts("ERR stream");}
            else {printf("OK ");for(unsigned i=0;i<n;i++)printf("%02x",output[i]);puts("");}
        } else if (sscanf(line,"R %x %u %c",&reg,&n,&tail)==2 && writer_read(reg,n,entered)) {
            stream_ready=0;
            if(i2c_read(dev,reg,n,output)) puts("ERR read");
            else {
                if(reg==0x6f) {mode=output[0];if(attempted)entered=(mode&0x80)!=0;}
                if(reg==0x60)engine=output[0];
                stream_ready=reg==0x70;
                printf("OK ");for(unsigned i=0;i<n;i++)printf("%02x",output[i]);puts("");
            }
        } else if (sscanf(line,"W %x %x %c",&reg,&n,&tail)==2 && reg<=255 && n<=255) {
            int allowed=0;uint8_t opcode=0,address[3];
            if(reg==0x6f && n==0x80 && !attempted && mode>=0 && !(mode&0x80) && engine>=0 && !(engine&1)) allowed=1;
            else if(reg==0xee && n==2 && attempted && !wp_changed && (!destructive || committed)) allowed=1;
            else if(entered) {
                if(reg==0x61 && (writer_opcode(n) || (armed&&wp_changed&&(n==1||n==0xd8)))) allowed=1;
                else if(reg==0x60 && writer_control(n)) {
                    if(!i2c_read(dev,0x61,1,&opcode)) {
                        allowed=(!(n&1) && read_control(n)) || (writer_opcode(opcode)&&read_control(n));
                        if(armed&&wp_changed&&(n==0x68||n==0xb8)) allowed=1;
                        if(armed&&wp_changed&&opcode==1&&n==0x68) allowed=1;
                        if(armed&&wp_changed&&opcode==1&&n==0x69&&status_payload>=0 &&
                            !i2c_read(dev,0x64,1,address)&&address[0]==status_payload) allowed=1;
                        if(armed&&wp_changed&&opcode==0xd8&&(n==0xb8||n==0xb9) &&
                            address_staged==7 && !read_registers(dev,0x64,3,address) &&
                            !memcmp(address,intended_address,3) && update_address(address,1)) allowed=1;
                        if(allowed&&(n&1)&&(opcode==1||opcode==0xd8)) destructive=1;
                    }
                } else if(reg>=0x64&&reg<=0x66) {allowed=1;if(reg==0x65)staged=0;}
                else if(reg==0x6a&&n==3)allowed=1;
                else if(armed) {
                    allowed=(reg==0x6d&&n==2)||(reg==0x71&&n==255)||
                        (reg==0x6f&&mode>=0&&(mode&0x80)&&!(mode&0x20)&&n==((unsigned)mode|4))||
                        (reg>=0x72&&reg<=0x74)||(reg==0x55)||
                        (reg==0xf2)|| (reg==0x56&&n==0x47)||(reg==0x57&&n==0)||
                        (reg==0x58&&n==0)||(reg==0x59&&n==3)||(reg==0x5a&&n==0x36)||
                        (reg==0x5b&&n==0x22)||(reg==0x5c&&n==0x26)||(reg==0x5f&&n==1)||
                        (reg==0x6b&&n==0x0b)||(reg==0x6c&&n==0)||(reg==0x62&&n==6)||
                        (reg==0x63&&n==0x50)||(reg==0xed&&n==0x88)||(reg==0xee&&n==4);
                    if(reg==0x6f&&n==0xa0&&wp_changed&&staged==256&&page_address_checked) {
                        allowed=1;destructive=1;staged=0;page_address_checked=0;
                    }
                }
            }
            if(!allowed) puts("ERR write-policy");
            else {
                stream_ready=0;if(reg==0x6f&&n==0x80)attempted=1;
                if(reg==0x64)status_payload=(int)n;
                if(reg>=0x64&&reg<=0x66) {intended_address[reg-0x64]=(uint8_t)n;address_staged|=1u<<(reg-0x64);page_address_checked=0;}
                if(reg==0x6f)mode=-1;
                if(reg==0xee&&n==2) {attempted=entered=0;}
                puts(i2c_write(dev,reg,n)?"ERR write-transfer":"OK");
                if(reg==0xee&&n==2) {status=0;fflush(stdout);break;}
            }
        } else puts("ERR command-policy");
        fflush(stdout);
    }
done:
    if(dev) {
        // Unexpected EOF/signal before a flash write must restore GPIO state
        // before resetting. Explicit Q with pending WP means the host asked
        // us to preserve its failed-cleanup state, so do not retry or reset.
        if(attempted && !hold && !destructive && wp_changed) {
            uint8_t a,b;
            if(indexed_write_wp(dev,wp) || i2c_write(dev,0xe3,e3) ||
                indexed_read_wp(dev,&a) || i2c_read(dev,0xe3,1,&b) || a!=wp || b!=e3) {hold=1;status=1;}
            else wp_changed=0;
        }
        if(attempted && !hold && !wp_changed && (!destructive||committed) && i2c_write(dev,0xee,2)) status=1;
        if(attempted && (hold || wp_changed || (destructive&&!committed))) fprintf(stderr,"Update uncommitted: preserving ISP state; do not power-cycle until recovery is assessed.\n");
        if(!replay_mode)IOHIDDeviceClose(dev,kIOHIDOptionsTypeNone);
    }
    if(devices)CFRelease(devices);
    if(manager) {IOHIDManagerUnscheduleFromRunLoop(manager,CFRunLoopGetCurrent(),kCFRunLoopDefaultMode);CFRelease(manager);}
    return status;
}
