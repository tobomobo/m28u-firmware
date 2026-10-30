/* Offline execution of one F11 scheduler in emu8051; no device APIs.
 * stdin must contain exactly the hash-verified F11 bank 8 (65536 bytes).
 * See tools/validate_timer_scheduler.py for the input attribution and build.
 */
#include "emu8051.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char code[65536], memory[65536], upper[128];
static struct em8051 cpu;
static unsigned max_steps;

static void exception(struct em8051 *unused, int reason) {
    (void)unused;
    fprintf(stderr,"Emulator exception %d at %04x\n",reason,cpu.mPC);
    exit(2);
}
static void write_memory(struct em8051 *unused, uint16_t address, uint8_t value) {
    (void)unused;
    if (!((address>=0xc9e2 && address<=0xc9ef) ||
          (address>=0xd46d && address<0xd46d+21*3))) {
        fprintf(stderr,"Unexpected XRAM write %04x at PC %04x\n",address,cpu.mPC);
        exit(2);
    }
    memory[address]=value;
}
static unsigned run_case(unsigned now, unsigned delay, unsigned mode) {
    memset(cpu.mLowerData,0,sizeof(cpu.mLowerData));
    memset(cpu.mSFR,0,sizeof(cpu.mSFR));
    memset(upper,0,sizeof(upper));
    memset(memory+0xc9e2,0,14);
    memset(memory+0xd46d,0,21*3);
    cpu.mLowerData[0x2d]=(unsigned char)(now>>8);
    cpu.mLowerData[0x2e]=(unsigned char)now;
    cpu.mLowerData[5]=6;
    cpu.mLowerData[6]=(unsigned char)(delay>>8);
    cpu.mLowerData[7]=(unsigned char)delay;
    cpu.mSFR[REG_SP]=0x5f;
    push_to_stack(&cpu,0xff); push_to_stack(&cpu,0xff);
    if (mode==1) { /* Existing different event, deadline due now. */
        memory[0xd46d]=5;
        memory[0xd46e]=(unsigned char)(now>>8);
        memory[0xd46f]=(unsigned char)now;
    } else if (mode==2) { /* Same event already pending: active API must keep it. */
        memory[0xd46d]=6; memory[0xd46e]=0x12; memory[0xd46f]=0x34;
    }
    cpu.mPC=0xca9b;
    unsigned steps;
    for (steps=0;steps<5000 && cpu.mPC!=0xffff;steps++) {
        if (!(cpu.mPC<0x5717 ||
              (cpu.mPC>=0xb4e5 && cpu.mPC<0xb5cb) ||
              (cpu.mPC>=0xc6f3 && cpu.mPC<0xc770) ||
              (cpu.mPC>=0xca9b && cpu.mPC<0xcb1e) ||
              (cpu.mPC>=0xec79 && cpu.mPC<0xeca7))) {
            fprintf(stderr,"Execution escaped scheduler at %04x\n",cpu.mPC);
            exit(2);
        }
        cpu.op[code[cpu.mPC]](&cpu); /* Instructions only: no emulated clock/IRQ. */
    }
    if (cpu.mPC!=0xffff || cpu.mSFR[REG_SP]!=0x5f) {
        fprintf(stderr,"Scheduler failed to return, PC=%04x SP=%02x\n",cpu.mPC,cpu.mSFR[REG_SP]);
        exit(2);
    }
    if (steps>max_steps) max_steps=steps;
    unsigned counter=(cpu.mLowerData[0x2d]<<8)|cpu.mLowerData[0x2e];
    unsigned slot=mode==1 ? 0xd470 : 0xd46d;
    unsigned deadline=(memory[slot+1]<<8)|memory[slot+2];
    unsigned expected=mode==2 ? 0x1234 : ((counter+delay)&65535);
    if (memory[slot]!=6 || deadline!=expected || (mode==2 && counter!=now)) {
        fprintf(stderr,"Wrong deadline now=%u delay=%u mode=%u counter=%u deadline=%u\n",
                now,delay,mode,counter,deadline);
        exit(2);
    }
    if (mode==1) {
        unsigned other=(memory[0xd46e]<<8)|memory[0xd46f];
        if (memory[0xd46d]!=5 || other!=counter) {
            fprintf(stderr,"Existing event deadline was not preserved/rebased\n");
            exit(2);
        }
    }
    return counter!=now;
}
int main(void) {
    if (fread(code,1,sizeof(code),stdin)!=sizeof(code) || fgetc(stdin)!=EOF) return 2;
    cpu.mCodeMem=code;cpu.mCodeMemMaxIdx=65535;
    cpu.mExtData=memory;cpu.mExtDataMaxIdx=65535;cpu.mUpperData=upper;
    cpu.except=exception;cpu.xwrite=write_memory;
    reset(&cpu,false);
    unsigned cases=0,rebases=0;
    for (unsigned mode=0;mode<3;mode++)
        for (unsigned now=0;now<65536;now++)
            for (unsigned d=0;d<2;d++) {
                rebases+=run_case(now,d ? 60000 : 5000,mode);
                cases++;
            }
    printf("{\"cases\":%u,\"counter_rebases\":%u,\"max_instructions\":%u,"
           "\"delays\":[5000,60000],\"all_16bit_counter_values\":true,"
           "\"hardware_access\":false,\"interrupts_or_wall_clock_modeled\":false}\n",
           cases,rebases,max_steps);
    return 0;
}
