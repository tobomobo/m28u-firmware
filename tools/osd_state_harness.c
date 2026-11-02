/* Offline OSD execution. Reuse the banked CPU/fixtures, never a live transport. */
#define main retained_kvm_harness_main
#include "kvm_state_harness.c"
#undef main

static unsigned menu_entries, main_entries, draw_calls, osd_peak;

static void osd_xwrite(struct em8051 *unused, uint16_t address, uint8_t value) {
    (void)unused;
    if (address == 0xffff) {
        unsigned next = (unsigned char)(value - cpu.mLowerData[0x30]);
        if (next > 20) fail("OSD bank escaped populated image");
        bank = next;
        memcpy(code, image + bank*65536, sizeof(code));
    } else if (!((address >= 0xc990 && address <= 0xcaff) ||
                 (address >= 0xd364 && address <= 0xd390) ||
                 (address >= 0xd46d && address < 0xd46d+63) ||
                 (address >= 0xd75c && address <= 0xd765) ||
                 (address >= 0xd8d0 && address <= 0xd8d5) ||
                 address == 0xd8e0 || address == 0xd8e1 || address == 0xd71b))
        fail("OSD unexpected XRAM write");
    memory[address] = value;
    writes[address]++;
}

static void osd_run(unsigned pc, unsigned stop) {
    unsigned initial_bank = bank;
    cpu.mSFR[REG_SP] = 0x5f;
    push_to_stack(&cpu, 0xff); push_to_stack(&cpu, 0xff); cpu.mPC = pc;
    for (unsigned step = 0; step < 20000 && cpu.mPC != stop; step++) {
        if (cpu.mSFR[REG_SP] > peak_sp) peak_sp = cpu.mSFR[REG_SP];
        if (peak_sp > osd_peak) osd_peak = peak_sp;
        if (cpu.mSFR[REG_SP] >= 0xf0) fail("OSD stack guard exceeded");
        if(bank==0 && cpu.mPC==0x88f0) {
            if(cpu.mLowerData[7]!=11)fail("OSD unexpected power action");
            power_actions++;ret();continue;
        }
        /* Rendering/mixer calls are deliberately intercepted. Menu state,
         * callback selection and the original opener execute on the real CPU. */
        switch (cpu.mPC) {
            case 0x3257: case 0x3275: case 0x329f: case 0x325d:
            case 0x326f: case 0x3311: case 0x32ab: case 0x32b1:
            case 0x327b: case 0x2e2b: case 0x3281: case 0x32b7:
            case 0x2d8f: case 0x32c3: case 0x3071: case 0x32cf:
            case 0x3353: case 0x328d: case 0x3359: case 0x356f: case 0x3131:
                draw_calls++; ret(); continue;
            case 0x32a5: carry(0); ret(); continue;
            default: break;
        }
        if (bank == 16 && cpu.mPC == 0xfef5) { ret(); continue; }
        if (bank == 19 && cpu.mPC == 0xe76e) { ret(); continue; }
        if (bank == 3 && cpu.mPC == 0xe382) menu_entries++;
        if (bank == 3 && cpu.mPC == 0xc75b) main_entries++;
        if (bank == 3 && (cpu.mPC == 0xb2a1 || cpu.mPC == 0xf837)) {
            draw_calls++; ret(); continue;
        }
        if (bank == 3 && (cpu.mPC == 0x67ed || cpu.mPC == 0x69cd)) {
            draw_calls++; ret(); continue;
        }
        if (!(cpu.mPC < 0x5717 ||
              (bank == 16 && ((cpu.mPC >= 0xe062 && cpu.mPC < 0xe0e8) ||
                               (cpu.mPC >= 0xfbfa && cpu.mPC < 0xfc14))) ||
              (bank == 20 && ((cpu.mPC >= 0x6731 && cpu.mPC < 0x675e) ||
                               (cpu.mPC >= 0x67df && cpu.mPC < 0x67ed))) ||
              (bank == 0 && ((cpu.mPC >= 0xe7cc && cpu.mPC < 0xe7fc) ||
                              (cpu.mPC >= 0xaa5a && cpu.mPC < 0xab44) ||
                              (cpu.mPC >= 0xe08a && cpu.mPC < 0xe095) ||
                              (cpu.mPC >= 0xf188 && cpu.mPC < 0xf1a9))) ||
              (bank == 3 && ((cpu.mPC >= 0xe382 && cpu.mPC < 0xe41f) ||
                              (cpu.mPC >= 0xc75b && cpu.mPC < 0xc89a) ||
                              (cpu.mPC >= 0x669b && cpu.mPC < 0x66ac) ||
                              (cpu.mPC >= 0x66c1 && cpu.mPC < 0x66cc) ||
                              (cpu.mPC >= 0x671b && cpu.mPC < 0x6724) ||
                              (cpu.mPC >= 0x679c && cpu.mPC < 0x67da) ||
                              (cpu.mPC >= 0x67e5 && cpu.mPC < 0x67ed) ||
                              (cpu.mPC >= 0x6933 && cpu.mPC < 0x693a) ||
                              (cpu.mPC >= 0x697d && cpu.mPC < 0x6995) ||
                              (cpu.mPC >= 0x69bf && cpu.mPC < 0x69da) ||
                              (cpu.mPC >= 0x6f75 && cpu.mPC < 0x6f83) ||
                              (cpu.mPC >= 0x6f90 && cpu.mPC < 0x6f9a))) ||
              (bank == 19 && ((cpu.mPC >= 0x8c9c && cpu.mPC < 0x8d7d) ||
                               cpu.mPC >= 0xff00 || cpu.mPC == 0xfeff ||
                               (cpu.mPC >= 0xa740 && cpu.mPC < 0xa747) ||
                               (cpu.mPC >= 0xa7c3 && cpu.mPC < 0xa809) ||
                               (cpu.mPC >= 0xa8a4 && cpu.mPC < 0xa8aa) ||
                               (cpu.mPC >= 0xfbb2 && cpu.mPC < 0xfbbe) ||
                               (cpu.mPC >= 0xeeca && cpu.mPC < 0xef17) ||
                               (cpu.mPC >= 0xf07c && cpu.mPC < 0xf0bd) ||
                               (cpu.mPC >= 0x93b0 && cpu.mPC < 0x93b7) ||
                               (cpu.mPC >= 0xf33c && cpu.mPC < 0xf371) ||
                               (cpu.mPC >= 0xfed5 && cpu.mPC < 0xfedb) ||
                               (cpu.mPC >= 0xad2c && cpu.mPC < 0xad97))) ||
              (bank == 4 && ((cpu.mPC >= 0x7f3f && cpu.mPC < 0x7f46) ||
                              (cpu.mPC >= 0xdf36 && cpu.mPC < 0xdf45) ||
                              (cpu.mPC >= 0xfe63 && cpu.mPC < 0xfe69) ||
                              (cpu.mPC >= 0xfdaf && cpu.mPC < 0xfdb8) ||
                              (cpu.mPC >= 0xfe7b && cpu.mPC < 0xfe80))) ||
              (bank == 5 && cpu.mPC >= 0xfeed && cpu.mPC < 0xfef6) ||
              (bank == 8 && ((cpu.mPC >= 0xca9b && cpu.mPC < 0xcb1e) ||
                              (cpu.mPC >= 0xc806 && cpu.mPC < 0xc88d) ||
                              (cpu.mPC >= 0xec79 && cpu.mPC < 0xeca7) ||
                              (cpu.mPC >= 0xf132 && cpu.mPC < 0xf156) ||
                              (cpu.mPC >= 0xb4e5 && cpu.mPC < 0xb5cb) ||
                              (cpu.mPC >= 0xc6f3 && cpu.mPC < 0xc770)))))
            fail("OSD escaped selected firmware instructions");
        cpu.op[code[cpu.mPC]](&cpu);
    }
    if (cpu.mPC != stop || bank != initial_bank || cpu.mLowerData[0x2f] != bank ||
        memory[0xffff] != bank + 0x20 ||
        cpu.mSFR[REG_SP] != (stop == 0xffff ? 0x5f : 0x61))
        fail("OSD failed to return to dispatcher boundary");
}

static void osd_fixture(unsigned phase, unsigned enabled, unsigned port) {
    setup(19); menu_entries=main_entries=draw_calls=0;
    state(phase==0 ? 0x26 : 0, phase==2 ? 4 : 3, enabled, port);
    memory[0xd8d4]=0x23;
    memory[0xd8d5]=phase==2 ? 0x20 : 0;
    memory[0xd368]=0;
    for (unsigned slot=0;slot<3;slot++) {
        memory[0xd46d+slot*3]=(unsigned char)(5+slot);
        memory[0xd46e + slot*3]=0;memory[0xd46f+slot*3]=100;
    }
    memory[0xd4a9]=0x42;
}
static unsigned timer_count(unsigned stage) {
    unsigned count=0;
    for(unsigned i=0;i<21;i++)count+=memory[0xd46d+i*3]==stage;
    return count;
}
static unsigned now(void) {
    return ((unsigned)cpu.mLowerData[0x2d] << 8) | cpu.mLowerData[0x2e];
}
static void deadline(unsigned stage, unsigned delay) {
    unsigned found=0;
    for(unsigned i=0;i<21;i++) {
        unsigned at=0xd46d+3*i;
        if(memory[at]!=stage)continue;
        if(++found!=1 || (((unsigned)memory[at+1]<<8)|memory[at+2])!=((now()+delay)&65535))
            fail("OSD timer deadline mismatch");
    }
    if(found!=1)fail("OSD timer missing");
}
static void assert_menu(void) {
    if (menu_entries!=1 || memory[0xd365] || memory[0xd366]!=1 || !draw_calls ||
        memory[0xd8d4]!=0x22 || timer_count(5) || timer_count(7) ||
        timer_count(6)!=1 || timer_count(8)!=1 || memory[0xd4a9]!=0x42)
        fail("OSD menu/power/timer state mismatch");
    deadline(6,60000);
    deadline(8,memory[0xd8e0]==3 ? (memory[0xd126]*5+5)*1000 : 3000);
    if (writes[0xd85f] || writes[0xd11f] || writes[0xd378] || writes[0xfe09])
        fail("OSD press changed source, saved setting or USB route");
}
static void osd_deliver(unsigned stage) {
    select_bank(19);cpu.mLowerData[7]=(unsigned char)stage;osd_run(0x2bf1,0xffff);
    select_bank(20);cpu.mLowerData[7]=(unsigned char)stage;osd_run(0x6731,0xffff);
    select_bank(19);osd_run(0xa740,0xffff);
}
static int suite(void) {
    unsigned opens=0,guards=0,capacity=0,sequences=0,navigation=0,clocks=0,events=0,timer_gates=0;
    for(unsigned phase=0;phase<3;phase++)
    for(unsigned enabled=0;enabled<2;enabled++)
    for(unsigned port=1;port<=2;port++)
    for(unsigned message=0;message<256;message++) {
        osd_fixture(phase,enabled,port);
        memory[0xd367]=(unsigned char)message;
        osd_run(0x8c9c,0xffff);assert_menu();
        if(memory[0xd367]!=(message>=1&&message<=6 ? 0 : message))
            fail("OSD dropped an unrelated message or kept stale standby");
        opens++;
    }
    for(unsigned phase=0;phase<3;phase++)
    for(unsigned guard=0;guard<15;guard++) {
        osd_fixture(phase,0,1);
        switch(guard) {
            case 0:memory[0xd11e]|=0x20;break;
            case 1:memory[0xd364]=4;break;
            case 2:memory[0xd364]=8;break;
            case 3:memory[0xd706]=1;break;
            case 4:memory[0xd706]=2;break;
            case 5:memory[0xd706]=4;break;
            case 6:memory[0xd143]=1;break;
            case 7:memory[0xd8d4]=0x21;break;
            case 8:memory[0xd8d4]=0x11;break;
            case 9:memory[0xd8d4]=0x1f;break;
            case 10:cpu.mLowerData[0x2a]|=1;break;
            case 11:memory[0xd365]=1;break;
            case 12:memory[0xd366]=0x25;break;
            case 13:memory[0xd8e0]=0x14;break;
            case 14:memory[0xd8e0]=5;break;
        }
        unsigned char before[63];memcpy(before,memory+0xd46d,63);
        unsigned power=memory[0xd8d4],screen=memory[0xd366];
        osd_run(0x8c9c,0x8c9f);
        if(menu_entries||draw_calls||writes[0xd8d4]||memory[0xd8d4]!=power||
           memory[0xd366]!=screen||memcmp(before,memory+0xd46d,63))
            fail("OSD bypassed a refusal guard");
        guards++;
    }
    for(unsigned event=1;event<256;event++) {
        if(event==9)continue; /* Its unchanged behavior has its own 38-case suite. */
        osd_fixture(0,0,2);memory[0xd368]=(unsigned char)event;
        osd_run(0x8c9c,0x8c9f);
        if(menu_entries||draw_calls||writes[0xd8d4])fail("OSD opened for another key event");
        events++;
    }
    const unsigned modes[]={2,3,4,0x14};
    for(unsigned m=0;m<4;m++)
    for(unsigned layout=0;layout<2;layout++)
    for(unsigned high=0;high<2;high++)
    for(unsigned screen=0;screen<256;screen++)
    for(unsigned port=1;port<=4;port++) {
        osd_fixture(0,0,port);
        memory[0xd8e0]=(unsigned char)modes[m];memory[0xd143]=(unsigned char)layout;
        memory[0xd365]=(unsigned char)high;memory[0xd366]=(unsigned char)screen;
        memory[0xd46d+9]=8;memory[0xd367]=5;
        unsigned expected=modes[m]==3&&!layout&&!high&&screen>=1&&screen<=0x24&&port<=2;
        osd_run(0xa740,expected ? 0xffff : 0xa7c6);
        if(expected) {
            if(memory[0xd366]!=screen||memory[0xd367]||timer_count(6)!=1)
                fail("Timer gate failed to defer active menu");
            deadline(6,60000);
        } else if(writes[0xd46d]||writes[0xd367]||memory[0xd366]!=screen||
                  cpu.mSFR[REG_DPH]!=0xd1||cpu.mSFR[REG_DPL]!=0x43)
            fail("Timer gate failed to replay stock continuation");
        timer_gates++;
    }
    /* At every slot position, one usable slot must refuse and two must open.
     * Stale stages5..8 count as reusable without losing unrelated entries. */
    for(unsigned first=0;first<21;first++)
    for(unsigned reusable=0;reusable<=8;reusable++) {
        if(reusable>0&&reusable<5)continue;
        for(unsigned available=1;available<=2;available++) {
            osd_fixture(0,0,2);
            for(unsigned i=0;i<21;i++) {
                memory[0xd46d+3*i]=0x42;
                memory[0xd46e + 3*i]=memory[0xd46f+3*i]=0;
            }
            memory[0xd46d+3*first]=(unsigned char)reusable;
            unsigned second=(first+1)%21;
            if(available==2)memory[0xd46d+3*second]=0;
            if(available==1) {
                osd_run(0x8c9c,0x8c9f);
                if(menu_entries||draw_calls||writes[0xd8d4])fail("OSD ignored timer capacity");
            } else {
                osd_run(0x8c9c,0xffff);
                if(menu_entries!=1||timer_count(6)!=1||timer_count(8)!=1)
                    fail("OSD did not reuse two available timer slots");
            }
            for(unsigned i=0;i<21;i++) {
                if(i==first||(available==2&&i==second))continue;
                if(memory[0xd46d+3*i]!=0x42||memory[0xd46e + 3*i]||memory[0xd46f+3*i])
                    fail("OSD overwrote unrelated timer");
            }
            capacity++;
        }
    }
    for(unsigned port=1;port<=2;port++)
    for(unsigned screen=1;screen<=0x24;screen++) {
        osd_fixture(0,0,port);osd_run(0x8c9c,0xffff);assert_menu();
        memory[0xd366]=(unsigned char)screen;
        osd_deliver(6);
        if(memory[0xd366]!=screen||memory[0xd367]||timer_count(6)!=1||timer_count(7)||
           memory[0xd8d4]!=0x22)fail("Standby timer closed an open menu");
        deadline(6,60000);
        /* Execute actual stock close cleanup, then actual stage6/7 handlers. */
        select_bank(19);osd_run(0x2dc5,0xffff);
        osd_deliver(6);
        if(memory[0xd366]||timer_count(6)||timer_count(7)!=1)
            fail("Closing menu did not restore stock standby chain");
        osd_deliver(7);
        if(memory[0xd8d4]!=0x23||memory[0xd367]||timer_count(7))
            fail("Closed menu did not return to standby request");
        sequences++;
    }
    /* Execute the real close-key callback. A stale visible screen without
     * stage8 must also stop deferring standby, even in source-state2. */
    for(unsigned port=1;port<=2;port++) {
        osd_fixture(0,0,port);osd_run(0x8c9c,0xffff);assert_menu();
        memory[0xd368]=0;osd_run(0x8c9c,0xffff);
        if(memory[0xd366]||timer_count(8))fail("Stock close key did not close quick menu");
        navigation++;
        osd_fixture(0,0,port);osd_run(0x8c9c,0xffff);
        cpu.mLowerData[7]=8;osd_run(0x2bf1,0xffff);
        osd_deliver(6);
        if(memory[0xd366]||timer_count(6)||timer_count(7)!=1)
            fail("Expired menu remained awake indefinitely");
        navigation++;
        osd_fixture(0,0,port);osd_run(0x8c9c,0xffff);
        memory[0xd368]=1;osd_run(0x8c9c,0xffff);
        if(main_entries!=1||memory[0xd366]!=0x1f||timer_count(8)!=1)
            fail("Stock main-menu navigation did not open screen1f");
        osd_deliver(6);
        if(memory[0xd366]!=0x1f||timer_count(6)!=1||timer_count(7))
            fail("Standby closed active main menu");
        navigation++;
    }
    const unsigned samples[]={0,1,0x1234,0xea47,0xee47,0xff00,0xffff};
    for(unsigned phase=0;phase<3;phase++)
    for(unsigned i=0;i<sizeof(samples)/sizeof(samples[0]);i++) {
        osd_fixture(phase,0,2);
        cpu.mLowerData[0x2d]=(unsigned char)(samples[i]>>8);
        cpu.mLowerData[0x2e]=(unsigned char)samples[i];
        osd_run(0x8c9c,0xffff);assert_menu();clocks++;
    }
    osd_fixture(2,0,2);power_actions=0;osd_run(0x8c9c,0xffff);assert_menu();
    select_bank(0);osd_run(0xaa5a,0xffff);osd_run(0x0eb7,0xffff);
    if(power_actions!=1||memory[0xd8d4]!=0x2f||memory[0xd8d5]||cpu.mLowerData[7]!=2)
        fail("Stock power service did not consume OSD wake request");
    select_bank(19);memory[0xd368]=1;osd_run(0x8c9c,0xffff);
    if(main_entries!=1||memory[0xd366]!=0x1f)fail("Menu keys failed after consumed wake");
    printf("{\"open_cases\":%u,\"guard_cases\":%u,\"event_cases\":%u,\"timer_gate_cases\":%u,\"capacity_cases\":%u,\"timer_sequences\":%u,\"navigation_cases\":%u,\"clock_cases\":%u,\"wake_sequences\":1,\"peak_sp\":%u,\"hardware_access\":false,\"rendering_stubbed\":true,\"physical_power_action_stubbed\":true}\n",
        opens,guards,events,timer_gates,capacity,sequences,navigation,clocks,osd_peak);
    return 0;
}

int main(int argc, char **argv) {
    if ((argc != 2 && argc != 3) || (strcmp(argv[1], "--require-no-signal-menu") &&
                      strcmp(argv[1], "--active-control") && strcmp(argv[1], "--suite"))) return 2;
    if (fread(image, 1, sizeof(image), stdin) != sizeof(image) || fgetc(stdin) != EOF) return 2;
    cpu.mCodeMem=code; cpu.mCodeMemMaxIdx=65535;
    cpu.mExtData=memory; cpu.mExtDataMaxIdx=65535; cpu.mUpperData=upper;
    cpu.except=exception; cpu.xwrite=osd_xwrite;
    if (!strcmp(argv[1],"--suite")) return suite();
    setup(19);
    state(!strcmp(argv[1], "--active-control") ? 0 : 0x26, 3, 1, argc == 3 ? (unsigned)strtoul(argv[2], 0, 0) : 4);
    memory[0xd8d4]=0x2f;
    memory[0xd368]=0;
    osd_run(0x8c9c, 0xffff);
    if (menu_entries != 1 || memory[0xd365] || memory[0xd366] != 1 || !draw_calls)
        fail("OSD button did not open menu screen1");
    printf("{\"menu_opened\":true,\"screen\":1,\"render_calls_intercepted\":%u,\"hardware_access\":false,\"peak_sp\":%u}\n",
           draw_calls,peak_sp);
    return 0;
}
