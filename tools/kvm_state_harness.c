/* Bounded offline execution of F11 key scanning -> UI event -> KVM request.
 * Bank gateways execute original instructions. Physical inputs, source request
 * transport, automatic-search/display follow-ups and timer service are not emulated.
 * Feed only a pinned image through validate_kvm_state.py; no device APIs here.
 */
#include "emu8051.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char image[27 * 65536], code[65536], memory[65536], upper[128];
static struct em8051 cpu;
static unsigned bank, source, power_mode, requested, requests, toggles, timers;
static unsigned peak_sp, bank_writes, event9_entries, shared_entries, cleanup_calls;
static unsigned cancelled[256], writes[65536], dialog_calls, helper_carry;
static unsigned patch_expected;
static unsigned upstream, alternate2, alternate3, callbacks, callback_address, wake_requests;
static unsigned source_loop, source_loop_followups;
static unsigned sequence, sleep_requests, power_transition;
static unsigned coordinated, power_actions;
static unsigned family, family_peaks[17];
static const char *family_names[] = {
    "scanner", "scanner_dispatch", "pacing", "wake", "upstream", "caller",
    "source_loop", "gate", "timer_handoff", "capacity", "binding",
    "source_route", "fallback", "normal_state", "screen", "enable_layout", "sequence"
};
/* Deeper cases execute source bookkeeping and USB routing. Only their named
 * lower-level hardware/display dependencies remain intercepted. */
static unsigned handoff, route_fault, route_writes, route_polls, source_followups;
static unsigned char route_frames[2][4];

static void fail(const char *why) {
    fprintf(stderr, "%s bank=%02x pc=%04x sp=%02x\n", why, bank, cpu.mPC, cpu.mSFR[REG_SP]);
    exit(2);
}
static void exception(struct em8051 *unused, int reason) {
    (void)unused; (void)reason; fail("8051 exception");
}
static void xwrite(struct em8051 *unused, uint16_t address, uint8_t value) {
    (void)unused;
    if (address == 0xffff) {
        unsigned next = (unsigned char)(value - cpu.mLowerData[0x30]);
        if (!(coordinated && next == 0) && next != 4 && next != 5 && next != 8 && next != 11 && next != 16 && next != 19 && next != 20) {
            fprintf(stderr, "next_bank=%02x\n", next);
            fail("Unexpected bank selection");
        }
        bank = next; bank_writes++;
        memcpy(code, image + bank * 65536, sizeof(code));
    } else if (!((address >= 0xc99b && address <= 0xc9ef) ||
                 (address >= 0xd46d && address < 0xd46d + 21*3) ||
                 (address >= 0xd364 && address <= 0xd378) ||
                 (address >= 0xd8d0 && address <= 0xd8d3) || address == 0xd71b || address == 0xd70c ||
                 (source_loop && address >= 0xca0a && address <= 0xca0b) ||
                 (power_transition && (address == 0xd8e0 || address == 0xd8e1)) ||
                 (coordinated && (address == 0xd8d4 || address == 0xd8d5)) ||
                 (handoff && ((address >= 0xd85f && address <= 0xd862) ||
                              address == 0xd766 || address == 0xfe09 || address == 0xfe22 ||
                              address == 0xfe23 || address == 0xfe2a))))
        fail("Unexpected XRAM write");
    memory[address] = value; writes[address]++;
}
static void ret(void) { cpu.op[0x22](&cpu); }
static void carry(unsigned value) {
    if (value) cpu.mSFR[REG_PSW] |= PSWMASK_C;
    else cpu.mSFR[REG_PSW] &= (unsigned char)~PSWMASK_C;
}
static void setup(unsigned selected) {
    memset(memory, 0, sizeof(memory)); memset(upper, 0, sizeof(upper));
    memset(writes, 0, sizeof(writes)); memset(cancelled, 0, sizeof(cancelled));
    reset(&cpu, false);
    memset(cpu.mLowerData, 0, sizeof(cpu.mLowerData));
    memset(cpu.mSFR, 0, sizeof(cpu.mSFR));
    bank = selected; memcpy(code, image + bank * 65536, sizeof(code));
    cpu.mLowerData[0x2f] = (unsigned char)bank; cpu.mLowerData[0x30] = 0x20;
    memory[0xffff] = (unsigned char)(bank + 0x20);
    cpu.mSFR[REG_SP] = 0x5f;
    requests = toggles = timers = event9_entries = shared_entries = cleanup_calls = 0;
    bank_writes = dialog_calls = 0; peak_sp = 0x5f; requested = 255;
    handoff = route_fault = route_writes = route_polls = source_followups = 0;
    upstream = alternate2 = alternate3 = callbacks = callback_address = wake_requests = 0;
    source_loop = source_loop_followups = 0;
    sequence = sleep_requests = power_transition = 0;
    memset(route_frames, 0, sizeof(route_frames));
}
static unsigned allowed(unsigned pc) {
    if (pc < 0x5717) return 1; /* Common code includes original bank gateways. */
    switch (bank) {
        case 0: return coordinated && ((pc >= 0xe7cc && pc < 0xe7fc) ||
                                      (pc >= 0xe08a && pc < 0xe095) ||
                                      (pc >= 0xf188 && pc < 0xf1a9) ||
                                      (pc >= 0xaa5a && pc < 0xab44));
        case 4: return (pc >= 0x7f3f && pc < 0x7f46) ||
                       (coordinated && pc >= 0xfa61 && pc < 0xfa7a) ||
                       (pc >= 0xfdaf && pc < 0xfdb8) || (pc >= 0xdf36 && pc < 0xdf45) ||
                       (pc >= 0xfe7b && pc < 0xfe80) ||
                       (upstream && pc >= 0xfe8f && pc < 0xfe93) ||
                       (upstream && pc >= 0xdf45 && pc < 0xdf50) ||
                       (upstream && pc >= 0xf9c0 && pc < 0xf9db) ||
                       (source_loop && ((pc >= 0xf74e && pc < 0xf76f) ||
                                        (pc >= 0xdf00 && pc < 0xdf10) ||
                                        (pc >= 0xdf2e && pc < 0xdf36) ||
                                        (pc >= 0xfe63 && pc < 0xfe69) ||
                                        (pc >= 0xf083 && pc < 0xf0bf))) ||
                       (handoff && ((pc >= 0xea2f && pc < 0xea76) ||
                                    (pc >= 0xeed8 && pc < 0xef16) ||
                                    (pc >= 0xdf10 && pc < 0xdf1f) ||
                                    (pc >= 0xfd0e && pc < 0xfd1a) ||
                                    (pc >= 0xdf45 && pc < 0xdf50) ||
                                    (pc >= 0xfe8f && pc < 0xfe93)));
        case 5: return pc >= 0xfeed && pc < 0xfef6;
        case 8: return (pc >= 0xb4e5 && pc < 0xb5cb) || (pc >= 0xc6f3 && pc < 0xc770) ||
                       (power_transition && ((pc >= 0x94c1 && pc < 0x94d3) ||
                                             (pc >= 0xc7d4 && pc < 0xc7db) ||
                                             (pc >= 0xdfac && pc < 0xdff4))) ||
                       (pc >= 0xca9b && pc < 0xcb1e) || (pc >= 0xec79 && pc < 0xeca7) ||
                       (pc >= 0xf132 && pc < 0xf156) ||
                       (upstream && ((pc >= 0xd92c && pc < 0xd93a) ||
                                     (pc >= 0xd963 && pc < 0xd989))) ||
                       (handoff && ((pc >= 0xf3fc && pc < 0xf419) ||
                                    (pc >= 0xfdc6 && pc < 0xfdd1) ||
                                    (pc >= 0x861b && pc < 0x8624) ||
                                    (pc >= 0x8685 && pc < 0x868d) ||
                                    (pc >= 0x8709 && pc < 0x8711)));
        case 11: return (pc >= 0xf7ed && pc < 0xf892) || (pc >= 0xf891 && pc < 0xfa2a) ||
                        (pc >= 0xfb16 && pc < 0xfb78) || (pc >= 0xfca8 && pc < 0xfcea) ||
                        (pc >= 0xfdcd && pc < 0xfdf9) || (pc >= 0xfe1b && pc < 0xfe5d) ||
                        (pc >= 0xfee3 && pc < 0xfeee) || pc == 0xfeff;
        case 16: return (pc >= 0xe6c3 && pc <= 0xe72d) || (pc >= 0xff00 && pc < 0xff80) ||
                        (sequence && pc >= 0xe062 && pc < 0xe0e8);
        case 19: return (pc >= 0x8c9c && pc < 0x8d33) || pc == 0x8d7c ||
                        (coordinated && pc >= 0xff00) ||
                        (sequence && ((pc >= 0xa740 && pc < 0xa747) ||
                                      (pc >= 0xa7c3 && pc < 0xa809) ||
                                      (pc >= 0xa8a4 && pc < 0xa8aa))) ||
                        (upstream && ((pc >= 0x8a84 && pc < 0x8aa3) ||
                                      (pc >= 0x8bf4 && pc < 0x8c4d))) ||
                        (upstream && pc >= 0x8d33 && pc < 0x8d7c) || (pc >= 0xfbb2 && pc < 0xfbbe) ||
                        (source_loop && ((pc >= 0x894d && pc < 0x8965) ||
                                         (pc >= 0x89f0 && pc < 0x8ac0) ||
                                         (pc >= 0xf66e && pc < 0xf676))) ||
                        (handoff && ((pc >= 0x8adf && pc < 0x8b26) ||
                                     (pc >= 0x8d86 && pc < 0x8d8f) ||
                                     (pc >= 0x8d99 && pc < 0x8da2) ||
                                     (pc >= 0xf660 && pc < 0xf66e)));
        case 20: return (pc >= 0x6731 && pc < 0x674f) || (pc >= 0x67c6 && pc < 0x67ce) ||
                        (sequence && ((pc >= 0x674f && pc < 0x675e) ||
                                      (pc >= 0x67df && pc < 0x67ed))) ||
                        (pc >= 0x8e73 && pc < 0x8f1e) ||
                        (pc >= 0x8483 && pc < 0x849a) || (pc >= 0x84ae && pc < 0x84b6) ||
                        (pc >= 0xa3ae && pc < 0xa408) || (pc >= 0xa514 && pc < 0xa56d) ||
                        (handoff && ((pc >= 0x7743 && pc < 0x7882) ||
                                     (pc >= 0xab06 && pc < 0xab32)));
    }
    return 0;
}
static void run(unsigned pc, unsigned stop) {
    unsigned original_bank = bank;
    cpu.mSFR[REG_SP] = 0x5f;
    push_to_stack(&cpu, 0xff); push_to_stack(&cpu, 0xff); cpu.mPC = pc;
    for (unsigned step = 0; step < 12000 && cpu.mPC != stop; step++) {
        if (cpu.mSFR[REG_SP] > peak_sp) peak_sp = cpu.mSFR[REG_SP];
        if (cpu.mSFR[REG_SP] > family_peaks[family]) family_peaks[family] = cpu.mSFR[REG_SP];
        if (cpu.mSFR[REG_SP] >= 0xf0) fail("Stack guard exceeded");
        /* External dependencies are intercepted before entering their wrappers.
         * System-mode/per-port getters and the KVM selection logic execute. */
        switch (cpu.mPC) {
            case 0x2e91: case 0x2beb: case 0x3035: case 0x3047:
                if (!source_loop) fail("Unexpected source-loop follow-up");
                source_loop_followups++; ret(); continue;
            case 0x0eb7:
                if (coordinated) break;
                cpu.mLowerData[7] = (unsigned char)power_mode; ret(); continue;
            case 0x0e45:
                if (handoff) break;
                cpu.mLowerData[7] = (unsigned char)source; ret(); continue;
            case 0x2f99:
                if (cpu.mLowerData[7] != 0 || requests) fail("Unexpected source request");
                requested = cpu.mLowerData[5]; requests++;
                if (handoff) break;
                ret(); continue;
            case 0x043a:
                if (!handoff || route_writes >= 2 || cpu.mLowerData[7] != 0xac ||
                    cpu.mLowerData[4] != 0 || cpu.mLowerData[5] != (route_writes ? 8u : 1u) || cpu.mLowerData[3] != 1 ||
                    memory[0xc9cf] != 4 || memory[0xc9d0] != 1 ||
                    memory[0xc9d1] != 0xc9 || memory[0xc9d2] != 0xc6) {
                    fprintf(stderr, "route write=%u regs=%02x/%02x/%02x/%02x buffer=%02x%02x ptr=%02x%02x%02x\n",
                            route_writes, cpu.mLowerData[7],cpu.mLowerData[4],cpu.mLowerData[5],cpu.mLowerData[3],
                            memory[0xc9ce],memory[0xc9cf],memory[0xc9d0],memory[0xc9d1],memory[0xc9d2]);
                    fail("Unexpected route transport request");
                }
                memcpy(route_frames[route_writes], memory + 0xc9c6, 4);
                route_writes++;
                carry(route_fault != (route_writes == 1 ? 1u : 3u)); ret(); continue;
            case 0x2e97:
                if (!handoff || route_polls >= 2 || cpu.mLowerData[7] != 0xac ||
                    cpu.mLowerData[4] != 0 || cpu.mLowerData[5] != 100 || cpu.mLowerData[3] != 0)
                    fail("Unexpected route completion poll");
                route_polls++;
                carry(route_fault != (route_polls == 1 ? 2u : 4u)); ret(); continue;
            case 0x28c1: case 0x28cd: case 0x28d3: case 0x1325:
                if (!handoff) fail("Unexpected source follow-up");
                source_followups++; ret(); continue;
            case 0x2bf1: cancelled[cpu.mLowerData[7]]++; break;
            case 0x2bf7: timers++; break;
            case 0x2fcf: timers++; ret(); continue;
            case 0x2e7f:
                if (coordinated) break;
                if (sequence && cpu.mLowerData[7] == 3) { sleep_requests++; ret(); continue; }
                if (cpu.mLowerData[7] != 2) fail("Unexpected wake request");
                wake_requests++; ret(); continue;
            case 0x2e2b: case 0x3353: case 0x3257: case 0x3275: case 0x329f: case 0x328d:
                if (!sequence) fail("Unexpected display-cleanup dependency");
                ret(); continue;
            /* Test diversion decisions, not the alternate UI or cleanup. */
            case 0x305f: alternate2++; ret(); continue;
            case 0x3065: alternate3++; ret(); continue;
            case 0x3071: ret(); continue;
            case 0x2e8b: case 0x2fe7: ret(); continue;
            case 0x324b: carry(helper_carry); ret(); continue;
            case 0x31c7: dialog_calls++; ret(); continue;
            case 0x3e39:
                callbacks++; callback_address = (cpu.mLowerData[2] << 8) | cpu.mLowerData[1];
                ret(); continue; /* Capture selected callback; do not execute UI. */
            default: break;
        }
        if (coordinated && bank == 0 && cpu.mPC == 0x88f0) {
            if (cpu.mLowerData[7] != 11) fail("Unexpected physical wake action");
            power_actions++; ret(); continue; /* Panel/hardware action, not modeled. */
        }
        if (bank == 16 && cpu.mPC == 0xe6c3) event9_entries++;
        if (upstream && bank == 19 && cpu.mPC == 0xe76e) { ret(); continue; }
        if (bank == 16 && cpu.mPC == 0xe062) {
            cleanup_calls++;
            if (!sequence) { ret(); continue; }
        }
        if (sequence && bank == 16 && cpu.mPC == 0xfef5) { ret(); continue; }
        if (bank == 20 && cpu.mPC == 0x8e73) shared_entries++;
        if (handoff && bank == 4 && (cpu.mPC == 0xc9a3 || cpu.mPC == 0xfebb)) {
            ret(); continue; /* Source cleanup / automatic search, not bookkeeping. */
        }
        if (bank == 20 && cpu.mPC == 0x7743) {
            toggles++;
            if (!handoff) { ret(); continue; }
        }
        if (!allowed(cpu.mPC)) fail("Escaped selected instructions");
        cpu.op[code[cpu.mPC]](&cpu);
    }
    if (cpu.mPC != stop || bank != original_bank || cpu.mLowerData[0x2f] != original_bank ||
        memory[0xffff] != original_bank + 0x20 ||
        cpu.mSFR[REG_SP] != (stop == 0xffff ? 0x5f : 0x61))
        fail("Execution did not return to expected boundary");
}
static void state(unsigned screen, unsigned system, unsigned enabled, unsigned port_state) {
    memory[0xd365] = (unsigned char)(screen >> 8); memory[0xd366] = (unsigned char)screen;
    memory[0xd8e0] = (unsigned char)system; memory[0xd11e] = (unsigned char)(enabled << 7);
    memory[0xd861] = (unsigned char)port_state;
    memory[0xd131] = 0x12; /* USB-C bound to source4; USB-B bound to source2. */
    source = 4; power_mode = 2; helper_carry = 0;
}
static void select_bank(unsigned selected) {
    bank = selected; cpu.mLowerData[0x2f] = (unsigned char)selected;
    memory[0xffff] = (unsigned char)(selected + 0x20);
    memcpy(code, image + selected*65536, sizeof(code));
}
/* Inspect every active entry, including an unrelated sentinel. Empty-slot
 * deadline bytes have no scheduler meaning and are deliberately ignored. */
static void sequence_queue(unsigned stage, unsigned deadline) {
    unsigned found = 0;
    for (unsigned slot = 0; slot < 21; slot++) {
        unsigned address = 0xd46d + slot*3, actual = memory[address];
        unsigned when = (memory[address+1] << 8) | memory[address+2];
        if (!actual) continue;
        if (slot == 20 && actual == 0x42 && when == 0) continue;
        if (!stage || actual != stage || when != deadline || found++) {
            fprintf(stderr, "slot=%u actual=%u/%u expected=%u/%u clock=%u\n", slot,
                    actual, when, stage, deadline,
                    (cpu.mLowerData[0x2d] << 8) | cpu.mLowerData[0x2e]);
            fail("Sequential timer table mismatch");
        }
    }
    if (found != (stage != 0) || memory[0xd4a9] != 0x42 ||
        memory[0xd4aa] || memory[0xd4ab])
        fail("Sequential timer/sentinel missing");
}
static void scan_press(void) {
    select_bank(11);
    memory[0xfe37] = 0; memory[0xff09] = memory[0xff0a] = 0xff;
    cpu.mSFR[REG_P3] = 8; memory[0xd369] = 3;
    /* Inject a released/debounced input before each separate press. */
    memory[0xd8d2] = memory[0xd8d3] = 0;
    run(0xf7ed, 0xffff);
    if (memory[0xd368] != 9) fail("Sequential KVM scan failed");
    select_bank(19); run(0x8c9c, coordinated ? 0xffff : 0x8d33);
}
static void deliver_stage(unsigned stage, unsigned message) {
    unsigned slots = 0;
    for (unsigned slot = 0; slot < 21; slot++) {
        unsigned address = 0xd46d + slot*3;
        if (memory[address] != stage) continue;
        slots++;
        cpu.mLowerData[0x2d] = memory[address+1];
        cpu.mLowerData[0x2e] = memory[address+2];
    }
    if (slots != 1) fail("Missing sequential callback timer");
    /* Delivery/order is supplied by the harness, not the real scheduler.
     * Original cancellation, callback dispatch and message handlers execute. */
    select_bank(19); cpu.mLowerData[7] = (unsigned char)stage; run(0x2bf1, 0xffff);
    select_bank(20); cpu.mLowerData[7] = (unsigned char)stage; run(0x6731, 0xffff);
    if (memory[0xd367] != message) fail("Sequential callback message changed");
    select_bank(19); run(0xa740, 0xffff);
    if (memory[0xd365] || memory[0xd366] || memory[0xd367])
        fail("Sequential no-signal cleanup did not clear screen/message");
}
static void coordinated_setup(unsigned direction, unsigned phase) {
    setup(19); state(phase == 0 ? 0x26 : 0, phase == 2 ? 4 : 3, 1, phase == 0 || phase == 3 ? 2 : 1);
    sequence = handoff = upstream = power_transition = 1;
    power_actions = 0;
    const unsigned map[] = {1, 2, 4, 5};
    for (unsigned i = 0; i < 4; i++) memory[0xd4fb+i] = (unsigned char)map[i];
    memory[0xd85f] = (unsigned char)(direction ? 1 : 2);
    memory[0xd376] = (unsigned char)((!direction) << 2); memory[0xd151] = 1;
    memory[0xfe09] = memory[0xfe22] = memory[0xfe23] = 0x5a;
    memory[0xd8d4] = 0x23; /* Active hardware, pending standby request. */
    memory[0xd8d5] = (unsigned char)(phase == 2 ? 0x20 : 0);
    cpu.mLowerData[0x2d] = 0xff; cpu.mLowerData[0x2e] = 0;
    for (unsigned i = 0; i < 3; i++) {
        memory[0xd46d+3*i] = (unsigned char)(5+i);
        memory[0xd46e + 3*i] = 0xff; memory[0xd46f + 3*i] = 1;
    }
    memory[0xd4a9] = 0x42;
}
static int coordinated_cases(void) {
    family = 16;
    unsigned cases = 0;
    for (unsigned direction = 0; direction < 2; direction++)
    for (unsigned phase = 0; phase < 4; phase++) {
        coordinated_setup(direction, phase);
        unsigned target = direction ? 4 : 2, index = direction ? 2 : 1;
        scan_press();
        if (requests != 1 || requested != target || memory[0xd85f] != index ||
            memory[0xd378] != target || !(memory[0xd377] & 4) ||
            route_writes != 2 || route_polls != 2 ||
            ((memory[0xd376] >> 2) & 1) != direction ||
            memory[0xfe09] != direction || memory[0xfe22] != direction ||
            memory[0xfe23] != !direction || memory[0xfe2a] != 1)
            fail("Manual destination must stay selected with its USB route");
        if (cancelled[5] != 1 || cancelled[6] != 1 || cancelled[7] != 1 ||
            memory[0xd8d4] != 0x22 || writes[0xd11f] ||
            memory[0xd8e0] != (phase == 2 ? 0x14 : 3))
            fail("Manual request must replace pending standby and old timers");
        unsigned now = (cpu.mLowerData[0x2d] << 8) | cpu.mLowerData[0x2e];
        sequence_queue(6, (now+60000)&65535);
        /* Supply an absent destination and execute the actual fallback. The
         * new snapshot must keep it selected without issuing another USB route. */
        memory[0xd861] = 1; requests = 0; requested = 255;
        run(0x8adf, 0xffff);
        if (requests != 1 || requested != target || memory[0xd85f] != index ||
            memory[0xd377] & 4 || route_writes != 2 || route_polls != 2 ||
            ((memory[0xd376] >> 2) & 1) != direction)
            fail("Absent destination must not split picture and USB");
        sequence_queue(6, (now+60000)&65535);
        if (phase == 2) {
            /* Consume the request through the stock power service. Its
             * physical action11 is intercepted, but flag consumption and the
             * public power getter execute original firmware instructions. */
            select_bank(0); run(0xaa5a, 0xffff);
            if (power_actions != 1 || memory[0xd8d4] != 0x2f || memory[0xd8d5])
                fail("Stock power service did not consume wake request");
            run(0x0eb7, 0xffff);
            if (cpu.mLowerData[7] != 2) fail("Power getter did not leave saving mode");
        }
        cases++;
    }
    /* No raw key, no added source/USB/wake action, with a pending standby. */
    coordinated_setup(0, 0);
    select_bank(11); memory[0xfe37] = 1;
    memory[0xff09] = memory[0xff0a] = 0xff; cpu.mSFR[REG_P3] = 8; memory[0xd369] = 3;
    run(0xf7ed, 0xffff); select_bank(19); run(0x8c9c, 0xffff);
    if (requests || toggles || memory[0xd8d4] != 0x23 || cancelled[5] || cancelled[6] || cancelled[7])
        fail("Signal loss without a press must retain stock behaviour");
    cases++;
    /* Narrow refusal controls. All these also refuse the original action. */
    for (unsigned guard = 0; guard < 18; guard++) {
        coordinated_setup(0, 2);
        switch (guard) {
            case 0: memory[0xd11e] = 0; break;
            case 1: memory[0xd143] = 1; break;
            case 2: memory[0xd364] = 4; break;
            case 3: memory[0xd364] = 8; break;
            case 4: memory[0xd706] = 1; break;
            case 5: memory[0xd706] = 2; break;
            case 6: memory[0xd706] = 4; break;
            case 7: memory[0xd8e0] = 0x14; break;
            case 8: memory[0xd8d4] = 0x11; memory[0xd8d5] = 0; break;
            case 9: memory[0xd366] = 0x20; break;
            case 10: memory[0xd365] = 1; break;
            case 11: memory[0xd8e0] = 1; break;
            case 12: memory[0xd8e0] = 2; break;
            case 13: memory[0xd8e0] = 5; break;
            case 14:
                for (unsigned i = 0; i < 21; i++) memory[0xd46d+3*i] = 0x42;
                break;
            case 15: memory[0xd131] = 0x11; break; /* Neither binding can change source4. */
            case 16: cpu.mLowerData[0x2a] |= 1; break; /* Stock VCP standby latch, bit50. */
            case 17: memory[0xd8d5] = 0; break; /* Mode4 but power getter2, not saving. */
        }
        unsigned char before[63]; memcpy(before, memory+0xd46d, sizeof(before));
        unsigned power_before = memory[0xd8d4];
        scan_press();
        if (requests || toggles || writes[0xd8d4] || memory[0xd8d4] != power_before ||
            memcmp(before, memory+0xd46d, sizeof(before)) ||
            ((cpu.mLowerData[0x2a] & 1) != (guard == 16)))
            fail("Coordinated switch bypassed a refusal guard");
        cases++;
    }
    /* An explicit off may be queued before mode3 has transitioned away.
     * Distinguish requested-off from already-off/no pending request. */
    const unsigned off_states[] = {0x21, 0x11, 0x1f};
    for (unsigned phase = 0; phase < 4; phase++) {
        if (phase == 2) continue;
        for (unsigned i = 0; i < sizeof(off_states)/sizeof(off_states[0]); i++) {
            coordinated_setup(0, phase); memory[0xd8d4] = (unsigned char)off_states[i];
            unsigned char before[63]; memcpy(before, memory+0xd46d, sizeof(before));
            scan_press();
            if (requests || toggles || writes[0xd8d4] || memory[0xd8d4] != off_states[i] ||
                memcmp(before, memory+0xd46d, sizeof(before)))
                fail("Mode3 must preserve pending or completed explicit off");
            cases++;
        }
    }
    /* The original active-picture KVM path is preserved, including its old
     * snapshot and lack of a new wake/timer request. */
    coordinated_setup(0, 0); state(0, 3, 1, 4);
    memory[0xd85f] = 2; memory[0xd8d4] = 0x2f;
    unsigned char before[63]; memcpy(before, memory+0xd46d, sizeof(before));
    scan_press();
    if (requests != 1 || requested != 2 || memory[0xd378] != 4 || route_writes != 2 ||
        writes[0xd8d4] || cancelled[5] || cancelled[6] || cancelled[7] ||
        memcmp(before, memory+0xd46d, sizeof(before)))
        fail("Active-picture KVM behaviour changed");
    cases++;
    /* A completely full table can reuse stage5; no unrelated entry may be
     * replaced. Use a zero clock so this checks capacity without rebasing. */
    coordinated_setup(0, 0); cpu.mLowerData[0x2d] = cpu.mLowerData[0x2e] = 0;
    for (unsigned i = 0; i < 21; i++) {
        memory[0xd46d+3*i] = (unsigned char)(i ? 0x42 : 5);
        memory[0xd46e + 3*i] = memory[0xd46f + 3*i] = 0;
    }
    scan_press();
    if (requests != 1 || memory[0xd8d4] != 0x22 || memory[0xd46d] != 6 ||
        memory[0xd46e] != 0xea || memory[0xd46f] != 0x60)
        fail("Full timer table could not reuse stale stage5");
    for (unsigned i = 1; i < 21; i++)
        if (memory[0xd46d+3*i] != 0x42 || memory[0xd46e + 3*i] || memory[0xd46f + 3*i])
            fail("Unrelated timer changed during stage5 reuse");
    cases++;
    printf("{\"coordinated_cases\":%u,\"hardware_access\":false,\"peak_sp\":%u,"
           "\"power_api_executed\":true,\"physical_power_action_stubbed\":true}\n", cases, family_peaks[16]);
    return 0;
}
int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--require-no-signal-switch")) patch_expected = 1;
    else if (argc == 2 && !strcmp(argv[1], "--require-coordinated-switch")) coordinated = 1;
    else if (argc != 1) return 2;
    if (fread(image, 1, sizeof(image), stdin) != sizeof(image) || fgetc(stdin) != EOF) return 2;
    cpu.mCodeMem = code; cpu.mCodeMemMaxIdx = 65535;
    cpu.mExtData = memory; cpu.mExtDataMaxIdx = 65535; cpu.mUpperData = upper;
    cpu.except = exception; cpu.xwrite = xwrite;
    if (coordinated) return coordinated_cases();
    unsigned scanner_cases = 0, gate_cases = 0, no_signal_blocked = 0, no_signal_switched = 0;
    unsigned max_stack = 0;
    family = 0;
    /* Original GPIO scanner and debounce/translation: synthetic FE37 is the
     * candidate active-low key input. A matured debounce state is supplied. */
    for (unsigned pressed = 0; pressed < 2; pressed++)
    for (unsigned p = 0; p < 4; p++)
    for (unsigned debounce = 0; debounce < 4; debounce++) {
        setup(11); state(0x26, 3, 1, 2); power_mode = p;
        memory[0xfe37] = (unsigned char)!pressed;
        memory[0xff09] = memory[0xff0a] = 0xff; cpu.mSFR[REG_P3] = 8;
        memory[0xd369] = (unsigned char)debounce;
        unsigned scanned = p == 0 || debounce == 3;
        run(0xf7ed, 0xffff);
        if (memory[0xd8d2] != (scanned && pressed ? 0x80 : 0) ||
            memory[0xd368] != (scanned && pressed ? 9 : 8))
            fail("Key scan/translation mismatch");
        scanner_cases++;
    }
    family = 1;
    unsigned chain_cases = 0;
    for (unsigned captured = 0; captured < 2; captured++)
    for (unsigned pressed = 0; pressed < 2; pressed++) {
        setup(11); state(0x26, 3, 1, 2);
        memory[0xfe37] = (unsigned char)!pressed;
        memory[0xff09] = memory[0xff0a] = 0xff; cpu.mSFR[REG_P3] = 8;
        memory[0xd369] = 3; memory[0xd706] = (unsigned char)(captured << 1);
        run(0xf7ed, 0xffff);
        if (memory[0xd368] != (pressed ? 9 : 8) ||
            memory[0xd70c] != (captured && pressed ? 0x40 : 0))
            fail("Post-scanner event capture mismatch");
        /* The main-loop call boundary changes banks, retaining the scanned
         * event and all XRAM, instead of injecting another synthetic event9. */
        if (pressed) {
            bank = 19; cpu.mLowerData[0x2f] = 19; memory[0xffff] = 0x33;
            memcpy(code, image + 19*65536, sizeof(code));
            run(0x8c9c, 0x8d33);
            if (requests != patch_expected || requested != (patch_expected ? 2 : 255))
                fail("Scanner-to-request chain mismatch");
        }
        chain_cases++;
    }
    unsigned pacing_cases = 0, wake_cases = 0, upstream_cases = 0;
    family = 2;
    /* Suppress successive scans until the real event-2 callback is manually
     * delivered. This models the callback, not timer scheduling/delivery. */
    for (unsigned p = 1; p < 4; p++)
    for (unsigned skip = 0; skip < 2; skip++)
    for (unsigned pressed = 0; pressed < 2; pressed++) {
        setup(11); state(0x26, 3, 1, 2); power_mode = p;
        memory[0xd368] = 8; memory[0xd376] = (unsigned char)(skip << 1);
        memory[0xfe37] = (unsigned char)!pressed;
        memory[0xff09] = memory[0xff0a] = 0xff; cpu.mSFR[REG_P3] = 8;
        if (skip) {
            run(0xf7ed, 0xffff);
            if (memory[0xd376] || timers || writes[0xd8d2]) fail("One-scan suppression mismatch");
        }
        for (unsigned scan = 0; scan < 4; scan++) {
            run(0xf7ed, 0xffff);
            if (memory[0xd369] != 2 || memory[0xd368] != 8 || timers != 1 || writes[0xd8d2])
                fail("Scanner ran without deferred release");
        }
        select_bank(20); cpu.mLowerData[7] = 2; run(0x6731, 0xffff);
        if (memory[0xd369] != 3) fail("Event-2 callback did not release scanning");
        select_bank(11); run(0xf7ed, 0xffff);
        if (memory[0xd8d2] != (pressed ? 0x80 : 0) || memory[0xd368] != (pressed ? 9 : 8))
            fail("Scanner did not resume after callback");
        pacing_cases++;
    }
    family = 3;
    /* Do not equate raw 02 with a physically identified key. Raw 80 is the
     * candidate KVM input used in the scanner cases. */
    for (unsigned p = 0; p < 4; p++)
    for (unsigned kvm = 0; kvm < 2; kvm++)
    for (unsigned held = 0; held < 2; held++) {
        setup(11); state(0x26, 3, 1, 2); power_mode = p;
        unsigned raw = kvm ? 0x80 : 2;
        memory[0xd8d2] = (unsigned char)raw; memory[0xd8d3] = (unsigned char)(held ? raw : 0);
        run(0xfe1b, 0xffff);
        if (wake_requests != (p == 1 && !kvm && !held)) fail("Wake edge selection mismatch");
        wake_cases++;
    }
    family = 4;
    /* Run the dispatcher to RET. Alternate UI, selected callbacks and final
     * display cleanup remain intercepted. Vary every D364 byte, not just 0. */
    const unsigned key_events[] = {0, 1, 2, 3, 4, 5, 9};
    for (unsigned mode = 0; mode < 16; mode++)
    for (unsigned flags = 0; flags < 256; flags++)
    for (unsigned port = 0; port < 6; port++)
    for (unsigned key = 0; key < sizeof(key_events)/sizeof(key_events[0]); key++) {
        setup(19); state(0x26, mode, 1, port); upstream = 1;
        memory[0xd364] = (unsigned char)flags; memory[0xd368] = (unsigned char)key_events[key];
        run(0x8c9c, 0xffff);
        unsigned active = mode >= 3 && mode != 5;
        unsigned second = active && (flags & 4);
        unsigned third = active && !second && (flags & 8) && port != 4;
        unsigned normal = active && !second && !third;
        unsigned event9 = key_events[key] == 9;
        unsigned request = normal && event9 && mode == 3 && patch_expected;
        if (alternate2 != second || alternate3 != third || event9_entries != (normal && event9) ||
            callbacks != (normal && !event9) || requests != request ||
            (callbacks && (callback_address != 0xfeff || image[19*65536+callback_address] != 0x22)))
            fail("Upstream dispatch diversion / no-signal callback mismatch");
        upstream_cases++;
    }
    family = 5;
    unsigned caller_gate_cases = 0;
    /* Conditional callers reached after external source checks: execute the
     * original 3041 helper as well as both early-return branches. D706.bit0's
     * separate display/power path is deliberately excluded. This is not a
     * complete signal-loss/main-loop reproduction. */
    for (unsigned entry = 0; entry < 2; entry++)
    for (unsigned flags = 0; flags < 256; flags += 2)
    for (unsigned no_signal = 0; no_signal < 2; no_signal++)
    for (unsigned key = 0; key < 8; key++) {
        setup(19); state(no_signal ? 0x26 : 0, 3, 1, 2); upstream = 1;
        unsigned event = key < 6 ? key : key + 2; /* Include no-key event8. */
        memory[0xd706] = (unsigned char)flags; memory[0xd368] = (unsigned char)event;
        run(entry ? 0x8bf4 : 0x8a84, 0xffff);
        unsigned blocked = (flags & 6) != 0;
        unsigned request = !blocked && event == 9 && patch_expected;
        if (event9_entries != (!blocked && event == 9) ||
            callbacks != (!blocked && event < 6) || requests != request ||
            toggles != request || memory[0xd706] != flags ||
            memory[0xd11f] || writes[0xd11f])
            fail("Caller skipped keys or changed routing/settings unexpectedly");
        if (blocked) {
            unsigned immediate = (flags & 6) == 2;
            unsigned count5 = 0, count7 = 0;
            unsigned now = (cpu.mLowerData[0x2d] << 8) | cpu.mLowerData[0x2e];
            for (unsigned slot = 0; slot < 21; slot++) {
                unsigned address = 0xd46d + slot*3, stage = memory[address];
                unsigned deadline = (memory[address+1] << 8) | memory[address+2];
                if (!stage) continue;
                if (!immediate || deadline != now) fail("Caller enqueued an unexpected timer");
                if (stage == 5) count5++;
                else if (stage == 7) count7++;
                else fail("Caller enqueued an unexpected stage");
            }
            if (timers != immediate*2 || count5 != immediate || count7 != immediate)
                fail("Caller immediate stage5/7 enqueues mismatch");
        }
        caller_gate_cases++;
    }
    family = 6;
    unsigned source_loop_cases = 0;
    /* Start with the GPIO scanner, retain its event, then enter the original
     * source/UI routine at 894d, before 302f chooses the conditional callers.
     * State 1/2 are the branches that enqueue stage5 / post message3. The
     * source flag bit6 is injected; signal detection and four named source
     * follow-ups are outside this seam. D11F.bit1 is varied, not attributed
     * to a physical setting. D706 remains zero throughout. */
    for (unsigned changed = 0; changed < 2; changed++)
    for (unsigned port = 1; port <= 2; port++)
    for (unsigned direction = 0; direction < 2; direction++)
    for (unsigned pressed = 0; pressed < 2; pressed++)
    for (unsigned search_bit = 0; search_bit < 2; search_bit++)
    for (unsigned no_signal = 0; no_signal < 2; no_signal++) {
        setup(11); state(no_signal ? 0x26 : 0, 3, 1, port);
        source_loop = upstream = handoff = 1;
        const unsigned current = direction ? 2 : 4, target = direction ? 4 : 2;
        const unsigned old_index = direction ? 1 : 2, new_index = direction ? 2 : 1;
        const unsigned map[] = {1, 2, 4, 5};
        for (unsigned i = 0; i < 4; i++) memory[0xd4fb+i] = (unsigned char)map[i];
        memory[0xd85f] = (unsigned char)old_index;
        memory[0xd860] = (unsigned char)(changed << 6);
        memory[0xd11f] = (unsigned char)(search_bit << 1);
        memory[0xd376] = (unsigned char)((!direction) << 2); /* Force actual route writes. */
        memory[0xd151] = 1;
        memory[0xfe37] = (unsigned char)!pressed;
        memory[0xff09] = memory[0xff0a] = 0xff; cpu.mSFR[REG_P3] = 8;
        memory[0xd369] = 3;
        run(0xf7ed, 0xffff);
        if (memory[0xd368] != (pressed ? 9 : 8)) fail("Source-loop scanner event mismatch");
        select_bank(19); run(0x894d, 0xffff);
        unsigned expected = patch_expected && pressed;
        if (requests != expected || requested != (expected ? target : 255) ||
            event9_entries != pressed || toggles != expected ||
            route_writes != expected*2 || route_polls != expected*2 ||
            memory[0xd85f] != (expected ? new_index : old_index) ||
            memory[0xd378] != (expected ? current : 0) ||
            memory[0xd11f] != search_bit*2 || writes[0xd11f] ||
            memory[0xd706] || writes[0xd706] ||
            source_loop_followups != changed*(3 + (port == 2)) ||
            memory[0xd367] != (expected ? 0x0a : (changed && port == 2 ? 3 : 0)))
            fail("Source-loop manual-only request / USB handoff mismatch");
        unsigned now = (cpu.mLowerData[0x2d] << 8) | cpu.mLowerData[0x2e];
        unsigned count5 = 0, count6 = 0;
        for (unsigned slot = 0; slot < 21; slot++) {
            unsigned address = 0xd46d + slot*3, stage = memory[address];
            unsigned deadline = (memory[address+1] << 8) | memory[address+2];
            if (!stage) continue;
            if (stage == 5 && changed && port == 1 && deadline == ((now+2000)&65535)) count5++;
            else if (stage == 6 && expected && deadline == ((now+60000)&65535)) count6++;
            else fail("Unexpected source-loop timer entry");
        }
        if (count5 != (changed && port == 1) || count6 != expected)
            fail("Source-loop stage5 survival / stage6 handoff changed");
        source_loop_cases++;
    }
    family = 7;
    /* Execute dispatch -> actual system/per-port getters -> event9 -> shared
     * selection and binding helpers, including real bank gateway returns. */
    const unsigned screens[] = {0, 0x20, 0x24, 0x25, 0x26, 0x27, 0x126, 0x2600, 0xffff};
    const unsigned layouts[] = {0, 1, 2, 3, 255};
    for (unsigned s = 0; s < sizeof(screens)/sizeof(screens[0]); s++)
    for (unsigned mode = 0; mode < 16; mode++)
    for (unsigned enabled = 0; enabled < 2; enabled++)
    for (unsigned port = 0; port < 6; port++)
    for (unsigned layout = 0; layout < sizeof(layouts)/sizeof(layouts[0]); layout++) {
        setup(19); state(screens[s], mode, enabled, port);
        memory[0xd368] = 9; memory[0xd143] = (unsigned char)layouts[layout];
        run(0x8c9c, mode < 3 || mode == 5 ? 0xffff : 0x8d33);
        unsigned expected = mode == 3 && enabled && screens[s] == 0 && port == 4;
        if (patch_expected && mode == 3 && enabled && screens[s] == 0x26 && !layouts[layout]) expected = 1;
        if (patch_expected && mode == 3 && enabled && screens[s] == 0 &&
            (port == 1 || port == 2) && !layouts[layout]) expected = 1;
        if (shared_entries != expected || requests != (expected && !layouts[layout]) ||
            toggles != (expected && layouts[layout] < 3) ||
            (expected && !layouts[layout] && (requested != 2 || memory[0xd367] != 0x0a)))
            fail("KVM request did not match explicit-button contract");
        if (screens[s] == 0x26 && mode == 3 && enabled && !layouts[layout]) {
            if (shared_entries) no_signal_switched++; else no_signal_blocked++;
        }
        if (cleanup_calls != (mode == 3 && enabled && screens[s] == 0x25))
            fail("Screen25 original cleanup continuation changed");
        if (peak_sp > max_stack) max_stack = peak_sp;
        gate_cases++;
    }
    family = 8;
    unsigned timer_cases = 0;
    const unsigned clocks[] = {0, 1, 5535, 5536, 32767, 32768, 60000, 65534, 65535};
    for (unsigned path = 0; path < 3; path++)
    for (unsigned c = 0; c < sizeof(clocks)/sizeof(clocks[0]); c++)
    for (unsigned occupied = 0; occupied < 4; occupied++)
    for (unsigned direction = 0; direction < 2; direction++) {
        setup(19); state(path ? 0 : 0x26, 3, 1, path ? path : 2); source = direction ? 2 : 4;
        memory[0xd368] = 9;
        unsigned now = clocks[c];
        cpu.mLowerData[0x2d] = (unsigned char)(now >> 8);
        cpu.mLowerData[0x2e] = (unsigned char)now;
        /* Include stale final-stage7 and a deliberately unrelated timer. */
        if (occupied) {
            memory[0xd46d] = 6; memory[0xd46e] = 0x12; memory[0xd46f] = 0x34;
            memory[0xd470] = 7; memory[0xd471] = 0x56; memory[0xd472] = 0x78;
        }
        memory[0xd473] = 0x42; memory[0xd474] = (unsigned char)(now >> 8);
        memory[0xd475] = (unsigned char)now;
        if (occupied >= 2) for (unsigned slot = occupied == 3 ? 0 : 3; slot < 21; slot++) {
            memory[0xd46d + slot*3] = (unsigned char)(0x42 + slot);
            memory[0xd46e + slot*3] = (unsigned char)(now >> 8);
            memory[0xd46f + slot*3] = (unsigned char)now;
        }
        run(0x8c9c, 0x8d33);
        if (patch_expected && occupied != 3) {
            unsigned count6 = 0, count7 = 0;
            unsigned counter = (cpu.mLowerData[0x2d] << 8) | cpu.mLowerData[0x2e];
            for (unsigned slot = 0; slot < 21; slot++) {
                unsigned address = 0xd46d + slot*3;
                unsigned event = memory[address];
                unsigned deadline = (memory[address+1] << 8) | memory[address+2];
                if (event == 6) {
                    count6++;
                    if (deadline != ((counter + 60000) & 65535)) fail("Stale standby deadline survived");
                } else if (event == 7) count7++;
                else if (event && deadline != counter) fail("Unrelated timer was corrupted");
            }
            if (count6 != 1 || count7 || cancelled[6] != 1 || cancelled[7] != 1 ||
                requested != (direction ? 4 : 2) || memory[0xd367] != 0x0a)
                fail("No-signal switching/timer handoff mismatch");
        } else if (requests || cancelled[6] || cancelled[7] || timers)
            fail("Blocked path unexpectedly touched routing or timers");
        timer_cases++;
    }
    family = 9;
    unsigned capacity_cases = 0;
    for (unsigned path = 0; path < 3; path++)
    for (unsigned reusable = 0; reusable < 3; reusable++)
    for (unsigned slot = 0; slot < 21; slot++) {
        setup(19); state(path ? 0 : 0x26, 3, 1, path ? path : 2); memory[0xd368] = 9;
        for (unsigned i = 0; i < 21; i++) memory[0xd46d + i*3] = (unsigned char)(0x40+i);
        memory[0xd46d + slot*3] = (unsigned char)(reusable ? reusable+5 : 0);
        unsigned char before[63]; memcpy(before, memory+0xd46d, sizeof(before));
        run(0x8c9c, 0x8d33);
        if (patch_expected) {
            unsigned six = 0, seven = 0;
            unsigned counter = (cpu.mLowerData[0x2d]<<8) | cpu.mLowerData[0x2e];
            for (unsigned i = 0; i < 21; i++) {
                unsigned address = 0xd46d + i*3, event = memory[address];
                unsigned deadline = (memory[address+1]<<8) | memory[address+2];
                if (event == 6) { six++; if (deadline != ((counter+60000)&65535)) fail("Capacity deadline mismatch"); }
                else if (event == 7) seven++;
                else if (event != before[i*3] || deadline != counter) fail("Capacity scan changed unrelated timer");
            }
            if (requests != 1 || six != 1 || seven) fail("Free/reusable slot was not used");
        } else if (requests || memcmp(before, memory+0xd46d, sizeof(before)))
            fail("Stock capacity fixture changed");
        capacity_cases++;
    }
    family = 10;
    unsigned binding_cases = 0;
    const unsigned destination[] = {5, 4, 2, 1};
    for (unsigned bindings = 0; bindings < 256; bindings++)
    for (unsigned current = 0; current < 6; current++)
    for (unsigned forced = 0; forced < 2; forced++)
    for (unsigned pending = 0; pending < 6; pending++) {
        setup(19); state(0x26, 3, 1, 2); source = current;
        memory[0xd368] = 9; memory[0xd131] = (unsigned char)bindings;
        memory[0xd11f] = (unsigned char)forced;
        const unsigned messages[] = {0, 5, 6, 0x0a, 0x1a, 255};
        memory[0xd367] = (unsigned char)messages[pending];
        memory[0xd46d] = 6; memory[0xd46e] = 0x12; memory[0xd46f] = 0x34;
        unsigned usb_b = bindings & 15, usb_c = bindings >> 4, expected = 255;
        if (!forced || current == 1) {
            if (usb_b < 4 && destination[usb_b] != current) expected = destination[usb_b];
        }
        if (expected == 255 && (!forced || current != 1)) {
            if (usb_c < 4 && destination[usb_c] != current) expected = destination[usb_c];
        }
        if (!patch_expected) expected = 255;
        run(0x8c9c, 0x8d33);
        if (requests != (expected != 255) || requested != expected || toggles != requests ||
            (expected == 255 && (cancelled[6] || cancelled[7] || timers)) ||
            (expected != 255 && (cancelled[6] != 1 || cancelled[7] != 1 || timers != 1)) ||
            memory[0xd367] != (expected == 255 ? messages[pending] : 0x0a))
            fail("Configured binding or rejected-request behaviour changed");
        /* A carry-clear/no-destination result is not side-effect-free: the
         * original selector already records a snapshot and pending flags. */
        if (memory[0xd375] != patch_expected ||
            memory[0xd378] != (patch_expected ? current : 0) ||
            memory[0xd377] != (patch_expected && !(forced && current == 1) ? 4u : 0u))
            fail("Selector rejected-request snapshot / pending flags changed");
        binding_cases++;
    }
    family = 11;
    unsigned handoff_cases = 0, route_early_returns = 0, route_completions = 0;
    /* All 24 synthetic source-map permutations exercise the real source getter
     * and setter, independently of the monitor's unobserved runtime table.
     * Route transport ACK/poll results are injected, never sent to a device. */
    const unsigned port_codes[] = {1, 2, 4, 5};
    for (unsigned a = 0; a < 4; a++)
    for (unsigned b = 0; b < 4; b++)
    for (unsigned c = 0; c < 4; c++)
    for (unsigned d = 0; d < 4; d++) {
        if (a == b || a == c || a == d || b == c || b == d || c == d) continue;
        const unsigned map[] = {port_codes[a], port_codes[b], port_codes[c], port_codes[d]};
        for (unsigned direction = 0; direction < 2; direction++)
        for (unsigned pin_enabled = 0; pin_enabled < 2; pin_enabled++)
        for (unsigned board = 0; board < 2; board++)
        for (unsigned previous = 0; previous < 2; previous++)
        for (unsigned fault = 0; fault < 5; fault++) {
            setup(19); state(0x26, 3, 1, 2); handoff = 1; route_fault = fault;
            unsigned current = direction ? 2 : 4, target = direction ? 4 : 2;
            unsigned route = direction, old_index = 255, new_index = 255;
            for (unsigned i = 0; i < 4; i++) {
                memory[0xd4fb+i] = (unsigned char)map[i];
                if (map[i] == current) old_index = i;
                if (map[i] == target) new_index = i;
            }
            memory[0xd85f] = (unsigned char)old_index;
            memory[0xd860] = 0xa5; memory[0xd862] = 0x5a;
            memory[0xd368] = 9; memory[0xd151] = (unsigned char)pin_enabled;
            memory[0xd376] = (unsigned char)(0xa3 | (previous << 2));
            memory[0xfe2c] = (unsigned char)board;
            memory[0xfe09] = memory[0xfe22] = memory[0xfe23] = 0x5a;
            memory[0xd766] = 0xa5;
            unsigned char queue_before[63]; memcpy(queue_before, memory+0xd46d, sizeof(queue_before));
            run(0x8c9c, 0x8d33);
            unsigned expected = patch_expected;
            unsigned early = previous == route && !pin_enabled;
            unsigned write_count = early ? 0 : (fault == 1 || fault == 2 ? 1 : 2);
            unsigned poll_count = early || fault == 1 ? 0 : (fault == 2 || fault == 3 ? 1 : 2);
            if (requests != expected || toggles != expected ||
                requested != (expected ? target : 255) || source_followups != expected*4 ||
                route_writes != expected*write_count || route_polls != expected*poll_count ||
                memory[0xd85f] != (expected ? new_index : old_index) ||
                memory[0xd860] != (expected ? 0 : 0xa5) || memory[0xd862] != (expected ? 0 : 0x5a) ||
                memory[0xd861] != (expected ? 0 : 2) ||
                memory[0xd367] != (expected ? 0x0a : 0) ||
                memory[0xd766] != (expected && !early && !fault ? 8 : 0xa5)) {
                fprintf(stderr, "handoff map=%u%u%u%u direction=%u pin=%u board=%u previous=%u fault=%u "
                        "requests=%u toggles=%u requested=%u followups=%u writes=%u polls=%u "
                        "source=%u state=%02x/%02x/%02x message=%02x completion=%02x\n",
                        a,b,c,d,direction,pin_enabled,board,previous,fault,requests,toggles,requested,
                        source_followups,route_writes,route_polls,memory[0xd85f],memory[0xd860],
                        memory[0xd861],memory[0xd862],memory[0xd367],memory[0xd766]);
                fail("Source bookkeeping / route handoff mismatch");
            }
            if (expected) {
                if (memory[0xfe2a] != 1 ||
                    memory[0xfe09] != (previous != route ? route : 0x5a) ||
                    memory[0xfe22] != (previous != route ? route : 0x5a) ||
                    memory[0xfe23] != (pin_enabled ? !route : 0x5a) ||
                    memory[0xd376] != (0xa3 | (route << 2)))
                    fail("USB route register writes mismatch");
                const unsigned char first_frame[] = {3, 0xda, 0x0b, 1};
                const unsigned char second_frame[] = {3, 0xa8, (unsigned char)board, (unsigned char)!route};
                if ((route_writes && memcmp(route_frames[0], first_frame, 4)) ||
                    (route_writes == 2 && memcmp(route_frames[1], second_frame, 4))) {
                    fprintf(stderr, "route=%u frames=%02x%02x%02x%02x/%02x%02x%02x%02x\n", route,
                            route_frames[0][0],route_frames[0][1],route_frames[0][2],route_frames[0][3],
                            route_frames[1][0],route_frames[1][1],route_frames[1][2],route_frames[1][3]);
                    fail("USB route frame mismatch");
                }
                if (cancelled[6] != 1 || cancelled[7] != 1 || timers != 1 || memory[0xd46d] != 6)
                    fail("Routing return prevented standby handoff");
                route_early_returns += early;
                route_completions += !early && !fault;
                /* The actual getter must now return the destination, while the
                 * KVM snapshot still records the original source. */
                cpu.mLowerData[7] = 0; run(0x0e45, 0xffff);
                if (cpu.mLowerData[7] != target || memory[0xd378] != current)
                    fail("Updated source getter / old-source snapshot mismatch");
            } else if (memcmp(queue_before, memory+0xd46d, sizeof(queue_before)) ||
                       writes[0xfe2a] || writes[0xd85f] || writes[0xd766])
                fail("Stock no-signal handler unexpectedly routed hardware");
            handoff_cases++;
        }
    }
    family = 12;
    unsigned fallback_cases = 0, fallback_requests = 0, fallback_searches = 0;
    /* Enter the original KVM-specific fallback branch after the external
     * signal/status test has selected it. Reachability/timing of that external
     * test is not supplied by this harness. Every other flag bit is varied. */
    for (unsigned flags = 0; flags < 256; flags++) {
        if (!(flags & 4)) continue;
        for (unsigned port = 0; port < 6; port++)
        for (unsigned forced = 0; forced < 2; forced++) {
            setup(19); state(0x26, 3, 1, port); handoff = 1;
            memory[0xd4fb] = 1; memory[0xd4fc] = 2;
            memory[0xd4fd] = 4; memory[0xd4fe] = 5;
            memory[0xd85f] = 1; /* Currently source2; snapshot is source4. */
            memory[0xd377] = (unsigned char)flags; memory[0xd378] = 4;
            memory[0xd11f] = (unsigned char)forced;
            unsigned char queue_before[63]; memcpy(queue_before, memory+0xd46d, sizeof(queue_before));
            run(0x8adf, port == 1 ? 0xffff : 0x8b26);
            unsigned fallback = port == 1, search = port == 4;
            if (requests != fallback || requested != (fallback ? 4 : 255) || toggles ||
                memory[0xd85f] != (fallback ? 2 : 1) ||
                memory[0xd377] != ((fallback || search) ? flags & ~4u : flags) ||
                source_followups != (fallback ? 4u : search) || route_writes || route_polls ||
                cancelled[6] || cancelled[7] || timers ||
                memcmp(queue_before, memory+0xd46d, sizeof(queue_before)))
                fail("Original conditional fallback contract changed");
            fallback_requests += fallback; fallback_searches += search;
            fallback_cases++;
        }
    }
    family = 13;
    unsigned normal_state_cases = 0;
    for (unsigned port = 0; port < 256; port++)
    for (unsigned layout = 0; layout < 256; layout++) {
        setup(19); state(0, 3, 1, port);
        memory[0xd143] = (unsigned char)layout; memory[0xd368] = 9;
        run(0x8c9c, 0x8d33);
        unsigned expected = port == 4 || (patch_expected && !layout && (port == 1 || port == 2));
        if (shared_entries != expected || requests != (expected && !layout) ||
            toggles != (expected && layout < 3) ||
            (requests && (requested != 2 || cancelled[6] != (port != 4) ||
                          cancelled[7] != (port != 4))))
            fail("Normal-screen source-state/layout contract mismatch");
        normal_state_cases++;
    }
    unsigned screen_cases = 0, flag_cases = 0;
    family = 14;
    for (unsigned screen = 0; screen < 65536; screen++) {
        setup(19); state(screen, 3, 1, 4); memory[0xd368] = 9;
        run(0x8c9c, 0x8d33);
        unsigned expected = screen == 0 || (patch_expected && screen == 0x26);
        if (requests != expected || (expected && requested != 2))
            fail("Patch changed another screen word");
        screen_cases++;
    }
    family = 15;
    for (unsigned layout = 0; layout < 256; layout++)
    for (unsigned flags = 0; flags < 256; flags++) {
        setup(19); state(0x26, 3, 0, 2);
        memory[0xd368] = 9; memory[0xd143] = (unsigned char)layout;
        memory[0xd11e] = (unsigned char)flags;
        run(0x8c9c, 0x8d33);
        unsigned expected = patch_expected && !layout && (flags & 128);
        if (requests != expected || shared_entries != expected || memory[0xd11e] != flags)
            fail("KVM enable/layout guard mismatch");
        flag_cases++;
    }
    unsigned sequence_cases = 0, split_routes = 0, post_sleep_requests = 0;
    family = 16;
    /* A continuous history, with two directions rather than a Cartesian
     * matrix: press -> supplied destination-state1 -> fallback -> stage6/7
     * callbacks -> press before/after the power-mode3 system transition.
     * Source-state changes and timer delivery are explicit external inputs. */
    for (unsigned direction = 0; direction < 2; direction++) {
        setup(19); state(0x26, 3, 1, 2); sequence = handoff = upstream = 1;
        unsigned current = direction ? 2 : 4, target = direction ? 4 : 2;
        unsigned old_index = direction ? 1 : 2, new_index = direction ? 2 : 1;
        const unsigned map[] = {1, 2, 4, 5};
        for (unsigned i = 0; i < 4; i++) memory[0xd4fb+i] = (unsigned char)map[i];
        memory[0xd85f] = (unsigned char)old_index;
        memory[0xd376] = (unsigned char)((!direction) << 2); memory[0xd151] = 1;
        memory[0xd46d] = 6; memory[0xd46e] = 0xea; memory[0xd46f] = 0x60;
        memory[0xd4a9] = 0x42; /* Unrelated already-due entry, delivery withheld. */
        scan_press();
        if (requests != patch_expected || requested != (patch_expected ? target : 255) ||
            memory[0xd85f] != (patch_expected ? new_index : old_index) ||
            memory[0xd378] != (patch_expected ? current : 0) ||
            memory[0xd377] != patch_expected*4 || memory[0xd375] != patch_expected ||
            route_writes != patch_expected*2 || route_polls != patch_expected*2)
            fail("Sequential first manual request mismatch");
        sequence_queue(6, 60000);
        /* Retain all state from the press; supply only the destination's
         * absent-signal result and enter after the external readiness test. */
        memory[0xd861] = 1; requests = 0; requested = 255;
        unsigned routes_before = route_writes;
        run(0x8adf, patch_expected ? 0xffff : 0x8b26);
        if (requests != patch_expected || requested != (patch_expected ? current : 255) ||
            memory[0xd85f] != old_index || memory[0xd377] ||
            route_writes != routes_before || route_polls != routes_before ||
            ((memory[0xd376] >> 2) & 1) != (patch_expected ? direction : !direction))
            fail("Sequential absent-destination fallback changed");
        split_routes += patch_expected;
        sequence_queue(6, 60000);
        deliver_stage(6, 5);
        unsigned now = (cpu.mLowerData[0x2d] << 8) | cpu.mLowerData[0x2e];
        sequence_queue(7, (now+1000)&65535);
        if (cleanup_calls != 1 || sleep_requests) fail("Sequential stage6 effects changed");
        deliver_stage(7, 6); sequence_queue(0, 0);
        if (cleanup_calls != 2 || sleep_requests != 1 || wake_requests || memory[0xd8e0] != 3)
            fail("Sequential stage7 power request changed");
        /* No power-service execution yet: D8E0 still3. This can request an
         * input but cannot retract the captured sleep request or wake. */
        memory[0xd861] = 1; requests = route_writes = route_polls = 0; requested = 255;
        scan_press();
        if (requests != patch_expected || requested != (patch_expected ? target : 255) ||
            memory[0xd85f] != (patch_expected ? new_index : old_index) ||
            route_writes != patch_expected*2 || wake_requests || sleep_requests != 1)
            fail("Sequential pre-power-service request changed");
        post_sleep_requests += requests;
        now = (cpu.mLowerData[0x2d] << 8) | cpu.mLowerData[0x2e];
        sequence_queue(patch_expected ? 6 : 0, (now+60000)&65535);
        /* Static 08:9496 selects 94c1 when power getter returns3. Execute
         * that branch and the real guarded mode setter, with flags clear.
         * The physical power service and panel shutdown remain unmodeled. */
        power_transition = 1; select_bank(8); run(0x94c1, 0x94d0);
        if (memory[0xd8e0] != 4 || memory[0xd8e1] != 15)
            fail("Power-mode3 did not request system-mode4");
        memory[0xd861] = 1; requests = 0; requested = 255;
        unsigned before = route_writes;
        scan_press();
        if (requests || route_writes != before || wake_requests || sleep_requests != 1)
            fail("Candidate unexpectedly bypassed system-mode4 / woke panel");
        sequence_queue(patch_expected ? 6 : 0, (now+60000)&65535);
        sequence_cases++;
    }
    unsigned all_stack = 0;
    for (unsigned i = 0; i < 17; i++) if (family_peaks[i] > all_stack) all_stack = family_peaks[i];
    printf("{\"scanner_cases\":%u,\"gate_cases\":%u,\"no_signal_blocked\":%u,"
           "\"no_signal_switched\":%u,\"peak_sp\":%u,\"gate_peak_sp\":%u,\"hardware_access\":false,"
           "\"original_bank_gateways_executed\":true,\"candidate_expected\":%s,"
           "\"timer_handoff_cases\":%u,\"timer_capacity_cases\":%u,\"binding_cases\":%u,\"scanner_dispatch_chain_cases\":%u,\"screen_word_cases\":%u,\"enable_layout_cases\":%u,"
           "\"source_route_cases\":%u,\"route_early_returns\":%u,\"route_completions\":%u,"
           "\"fallback_cases\":%u,\"fallback_requests\":%u,\"fallback_searches\":%u,\"route_transport_stubbed\":true,"
           "\"scanner_pacing_cases\":%u,\"wake_edge_cases\":%u,\"upstream_dispatch_cases\":%u,"
           "\"caller_gate_cases\":%u,\"source_loop_cases\":%u,\"normal_state_cases\":%u,"
           "\"sequence_cases\":%u,\"sequential_split_routes\":%u,\"post_sleep_requests\":%u,\"stack_peaks\":{", scanner_cases, gate_cases,
           no_signal_blocked, no_signal_switched, all_stack, max_stack, patch_expected ? "true" : "false", timer_cases, capacity_cases, binding_cases, chain_cases, screen_cases, flag_cases,
           handoff_cases, route_early_returns, route_completions, fallback_cases, fallback_requests, fallback_searches,
           pacing_cases, wake_cases, upstream_cases, caller_gate_cases, source_loop_cases, normal_state_cases,
           sequence_cases, split_routes, post_sleep_requests);
    for (unsigned i = 0; i < 17; i++)
        printf("%s\"%s\":%u", i ? "," : "", family_names[i], family_peaks[i]);
    printf("}}\n");
    return 0;
}
