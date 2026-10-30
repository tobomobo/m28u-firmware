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
        if (next != 4 && next != 5 && next != 8 && next != 11 && next != 16 && next != 19 && next != 20)
            fail("Unexpected bank selection");
        bank = next; bank_writes++;
        memcpy(code, image + bank * 65536, sizeof(code));
    } else if (!((address >= 0xc99b && address <= 0xc9ef) ||
                 (address >= 0xd46d && address < 0xd46d + 21*3) ||
                 (address >= 0xd364 && address <= 0xd378) ||
                 (address >= 0xd8d0 && address <= 0xd8d3) || address == 0xd71b || address == 0xd70c ||
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
    memset(route_frames, 0, sizeof(route_frames));
}
static unsigned allowed(unsigned pc) {
    if (pc < 0x5717) return 1; /* Common code includes original bank gateways. */
    switch (bank) {
        case 4: return (pc >= 0x7f3f && pc < 0x7f46) ||
                       (pc >= 0xfdaf && pc < 0xfdb8) || (pc >= 0xdf36 && pc < 0xdf45) ||
                       (pc >= 0xfe7b && pc < 0xfe80) ||
                       (handoff && ((pc >= 0xea2f && pc < 0xea76) ||
                                    (pc >= 0xeed8 && pc < 0xef16) ||
                                    (pc >= 0xdf10 && pc < 0xdf1f) ||
                                    (pc >= 0xfd0e && pc < 0xfd1a) ||
                                    (pc >= 0xdf45 && pc < 0xdf50) ||
                                    (pc >= 0xfe8f && pc < 0xfe93)));
        case 5: return pc >= 0xfeed && pc < 0xfef6;
        case 8: return (pc >= 0xb4e5 && pc < 0xb5cb) || (pc >= 0xc6f3 && pc < 0xc770) ||
                       (pc >= 0xca9b && pc < 0xcb1e) || (pc >= 0xec79 && pc < 0xeca7) ||
                       (pc >= 0xf132 && pc < 0xf156) ||
                       (handoff && ((pc >= 0xf3fc && pc < 0xf419) ||
                                    (pc >= 0xfdc6 && pc < 0xfdd1) ||
                                    (pc >= 0x861b && pc < 0x8624) ||
                                    (pc >= 0x8685 && pc < 0x868d) ||
                                    (pc >= 0x8709 && pc < 0x8711)));
        case 11: return (pc >= 0xf7ed && pc < 0xf892) || (pc >= 0xf891 && pc < 0xfa2a) ||
                        (pc >= 0xfb16 && pc < 0xfb78) || (pc >= 0xfca8 && pc < 0xfcea) ||
                        (pc >= 0xfdcd && pc < 0xfdf9) || (pc >= 0xfe1b && pc < 0xfe5d) ||
                        (pc >= 0xfee3 && pc < 0xfeee);
        case 16: return (pc >= 0xe6c3 && pc <= 0xe72d) || (pc >= 0xff00 && pc < 0xff80);
        case 19: return (pc >= 0x8c9c && pc < 0x8d33) || pc == 0x8d7c || (pc >= 0xfbb2 && pc < 0xfbbe) ||
                        (handoff && ((pc >= 0x8adf && pc < 0x8b26) ||
                                     (pc >= 0x8d86 && pc < 0x8d8f) ||
                                     (pc >= 0x8d99 && pc < 0x8da2) ||
                                     (pc >= 0xf660 && pc < 0xf66e)));
        case 20: return (pc >= 0x8e73 && pc < 0x8f1e) ||
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
        if (cpu.mSFR[REG_SP] >= 0xf0) fail("Stack guard exceeded");
        /* External dependencies are intercepted before entering their wrappers.
         * System-mode/per-port getters and the KVM selection logic execute. */
        switch (cpu.mPC) {
            case 0x0eb7: cpu.mLowerData[7] = (unsigned char)power_mode; ret(); continue;
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
            case 0x2e8b: case 0x2fe7: ret(); continue;
            case 0x324b: carry(helper_carry); ret(); continue;
            case 0x31c7: dialog_calls++; ret(); continue;
            case 0x3e39: ret(); continue; /* Ordinary screen callback, not this investigation. */
            default: break;
        }
        if (bank == 16 && cpu.mPC == 0xe6c3) event9_entries++;
        if (bank == 16 && cpu.mPC == 0xe062) { cleanup_calls++; ret(); continue; }
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
int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--require-no-signal-switch")) patch_expected = 1;
    else if (argc != 1) return 2;
    if (fread(image, 1, sizeof(image), stdin) != sizeof(image) || fgetc(stdin) != EOF) return 2;
    cpu.mCodeMem = code; cpu.mCodeMemMaxIdx = 65535;
    cpu.mExtData = memory; cpu.mExtDataMaxIdx = 65535; cpu.mUpperData = upper;
    cpu.except = exception; cpu.xwrite = xwrite;
    unsigned scanner_cases = 0, gate_cases = 0, no_signal_blocked = 0, no_signal_switched = 0;
    unsigned max_stack = 0;
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
        if (shared_entries != expected || requests != (expected && !layouts[layout]) ||
            toggles != (expected && layouts[layout] < 3) ||
            (expected && !layouts[layout] && (requested != 2 || memory[0xd367] != 0x0a)))
            fail("KVM request did not match explicit-button contract");
        if (screens[s] == 0x26 && mode == 3 && enabled && !layouts[layout]) {
            if (shared_entries) no_signal_switched++; else no_signal_blocked++;
        }
        if (peak_sp > max_stack) max_stack = peak_sp;
        gate_cases++;
    }
    unsigned timer_cases = 0;
    const unsigned clocks[] = {0, 1, 5535, 5536, 32767, 32768, 60000, 65534, 65535};
    for (unsigned c = 0; c < sizeof(clocks)/sizeof(clocks[0]); c++)
    for (unsigned occupied = 0; occupied < 4; occupied++)
    for (unsigned direction = 0; direction < 2; direction++) {
        setup(19); state(0x26, 3, 1, 2); source = direction ? 2 : 4;
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
    unsigned capacity_cases = 0;
    for (unsigned reusable = 0; reusable < 3; reusable++)
    for (unsigned slot = 0; slot < 21; slot++) {
        setup(19); state(0x26, 3, 1, 2); memory[0xd368] = 9;
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
        binding_cases++;
    }
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
    unsigned screen_cases = 0, flag_cases = 0;
    for (unsigned screen = 0; screen < 65536; screen++) {
        setup(19); state(screen, 3, 1, 4); memory[0xd368] = 9;
        run(0x8c9c, 0x8d33);
        unsigned expected = screen == 0 || (patch_expected && screen == 0x26);
        if (requests != expected || (expected && requested != 2))
            fail("Patch changed another screen word");
        screen_cases++;
    }
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
    printf("{\"scanner_cases\":%u,\"gate_cases\":%u,\"no_signal_blocked\":%u,"
           "\"no_signal_switched\":%u,\"peak_sp\":%u,\"hardware_access\":false,"
           "\"original_bank_gateways_executed\":true,\"candidate_expected\":%s,"
           "\"timer_handoff_cases\":%u,\"timer_capacity_cases\":%u,\"binding_cases\":%u,\"scanner_dispatch_chain_cases\":%u,\"screen_word_cases\":%u,\"enable_layout_cases\":%u,"
           "\"source_route_cases\":%u,\"route_early_returns\":%u,\"route_completions\":%u,"
           "\"fallback_cases\":%u,\"fallback_requests\":%u,\"fallback_searches\":%u,\"route_transport_stubbed\":true}\n", scanner_cases, gate_cases,
           no_signal_blocked, no_signal_switched, max_stack, patch_expected ? "true" : "false", timer_cases, capacity_cases, binding_cases, chain_cases, screen_cases, flag_cases,
           handoff_cases, route_early_returns, route_completions, fallback_cases, fallback_requests, fallback_searches);
    return 0;
}
