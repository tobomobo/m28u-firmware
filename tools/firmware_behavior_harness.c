/* Offline bounded execution of stock F11 KVM gate and brightness arithmetic.
 * Hardware-facing callees are explicitly stubbed. No USB/OS device APIs.
 * stdin: pinned public F11, checked by validate_firmware_behavior.py.
 */
#include "emu8051.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char image[27 * 65536], code[65536], memory[65536], upper[128];
static struct em8051 cpu;
static unsigned route, route_test_result, calls_a3ae, calls_a514, calls_toggle, calls_timer;
static unsigned period_value, output_value, period_calls, output_calls;
static unsigned system_mode, key_calls, key_dialog_calls, key_helper_carry;
static unsigned callback_pc, callback_calls, event9_calls;

static void fail(const char *reason) {
    fprintf(stderr, "%s PC=%04x\n", reason, cpu.mPC);
    exit(2);
}
static void exception(struct em8051 *unused, int reason) {
    (void)unused; (void)reason;
    fail("8051 exception");
}
static void write_memory(struct em8051 *unused, uint16_t address, uint8_t value) {
    (void)unused;
    if (!(address == 0xc9df || address == 0xc9e0 ||
          address == 0xd367 || (address >= 0xd375 && address <= 0xd378))) fail("Unexpected XRAM write");
    memory[address] = value;
}
static void setup(unsigned bank, unsigned pc) {
    memcpy(code, image + bank * 65536, 65536);
    memset(memory, 0, sizeof(memory));
    memset(upper, 0, sizeof(upper));
    reset(&cpu, false);
    memset(cpu.mLowerData, 0, sizeof(cpu.mLowerData));
    memset(cpu.mSFR, 0, sizeof(cpu.mSFR));
    cpu.mSFR[REG_SP] = 0x5f;
    push_to_stack(&cpu, 0xff); push_to_stack(&cpu, 0xff);
    cpu.mPC = pc;
}
static void return_stub(void) { cpu.op[0x22](&cpu); }
static void run_kvm(void) {
    unsigned steps;
    for (steps = 0; steps < 2000 && cpu.mPC != 0xffff; steps++) {
        switch (cpu.mPC) {
            case 0x0e45: /* Stub current upstream/route snapshot. */
                cpu.mLowerData[7] = (unsigned char)route; return_stub(); continue;
            case 0xa3ae: calls_a3ae++; return_stub(); continue;
            case 0xa514:
                calls_a514++;
                if (route_test_result) cpu.mSFR[REG_PSW] |= PSWMASK_C;
                else cpu.mSFR[REG_PSW] &= (unsigned char)~PSWMASK_C;
                return_stub(); continue;
            case 0x2e8b: return_stub(); continue; /* External switching dependency. */
            case 0x2fcf: /* Timer requests are observed, not scheduled. */
                if (cpu.mLowerData[5] != 0x26 || cpu.mLowerData[6] != 7 || cpu.mLowerData[7] != 0xd0)
                    fail("Unexpected KVM timer arguments");
                calls_timer++; return_stub(); continue;
            case 0x7743: calls_toggle++; return_stub(); continue;
            default: break;
        }
        if (!((cpu.mPC >= 0x8e73 && cpu.mPC < 0x8f1e) ||
              (cpu.mPC >= 0x8492 && cpu.mPC < 0x849a) ||
              (cpu.mPC >= 0x84ae && cpu.mPC < 0x84b6))) fail("Escaped KVM gate");
        cpu.op[code[cpu.mPC]](&cpu);
    }
    if (cpu.mPC != 0xffff || cpu.mSFR[REG_SP] != 0x5f) fail("KVM gate did not return");
}
static void run_brightness(void) {
    unsigned steps;
    for (steps = 0; steps < 10000 && cpu.mPC != 0xffff; steps++) {
        if (cpu.mPC == 0x2ed9) {
            period_value = (cpu.mLowerData[6] << 8) | cpu.mLowerData[7];
            period_calls++; return_stub(); continue;
        }
        if (cpu.mPC == 0x2cbd) {
            output_value = (cpu.mLowerData[6] << 8) | cpu.mLowerData[7];
            output_calls++; return_stub(); continue;
        }
        if (!((cpu.mPC >= 0xf72d && cpu.mPC < 0xf761) ||
              (cpu.mPC >= 0xe991 && cpu.mPC < 0xe998) ||
              (cpu.mPC >= 0xe99f && cpu.mPC < 0xe9a7) ||
              (cpu.mPC >= 0x3a42 && cpu.mPC < 0x3b87))) fail("Escaped brightness arithmetic");
        cpu.op[code[cpu.mPC]](&cpu);
    }
    if (cpu.mPC != 0xffff || cpu.mSFR[REG_SP] != 0x5f) fail("Brightness routine did not return");
}
/* The actual event-9 implementation. Dependencies return explicit synthetic
 * inputs; this does not emulate source detection or physical button delivery. */
static void run_key_gate(void) {
    for (unsigned steps = 0; steps < 2000 && cpu.mPC != 0xffff; steps++) {
        switch (cpu.mPC) {
            case 0x2a8f: cpu.mLowerData[7] = (unsigned char)system_mode; return_stub(); continue;
            case 0x2bd9: cpu.mLowerData[7] = (unsigned char)route; return_stub(); continue;
            case 0xe062: return_stub(); continue;
            case 0x324b:
                if (key_helper_carry) cpu.mSFR[REG_PSW] |= PSWMASK_C;
                else cpu.mSFR[REG_PSW] &= (unsigned char)~PSWMASK_C;
                return_stub(); continue;
            case 0x3371: key_calls++; return_stub(); continue;
            case 0x31c7: key_dialog_calls++; return_stub(); continue;
            default: break;
        }
        if (!(cpu.mPC >= 0xe6c3 && cpu.mPC <= 0xe72d)) fail("Escaped event-9 gate");
        cpu.op[code[cpu.mPC]](&cpu);
    }
    if (cpu.mPC != 0xffff || cpu.mSFR[REG_SP] != 0x5f) fail("Event-9 gate did not return");
}
/* Run only the actual screen/event callback selection; intercept the selected
 * callee. The no-signal screen's callback pointers all name a literal RET. */
static void run_screen_dispatch(void) {
    for (unsigned steps = 0; steps < 500 && cpu.mPC != 0x8d33; steps++) {
        if (cpu.mPC == 0x3e39) {
            callback_pc = (cpu.mLowerData[2] << 8) | cpu.mLowerData[1];
            callback_calls++; return_stub(); continue;
        }
        if (cpu.mPC == 0x306b) { event9_calls++; return_stub(); continue; }
        if (!((cpu.mPC >= 0x8cf3 && cpu.mPC < 0x8d33) ||
              (cpu.mPC >= 0x3d17 && cpu.mPC < 0x3d23))) fail("Escaped screen dispatch");
        cpu.op[code[cpu.mPC]](&cpu);
    }
    if (cpu.mPC != 0x8d33 || cpu.mSFR[REG_SP] != 0x61) fail("Screen dispatch did not finish");
}
int main(void) {
    if (fread(image, 1, sizeof(image), stdin) != sizeof(image) || fgetc(stdin) != EOF) return 2;
    cpu.mCodeMem = code; cpu.mCodeMemMaxIdx = 65535;
    cpu.mExtData = memory; cpu.mExtDataMaxIdx = 65535; cpu.mUpperData = upper;
    cpu.except = exception; cpu.xwrite = write_memory;
    unsigned kvm_cases = 0, ignored = 0;
    for (unsigned state = 0; state < 256; state++)
        for (route = 0; route < 6; route++)
            for (unsigned flag = 0; flag < 2; flag++)
                for (route_test_result = 0; route_test_result < 2; route_test_result++) {
                    setup(20, 0x8e73);
                    memory[0xd143] = (unsigned char)state;
                    memory[0xd11f] = (unsigned char)flag;
                    memory[0xd376] = (unsigned char)((route & 1) << 6);
                    calls_a3ae = calls_a514 = calls_toggle = calls_timer = 0;
                    run_kvm();
                    if (state >= 3) {
                        if (calls_a3ae || calls_a514 || calls_toggle || calls_timer)
                            fail("Expected no switching callee for state>=3");
                        ignored++;
                    } else if (state == 1 || state == 2) {
                        if (calls_toggle != 1 || calls_timer != 1 || calls_a3ae || calls_a514)
                            fail("Expected alternate switching path for state1/2");
                    } else if (!calls_a3ae && !calls_a514) fail("Expected state0 switching path");
                    if ((state != 0 || flag != 1 || route != 1) && !(memory[0xd377] & 4))
                        fail("Pending KVM flag not set");
                    kvm_cases++;
                }
    for (unsigned input = 0; input <= 100; input++) {
        setup(13, 0xf72d);
        cpu.mLowerData[6] = 0;
        cpu.mLowerData[7] = (unsigned char)input;
        period_calls = output_calls = 0;
        run_brightness();
        if (output_value != 48 + 357 * input / 100 || period_value != 3900 || period_calls != 1 || output_calls != 1)
            fail("Brightness arithmetic did not match observed formula");
    }
    unsigned key_cases = 0, no_signal_cases = 0, dispatch_cases = 0;
    const unsigned screens[] = {0, 0x20, 0x25, 0x26, 0x100, 0x126};
    for (system_mode = 0; system_mode < 16; system_mode++)
        for (unsigned s = 0; s < sizeof(screens)/sizeof(screens[0]); s++)
            for (unsigned enabled = 0; enabled < 2; enabled++)
                for (route = 0; route < 6; route++)
                    for (key_helper_carry = 0; key_helper_carry < 2; key_helper_carry++) {
                        unsigned screen = screens[s];
                        setup(16, 0xe6c3);
                        memory[0xd365] = (unsigned char)(screen >> 8);
                        memory[0xd366] = (unsigned char)screen;
                        memory[0xd11e] = (unsigned char)(enabled << 7);
                        key_calls = key_dialog_calls = 0;
                        run_key_gate();
                        unsigned expected_switch = system_mode == 3 && enabled && screen == 0 && route == 4;
                        unsigned expected_dialog = system_mode == 3 && screen == 0x20;
                        unsigned expected_message = system_mode == 3 && enabled && screen == 0x25 && key_helper_carry;
                        if (key_calls != expected_switch || key_dialog_calls != expected_dialog ||
                            memory[0xd367] != (expected_message ? 0x1a : 0)) fail("Unexpected event-9 gate outcome");
                        if (screen == 0x26) no_signal_cases++;
                        key_cases++;
                    }
    const unsigned normal_callbacks[] = {0xeeca, 0xeccf, 0xec74, 0xeaab, 0xeb07, 0xfeff};
    for (unsigned s = 0; s < 2; s++)
        for (unsigned event = 0; event < 10; event++) {
            setup(19, 0x8cf3);
            memory[0xd366] = (unsigned char)(s ? 0x26 : 0);
            memory[0xd368] = (unsigned char)event;
            callback_calls = callback_pc = event9_calls = 0;
            run_screen_dispatch();
            if (event < 6) {
                if (callback_calls != 1 || callback_pc != (s ? 0xfeff : normal_callbacks[event]))
                    fail("Unexpected screen callback");
                if (s && code[callback_pc] != 0x22) fail("No-signal callback was not RET");
            } else if (callback_calls) fail("Unexpected callback for non-table event");
            if (event9_calls != (event == 9)) fail("Event-9 routing mismatch");
            dispatch_cases++;
        }
    printf("{\"kvm_cases\":%u,\"kvm_state_ge3_without_switch_callees\":%u,"
           "\"brightness_cases\":101,\"brightness_formula\":\"48 + floor(357 * value / 100)\","
           "\"brightness_output_at_0\":48,\"brightness_output_at_100\":405,"
           "\"second_driver_argument\":3900,\"hardware_access\":false,"
           "\"hardware_callees_stubbed\":true,\"event9_gate_cases\":%u,"
           "\"no_signal_event9_cases_without_switch\":%u,\"screen_dispatch_cases\":%u}\n",
           kvm_cases, ignored, key_cases, no_signal_cases, dispatch_cases);
    return 0;
}
