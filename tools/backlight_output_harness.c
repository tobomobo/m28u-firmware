/* Offline execution of bounded F11 backlight instructions. No device APIs.
 * Mode predicates and the transport are intercepted explicitly. Input pinning
 * and attribution are handled by validate_backlight_output.py.
 */
#include "emu8051.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char image[27 * 65536], code[65536], memory[65536], upper[128];
static struct em8051 cpu;
static unsigned mode, boost, special, transport_calls, finish_calls, buffer_calls;
static unsigned output_bytes[2], expected_buffer;
static int buffer_test, experiment;

static void fail(const char *reason) {
    fprintf(stderr, "%s PC=%04x\n", reason, cpu.mPC);
    exit(2);
}
static void exception(struct em8051 *unused, int reason) {
    (void)unused; (void)reason; fail("8051 exception");
}
static void write_memory(struct em8051 *unused, uint16_t address, uint8_t value) {
    (void)unused;
    if (!((address >= 0xc9e1 && address <= (buffer_test ? 0xc9fe : 0xc9e4)) ||
          (!buffer_test && address >= 0xca18 && address <= 0xca1a)))
        fail("Unexpected XRAM write");
    memory[address] = value;
}
static void setup(unsigned bank, unsigned pc, unsigned argument) {
    /* Pinned F11 repeats the common 0000..3fff bytes in the banks used here.
     * Thus 3845/3857 execute the same math-helper bytes as image bank zero. */
    memcpy(code, image + bank * 65536, sizeof(code));
    memset(memory, 0, sizeof(memory)); memset(upper, 0, sizeof(upper));
    reset(&cpu, false);
    memset(cpu.mLowerData, 0, sizeof(cpu.mLowerData));
    memset(cpu.mSFR, 0, sizeof(cpu.mSFR));
    cpu.mSFR[REG_SP] = 0x5f;
    push_to_stack(&cpu, 0xff); push_to_stack(&cpu, 0xff);
    cpu.mPC = pc;
    cpu.mLowerData[6] = (unsigned char)(argument >> 8);
    cpu.mLowerData[7] = (unsigned char)argument;
    transport_calls = finish_calls = buffer_calls = 0;
}
static void ret(void) { cpu.op[0x22](&cpu); }
static void carry(unsigned value) {
    if (value) cpu.mSFR[REG_PSW] |= PSWMASK_C;
    else cpu.mSFR[REG_PSW] &= (unsigned char)~PSWMASK_C;
}
static void capture_output(void) {
    unsigned n = cpu.mLowerData[3], reg = cpu.mLowerData[5];
    if (cpu.mLowerData[7] != 0x21 || memory[0xca18] != 1 ||
        memory[0xca19] != 0xc9 || memory[0xca1a] != 0xe3)
        fail("Unexpected output transport arguments");
    if (transport_calls == 0) {
        if (n != 1 || reg != 0x36 || memory[0xc9e3] != 0xca ||
            (cpu.mLowerData[0x20] & 0x40)) fail("Unexpected initial register-36 request");
    } else if (transport_calls == 1) {
        if (n != 2 || reg != 0x0c || (cpu.mLowerData[0x20] & 0x40))
            fail("Unexpected two-byte output request");
        output_bytes[0] = memory[0xc9e3]; output_bytes[1] = memory[0xc9e4];
    } else if (transport_calls == 2) {
        if (n != 1 || reg != 0x36 || memory[0xc9e3] != 0x0a ||
            !(cpu.mLowerData[0x20] & 0x40)) fail("Unexpected final register-36 request");
    } else fail("Unexpected extra transport request");
    transport_calls++;
    /* Callee register clobbers and bus failures are not modelled. */
    ret();
}
static void run_output(void) {
    for (unsigned steps = 0; steps < 4000 && cpu.mPC != 0xffff; steps++) {
        switch (cpu.mPC) {
            case 0x2bc1: carry(mode); ret(); continue;
            case 0x27b9: cpu.mLowerData[7] = (unsigned char)boost; ret(); continue;
            case 0x2555: cpu.mLowerData[7] = (unsigned char)special; ret(); continue;
            case 0x2baf: capture_output(); continue;
            case 0x2bb5: finish_calls++; ret(); continue;
            default: break;
        }
        if (!((cpu.mPC >= 0x8d03 && cpu.mPC < 0x8dc7) ||
              (cpu.mPC >= 0x9818 && cpu.mPC < 0x983e) ||
              (cpu.mPC >= 0x9877 && cpu.mPC < 0x9881) ||
              (experiment && cpu.mPC >= 0xc000 && cpu.mPC < 0xc060) ||
              (cpu.mPC >= 0x3845 && cpu.mPC < 0x38ac)))
            fail("Escaped output routine");
        cpu.op[code[cpu.mPC]](&cpu);
    }
    if (cpu.mPC != 0xffff || cpu.mSFR[REG_SP] != 0x5f ||
        transport_calls != 3 || finish_calls != 1) fail("Output did not finish");
}
static void run_buffer(void) {
    for (unsigned steps = 0; steps < 4000 && cpu.mPC != 0xffff; steps++) {
        if (cpu.mPC == 0xfc40) {
            if (cpu.mLowerData[7] != 0x37 || cpu.mLowerData[5] != 30 ||
                cpu.mLowerData[3] != 1 || cpu.mLowerData[2] != 0xc9 ||
                cpu.mLowerData[1] != 0xe1) fail("Unexpected buffer transport arguments");
            for (unsigned i = 0; i < 15; i++)
                if (memory[0xc9e1 + 2*i] != (expected_buffer & 255) ||
                    memory[0xc9e2 + 2*i] != (expected_buffer >> 8)) fail("Buffer mismatch");
            buffer_calls++; ret(); continue;
        }
        if (!((cpu.mPC >= 0xfd6a && cpu.mPC < 0xfda5) ||
              (cpu.mPC >= 0xf054 && cpu.mPC < 0xf062))) fail("Escaped buffer routine");
        cpu.op[code[cpu.mPC]](&cpu);
    }
    if (cpu.mPC != 0xffff || cpu.mSFR[REG_SP] != 0x5f || buffer_calls != 1)
        fail("Buffer routine did not finish");
}
int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--experimental-sdr540")) experiment = 1;
    else if (argc != 1) return 2;
    if (fread(image, 1, sizeof(image), stdin) != sizeof(image) || fgetc(stdin) != EOF) return 2;
    cpu.mCodeMem = code; cpu.mCodeMemMaxIdx = 65535;
    cpu.mExtData = memory; cpu.mExtDataMaxIdx = 65535; cpu.mUpperData = upper;
    cpu.except = exception; cpu.xwrite = write_memory;
    unsigned cases = 0;
    const unsigned layouts[] = {0, 1, 2, 3, 255};
    /* All slider inputs, predicates, override-bit states, and five-bit fields.
     * Some combinations cannot occur on hardware; none are asserted reachable. */
    for (unsigned input = 0; input <= 100; input++)
        for (mode = 0; mode < 2; mode++)
            for (boost = 0; boost < 2; boost++)
                for (special = 0; special < 2; special++)
                    for (unsigned override = 0; override < 2; override++)
                        for (unsigned field = 0; field < 32; field++)
                            for (unsigned local = 0; local < 2; local++)
                                for (unsigned layout = 0; layout < 5; layout++) {
                            unsigned value = 48 + 357 * input / 100;
                            setup(20, 0x8d03, value);
                            memory[0xd0e9] = (unsigned char)(override | (local << 4));
                            memory[0xd0f3] = (unsigned char)(field << 3);
                            memory[0xd143] = (unsigned char)layouts[layout];
                            run_output();
                            unsigned expected = override ? 400 : mode && boost ? 643 :
                                !mode && special ? (405 * field / 7) & 1023 : value;
                            if (experiment && !override && !mode && !special && !local && !layouts[layout])
                                expected = 48 + (value - 48) * 164 / 119;
                            if (output_bytes[0] != (expected >> 2) || output_bytes[1] != (expected & 3))
                                fail("Unexpected output bytes");
                            cases++;
                        }
    /* Every 16-bit direct argument in the ordinary branch: inserted guard must
     * leave out-of-range arguments unchanged, including their original masking. */
    for (unsigned input = 0; input <= 65535; input++) {
        mode = boost = special = 0;
        setup(20, 0x8d03, input);
        run_output();
        unsigned expected = experiment && input >= 48 && input <= 405 ?
            48 + (input - 48) * 164 / 119 : input & 1023;
        if (output_bytes[0] != (expected >> 2) || output_bytes[1] != (expected & 3))
            fail("Direct argument guard mismatch");
    }
    buffer_test = 1;
    /* Every possible unsigned 16-bit request, including the clamp boundary. */
    for (unsigned input = 0; input <= 65535; input++) {
        setup(2, 0xfd6a, input);
        expected_buffer = input > 3900 ? 3900 : input;
        run_buffer();
    }
    printf("{\"output_cases\":%u,\"direct_argument_cases\":65536,\"buffer_cases\":65536,"
           "\"normal_max_bytes\":[%u,%u],\"boost_bytes\":[160,3],"
           "\"override_bytes\":[100,0],\"boost_decoded_10bit\":643,"
           "\"buffer_words\":15,\"buffer_max\":3900,\"hardware_access\":false,"
           "\"predicates_and_transport_stubbed\":true,\"experiment\":%s}\n", cases,
           experiment ? 135u : 101u, experiment ? 0u : 1u,
           experiment ? "true" : "false");
    return 0;
}
