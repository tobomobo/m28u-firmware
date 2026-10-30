"""Offline real native-worker policy/packet validation using public F11 only."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]
from writer_model import HardwareModel, NativeFakeWriter, FixedRegisterReadModel
from m28u_toolkit.images import IMAGE_SIZE, identify_stock, make_candidate, read_exact_file
from m28u_toolkit.writer import Programmer, preflight


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output",type=Path)
    parser.add_argument("--fixed-register-reads",action="store_true",
                        help="Model observed nonincrementing register bursts (FIFO still advances)")
    args=parser.parse_args()
    stock=read_exact_file(ROOT/"firmware/original/GIGABYTE_M28U_F11.bin",IMAGE_SIZE)
    if identify_stock(stock)[0]!="F11": raise ValueError("F11 required")
    candidate=make_candidate(stock)[0]
    model=(FixedRegisterReadModel if args.fixed_register_reads else HardwareModel)(stock)
    records=[]
    with NativeFakeWriter(model) as bus:
        reader,checks=preflight(bus,model.chip.initial,stock)
        actual=Programmer(bus,reader,record=lambda event,data:records.append({"event":event,"data":data})).update(candidate,tuple(checks["status"]))
        assert actual==candidate and bus.committed
        assert all(x=="ffff" for x in model.marker_states[:-1]) and model.marker_states[-1]=="aa55"
        assert model.status==checks["status"] and model.chip.indexed[0x100a]==0xb6 and model.chip.regs[0xe3]==0x90
        count=bus.native_packets
        bus.write(0xee,2)
    report={"hardware_access":False,"native_worker":"--stdio-writer-dry-run",
            "register_read_model":type(model).__name__,
            "source":"Known public F11, derived two-byte candidate and synthetic chip",
            "native_hid_output_reports":count,"programmed_pages":model.programmed,
            "readback_sha256":hashlib.sha256(actual).hexdigest(),
            "complete_image_matches":actual==candidate,"marker_committed_last":True,
            "original_protection_restored":True,"records":records,
            "limits":["Real native policy/parser/packets; simulated USB/SPI responses",
                      "Not a hardware programming result"]}
    with args.output.open("x") as f: json.dump(report,f,indent=2);f.write("\n")
    print(json.dumps({k:v for k,v in report.items() if k!="records"},indent=2))


if __name__=="__main__":main()
