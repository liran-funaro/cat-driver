"""
A simple tool to allow control over CAT via python.
Require root privileges to run.

Author: Liran Funaro <liran.funaro@gmail.com>

Copyright (C) 2006-2018 Liran Funaro

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""
import os
import sys
import inspect
import argparse
from threading import Lock
from subprocess import Popen, PIPE


class Run:
    def __init__(self, cmd_args, as_root=False, **kwarg):
        self.cmd_args = map(str, cmd_args)

        if as_root:
            self.cmd_args = ["sudo", *self.cmd_args]

        kwarg["stdout"] = PIPE
        kwarg["stderr"] = PIPE

        out, err = Popen(self.cmd_args, **kwarg).communicate()

        self.out = out.strip()
        self.err = err.strip()


"""
msb/lsb code is from:
http://rosettacode.org/wiki/Find_first_and_last_set_bit_of_a_long_integer#Python
"""


def msb(x):
    return x.bit_length() - 1


def lsb(x):
    return msb(x & -x)


def ways_bit_count(first_way, last_way):
    return last_way - first_way + 1


def ways_to_mask(first_way, last_way):
    bit_count = ways_bit_count(first_way, last_way)
    return ((1 << bit_count) - 1) << first_way


def mask_to_ways(mask):
    return lsb(mask), msb(mask)


def activate_msr():
    res = Run(["modprobe", "msr"], as_root=True)
    if res.err:
        raise ValueError(res.err)


def rdmsr(cpu, msr):
    res = Run(["rdmsr", "-p", str(cpu), hex(msr)], as_root=True)
    if res.err:
        raise ValueError(res.err)
    else:
        return int(res.out, 16)


def wrmsr(cpu, msr, data):
    res = Run(["wrmsr", "-p", str(cpu), hex(msr), hex(data)], as_root=True)
    if res.err:
        raise ValueError(res.err)


def set_mask(start_bit, end_bit):
    low_mask = (1 << start_bit) - 1
    high_mask = (1 << (end_bit + 1)) - 1
    return high_mask - low_mask


def clear_mask(bit_count, start_bit, end_bit):
    all_mask = (1 << bit_count) - 1
    return set_mask(start_bit, end_bit) ^ all_mask


def rdmsr_bits(cpu, msr, start_bit, end_bit):
    rd_msr = rdmsr(cpu, msr)
    mask = set_mask(start_bit, end_bit)
    return (rd_msr & mask) >> start_bit


def wrmsr_bits(cpu, msr, data, start_bit, end_bit, msr_size=64):
    rd_msr = rdmsr(cpu, msr)
    mask = clear_mask(msr_size, start_bit, end_bit)
    wrmsr(cpu, msr, (rd_msr & mask) | (data << start_bit))


def get_module_relative_path(file_path):
    current_module = sys.modules[__name__]
    this_file = inspect.getfile(current_module)
    this_folder = os.path.dirname(this_file)
    return os.path.join(this_folder, file_path)


def cpuid(in_eax, in_ecx):
    cpuid_path = get_module_relative_path("cpuid-tool/cpuid")
    res = Run([cpuid_path, hex(in_eax), hex(in_ecx)])
    _in_eax, _out_eax, eax, ebx, ecx, edx = res.out.split(",")
    return int(eax, 16), int(ebx, 16), int(ecx, 16), int(edx, 16)


class CatDriver:
    IA32_PQR_ASSOC = 0xc8f
    IA32_L3_MASK_0 = 0xc90
    IA32_QM_EVTSEL = 0xc8d
    IA32_QM_CTR    = 0xc8e

    COS_BITS = 32, 63
    RMID_BITS = 0, 9

    MAX_POSSIBLE_COS = 1 << (COS_BITS[1] - COS_BITS[0] + 1)
    MAX_POSSIBLE_RMID = 1 << (RMID_BITS[1] - RMID_BITS[0] + 1)

    EVTSEL_L3_OCCUPENCY                = 0x1
    EVTSEL_L3_TOTAL_EXTERNAL_BANDWIDTH = 0x2
    EVTSEL_L3_LOCAL_EXTERNAL_BANDWIDTH = 0x3

    WORK_LOCK = Lock()

    next_rmid = 0
    msr_activated = False
    cos_count = None
    min_alloc = None
    max_alloc = None
    rmid_count = None
    ctr_scale_factor = None

    def __init__(self, master_cpu=0, detect=True):
        self.master_cpu = master_cpu

        if detect:
            with CatDriver.WORK_LOCK:
                if not CatDriver.msr_activated:
                    activate_msr()
                    CatDriver.msr_activated = True
                if CatDriver.cos_count is None:
                    CatDriver.cos_count = self.detect_cos_count()
                if self.min_alloc is None or self.max_alloc is None:
                    CatDriver.min_alloc, CatDriver.max_alloc = self.detect_min_max_alloc()
                if CatDriver.rmid_count is None:
                    CatDriver.rmid_count = self.detect_rmid_count()
                if CatDriver.ctr_scale_factor is None:
                    self.update_scale_factor()

    @staticmethod
    def update_scale_factor():
        try:
            CatDriver.ctr_scale_factor = cpuid(0xf, 0x1)[1]
        except Exception as e:
            print("Detection of scale factor failed with error:", e)
            print("Did you compile the cpuid-tool? (cd cpuid-tool; make)")

    def allocate_rmid(self):
        with CatDriver.WORK_LOCK:
            if CatDriver.next_rmid >= CatDriver.rmid_count:
                raise Exception(f"Not enough RMIDs, max is: {self.rmid_count}")
            res = CatDriver.next_rmid
            CatDriver.next_rmid += 1

        return res

    def set_cpu_cos(self, cpu, cos):
        wrmsr_bits(cpu, self.IA32_PQR_ASSOC, cos, *self.COS_BITS)

    def get_cpu_cos(self, cpu):
        return rdmsr_bits(cpu, self.IA32_PQR_ASSOC, *self.COS_BITS)

    def set_cpu_rmid(self, cpu, rmid):
        wrmsr_bits(cpu, self.IA32_PQR_ASSOC, rmid, *self.RMID_BITS)

    def get_cpu_rmid(self, cpu):
        return rdmsr_bits(cpu, self.IA32_PQR_ASSOC, *self.RMID_BITS)

    def set_cos_mask(self, cos, mask):
        wrmsr(self.master_cpu, self.IA32_L3_MASK_0 + cos, mask)

    def get_cos_mask(self, cos):
        return rdmsr(self.master_cpu, self.IA32_L3_MASK_0 + cos)

    def read_event(self, rmid, eventid, no_exception=True):
        with CatDriver.WORK_LOCK:
            wr_qm = eventid | (rmid << 32)
            wrmsr(self.master_cpu, self.IA32_QM_EVTSEL, wr_qm)
            rd_ctr_err = rdmsr_bits(self.master_cpu, self.IA32_QM_CTR, 62, 63)
            if rd_ctr_err != 0 and no_exception:
                return None
            elif rd_ctr_err == 0x1:
                raise ValueError("Data is not available")
            elif rd_ctr_err == 0x2:
                raise ValueError("There is no valid data to report")
            elif rd_ctr_err == 0x3:
                raise ValueError("Unknown error reading CTR")

            return rdmsr_bits(self.master_cpu, self.IA32_QM_CTR, 0, 61) * CatDriver.ctr_scale_factor

    def read_l3_occupancy(self, rmid):
        return self.read_event(rmid, self.EVTSEL_L3_OCCUPENCY)

    def read_local_external_bandwidth(self, rmid):
        return self.read_event(rmid, self.EVTSEL_L3_LOCAL_EXTERNAL_BANDWIDTH)

    def read_total_external_bandwidth(self, rmid):
        return self.read_event(rmid, self.EVTSEL_L3_TOTAL_EXTERNAL_BANDWIDTH)

    def detect_cos_count(self):
        for cos in range(self.MAX_POSSIBLE_COS):
            try:
                self.set_cpu_cos(self.master_cpu, cos)
            except:
                return cos

    def detect_rmid_count(self):
        for rmid in range(self.MAX_POSSIBLE_RMID):
            try:
                self.set_cpu_rmid(self.master_cpu, rmid)
            except:
                return rmid

    def detect_min_max_alloc(self):
        min_alloc = None

        for alloc_size in range(64):
            mask = (1 << alloc_size) - 1
            try:
                self.set_cos_mask(0, mask)
                if min_alloc is None:
                    min_alloc = alloc_size
            except:
                if min_alloc is not None:
                    return min_alloc, alloc_size-1

        return None, None

    def set_cos_alloc(self, cos, first_way, last_way):
        return self.set_cos_mask(cos, ways_to_mask(first_way, last_way))

    def get_cos_alloc(self, cos):
        return mask_to_ways(self.get_cos_mask(cos))

    def get_cpu_alloc(self, cpu):
        cos = self.get_cpu_cos(cpu)
        return self.get_cos_alloc(cos)


def main():
    parser = argparse.ArgumentParser(description="Intel's Cache Allocation Technology (CAT) Driver.")
    parser.add_argument('-m', '--master-cpu', metavar="CPU", type=int, default=0)
    parser.add_argument('-d', '--detect', action='store_true')

    group = parser.add_mutually_exclusive_group()

    group.add_argument('-c', '--get-cpu-cos', metavar='CPU', type=int)
    group.add_argument('-C', '--set-cpu-cos', metavar=('CPU', 'COS'), type=int, nargs=2)

    group.add_argument('-a', '--get-cos-alloc', metavar='COS', type=int)
    group.add_argument('-A', '--set-cos-alloc', metavar=('COS', 'WAY1', 'WAY2'), type=int, nargs=3)

    group.add_argument('-g', '--get-cpu-alloc', metavar='CPU', type=int)

    group.add_argument('-r', '--get-cpu-rmid', metavar='CPU', type=int)
    group.add_argument('-R', '--set-cpu-rmid', metavar=('CPU', 'RMID'), type=int, nargs=2)

    group.add_argument('-o', '--read-llc-occupency', metavar='RMID', type=int)
    args = parser.parse_args()

    c = CatDriver(args.master_cpu, args.detect)
    if args.detect:
        print("COS count:", c.cos_count)
        print("RMID count:", c.rmid_count)
        print("MIN alloc:", c.min_alloc)
        print("MAX alloc:", c.max_alloc)

    if args.get_cpu_cos is not None:
        print(c.get_cpu_cos(args.get_cpu_cos))
    elif args.set_cpu_cos is not None:
        c.set_cpu_cos(*args.set_cpu_cos)
    elif args.get_cos_alloc is not None:
        print(c.get_cos_alloc(args.get_cos_alloc))
    elif args.set_cos_alloc is not None:
        c.set_cos_alloc(*args.set_cos_alloc)
    elif args.get_cpu_alloc is not None:
        print(c.get_cpu_alloc(args.get_cpu_alloc))
    elif args.get_cpu_rmid is not None:
        print(c.get_cpu_rmid(args.get_cpu_rmid))
    elif args.set_cpu_rmid is not None:
        c.set_cpu_rmid(*args.set_cpu_rmid)
    elif args.read_llc_occupency is not None:
        if not args.detect:
            c.update_scale_factor()
        print(c.read_l3_occupancy(args.read_llc_occupency))


if __name__ == '__main__':
    main()
