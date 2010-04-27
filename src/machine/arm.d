/*-
 * Copyright (c) 2009-2010 Doug Rabson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

module machine.arm;
import machine.machine;
import debuginfo.debuginfo;
import debuginfo.expr;
import debuginfo.language;
import debuginfo.types;
import target.target;
private import machine.armdis;
import sys.ptrace;

import std.format;
import std.stdint;
import std.stdio;
import std.string;

/**
 * Register numbers are chosen to match Dwarf debug info.
 */
enum ArmReg
{
    R0,
    R1,
    R2,
    R3,
    R4,
    R5,
    R6,
    R7,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    PC,
    CPSR,
    GR_COUNT
}

private string[] ArmRegNames =
[
    "r0",
    "r1",
    "r2",
    "r3",
    "r4",
    "r5",
    "r6",
    "r7",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "pc",
    "cpsr",
];

class ArmState: MachineState
{
    /**
     * Register numbers are chosen to match Dwarf debug info.
     */
    enum
    {
	R0,
	R1,
	R2,
	R3,
	R4,
	R5,
	R6,
	R7,
	R8,
	R9,
	R10,
	R11,
	R12,
	SP,
	LR,
	PC,
	CPSR
    }

    private static string[] ArmRegNames =
    [
	"r0",
	"r1",
	"r2",
	"r3",
	"r4",
	"r5",
	"r6",
	"r7",
	"r8",
	"r9",
	"r10",
	"r11",
	"r12",
	"sp",
	"lr",
	"pc",
	"cpsr",
    ];

    mixin MachineRegisters;

    this(Target target)
    {
	target_ = target;
	initRegisters;
    }

    static this()
    {
	auto lang = CLikeLanguage.instance;
	Type intType = lang.integerType("uint32_t", false, TS4);
	foreach (reg; ArmRegNames)
	    addRegister(intType, reg);
    }

    override {
	void dumpState()
	{
	    for (auto i = 0; i < registerCount; i++) {
		MachineRegister val = readIntRegister(i);
		writef("%6s:%08x ", ArmRegNames[i], val);
		if ((i & 3) == 3)
		    writefln("");
	    }
	}

	TargetAddress pc()
	{
	    return cast(TargetAddress) readIntRegister(PC);
	}

	void pc(TargetAddress pc)
	{
	    writeIntRegister(PC, cast(MachineRegister) pc);
	}

	TargetAddress tp()
	{
	    return cast(TargetAddress) tp_;
	}

	TargetAddress tls_get_addr(uint index, ulong offset)
	{
	    if (!tp_)
		return TA0;
	    ulong dtv =
                readInteger(readMemory(cast(TargetAddress)(tp_ + 4),
                                       TS4));
	    ulong base =
                readInteger(readMemory(cast(TargetAddress)(dtv + 4 + 4*index),
                                       TS4));
	    return cast(TargetAddress)(base + offset);
	}

	void ptraceReadState(Ptrace pt)
	{
	    version (FreeBSD) {
		ubyte[reg.sizeof] regs;
		setGRs(regs.ptr);
		pt.ptrace(PT_GETREGS, regs.ptr, 0);
	    }
	    foreach (ref d; dirty_)
		d = false;
	}

	void ptraceWriteState(Ptrace pt)
	{
	    bool grdirty = false;
	    foreach (regno, ref d; dirty_) {
		if (d) {
		    grdirty = true;
		    d = false;
		}
	    }
	    version (FreeBSD) {
		if (grdirty) {
		    ubyte[reg.sizeof] regs;
		    getGRs(regs.ptr);
		    pt.ptrace(PT_SETREGS, regs.ptr, 0);
		}
	    }
	}

	void setGRs(ubyte* p)
	{
	    reg32* r = cast(reg32*) p;

	    foreach (regno, v; r.r)
		writeIntRegister(regno, v);
	    writeIntRegister(SP, r.r_sp);
	    writeIntRegister(LR, r.r_lr);
	    writeIntRegister(PC, r.r_pc);
	    writeIntRegister(CPSR, r.r_cpsr);
	}

	void getGRs(ubyte* p)
	{
	    reg32* r = cast(reg32*) p;

	    foreach (regno, ref v; r.r)
		v = readIntRegister(regno);
	    r.r_sp = readIntRegister(SP);
	    r.r_lr = readIntRegister(LR);
	    r.r_pc = readIntRegister(PC);
	    r.r_cpsr = readIntRegister(CPSR);
	}

	uint spregno()
	{
	    return SP;
	}

	MachineState dup()
	{
	    ArmState newState = new ArmState(target_);
	    newState.bytes_[] = bytes_[];
	    newState.tp_ = tp_;
	    return newState;
	}

	void dumpFloat()
	{
	}

	void setFRs(ubyte* regs)
	{
	}

	void getFRs(ubyte* regs)
	{
	}

	uint mapDwarfRegno(uint dwregno)
	{
	    return dwregno;
	}

	ubyte[] breakpoint()
	{
	    static ubyte[] inst = [ 0x11,0x00,0x00,0xe6 ];
	    return inst;
	}

	void adjustPcAfterBreak()
	{
	    writeIntRegister(PC, readIntRegister(PC) - 4);
	}

	TargetSize pointerWidth()
	{
	    return TS4;
	}

	ulong readInteger(ubyte[] bytes)
	{
	    ulong value = 0;
	    foreach_reverse (b; bytes)
		value = (value << 8L) | b;
	    return value;
	}

	void writeInteger(ulong val, ubyte[] bytes)
	{
	    foreach (ref b; bytes) {
		b = val & 0xff;
		val >>= 8;
	    }
	}

	real readFloat(ubyte[] bytes)
	{
	    float32 f32;
	    float64 f64;
	    switch (bytes.length) {
	    case 4:
		f32.i = readInteger(bytes);
		return f32.f;
	    case 8:
		f64.i = readInteger(bytes);
		return f64.f;
	    default:
		assert(false);
	    }
	}

	void writeFloat(real val, ubyte[] bytes)
	{
	}

	ubyte[] readMemory(TargetAddress address, TargetSize bytes)
	{
	    return target_.readMemory(address, bytes);
	}

	void writeMemory(TargetAddress address, ubyte[] toWrite)
	{
	    target_.writeMemory(address, toWrite);
	}

	Value call(TargetAddress address, Type returnType, Value[] args)
	{
	    throw new EvalException("function call not supported");
	}

	Value returnValue(Type returnType)
	{
	    // XXX do this properly
	    return new Value(new ConstantLocation(readRegister
						  (0, registerWidth(0))),
			     returnType);
	}

	TargetAddress findFlowControl(TargetAddress start, TargetAddress end)
	{
	    TargetAddress addr = start;
	    while (addr < end) {
		uint insn = readInteger(readMemory(addr, TS4));
		if (((insn >> 24) & 7) == 5)	// B, BL
		    break;
		if (((insn >> 20) & 0xff) == 0x12) // BX
		    break;
		if (((insn >> 20) & 0xfe) == 0x36) // MOV
		    if (((insn >> 12) & 15) == 15)
			break;
		if (((insn >> 20) & 0xc5) == 0x41) // LDR
		    if (((insn >> 12) & 15) == 15)
			break;
		addr += 4;
	    }
	    return addr;
	}

	TargetAddress findJump(TargetAddress start, TargetAddress end)
	{
	    TargetAddress addr = start;
	    while (addr < end) {
		uint insn = readInteger(readMemory(addr, TS4));
		if (((insn >> 24) & 7) == 5)	// B, BL
		    break;
		addr += 4;
	    }
	    return addr;
	}

	string disassemble(ref TargetAddress address,
			   string delegate(TargetAddress) lookupAddress)
	{
	    uint readWord(TargetAddress address)
	    {
		ubyte[] t = readMemory(address, TS4);
		uint v = readInteger(t);
		return v;
	    }
	    return machine.armdis.disasm(address, &readWord, lookupAddress);
	}
    }

private:
    union float32 {
	uint i;
	float f;
    }
    union float64 {
	ulong i;
	double f;
    }
    Target	target_;
    uint32_t	tp_;
}

private:
/*	$NetBSD: reg.h,v 1.2 2001/02/23 21:23:52 reinoud Exp $	*/
/* $FreeBSD: stable/7/sys/arm/include/reg.h 137229 2004-11-04 19:20:54Z cognet $ */

struct reg32 {
	uint r[13];
	uint r_sp;
	uint r_lr;
	uint r_pc;
	uint r_cpsr;
};

/+

struct fpreg {
	unsigned int fpr_fpsr;
	fp_reg_t fpr[8];
};

struct dbreg {
	        unsigned int  dr[8];    /* debug registers */
};

+/
