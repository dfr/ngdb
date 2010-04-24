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
    this(Target target)
    {
	target_ = target;
    }

    override {
	void dumpState()
	{
	    foreach (i, val; gregs_) {
		writef("%6s:%08x ", ArmRegNames[i], val);
		if ((i & 3) == 3)
		    writefln("");
	    }
	}

	TargetAddress pc()
	{
            return cast(TargetAddress) gregs_[ArmReg.PC];
	}

	void pc(TargetAddress pc)
	{
	    gregs_[ArmReg.PC] = cast(uint) pc;
	    grdirty_ = true;
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

	PtraceCommand[] ptraceReadCommands()
	{
	    grdirty_ = false;
	    version (FreeBSD)
		return [PtraceCommand(PT_GETREGS, cast(ubyte*) gregs_.ptr)];
	    return null;
	}

	PtraceCommand[] ptraceWriteCommands()
	{
	    if (grdirty_) {
		grdirty_ = false;
		version (FreeBSD)
		    return [PtraceCommand(PT_GETREGS, cast(ubyte*) gregs_.ptr, 0)];
	    }
	    return null;
	}

	void setGRs(ubyte* p)
	{
	    grdirty_ = true;
	}

	void getGRs(ubyte* p)
	{
	}

	uint spregno()
	{
	    return 4;
	}

	uint grCount()
	{
	    return ArmReg.GR_COUNT;
	}

	MachineState dup()
	{
	    ArmState newState = new ArmState(target_);
	    newState.gregs_[] = gregs_[];
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

	MachineRegister readIntRegister(uint regno)
	{
	    if (regno >= ArmReg.GR_COUNT)
		throw new TargetException(
		    format("Unsupported register index %d", regno));
	    return cast(MachineRegister) gregs_[regno];
	}

	uint mapDwarfRegno(int dwregno)
	{
	    return dwregno;
	}

	TargetSize registerWidth(int regno)
	{
	    if (regno < ArmReg.GR_COUNT)
		return TS4;
	    else
		throw new TargetException(
		    format("Unsupported register index %d", regno));
	}

	void writeIntRegister(uint regno, MachineRegister val)
	{
	    if (regno >= ArmReg.GR_COUNT)
		throw new TargetException(
		    format("Unsupported register index %d", regno));
	    gregs_[regno] = val;
	    grdirty_ = true;
	}

	ubyte[] readRegister(uint regno, TargetSize bytes)
	{
	    if (regno < ArmReg.GR_COUNT) {
		ubyte[] v;
		assert(bytes <= 4);
		v.length = bytes;
		v[] = (cast(ubyte*) &gregs_[regno])[0..bytes];
		return v;
	    } else {
		throw new TargetException(
		    format("Unsupported register index %d", regno));
	    }
	}

	void writeRegister(uint regno, ubyte[] v)
	{
	    if (regno < ArmReg.GR_COUNT) {
		assert(v.length <= 4);
		(cast(ubyte*) &gregs_[regno])[0..v.length] = v[];
		grdirty_ = true;
	    } else {
		throw new TargetException(
		    format("Unsupported register index %d", regno));
	    }
	}

	ubyte[] breakpoint()
	{
	    static ubyte[] inst = [ 0x11,0x00,0x00,0xe6 ];
	    return inst;
	}

	void adjustPcAfterBreak()
	{
	    gregs_[ArmReg.PC] -= 4;
	    grdirty_ = true;
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

	string[] contents(MachineState)
	{
	    return ArmRegNames[];
	}

	bool lookup(string reg, MachineState, out DebugItem val)
	{
	    if (reg.length > 0 && reg[0] == '$')
		reg = reg[1..$];
	    foreach (i, s; ArmRegNames) {
		if (s == reg) {
		    val = regAsValue(i);
		    return true;
		}
	    }
	    return false;
	}
	bool lookupStruct(string reg, out Type)
	{
	    return false;
	}
	bool lookupUnion(string reg, out Type)
	{
	    return false;
	}
	bool lookupTypedef(string reg, out Type)
	{
	    return false;
	}
    }

    Value regAsValue(uint i)
    {
	auto loc = new RegisterLocation(i, registerWidth(i));
	auto ty = CLikeLanguage.instance.integerType(
	    "uint32_t", false, registerWidth(i));
	return new Value(loc, ty);
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
    uint32_t	gregs_[ArmReg.GR_COUNT];
    bool	grdirty_;
    uint32_t	tp_;
}
