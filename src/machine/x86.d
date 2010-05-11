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

module machine.x86;
import machine.machine;
import debuginfo.debuginfo;
import debuginfo.expr;
import debuginfo.language;
import debuginfo.types;
import debuginfo.unwind;
private import machine.x86dis;
import target.target;
import sys.ptrace;

import std.math;
import std.stdio;
import std.stdint;
import std.string;

version (LittleEndian)
{
    static if (real.sizeof == 10 || real.sizeof == 12 || real.sizeof == 16)
	version = nativeFloat80;
}

private {
    template DumpFloat()
    {
	void dumpFloat()
	{
	    uint control = readIntRegister(FCTRL);
	    uint status = readIntRegister(FSTAT);
	    uint tag = readIntRegister(FTAG);
	    uint top = (status >> 11) & 7;
	    static string tagNames[] = [
		"Valid",
		"Zero",
		"Special",
		"Empty"];
	    static string precisionNames[] = [
		"Single Precision (24 bits),",
		"Reserved",
		"Double Precision (53 bits),",
		"Double Extended Precision (64 bits),",
		];
	    static string roundingNames[] = [
		"Round to nearest",
		"Round down",
		"Roumnd up",
		"Round toward zero",
		];

	    /*
	     * Regenerate the tag word from its abridged version
	     */
	    ushort newtag = 0;
	    for (auto i = 0; i < 8; i++) {
		if (tag & (1 << i)) {
		    auto fi = (i - top) & 7;
		    ubyte[] acc = readRegister(ST0 + fi, TS10);
		    auto exp = readInteger(acc[8..10]);
		    auto frac = readInteger(acc[0..8]);
		    if ((exp & 0x7fff) == 0x7fff)
			newtag |= 2 << (2*i); // special
		    else if (exp == 0 && frac == 0)
			newtag |= 1 << (2*i); // zero
		    else
			newtag |= 0 << (2*i); // valid
		} else {
		    newtag |= 3 << (2*i);
		}
	    }
	    tag = newtag;

	    for (auto i = 7; i >= 0; i--) {
		auto fi = (i - top) & 7;
		ubyte[] acc = readRegister(ST0 + fi, TS10);
		writef("%sR%d: %-7s 0x%04x%016x ",
		       i == top ? "=>" : "  ",
		       i,
		       tagNames[(tag >> 2*i) & 3],
		       readInteger(acc[8..10]),
		       readInteger(acc[0..8]));
		switch ((tag >> (2*i)) & 3) {
		case 0:
		    writefln("%g", readFloat(acc));
		    break;
		case 1:
		    writefln("+0");
		    break;
		case 2:
		    writefln("%g", readFloat(acc));
		    break;
		case 3:
		    writefln("");
		}
	    }
	    writefln("");
	    writefln("%-22s0x%04x", "Status Word:", status);
	    writefln("%-22s  TOP: %d", "", top);
	    writef("%-22s0x%04x   ", "Control Word:", control);
	    if (control & 1) writef("IM ");
	    if (control & 2) writef("DM ");
	    if (control & 4) writef("ZM ");
	    if (control & 8) writef("OM ");
	    if (control & 16) writef("UM ");
	    if (control & 32) writef("PM ");
	    if (control & (1<<12)) writef("X");
	    writefln("");
	    writefln("%-22s  PC: %s", "",
		     precisionNames[(control >> 8) & 3]);
	    writefln("%-22s  RC: %s", "",
		     roundingNames[(control >> 10) & 3]);
	    writefln("%-22s0x%04x", "Tag Word:", tag);
	    writefln("%-22s0x%02x:0x%08x", "Instruction Pointer:",
		     readIntRegister(FISEG),
		     readIntRegister(FIOFF));
	    writefln("%-22s0x%02x:0x%08x", "Operand Pointer:",
		     readIntRegister(FOSEG),
		     readIntRegister(FOOFF));
	    writefln("%-22s0x%04x", "Opcode:",
		     0xd800 + readIntRegister(FOP));
	}
    }

    Type xmmType()
    {
	static CompoundType ty;

	if (ty)
	    return ty;
	
	auto lang = CLikeLanguage.instance;
	ty = new CompoundType(lang, "union", "xmmreg_t", TS16);

	void addXmmP(string name, Type fTy)
	{
	    auto aTy = new ArrayType(lang, fTy);
	    aTy.addDim(TS0,
                       cast(TargetSize) (16 / fTy.byteWidth));
	    ty.addField(new Variable(name,
		new Value(new FirstFieldLocation(TS16), aTy)));
	}

	void addXmmS(string name, Type fTy)
	{
	    ty.addField(new Variable(name,
		new Value(new FirstFieldLocation(fTy.byteWidth), fTy)));
	}

	addXmmS("ss", lang.floatType("float", TS4));
	addXmmS("sd", lang.floatType("double", TS8));
	addXmmP("ps", lang.floatType("float", TS4));
	addXmmP("pd", lang.floatType("double", TS8));
	addXmmP("pb", lang.integerType("uint8_t", false, TS1));
	addXmmP("pw", lang.integerType("uint16_t", false, TS2));
	addXmmP("pi", lang.integerType("uint32_t", false, TS4));
	addXmmP("psb", lang.integerType("int8_t", true, TS1));
	addXmmP("psw", lang.integerType("int16_t", true, TS2));
	addXmmP("psi", lang.integerType("int32_t", true, TS4));

	return ty;
    }

    Type mmType()
    {
	static CompoundType ty;

	if (ty)
	    return ty;
	
	auto lang = CLikeLanguage.instance;
	ty = new CompoundType(lang, "union", "mmreg_t", TS8);

	void addMmP(string name, Type fTy)
	{
	    auto aTy = new ArrayType(lang, fTy);
	    aTy.addDim(TS0,
                       cast(TargetSize) (8 / fTy.byteWidth));
	    ty.addField(new Variable(name,
		new Value(new FirstFieldLocation(TS8), aTy)));
	}

	addMmP("pb", lang.integerType("uint8_t", false, TS1));
	addMmP("pw", lang.integerType("uint16_t", false, TS2));
	addMmP("pi", lang.integerType("uint32_t", false, TS4));
	addMmP("psb", lang.integerType("int8_t", true, TS1));
	addMmP("psw", lang.integerType("int16_t", true, TS2));
	addMmP("psi", lang.integerType("int32_t", true, TS4));

	return ty;
    }
}

class X86State: MachineState
{
    /**
     * Register numbers are chosen to match GDB.
     */
    enum
    {
	EAX,
	ECX,
	EDX,
	EBX,
	ESP,
	EBP,
	ESI,
	EDI,
	EIP,
	EFLAGS,
	CS,
	SS,
	DS,
	ES,
	FS,
	GS,
	ST0,
	ST1,
	ST2,
	ST3,
	ST4,
	ST5,
	ST6,
	ST7,
	FCTRL,
	FSTAT,
	FTAG,
	FISEG,
	FIOFF,
	FOSEG,
	FOOFF,
	FOP,
	XMM0,
	XMM1,
	XMM2,
	XMM3,
	XMM4,
	XMM5,
	XMM6,
	XMM7,
	MXCSR,
	MM0,
	MM1,
	MM2,
	MM3,
	MM4,
	MM5,
	MM6,
	MM7,
    }

    /**
     * Dwarf uses different register numbers
     */
    enum
    {
	DW_EAX	= 0,
	DW_ECX	= 1,
	DW_EDX	= 2,
	DW_EBX	= 3,
	DW_ESP	= 4,
	DW_EBP	= 5,
	DW_ESI	= 6,
	DW_EDI	= 7,
	DW_EIP	= 8,
	DW_EFLAGS = 9,

	DW_ST0	= 11,
	DW_ST1	= 12,
	DW_ST2	= 13,
	DW_ST3	= 14,
	DW_ST4	= 15,
	DW_ST5	= 16,
	DW_ST6	= 17,
	DW_ST7	= 18,

	DW_XMM0	= 21,
	DW_XMM1	= 22,
	DW_XMM2	= 23,
	DW_XMM3	= 24,
	DW_XMM4	= 25,
	DW_XMM5	= 26,
	DW_XMM6	= 27,
	DW_XMM7	= 28,

	DW_MM0	= 29,
	DW_MM1	= 30,
	DW_MM2	= 31,
	DW_MM3	= 32,
	DW_MM4	= 33,
	DW_MM5	= 34,
	DW_MM6	= 35,
	DW_MM7	= 36,
    }

    static string[] RegNames = [
	"eax",
	"ecx",
	"edx",
	"ebx",
	"esp",
	"ebp",
	"esi",
	"edi",
	"eip",
	"eflags",
	"trapno",
	];

    mixin MachineRegisters MR;
    mixin DumpFloat;

    this(Target target)
    {
	initRegisters;
	target_ = target;
    }

    static this()
    {
	auto lang = CLikeLanguage.instance;
	Type intType = lang.integerType("uint32_t", false, TS4);
	Type floatType = lang.floatType("real", TS10);


	addRegister(intType, "eax");
	addRegister(intType, "ecx");
	addRegister(intType, "edx");
	addRegister(intType, "ebx");
	addRegister(intType, "esp");
	addRegister(intType, "ebp");
	addRegister(intType, "esi");
	addRegister(intType, "edi");
	addRegister(intType, "eip");
	addRegister(intType, "eflags");
	addRegister(intType, "cs");
	addRegister(intType, "ss");
	addRegister(intType, "ds");
	addRegister(intType, "es");
	addRegister(intType, "fs");
	addRegister(intType, "gs");
	addRegister(floatType, "st0", false);
	addRegister(floatType, "st1", false);
	addRegister(floatType, "st2", false);
	addRegister(floatType, "st3", false);
	addRegister(floatType, "st4", false);
	addRegister(floatType, "st5", false);
	addRegister(floatType, "st6", false);
	addRegister(floatType, "st7", false);
	addRegister(intType, "fctrl");
	addRegister(intType, "fstat");
	addRegister(intType, "ftag");
	addRegister(intType, "fiseg");
	addRegister(intType, "fioff");
	addRegister(intType, "foseg");
	addRegister(intType, "fooff");
	addRegister(intType, "fop");
	addRegister(xmmType, "xmm0");
	addRegister(xmmType, "xmm1");
	addRegister(xmmType, "xmm2");
	addRegister(xmmType, "xmm3");
	addRegister(xmmType, "xmm4");
	addRegister(xmmType, "xmm5");
	addRegister(xmmType, "xmm6");
	addRegister(xmmType, "xmm7");
	addRegister(intType, "mxcsr");
	addRegisterAlias(intType, "pc", EIP);
	addRegisterAlias(mmType, "mm0", ST0);
	addRegisterAlias(mmType, "mm1", ST1);
	addRegisterAlias(mmType, "mm2", ST2);
	addRegisterAlias(mmType, "mm3", ST3);
	addRegisterAlias(mmType, "mm4", ST4);
	addRegisterAlias(mmType, "mm5", ST5);
	addRegisterAlias(mmType, "mm6", ST6);
	addRegisterAlias(mmType, "mm7", ST7);
    }

    override {
	void dumpState()
	{
	    for (auto i = 0; i <= EFLAGS; i++) {
		uint32_t val = readIntRegister(i);
		writef("%6s:%08x ", RegNames[i], val);
		if ((i & 3) == 3)
		    writefln("");
	    }
	    writef("%6s:%08x ", "cs", readIntRegister(CS));
	    writefln("%6s:%08x ", "ss", readIntRegister(SS));
	    writef("%6s:%08x ", "ds", readIntRegister(DS));
	    writef("%6s:%08x ", "es", readIntRegister(ES));
	    writef("%6s:%08x ", "fs", readIntRegister(FS));
	    writefln("%6s:%08x ", "gs", readIntRegister(GS));
	}

	TargetAddress pc()
	{
	    return cast(TargetAddress) readIntRegister(EIP);
	}

	void pc(TargetAddress pc)
	{
	    writeIntRegister(EIP, cast(MachineRegister) pc);
	}

	TargetAddress tp()
	{
	    return cast(TargetAddress) tp_;
	}

	TargetAddress tls_get_addr(uint index, ulong offset)
	{
	    if (!tp_)
		return cast(TargetAddress) 0;
	    ulong dtv = readInteger(readMemory(cast(TargetAddress) (tp_ + 4),
                                               TS4));
	    ulong base = readInteger(readMemory(cast(TargetAddress) (dtv + 4 + 4*index),
                                                TS4));
	    return cast(TargetAddress) (base + offset);
	}

	void ptraceReadState(Ptrace pt)
	{
	    version (FreeBSD) {
		ubyte[reg32.sizeof] regs;
		pt.ptrace(PT_GETREGS, regs.ptr, 0);
		setGRs(regs.ptr);

		ubyte[xmmreg32.sizeof] fpregs;
		pt.ptrace(PT_GETXMMREGS, fpregs.ptr, 0);
		setFRs(fpregs.ptr);

		pt.ptrace(PT_GETGSBASE, cast(ubyte*) &tp_, 0);
	    }
	    version (linux) {
		ubyte[reg32.sizeof] regs;
		pt.ptrace(PT_GETREGS, regs.ptr, 0);
		setGRs(regs.ptr);
	    }
	    foreach (ref d; dirty_)
		d = false;
	}

	void ptraceWriteState(Ptrace pt)
	{
	    bool grdirty = false;
	    bool frdirty = false;
	    foreach (regno, ref d; dirty_) {
		if (d) {
		    if (regno < ST0)
			grdirty = true;
		    else
			frdirty = true;
		    d = false;
		}
	    }
	    version (FreeBSD) {
		if (grdirty) {
		    ubyte[reg32.sizeof] regs;
		    getGRs(regs.ptr);
		    pt.ptrace(PT_SETREGS, regs.ptr, 0);
		}
		if (frdirty) {
		    ubyte[xmmreg32.sizeof] fpregs;
		    getFRs(fpregs.ptr);
		    //pt.ptrace(PT_SETXMMREGS, fpregs.ptr, 0);
		}
	    }
	    version (linux) {
		if (grdirty) {
		    ubyte[reg32.sizeof] regs;
		    getGRs(regs.ptr);
		    pt.ptrace(PT_SETREGS, regs.ptr, 0);
		}
		if (frdirty) {
		    ubyte[xmmreg32.sizeof] fpregs;
		    getFRs(fpregs.ptr);
		    pt.ptrace(PT_SETXMMREGS, fpregs.ptr, 0);
		}
	    }
	}

	void setGRs(ubyte* p)
	{
	    foreach (i, off; regmap_)
		writeRegister(i, p[off..off+4]);
	}

	void getGRs(ubyte* p)
	{
	    foreach (i, off; regmap_)
		p[off..off+4] = readRegister(i, TS4);
	}

	uint spregno()
	{
	    return 4;
	}

	MachineState dup()
	{
	    X86State newState = new X86State(target_);
	    newState.bytes_[] = bytes_[];
	    newState.tp_ = tp_;
	    return newState;
	}

	void setFRs(ubyte* regs)
	{
	    xmmreg32* f = cast(xmmreg32*) regs;
	    
	    writeIntRegister(FCTRL, f.xmm_env[0] & 0xffff);
	    writeIntRegister(FSTAT, f.xmm_env[0] >> 16);
	    writeIntRegister(FTAG, f.xmm_env[1] & 0xffff);
	    writeIntRegister(FOP, (f.xmm_env[1] >> 16) & 0x7ff);
	    writeIntRegister(FIOFF, f.xmm_env[2]);
	    writeIntRegister(FISEG, f.xmm_env[3] & 0xffff);
	    writeIntRegister(FOOFF, f.xmm_env[4]);
	    writeIntRegister(FOSEG, f.xmm_env[5] & 0xffff);
	    writeIntRegister(MXCSR, f.xmm_env[6]);

	    for (uint i = 0; i < 8; i++) {
		writeRegister(ST0 + i, f.xmm_acc[i][0..10]);
		writeRegister(XMM0 + i, f.xmm_reg[i][0..16]);
	    }
	}

	void getFRs(ubyte* regs)
	{
	    xmmreg32* f = cast(xmmreg32*) regs;

	    f.xmm_env[0] = readIntRegister(FCTRL)
		+ (readIntRegister(FSTAT) << 16);
	    f.xmm_env[1] = readIntRegister(FTAG)
		+ ((readIntRegister(FOP) & 0x7ff) << 16);
	    f.xmm_env[2] = readIntRegister(FIOFF);
	    f.xmm_env[3] = readIntRegister(FISEG);
	    f.xmm_env[4] = readIntRegister(FOOFF);
	    f.xmm_env[5] = readIntRegister(FOSEG);
	    f.xmm_env[6] = readIntRegister(MXCSR);
	    for (uint i = 0; i < 8; i++) {
		f.xmm_acc[i][0..10] = readRegister(ST0 + i, TS10);
		f.xmm_reg[i][0..16] = readRegister(XMM0 + i, TS16);
	    }
	}

	uint mapDwarfRegno(uint dwregno)
	{
	    if (dwregno <= DW_EFLAGS)
		return dwregno;
	    if (dwregno >= DW_ST0 && dwregno < DW_ST7)
		return dwregno - DW_ST0 + ST0;
	    if (dwregno >= DW_XMM0 && dwregno < DW_XMM7)
		return dwregno - DW_XMM0 + XMM0;
	    if (dwregno >= DW_MM0 && dwregno < DW_MM7)
		return dwregno - DW_MM0 + MM0;
	    assert(false);
	}

	ubyte[] breakpoint()
	{
	    static ubyte[] inst = [ 0xcc ];
	    return inst;
	}

	void adjustPcAfterBreak()
	{
	    writeIntRegister(EIP, readIntRegister(EIP) - 1);
	}

	TargetSize pointerWidth()
	{
            return cast(TargetSize)  4;
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
	    case 10:
	    case 12:
	    case 16:
		version (nativeFloat80) {
		    return *cast(real*) &bytes[0];
		} else {
		    ulong frac = readInteger(bytes[0..8]);
		    ushort exp = readInteger(bytes[8..10]);
		    real sign = 1;
		    if (exp & 0x8000) {
			sign = -1;
			exp &= 0x7fff;
		    }
		    return sign * ldexp(cast(real) frac / cast(real) ~0UL,
					cast(int) exp - 16382);
		}
		break;
	    default:
		assert(false);
	    }
	}

	void writeFloat(real val, ubyte[] bytes)
	{
	    float32 f32;
	    float64 f64;
	    switch (bytes.length) {
	    case 4:
		f32.f = val;
		writeInteger(f32.i, bytes);
		break;
	    case 8:
		f64.f = val;
		writeInteger(f64.i, bytes);
		break;
	    case 10:
	    case 12:
	    case 16:
		version (nativeFloat80) {
		    int sign = 0;
		    if (val < 0) {
			sign = 0x8000;
			val = -val;
		    }
		    int exp;
		    ulong frac = cast(ulong)
			(frexp(val, exp) * cast(real) ~0UL);
		    writeInteger(frac, bytes[0..8]);
		    writeInteger(exp + 16382 + sign, bytes[8..10]);
		} else {
		    assert(false);
		}
		break;
	    default:
		assert(false);
	    }
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
	    X86State saveState = new X86State(target_);
	    saveState.bytes_[] = bytes_[];

	    /*
	     * If the return value is a structure, reserve some space
	     * on the stack and add a hidden first argument to point
	     * at it.
	     */
	    auto cTy = cast(CompoundType) returnType;
	    version (FreeBSD)
		auto regStructSize = 8;
	    version (linux)
		auto regStructSize = 0;
	    if (cTy && cTy.byteWidth > regStructSize) {
		MachineRegister esp = readIntRegister(ESP);
		esp -= cTy.byteWidth;
		writeIntRegister(ESP, esp);
		ubyte[4] v;
		writeInteger(esp, v);
		args = new Value(new ConstantLocation(v),
				 registerType(EAX)) ~ args;
	    }

	    ubyte[] argval;
	    foreach(arg; args) {
		if (arg.type.isIntegerType) {
		    /*
		     * Pad small integers
		     */
		    auto val = arg.loc.readValue(this);
		    if (val.length < 4) {
			static ubyte[4] zeros;
			val ~= zeros[0..4-val.length];
		    }
		    argval ~= val; 
		} else {
		    auto val = arg.loc.readValue(this);
		    argval ~= val;
		}
	    }

	    /*
	     * Allocate the new stack frame including space for the
	     * return address and arguments. We arrange things so that
	     * ebp will be aligned to a 16-byte boundard after the
	     * called function executes its prologue.
	     */
	    MachineRegister esp = readIntRegister(ESP);
	    auto newFrame = esp - (argval.length + 8);
	    newFrame &= ~15;
	    writeIntRegister(ESP, newFrame + 4);

	    /*
	     * Put arguments on the stack. Possibly we should keep the
	     * stack 16-byte aligned here.
	     */
	    if (argval.length > 0)
		writeMemory(cast(TargetAddress) (newFrame + 8), argval);

	    static class callBreakpoint: TargetBreakpointListener
	    {
		bool onBreakpoint(Target, TargetThread)
		{
		    callBpHit_ = true;
		    return true;
		}
		bool callBpHit_ = false;
	    }

	    /*
	     * Write the return address. We arrange for the function to
	     * return to _start and we set a breakpoint there to catch
	     * it.
	     */
	    ubyte[4] ret;
	    writeInteger(target_.entry, ret);
	    writeMemory(cast(TargetAddress) (newFrame + 4), ret);
	    auto bpl = new callBreakpoint;
	    target_.setBreakpoint(target_.entry, bpl);

	    /*
	     * Set the thing running at the start of the function.
	     */
	    writeIntRegister(EIP, cast(MachineRegister) address);
	    target_.cont(0);
	    target_.wait;

	    target_.clearBreakpoint(bpl);

	    if (!bpl.callBpHit_)
		throw new EvalException(
		    "Function call terminated unexpectedly");

	    /*
	     * Get the return value first then restore the machine state.
	     */
	    Value retval;
	    try {
		retval = returnValue(returnType);
	    } catch (EvalException e) {
		bytes_[] = saveState.bytes_[];
		foreach (ref d; dirty_)
		    d = false;
		throw e;
	    }

	    bytes_[] = saveState.bytes_[];
	    foreach (ref d; dirty_)
		d = false;

	    return retval;
	}

	Value returnValue(Type returnType)
	{
	    ubyte[] retval;
	    auto cTy = cast(CompoundType) returnType;
	    version (FreeBSD)
		auto regStructSize = 8;
	    version (linux)
		auto regStructSize = 0;
	    if (cTy && cTy.byteWidth > regStructSize) {
		auto eax = readIntRegister(EAX);
		retval = readMemory(cast(TargetAddress) eax,
                                    cTy.byteWidth);
	    } else if (returnType.isNumericType && !returnType.isIntegerType) {
		retval = readRegister(ST0, returnType.byteWidth);
	    } else if (returnType.byteWidth <= 4) {
		retval = readRegister(EAX, returnType.byteWidth);
	    } else if (returnType.byteWidth <= 8) {
		retval = readRegister(EAX, TS4)
		    ~ readRegister(EDX,
                                   cast(TargetSize) (returnType.byteWidth - 4));
	    } else
		throw new EvalException(
		    "Can't read return value for function call");

	    return new Value(new ConstantLocation(retval), returnType);
	}

	FDE parsePrologue(TargetAddress func)
	{
	    /*
	     * We will create unwind records which use a frame address
	     * pointing at the first stack byte after the return
	     * address.
	     *
	     * First make a CIE describing the stack frame at the
	     * beginning of the function. The CFA value is ESP+4 and
	     * the saved EIP value is located at CFA-4.
	     */
	    char[] cieIns;
	    cieIns ~= [ DW_CFA_def_cfa, 4, 4,
	    		DW_CFA_offset + 8, 1 ];
	    auto cie = new CIE;
	    cie.codeAlign = 1;
	    cie.dataAlign = -4;
	    cie.returnAddress = 8;
	    cie.instructionStart = cieIns.ptr;
	    cie.instructionEnd = cieIns.ptr + cieIns.length;

	    /*
	     * Look for something like this:
	     *
	     *		push ebp
	     *		mov ebp,esp
	     *		sub esp,<framesize>
	     *		push <reg>
	     *		...
	     */
	    ubyte[] prologue = readMemory(func, 32);
	    uint i;
	    char[] fdeIns;
	    uint off;		// offset from ESP to frame address
	    uint cfa;		// current CFA register
	    uint cfaOff;	// offset from CFA reg to frame address
	    /*
	     * 55	push ebp
	     */
	    i = 0;
	    off = 4;
	    cfa = 4;
	    cfaOff = 4;
	    for (;;) {
		//writefln("%02x: CFA at r%d+%d (ESP+%d)", prologue[i], cfa, cfaOff, off);
		/*
		 * 5N	push <reg N>
		 */
		if ((prologue[i] & 0xf8) == 0x50) {
		    /*
		     * After the push, PC advances by one, reg is at CFA-off
		     * If the CFA is still based on ESP, adjust the CFA
		     * offset.
		     */
		    auto reg = prologue[i] & 0x07;
		    off += 4;
		    fdeIns ~= [ DW_CFA_advance_loc + 1,
				DW_CFA_offset + reg, off / 4 ];
		    if (cfa == 4) {
			fdeIns ~= [ DW_CFA_def_cfa_offset, off ];
			cfaOff = off;
		    }
		    i += 1;
		    continue;
		}
		/*
		 * 89 e5	mov ebp,esp
		 */
		if (prologue[i] == 0x8b && prologue[i+1] == 0xec) {
		    /*
		     * After the move, PC advances by two, CFA register
		     * changes to EBP.
		     */
		    fdeIns ~= [ DW_CFA_advance_loc + 2,
				DW_CFA_def_cfa_register, 5 ];
		    cfa = 5;
		    i += 2;
		    continue;
		}
		/*
		 * 83 ec NN	sub esp,NN
		 */
		if (prologue[i] == 0x83 && prologue[i+1] == 0xec) {
		    /*
		     * After the subtract, PC advances by 3.
		     */
		    off += prologue[i+2];
		    i += 3;
		    continue;
		}
		break;
	    }
	    auto fde = new FDE;
	    fde.cie = cie;
	    fde.initialLocation = func;
	    fde.instructionStart = fdeIns.ptr;
	    fde.instructionEnd = fdeIns.ptr + fdeIns.length;
	    return fde;
	}

	TargetAddress findFlowControl(TargetAddress start, TargetAddress end)
	{
	    char readByte(TargetAddress loc) {
		ubyte[] t = readMemory(loc, TS1);
		return cast(char) t[0];
	    }

	    Disassembler dis = new Disassembler;
	    TargetAddress loc = start;
	    while (loc < end) {
		TargetAddress tloc = loc;
		if (dis.isFlowControl(loc, &readByte))
		    return tloc;
	    }
	    return end;
	}

	TargetAddress findJump(TargetAddress start, TargetAddress end)
	{
	    char readByte(TargetAddress loc) {
		ubyte[] t = readMemory(loc, TS1);
		return cast(char) t[0];
	    }

	    Disassembler dis = new Disassembler;
	    TargetAddress loc = start;
	    while (loc < end) {
		TargetAddress tloc = loc;
		TargetAddress target;
		if (dis.isJump(loc, target, &readByte))
		    return target;
	    }
	    return end;
	}

	string disassemble(ref TargetAddress address,
			   string delegate(TargetAddress) lookupAddress)
	{
	    char readByte(TargetAddress loc) {
		ubyte[] t = readMemory(loc, TS1);
		return cast(char) t[0];
	    }

	    Disassembler dis = new Disassembler;
	    dis.setOption("intel");
	    return dis.disassemble(address, &readByte, lookupAddress);
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
    version (FreeBSD) {
	static uint[] regmap_ = [
	    reg32.r_eax.offsetof,	// EAX
	    reg32.r_ecx.offsetof,	// ECX
	    reg32.r_edx.offsetof,	// EDX
	    reg32.r_ebx.offsetof,	// EBX
	    reg32.r_esp.offsetof,	// ESP
	    reg32.r_ebp.offsetof,	// EBP
	    reg32.r_esi.offsetof,	// ESI
	    reg32.r_edi.offsetof,	// EDI
	    reg32.r_eip.offsetof,	// EIP
	    reg32.r_eflags.offsetof,	// EFLAGS
	    reg32.r_cs.offsetof,	// CS
	    reg32.r_ss.offsetof,	// SS
	    reg32.r_ds.offsetof,	// DS
	    reg32.r_es.offsetof,	// ES
	    reg32.r_fs.offsetof,	// FS
	    reg32.r_gs.offsetof,	// GS
	    ];
    }
    version (linux) {
	static uint[] regmap_ = [
	    reg32.r_eax.offsetof,	// EAX
	    reg32.r_ecx.offsetof,	// ECX
	    reg32.r_edx.offsetof,	// EDX
	    reg32.r_ebx.offsetof,	// EBX
	    reg32.r_esp.offsetof,	// ESP
	    reg32.r_ebp.offsetof,	// EBP
	    reg32.r_esi.offsetof,	// ESI
	    reg32.r_edi.offsetof,	// EDI
	    reg32.r_eip.offsetof,	// EIP
	    reg32.r_eflags.offsetof,	// EFLAGS
	    reg32.r_orig_eax.offsetof,	// TRAPNO (??)
	    ];
    }
    Target	target_;
    uint32_t	tp_;
}

class X86_64State: MachineState
{
    enum
    {
	DW_RAX	= 0,
	DW_RDX	= 1,
	DW_RCX	= 2,
	DW_RBX	= 3,
	DW_RSI	= 4,
	DW_RDI	= 5,
	DW_RBP	= 6,
	DW_RSP	= 7,
	DW_R8	= 8,
	DW_R9	= 9,
	DW_R10	= 10,
	DW_R11	= 11,
	DW_R12	= 12,
	DW_R13	= 13,
	DW_R14	= 14,
	DW_R15	= 15,
	DW_RIP	= 16,

	DW_XMM0	= 17,
	DW_XMM1	= 18,
	DW_XMM2	= 19,
	DW_XMM3	= 20,
	DW_XMM4	= 21,
	DW_XMM5	= 22,
	DW_XMM6	= 23,
	DW_XMM7	= 24,
	DW_XMM8	= 25,
	DW_XMM9	= 26,
	DW_XMM10 = 27,
	DW_XMM11 = 28,
	DW_XMM12 = 29,
	DW_XMM13 = 30,
	DW_XMM14 = 31,
	DW_XMM15 = 32,

	DW_ST0	= 33,
	DW_ST1	= 34,
	DW_ST2	= 35,
	DW_ST3	= 36,
	DW_ST4	= 37,
	DW_ST5	= 38,
	DW_ST6	= 39,
	DW_ST7	= 40,

	DW_MM0	= 41,
	DW_MM1	= 42,
	DW_MM2	= 43,
	DW_MM3	= 44,
	DW_MM4	= 45,
	DW_MM5	= 46,
	DW_MM6	= 47,
	DW_MM7	= 48,

	DW_RFLAGS = 49,
	DW_CS	= 50,
	DW_SS	= 51,
	DW_DS	= 52,
	DW_ES	= 53,
	DW_FS	= 54,
	DW_GS	= 55,

	DW_FSBASE = 58,
	DW_GSBASE = 59,

	DW_TR	= 62,
	DW_LDTR	= 63,
	DW_MXCSR = 64,
	DW_FCW	= 65,
	DW_FSW	= 66,
    }

    enum
    {
	RAX,
	RDX,
	RCX,
	RBX,
	RSI,
	RDI,
	RBP,
	RSP,
	R8,
	R9,
	R10,
	R11,
	R12,
	R13,
	R14,
	R15,
	RIP,
	EFLAGS,
	CS,
	SS,
	DS,
	ES,
	FS,
	GS,
	ST0,
	ST1,
	ST2,
	ST3,
	ST4,
	ST5,
	ST6,
	ST7,
	FCTRL,
	FSTAT,
	FTAG,
	FISEG,
	FIOFF,
	FOSEG,
	FOOFF,
	FOP,
	XMM0,
	XMM1,
	XMM2,
	XMM3,
	XMM4,
	XMM5,
	XMM6,
	XMM7,
	XMM8,
	XMM9,
	XMM10,
	XMM11,
	XMM12,
	XMM13,
	XMM14,
	XMM15,
	MXCSR,
	MM0,
	MM1,
	MM2,
	MM3,
	MM4,
	MM5,
	MM6,
	MM7,
    }

    static  string[] RegNames = [
	"rax",
	"rdx",
	"rcx",
	"rbx",
	"rsi",
	"rdi",
	"rbp",
	"rsp",
	"r8",
	"r9",
	"r10",
	"r11",
	"r12",
	"r13",
	"r14",
	"r15",
	"rip",
	];

    mixin MachineRegisters MR;
    mixin DumpFloat;

    this(Target target)
    {
	initRegisters;
	target_ = target;
    }

    static this()
    {
	auto lang = CLikeLanguage.instance;
	Type int4Type = lang.integerType("uint32_t", false, TS4);
	Type int8Type = lang.integerType("uint64_t", false, TS8);
	Type floatType = lang.floatType("real", TS10);

	addRegister(int8Type, "rax");
	addRegister(int8Type, "rbx");
	addRegister(int8Type, "rcx");
	addRegister(int8Type, "rdx");
	addRegister(int8Type, "rsi");
	addRegister(int8Type, "rdi");
	addRegister(int8Type, "rbp");
	addRegister(int8Type, "rsp");
	addRegister(int8Type, "r8");
	addRegister(int8Type, "r9");
	addRegister(int8Type, "r10");
	addRegister(int8Type, "r11");
	addRegister(int8Type, "r12");
	addRegister(int8Type, "r13");
	addRegister(int8Type, "r14");
	addRegister(int8Type, "r15");
	addRegister(int8Type, "rip");
	addRegister(int4Type, "eflags");
	addRegister(int4Type, "cs");
	addRegister(int4Type, "ss");
	addRegister(int4Type, "ds");
	addRegister(int4Type, "es");
	addRegister(int4Type, "fs");
	addRegister(int4Type, "gs");
	addRegister(floatType, "st0", false);
	addRegister(floatType, "st1", false);
	addRegister(floatType, "st2", false);
	addRegister(floatType, "st3", false);
	addRegister(floatType, "st4", false);
	addRegister(floatType, "st5", false);
	addRegister(floatType, "st6", false);
	addRegister(floatType, "st7", false);
	addRegister(int4Type, "fctrl");
	addRegister(int4Type, "fstat");
	addRegister(int4Type, "ftag");
	addRegister(int4Type, "fiseg");
	addRegister(int4Type, "fioff");
	addRegister(int4Type, "foseg");
	addRegister(int4Type, "fooff");
	addRegister(int4Type, "fop");
	addRegister(xmmType, "xmm0");
	addRegister(xmmType, "xmm1");
	addRegister(xmmType, "xmm2");
	addRegister(xmmType, "xmm3");
	addRegister(xmmType, "xmm4");
	addRegister(xmmType, "xmm5");
	addRegister(xmmType, "xmm6");
	addRegister(xmmType, "xmm7");
	addRegister(xmmType, "xmm8");
	addRegister(xmmType, "xmm9");
	addRegister(xmmType, "xmm10");
	addRegister(xmmType, "xmm11");
	addRegister(xmmType, "xmm12");
	addRegister(xmmType, "xmm13");
	addRegister(xmmType, "xmm14");
	addRegister(xmmType, "xmm15");
	addRegister(int4Type, "mxcsr");
	addRegisterAlias(int8Type, "pc", RIP);
	addRegisterAlias(mmType, "mm0", ST0);
	addRegisterAlias(mmType, "mm1", ST1);
	addRegisterAlias(mmType, "mm2", ST2);
	addRegisterAlias(mmType, "mm3", ST3);
	addRegisterAlias(mmType, "mm4", ST4);
	addRegisterAlias(mmType, "mm5", ST5);
	addRegisterAlias(mmType, "mm6", ST6);
	addRegisterAlias(mmType, "mm7", ST7);
    }

    override {
	void dumpState()
	{
	    for (auto i = 0; i <= RIP; i++) {
		uint64_t val = readIntRegister(i);
		writef("%6s:%016x ", RegNames[i], val);
		if ((i & 1) == 1)
		    writefln("");
	    }
	    writefln("%6s:%016x ", "rflags", readIntRegister(EFLAGS));
	    writefln("    cs:%04x ss:%04x ds:%04x es:%04x gs:%04x fs:%04x",
		     readIntRegister(CS),
		     readIntRegister(SS),
		     readIntRegister(DS),
		     readIntRegister(ES),
		     readIntRegister(FS),
		     readIntRegister(GS));
	}

	TargetAddress pc()
	{
	    return cast(TargetAddress) readIntRegister(RIP);
	}

	void pc(TargetAddress pc)
	{
	    writeIntRegister(RIP, pc);
	}

	TargetAddress tp()
	{
	    return cast(TargetAddress) tp_;
	}

	TargetAddress tls_get_addr(uint index, ulong offset)
	{
	    if (!tp_)
		return cast(TargetAddress) 0;
	    ulong dtv = readInteger(readMemory(cast(TargetAddress) (tp_ + 8),
                                               TS8));
	    ulong base = readInteger( readMemory(cast(TargetAddress) (dtv + 8 + 8*index),
                                                 TS8));
	    return cast(TargetAddress) (base + offset);
	}

	void ptraceReadState(Ptrace pt)
	{
	    version (FreeBSD) {
		ubyte[reg64.sizeof] regs;
		pt.ptrace(PT_GETREGS, regs.ptr, 0);
		setGRs(regs.ptr);

		ubyte[xmmreg64.sizeof] fpregs;
		pt.ptrace(PT_GETFPREGS, fpregs.ptr, 0);
		setFRs(fpregs.ptr);

		pt.ptrace(PT_GETGSBASE, cast(ubyte*) &tp_, 0);
	    }
	    version (linux) {
		ubyte[reg64.sizeof] regs;
		pt.ptrace(PT_GETREGS, regs.ptr, 0);
		setGRs(regs.ptr);
	    }
	    foreach (ref d; dirty_)
		d = false;
	}

	void ptraceWriteState(Ptrace pt)
	{
	    bool grdirty = false;
	    bool frdirty = false;
	    foreach (regno, ref d; dirty_) {
		if (d) {
		    if (regno < ST0)
			grdirty = true;
		    else
			frdirty = true;
		    d = false;
		}
	    }
	    version (FreeBSD) {
		if (grdirty) {
		    ubyte[reg64.sizeof] regs;
		    getGRs(regs.ptr);
		    pt.ptrace(PT_SETREGS, regs.ptr, 0);
		}
		if (frdirty) {
		    ubyte[xmmreg64.sizeof] fpregs;
		    getFRs(fpregs.ptr);
		    pt.ptrace(PT_SETFPREGS, fpregs.ptr, 0);
		}
	    }
	    version (linux) {
		if (grdirty) {
		    ubyte[reg64.sizeof] regs;
		    getGRs(regs.ptr);
		    pt.ptrace(PT_SETREGS, regs.ptr, 0);
		}
		if (frdirty) {
		    ubyte[xmmreg64.sizeof] fpregs;
		    getFRs(fpregs.ptr);
		    //pt.ptrace(PT_SETXMMREGS, fpregs.ptr, 0);
		}
	    }
	}

	void setGRs(ubyte* p)
	{
	    foreach (i, off; regmap_)
		writeRegister(i, p[off..off+8]);
	}

	void getGRs(ubyte* p)
	{
	    foreach (i, off; regmap_)
		p[off..off+8] = readRegister(i, TS8);
	}

	uint spregno()
	{
	    return 7;
	}

	MachineState dup()
	{
	    X86_64State newState = new X86_64State(target_);
	    newState.bytes_[] = bytes_[];
	    newState.tp_ = tp_;
	    return newState;
	}

	void setFRs(ubyte* regs)
	{
	    xmmreg64* f = cast(xmmreg64*) regs;
	    
	    writeIntRegister(FCTRL, f.xmm_env[0] & 0xffff);
	    writeIntRegister(FSTAT, f.xmm_env[0] >> 16);
	    writeIntRegister(FTAG, f.xmm_env[1] & 0xffff);
	    writeIntRegister(FOP, (f.xmm_env[1] >> 16) & 0x7ff);
	    writeIntRegister(FIOFF, f.xmm_env[2]);
	    writeIntRegister(FISEG, f.xmm_env[3] & 0xffff);
	    writeIntRegister(FOOFF, f.xmm_env[4]);
	    writeIntRegister(FOSEG, f.xmm_env[5] & 0xffff);
	    writeIntRegister(MXCSR, f.xmm_env[6]);

	    for (uint i = 0; i < 8; i++)
		writeRegister(ST0 + i, f.xmm_acc[i][0..10]);
	    for (uint i = 0; i < 16; i++)
		writeRegister(XMM0 + i, f.xmm_reg[i][0..16]);
	}

	void getFRs(ubyte* regs)
	{
	    xmmreg64* f = cast(xmmreg64*) regs;

	    f.xmm_env[0] = readIntRegister(FCTRL)
		+ (readIntRegister(FSTAT) << 16);
	    f.xmm_env[1] = readIntRegister(FTAG)
		+ ((readIntRegister(FOP) & 0x7ff) << 16);
	    f.xmm_env[2] = readIntRegister(FIOFF);
	    f.xmm_env[3] = readIntRegister(FISEG);
	    f.xmm_env[4] = readIntRegister(FOOFF);
	    f.xmm_env[5] = readIntRegister(FOSEG);
	    f.xmm_env[6] = readIntRegister(MXCSR);
	    for (uint i = 0; i < 8; i++)
		f.xmm_acc[i][0..10] = readRegister(ST0 + i, TS10);
	    for (uint i = 0; i < 16; i++)
		f.xmm_reg[i][0..16] = readRegister(XMM0 + i, TS16);
	}

	uint mapDwarfRegno(uint dwregno)
	{
	    assert(false);
	}

	ubyte[] breakpoint()
	{
	    static ubyte[] inst = [ 0xcc ];
	    return inst;
	}

	void adjustPcAfterBreak()
	{
	    writeIntRegister(RIP, readIntRegister(RIP) - 1);
	}

	TargetSize pointerWidth()
	{
	    return TS8;
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
	    case 10:
	    case 12:
	    case 16:
		version (nativeFloat80) {
		    return *cast(real*) &bytes[0];
		} else {
		    ulong frac = readInteger(bytes[0..8]);
		    ushort exp = readInteger(bytes[8..10]);
		    real sign = 1;
		    if (exp & 0x8000) {
			sign = -1;
			exp &= 0x7fff;
		    }
		    return sign * ldexp(cast(real) frac / cast(real) ~0UL,
					cast(int) exp - 16382);
		}
		break;
	    default:
		assert(false);
	    }
	}

	void writeFloat(real val, ubyte[] bytes)
	{
	    float32 f32;
	    float64 f64;
	    switch (bytes.length) {
	    case 4:
		f32.f = val;
		writeInteger(f32.i, bytes);
		break;
	    case 8:
		f64.f = val;
		writeInteger(f64.i, bytes);
		break;
	    case 10:
	    case 12:
	    case 16:
		version (nativeFloat80) {
		    int sign = 0;
		    if (val < 0) {
			sign = 0x8000;
			val = -val;
		    }
		    int exp;
		    ulong frac = cast(ulong)
			(frexp(val, exp) * cast(real) ~0UL);
		    writeInteger(frac, bytes[0..8]);
		    writeInteger(exp + 16382 + sign, bytes[8..10]);
		} else {
		    assert(false);
		}
		break;
	    default:
		assert(false);
	    }
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
	    X86_64State saveState = new X86_64State(target_);
	    saveState.bytes_[] = bytes_[];

	    /*
	     * If the return value is a structure, reserve some space
	     * on the stack and add a hidden first argument to point
	     * at it.
	     */
	    auto retcls = classify(returnType);
	    if (retcls[0] == MEMORY) {
		MachineRegister rsp = readIntRegister(RSP);
		rsp -= 8 * retcls.length;
		writeIntRegister(RSP, rsp);
		ubyte[8] v;
		writeInteger(rsp, v);
		args = new Value(new ConstantLocation(v),
				 registerType(RAX)) ~ args;
	    }

	    /*
	     * Classify the arguments and divide the values into
	     * eightbyte pieces.
	     */
	    alias ubyte[8] eightbyte;
	    int[] argclass;
	    eightbyte[] argval;
	    argclass.length = args.length;
	    argval.length = args.length;
	    int j = 0;
	    foreach(i, arg; args) {
		static ubyte[8] zeros;
		auto val = arg.loc.readValue(this);
		if (val.length & 7)
		    val ~= zeros[0..8-(val.length & 7)];
		auto cls = classify(arg.type);
		debug (call) {
		    writefln("val.length = %d", val.length);
		    foreach (ci, cl; cls)
			writefln("class %d = %d", ci, cl);
		}
		if (cls.length != val.length / 8)
		    throw new EvalException("Can't classify arguments");
		while (val.length > 0) {
		    eightbyte piece = val[0..8];
		    argclass ~= cls[0];
		    argval ~= piece;
		    cls = cls[1..$];
		    val = val[8..$];
		    j++;
		}
	    }

	    /*
	     * Now assign the pieces to their correct places.
	     */
	    static auto intregs = [RDI, RSI, RDX, RCX, R8, R9];
	    int intreg = 0;
	    static auto sseregs = [XMM0, XMM1, XMM2, XMM3,
				   XMM4, XMM5, XMM7, XMM7];
	    int ssereg = 0;
	    ubyte[] memargs;

	    foreach (i, ac; argclass) {
		if (ac == MEMORY)
		    memargs ~= argval[i];
		else if (ac == INTEGER) {
		    if (intreg < intregs.length)
			writeRegister(intregs[intreg++], argval[i]);
		    else
			memargs ~= argval[i];
		} else if (ac == SSE) {
		    if (ssereg < sseregs.length)
			writeRegister(sseregs[ssereg++], argval[i]);
		    else
			memargs ~= argval[i];
		} else if (ac == SSEUP) {
		    if (ssereg == 0)
			memargs ~= argval[i];
		    else {
			auto v = readRegister(sseregs[ssereg - 1],
                                              TS8);
			v ~= argval[i];
			writeRegister(sseregs[ssereg - 1], v);
		    }
		} else {
		    memargs ~= argval[i];
		}
	    }

	    /*
	     * Allocate the new stack frame including space for the
	     * return address and arguments. We arrange things so that
	     * rbp will be aligned to a 16-byte boundard after the
	     * called function executes its prologue. We also make
	     * sure we avoid the red zone of the current function.
	     */
	    MachineRegister rsp = readIntRegister(RSP);
	    auto newFrame = rsp - 128 - (memargs.length + 16);
	    newFrame &= ~15;
	    writeIntRegister(RSP, newFrame + 8);

	    /*
	     * Put arguments on the stack. Possibly we should keep the
	     * stack 16-byte aligned here.
	     */
	    if (memargs.length > 0)
		writeMemory(cast(TargetAddress) (newFrame + 16), memargs);

	    static class callBreakpoint: TargetBreakpointListener
	    {
		bool onBreakpoint(Target, TargetThread)
		{
		    callBpHit_ = true;
		    return true;
		}
		bool callBpHit_ = false;
	    }

	    /*
	     * Write the return address. We arrange for the function to
	     * return to _start and we set a breakpoint there to catch
	     * it.
	     */
	    ubyte[8] ret;
	    writeInteger(target_.entry, ret);
	    writeMemory(cast(TargetAddress) (newFrame + 8), ret);
	    auto bpl = new callBreakpoint;
	    target_.setBreakpoint(target_.entry, bpl);

	    /*
	     * Set the thing running at the start of the function.
	     */
	    writeIntRegister(RIP, address);
	    target_.cont(0);
	    target_.wait;

	    target_.clearBreakpoint(bpl);

	    if (!bpl.callBpHit_)
		throw new EvalException(
		    "Function call terminated unexpectedly");

	    /*
	     * Get the return value first then restore the machine state.
	     */
	    Value retval;
	    try {
		retval = returnValue(returnType);
	    } catch (EvalException e) {
		bytes_[] = saveState.bytes_[];
		foreach (ref d; dirty_)
		    d = true;
		throw e;
	    }

	    bytes_[] = saveState.bytes_[];
	    foreach (ref d; dirty_)
		d = true;

	    return retval;
	}

	Value returnValue(Type returnType)
	{
	    auto retcls = classify(returnType);
	    ubyte[] retval;
	    int intreg = 0;
	    int ssereg = 0;
	    foreach (i, cl; retcls) {
		if (cl == INTEGER) {
		    if (intreg == 0)
			retval ~= readRegister(RAX, TS8);
		    else
			retval ~= readRegister(RDX, TS8);
		    intreg++;
		}
		else if (cl == SSE) {
		    if (ssereg == 0)
			retval ~= readRegister(XMM0, TS8);
		    else
			retval ~= readRegister(XMM1, TS8);
		    ssereg++;
		}
		else if (cl == SSEUP) {
		    if (ssereg == 1)
			retval ~= readRegister(XMM0, TS16)[8..$];
		    else
			retval ~= readRegister(XMM1, TS16)[8..$];
		}
		else if (cl == X87) {
		    if (i < retcls.length - 1
			&& retcls[i + 1] == X87UP)
			retval ~= readRegister(ST0, TS16);
		    else
			retval ~= readRegister(ST0, returnType.byteWidth);
		} else if (cl == MEMORY) {
		    retval = readMemory(cast(TargetAddress)
					readIntRegister(RAX),
                                        returnType.byteWidth);
		    break;
		}
		else {
		    throw new EvalException(
			"Can't read return value for function call");
		}
		if (retval.length > returnType.byteWidth)
		    retval.length = returnType.byteWidth;
	    }

	    return new Value(new ConstantLocation(retval), returnType);
	}

	FDE parsePrologue(TargetAddress func)
	{
	    return null;
	}

	TargetAddress findFlowControl(TargetAddress start, TargetAddress end)
	{
	    char readByte(TargetAddress loc) {
		ubyte[] t = readMemory(loc, TS1);
		return cast(char) t[0];
	    }

	    Disassembler dis = new Disassembler;
	    dis.setOption("x86_64");
	    TargetAddress loc = start;
	    while (loc < end) {
		TargetAddress tloc = loc;
		if (dis.isFlowControl(loc, &readByte))
		    return tloc;
	    }
	    return end;
	}

	TargetAddress findJump(TargetAddress start, TargetAddress end)
	{
	    char readByte(TargetAddress loc) {
		ubyte[] t = readMemory(loc, TS1);
		return cast(char) t[0];
	    }

	    Disassembler dis = new Disassembler;
	    dis.setOption("x86_64");
	    TargetAddress loc = start;
	    while (loc < end) {
		TargetAddress tloc = loc;
		TargetAddress target;
		if (dis.isJump(loc, target, &readByte))
		    return target;
	    }
	    return end;
	}

	string disassemble(ref TargetAddress address,
			   string delegate(TargetAddress) lookupAddress)
	{
	    char readByte(TargetAddress loc) {
		ubyte[] t = readMemory(loc, TS1);
		return cast(char) t[0];
	    }

	    Disassembler dis = new Disassembler;
	    dis.setOption("intel");
	    dis.setOption("x86_64");
	    return dis.disassemble(address, &readByte, lookupAddress);
	}

    }

private:
    enum {
	INTEGER, SSE, SSEUP, X87, X87UP, COMPLEX_X87, NO_CLASS, MEMORY,
    }

    int[] classify(Type ty)
    {
	if (ty.isIntegerType)
	    return [INTEGER];
	if (cast(PointerType) ty)
	    return [INTEGER];
	if (ty.isNumericType && ty.byteWidth <= 8)
	    return [SSE];
	if (ty.isNumericType)
	    return [X87, X87UP];
	auto aTy = cast(ArrayType) ty;
	if (aTy) {
	    /*
	     * XXX need a better way of recognising vector
	     * types.
	     */
	    if (!aTy.baseType.isIntegerType
		&& aTy.baseType.isNumericType
		&& aTy.baseType.byteWidth == 4
		&& aTy.byteWidth == 128) {
		return [SSE, SSEUP];
	    }
	    /*
	     * XXX need to pass a pointer
	     */
	}
	auto cTy = cast(CompoundType) ty;
	if (cTy) {
	    int[] classes;
	    classes.length = (cTy.byteWidth + 7) / 8;
	    foreach (ref cl; classes)
		cl = NO_CLASS;

	    if (cTy.byteWidth > 4 * 8) {
	    inmemory:
		foreach (ref cl; classes)
		    cl = MEMORY;
		return classes;
	    }
		    
	    for (auto i = 0; i < cTy.length; i++) {
		auto f = cTy[i].value;
		Location loc = new MemoryLocation(cast(TargetAddress) 0,
                                                  TS0);
		loc = f.loc.fieldLocation(loc, this);
		auto start = loc.address(this) / 8;
		auto end = (loc.address(this)
			    + f.type.byteWidth + 7) / 8;
		auto fieldClass = classify(f.type);
		for (auto j = start; j < end; j++) {
		    auto k = j - start;
		    if (classes[j] == NO_CLASS)
			classes[j] = fieldClass[k];
		    else if (classes[j] == MEMORY
			     || fieldClass[k] == MEMORY)
			classes[j] = MEMORY;
		    else if (classes[j] == INTEGER
			     || fieldClass[k] == INTEGER)
			classes[j] = INTEGER;
		    else if (classes[j] == X87
			     || classes[j] == X87UP
			     || classes[j] == COMPLEX_X87
			     || fieldClass[k] == X87
			     || fieldClass[k] == X87UP
			     || fieldClass[k] == COMPLEX_X87)
			classes[j] = MEMORY;
		    else
			classes[j] = SSE;
		}
	    }
	    foreach (i, cl; classes) {
		if (cl == MEMORY)
		    goto inmemory;
		if (cl == X87UP
		    && (i == 0 || classes[i - 1] != X87))
		    goto inmemory;
	    }
	    if (classes.length > 1) {
		foreach (i, ref cl; classes) {
		    if (i == 0 && cl != SSE)
			goto inmemory;
		    if (i > 0) {
			if (cl != SSEUP)
			    goto inmemory;
			if (classes[i - 1] != SSE
			    || classes[i - 1] != SSEUP)
			    cl = SSE;
		    }
		}
	    }
	    return classes;
	}
	auto n = (ty.byteWidth + 7) / 8;
	int[] classes;
	classes.length = n;
	foreach (ref cl; classes)
	    cl = MEMORY;
	return classes;
    }

    union float32 {
	uint i;
	float f;
    }
    union float64 {
	ulong i;
	double f;
    }
    version (FreeBSD) {
	static uint[] regmap_ = [
	    reg64.r_rax.offsetof,	// X86_64Reg.RAX
	    reg64.r_rdx.offsetof,	// X86_64Reg.RDX
	    reg64.r_rcx.offsetof,	// X86_64Reg.RCX
	    reg64.r_rbx.offsetof,	// X86_64Reg.RBX
	    reg64.r_rsi.offsetof,	// X86_64Reg.RSI
	    reg64.r_rdi.offsetof,	// X86_64Reg.RDI
	    reg64.r_rbp.offsetof,	// X86_64Reg.RBP
	    reg64.r_rsp.offsetof,	// X86_64Reg.RSP
	    reg64.r_r8.offsetof,	// X86_64Reg.R8
	    reg64.r_r9.offsetof,	// X86_64Reg.R9
	    reg64.r_r10.offsetof,	// X86_64Reg.R10
	    reg64.r_r11.offsetof,	// X86_64Reg.R11
	    reg64.r_r12.offsetof,	// X86_64Reg.R12
	    reg64.r_r13.offsetof,	// X86_64Reg.R13
	    reg64.r_r14.offsetof,	// X86_64Reg.R14
	    reg64.r_r15.offsetof,	// X86_64Reg.R15
	    reg64.r_rip.offsetof,	// X86_64Reg.RIP
	    ];
    }
    version (linux) {
	static uint[] regmap_ = [
	    reg64.r_rax.offsetof,	// X86_64Reg.RAX
	    reg64.r_rdx.offsetof,	// X86_64Reg.RDX
	    reg64.r_rcx.offsetof,	// X86_64Reg.RCX
	    reg64.r_rbx.offsetof,	// X86_64Reg.RBX
	    reg64.r_rsi.offsetof,	// X86_64Reg.RSI
	    reg64.r_rdi.offsetof,	// X86_64Reg.RDI
	    reg64.r_rbp.offsetof,	// X86_64Reg.RBP
	    reg64.r_rsp.offsetof,	// X86_64Reg.RSP
	    reg64.r_r8.offsetof,	// X86_64Reg.R8
	    reg64.r_r9.offsetof,	// X86_64Reg.R9
	    reg64.r_r10.offsetof,	// X86_64Reg.R10
	    reg64.r_r11.offsetof,	// X86_64Reg.R11
	    reg64.r_r12.offsetof,	// X86_64Reg.R12
	    reg64.r_r13.offsetof,	// X86_64Reg.R13
	    reg64.r_r14.offsetof,	// X86_64Reg.R14
	    reg64.r_r15.offsetof,	// X86_64Reg.R15
	    reg64.r_rip.offsetof,	// X86_64Reg.RIP
	    ];
    }

    Target	target_;
    uint32_t	tp_;
}

private:

version (FreeBSD) {
/*-
 * Copyright (c) 1990 The Regents of the University of California.
 * All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * William Jolitz.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	from: @(#)reg.h	5.5 (Berkeley) 1/18/91
 * $FreeBSD: src/sys/i386/include/reg.h,v 1.33 2006/11/17 19:20:32 jhb Exp $
 */

/*
 * Register set accessible via /proc/$pid/regs and PT_{SET,GET}REGS.
 */
    struct reg32 {
	uint	r_fs;
	uint	r_es;
	uint	r_ds;
	uint	r_edi;
	uint	r_esi;
	uint	r_ebp;
	uint	r_isp;
	uint	r_ebx;
	uint	r_edx;
	uint	r_ecx;
	uint	r_eax;
	uint	r_trapno;
	uint	r_err;
	uint	r_eip;
	uint	r_cs;
	uint	r_eflags;
	uint	r_esp;
	uint	r_ss;
	uint	r_gs;
    };

    struct reg64 {
	ulong	r_r15;
	ulong	r_r14;
	ulong	r_r13;
	ulong	r_r12;
	ulong	r_r11;
	ulong	r_r10;
	ulong	r_r9;
	ulong	r_r8;
	ulong	r_rdi;
	ulong	r_rsi;
	ulong	r_rbp;
	ulong	r_rbx;
	ulong	r_rdx;
	ulong	r_rcx;
	ulong	r_rax;
	uint	r_trapno;
	ushort	r_fs;
	ushort	r_gs;
	uint	r_err;
	ushort	r_es;
	ushort	r_ds;
	ulong	r_rip;
	ulong	r_cs;
	ulong	r_rflags;
	ulong	r_rsp;
	ulong	r_ss;
    };

/*
 * Register set accessible via /proc/$pid/fpregs.
 */
    struct fpreg {
	/*
	 * XXX should get struct from npx.h.  Here we give a slightly
	 * simplified struct.  This may be too much detail.  Perhaps
	 * an array of unsigned longs is best.
	 */
	uint	fpr_env[7];
	ubyte	fpr_acc[8][10];
	uint	fpr_ex_sw;
	ubyte	fpr_pad[64];
    };

    struct xmmreg32 {
	/*
	 * XXX should get struct from npx.h.  Here we give a slightly
	 * simplified struct.  This may be too much detail.  Perhaps
	 * an array of ulongs is best.
	 */
	uint	xmm_env[8];
	ubyte	xmm_acc[8][16];
	ubyte	xmm_reg[8][16];
	ubyte	xmm_pad[224];
    };

    struct xmmreg64 {
	/*
	 * XXX should get struct from npx.h.  Here we give a slightly
	 * simplified struct.  This may be too much detail.  Perhaps
	 * an array of ulongs is best.
	 */
	uint	xmm_env[8];
	ubyte	xmm_acc[8][16];
	ubyte	xmm_reg[16][16];
	ulong	xmm_pad[12];
    };

/*
 * Register set accessible via /proc/$pid/dbregs.
 */
    struct dbreg {
	uint  dr[8];	/* debug registers */
	/* Index 0-3: debug address registers */
	/* Index 4-5: reserved */
	/* Index 6: debug status */
	/* Index 7: debug control */
    };

    /+
     #define	DBREG_DR7_LOCAL_ENABLE	0x01
     #define	DBREG_DR7_GLOBAL_ENABLE	0x02
     #define	DBREG_DR7_LEN_1		0x00	/* 1 byte length          */
     #define	DBREG_DR7_LEN_2		0x01
     #define	DBREG_DR7_LEN_4		0x03
     #define	DBREG_DR7_EXEC		0x00	/* break on execute       */
     #define	DBREG_DR7_WRONLY	0x01	/* break on write         */
     #define	DBREG_DR7_RDWR		0x03	/* break on read or write */
     #define	DBREG_DR7_MASK(i)	(0xf << ((i) * 4 + 16) | 0x3 << (i) * 2)
     #define	DBREG_DR7_SET(i, len, access, enable)				\
     (((len) << 2 | (access)) << ((i) * 4 + 16) | (enable) << (i) * 2)
     #define	DBREG_DR7_GD		0x2000
     #define	DBREG_DR7_ENABLED(d, i)	(((d) & 0x3 << (i) * 2) != 0)
     #define	DBREG_DR7_ACCESS(d, i)	((d) >> ((i) * 4 + 16) & 0x3)
     #define	DBREG_DR7_LEN(d, i)	((d) >> ((i) * 4 + 18) & 0x3)

     #define	DBREG_DRX(d,x)	((d)->dr[(x)])	/* reference dr0 - dr7 by
     register number */
     +/

    enum
    {
	PT_GETXMMREGS = PT_FIRSTMACH + 0,
	PT_SETXMMREGS = PT_FIRSTMACH + 1,
	PT_GETFSBASE = PT_FIRSTMACH + 2,
	PT_GETGSBASE = PT_FIRSTMACH + 3
    }
}
version (linux) {
/* this struct defines the way the registers are stored on the 
   stack during a system call. */

    struct reg32 {
	uint r_ebx;
	uint r_ecx;
	uint r_edx;
	uint r_esi;
	uint r_edi;
	uint r_ebp;
	uint r_eax;
	uint r_ds;
	uint r_es;
	uint r_fs;
	uint r_gs;
	uint r_orig_eax;
	uint r_eip;
	uint r_cs;
	uint r_eflags;
	uint r_esp;
	uint r_ss;
    }
    struct reg64 {
	ulong	r_r15;
	ulong	r_r14;
	ulong	r_r13;
	ulong	r_r12;
	ulong	r_r11;
	ulong	r_r10;
	ulong	r_r9;
	ulong	r_r8;
	ulong	r_rdi;
	ulong	r_rsi;
	ulong	r_rbp;
	ulong	r_rbx;
	ulong	r_rdx;
	ulong	r_rcx;
	ulong	r_rax;
	uint	r_trapno;
	ushort	r_fs;
	ushort	r_gs;
	uint	r_err;
	ushort	r_es;
	ushort	r_ds;
	ulong	r_rip;
	ulong	r_cs;
	ulong	r_rflags;
	ulong	r_rsp;
	ulong	r_ss;
    };
    struct xmmreg32 {
	/*
	 * XXX should get struct from npx.h.  Here we give a slightly
	 * simplified struct.  This may be too much detail.  Perhaps
	 * an array of ulongs is best.
	 */
	uint	xmm_env[8];
	ubyte	xmm_acc[8][16];
	ubyte	xmm_reg[8][16];
	ubyte	xmm_pad[224];
    };
    struct xmmreg64 {
	/*
	 * XXX should get struct from npx.h.  Here we give a slightly
	 * simplified struct.  This may be too much detail.  Perhaps
	 * an array of ulongs is best.
	 */
	uint	xmm_env[8];
	ubyte	xmm_acc[8][16];
	ubyte	xmm_reg[16][16];
	ulong	xmm_pad[12];
    };
    enum {
	PTRACE_GETREGS =            12,
	    PTRACE_SETREGS =            13,
	    PTRACE_GETFPREGS =          14,
	    PTRACE_SETFPREGS =          15,
	    PTRACE_GETFPXREGS =         18,
	    PTRACE_SETFPXREGS =         19,

	    PTRACE_OLDSETOPTIONS =      21,

	    PTRACE_GET_THREAD_AREA =    25,

	    PTRACE_SET_THREAD_AREA =    26,

	    PTRACE_SYSEMU =		31,
	    PTRACE_SYSEMU_SINGLESTEP =  32
    }
}
