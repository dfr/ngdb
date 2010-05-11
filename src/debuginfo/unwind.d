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

module debuginfo.unwind;

import debuginfo.debuginfo;
import debuginfo.language;
import debuginfo.types;
import debuginfo.utils;
import machine.machine;
import target.target;

version(tangobos) import std.compat;

enum
{
    DW_CFA_advance_loc			= 0x40,
    DW_CFA_offset			= 0x80,
    DW_CFA_restore			= 0xc0,
    DW_CFA_nop				= 0x00,
    DW_CFA_set_loc			= 0x01,
    DW_CFA_advance_loc1			= 0x02,
    DW_CFA_advance_loc2			= 0x03,
    DW_CFA_advance_loc4			= 0x04,
    DW_CFA_offset_extended		= 0x05,
    DW_CFA_restore_extended		= 0x06,
    DW_CFA_undefined			= 0x07,
    DW_CFA_same_value			= 0x08,
    DW_CFA_register			= 0x09,
    DW_CFA_remember_state		= 0x0a,
    DW_CFA_restore_state		= 0x0b,
    DW_CFA_def_cfa			= 0x0c,
    DW_CFA_def_cfa_register		= 0x0d,
    DW_CFA_def_cfa_offset		= 0x0e,
    DW_CFA_def_cfa_expression		= 0x0f,
    DW_CFA_expression			= 0x10,
    DW_CFA_offset_extended_sf		= 0x11,
    DW_CFA_def_cfa_sf			= 0x12,
    DW_CFA_def_cfa_offset_sf		= 0x13,
    DW_CFA_val_offset			= 0x14,
    DW_CFA_val_offset_sf		= 0x15,
    DW_CFA_val_expression		= 0x16,
    DW_CFA_lo_user			= 0x1c,
    DW_CFA_hi_user			= 0x3f,

    // Extensions
    DW_CFA_MIPS_advance_loc8	= 0x1d,
    DW_CFA_GNU_window_save		= 0x2d,
    DW_CFA_GNU_args_size		= 0x2e,
    DW_CFA_GNU_negative_offset_extended	= 0x2f,
}

class CIE
{
    uint codeAlign;
    int dataAlign;
    uint returnAddress;
    char* instructionStart;
    char* instructionEnd;
}

class FDE
{
    CIE cie;
    ulong initialLocation;
    ulong addressRange;
    char* instructionStart;
    char* instructionEnd;

    struct RLoc {
	enum Rule {
	    undefined,
	    sameValue,
	    offsetN,
	    valOffsetN,
	    registerR,
	    expressionE,
	    valExpressionE,
	}
	Rule rule;
	union {
	    long N;
	    uint R;
	    struct block {
		char* start;
		char* end;
	    }
	    block E;
	}
    }
    struct FrameState {
	void clear(FDE fde, uint numRegs)
	{
	    regs.length = numRegs;
	    foreach (rloc; regs) {
		rloc.rule = RLoc.Rule.undefined;
	    }
	    loc = fde.initialLocation;
	}

	RLoc regs[];
	ulong loc;
	uint cfaReg;
	long cfaOffset;
    }

    bool contains(ulong pc)
    {
	return pc >= initialLocation && pc < initialLocation + addressRange;
    }

    Location frameLocation(MachineState state)
    {
	FrameState cieFs, fdeFs;

	cieFs.clear(this, state.registerCount);
	fdeFs.clear(this, state.registerCount);

	auto pc = state.pc;
	execute(state, cie.instructionStart, cie.instructionEnd,
		pc, cieFs, cieFs);

	fdeFs = cieFs;
	execute(state, instructionStart, instructionEnd, pc, fdeFs, cieFs);

	auto reg = state.readIntRegister(fdeFs.cfaReg);
	return new MemoryLocation(cast(TargetAddress) (reg + fdeFs.cfaOffset),
                                  TS1);
    }

    MachineState unwind(MachineState state)
    {
	FrameState cieFs, fdeFs;

	cieFs.clear(this, state.registerCount);
	fdeFs.clear(this, state.registerCount);

	auto pc = state.pc;
	execute(state, cie.instructionStart, cie.instructionEnd,
		pc, cieFs, cieFs);

	fdeFs = cieFs;
	execute(state, instructionStart, instructionEnd,
		pc, fdeFs, cieFs);

	if (fdeFs.regs[cie.returnAddress].rule == RLoc.Rule.undefined)
	    return null;
	MachineState newState = state.dup;
	MachineRegister cfa = 
            state.readIntRegister(fdeFs.cfaReg) + fdeFs.cfaOffset;
	debug (unwind)
	    writefln("CFA = r%d+%d (0x%x)", fdeFs.cfaReg, fdeFs.cfaOffset, cfa);
	foreach (regno, rl; fdeFs.regs) {
	    long off;
	    ubyte[] b;
	    switch (rl.rule) {
	    case RLoc.Rule.undefined:
	    case RLoc.Rule.sameValue:
		if (regno == state.spregno)
		    newState.writeIntRegister(regno, cfa);
		break;

	    case RLoc.Rule.offsetN:
		off = rl.N;
		b = state.readMemory(cast(TargetAddress) (cfa + off),
                                     state.pointerWidth);
		debug (unwind)
		    writefln("reg%d at CFA-%d", regno, -off);
		newState.writeRegister(regno, b);
		break;

	    case RLoc.Rule.valOffsetN:
		off = rl.N;
		newState.writeIntRegister(regno, cfa + off);
		break;
		    
	    case RLoc.Rule.registerR:
		newState.writeIntRegister(regno, state.readIntRegister(rl.R));
		break;

	    case RLoc.Rule.expressionE:
	    case RLoc.Rule.valExpressionE:
		throw new Exception("no support for frame state stacks");
	    }
	}
	return newState;
    }

private:
    void execute(MachineState state,
		 char* p, char* pEnd, ulong pc, ref FrameState fs,
		 in FrameState cieFs)
    {
	uint reg;
	ulong off;

	ulong parseInteger(ref char* p, uint width)
	{
	    ubyte* bp;
	    bp = cast(ubyte*) p;
	    p += width;
	    return state.readInteger(bp[0..width]);
	}

	ulong parseUByte(ref char* p)
	{
	    return parseInteger(p, 1);
	}

	ulong parseUShort(ref char* p)
	{
	    return parseInteger(p, 2);
	}

	ulong parseUInt(ref char* p)
	{
	    return parseInteger(p, 4);
	}

	ulong parseULong(ref char* p)
	{
	    return parseInteger(p, 8);
	}

	TargetAddress parseAddress(ref char* p)
	{
	    if (state.pointerWidth == 8)
		return parseULong(p);
	    else
		return parseUInt(p);
	}

	while (p < pEnd) {
	    auto op = *p++;
	    switch ((op & 0xc0) ? (op & 0xc0) : op) {
	    case DW_CFA_set_loc:
		fs.loc = parseAddress(p);
		debug(unwind)
		    writefln("DW_CFA_set_loc: 0x%x", fs.loc);
		break;

	    case DW_CFA_advance_loc:
		off = (op & 0x3f) * cie.codeAlign;
		fs.loc += off;
		debug(unwind)
		    writefln("DW_CFA_advance_loc: %d to 0x%x", off, fs.loc);
		break;

	    case DW_CFA_advance_loc1:
		off = parseUByte(p) * cie.codeAlign;
		fs.loc += off;
		debug(unwind)
		    writefln("DW_CFA_advance_loc1: %d to 0x%x", off, fs.loc);
		break;

	    case DW_CFA_advance_loc2:
		off = parseUShort(p) * cie.codeAlign;
		fs.loc += off;
		debug(unwind)
		    writefln("DW_CFA_advance_loc2: %d to 0x%x", off, fs.loc);
		break;

	    case DW_CFA_advance_loc4:
		off = parseUInt(p) * cie.codeAlign;
		fs.loc += off;
		debug(unwind)
		    writefln("DW_CFA_advance_loc4: %d to 0x%x", off, fs.loc);
		break;

	    case DW_CFA_MIPS_advance_loc8:
		off = parseULong(p) * cie.codeAlign;
		fs.loc += off;
		debug(unwind)
		    writefln("DW_CFA_MIPS_advance_loc8: %d to 0x%x", off, fs.loc);
		break;

	    case DW_CFA_def_cfa:
		fs.cfaReg = state.mapDwarfRegno(parseULEB128(p));
		fs.cfaOffset = parseULEB128(p);
		debug(unwind)
		    writefln("DW_CFA_def_cfa: cfa=%d, off=%d",
			     fs.cfaReg, fs.cfaOffset);
		break;

	    case DW_CFA_def_cfa_sf:
		fs.cfaReg = state.mapDwarfRegno(parseULEB128(p));
		fs.cfaOffset = parseSLEB128(p) * cie.dataAlign;
		debug(unwind)
		    writefln("DW_CFA_def_cfa_sf: cfa=%d, off=%d",
			     fs.cfaReg, fs.cfaOffset);
		break;

	    case DW_CFA_def_cfa_register:
		fs.cfaReg = state.mapDwarfRegno(parseULEB128(p));
		debug(unwind)
		    writefln("DW_CFA_def_cfa_register: cfa=%d, off=%d",
			     fs.cfaReg, fs.cfaOffset);
		break;

	    case DW_CFA_def_cfa_offset:
		fs.cfaOffset = parseULEB128(p);
		debug(unwind)
		    writefln("DW_CFA_def_cfa_offset: cfa=%d, off=%d",
			     fs.cfaReg, fs.cfaOffset);
		break;

	    case DW_CFA_def_cfa_offset_sf:
		fs.cfaOffset = parseSLEB128(p) * cie.dataAlign;
		debug(unwind)
		    writefln("DW_CFA_def_cfa_offset_sf: cfa=%d, off=%d",
			     fs.cfaReg, fs.cfaOffset);
		break;

	    case DW_CFA_def_cfa_expression:
		throw new Exception("no support for CFA expressions");

	    case DW_CFA_undefined:
		reg = parseULEB128(p);
		fs.regs[reg].rule = RLoc.Rule.undefined;
		debug(unwind)
		    writefln("DW_CFA_undefined: reg=%d", reg);
		break;

	    case DW_CFA_same_value:
		reg = state.mapDwarfRegno(parseULEB128(p));
		fs.regs[reg].rule = RLoc.Rule.sameValue;
		debug(unwind)
		    writefln("DW_CFA_same_value: reg=%d", reg);
		break;

	    case DW_CFA_offset:
		reg = state.mapDwarfRegno(op & 0x3f);
		fs.regs[reg].rule = RLoc.Rule.offsetN;
		fs.regs[reg].N = parseULEB128(p) * cie.dataAlign;
		debug(unwind)
		    writefln("DW_CFA_offset: reg=%d, off=%d",
			     reg, fs.regs[reg].N);
		break;
			
	    case DW_CFA_offset_extended:
		reg = state.mapDwarfRegno(parseULEB128(p));
		fs.regs[reg].rule = RLoc.Rule.offsetN;
		fs.regs[reg].N = parseULEB128(p) * cie.dataAlign;
		debug(unwind)
		    writefln("DW_CFA_offset_extended: reg=%d, off=%d",
			     reg, fs.regs[reg].N);
		break;

	    case DW_CFA_offset_extended_sf:
		reg = state.mapDwarfRegno(parseULEB128(p));
		fs.regs[reg].rule = RLoc.Rule.offsetN;
		fs.regs[reg].N = parseSLEB128(p) * cie.dataAlign;
		debug(unwind)
		    writefln("DW_CFA_offset_extended_sf: reg=%d, off=%d",
			     reg, fs.regs[reg].N);
		break;

	    case DW_CFA_val_offset:
		reg = state.mapDwarfRegno(parseULEB128(p));
		fs.regs[reg].rule = RLoc.Rule.valOffsetN;
		fs.regs[reg].N = parseULEB128(p) * cie.dataAlign;
		debug(unwind)
		    writefln("DW_CFA_val_offset: reg=%d, off=%d",
			     reg, fs.regs[reg].N);
		break;

	    case DW_CFA_register:
		reg = state.mapDwarfRegno(parseULEB128(p));
		fs.regs[reg] = fs.regs[state.mapDwarfRegno(parseULEB128(p))];
		debug(unwind)
		    writefln("DW_CFA_register: reg=%d", reg);
		break;

	    case DW_CFA_expression:
		throw new Exception("no support for CFA expressions");

	    case DW_CFA_val_expression:
		throw new Exception("no support for CFA expressions");

	    case DW_CFA_restore:
		reg = state.mapDwarfRegno(op & 0x3f);
		fs.regs[reg] = cieFs.regs[reg];
		debug(unwind)
		    writefln("DW_CFA_restore: reg=%d", reg);
		break;

	    case DW_CFA_restore_extended:
		reg = state.mapDwarfRegno(parseULEB128(p));
		fs.regs[reg] = cieFs.regs[state.mapDwarfRegno(op & 0x3f)];
		debug(unwind)
		    writefln("DW_CFA_restore_extended: reg=%d", reg);
		break;

	    case DW_CFA_remember_state:
	    case DW_CFA_restore_state:
		throw new Exception("no support for frame state stacks");

	    case DW_CFA_GNU_window_save:
		throw new Exception("DW_CFA_GNU_window_save");

	    case DW_CFA_GNU_args_size:
		parseULEB128(p);
		break;

	    case DW_CFA_GNU_negative_offset_extended:
		throw new Exception("DW_CFA_GNU_negative_offset_extended");

	    case DW_CFA_nop:
		break;

	    default:
		throw new Exception(std.string.format(
					"unknown CFA opcode %x", op));
	    }
	    // If we have advanced past the PC, stop
	    if (pc < fs.loc)
		return;
	}
    }
}
