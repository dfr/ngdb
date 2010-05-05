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

module machine.machine;
import target.target;
import debuginfo.debuginfo;
import debuginfo.dwarf;
import debuginfo.types;
version(tangobos) import std.compat;
import std.bitarray;
import std.stdio;
import std.string;

/**
 * An interface to ptrace(2)
 */
interface Ptrace
{
    void ptrace(int op, ubyte* addr, uint data);
}

/**
 * An integer register value.
 */
alias ulong MachineRegister;

/**
 * A representation of the target machine. Registers are indexed by
 * dwarf register number.
 */
class MachineState: Scope
{
    /**
     * Print the register state.
     */
    abstract void dumpState();

    /**
     * Return the machine's program counter register.
     */
    abstract TargetAddress pc();

    /**
     * Set the program counter register.
     */
    abstract void pc(TargetAddress);

    /**
     * Return the thread pointer register.
     */
    abstract TargetAddress tp();

    /**
     * Return the address of the TLS object at the given module index
     * and offset.
     */
    abstract TargetAddress tls_get_addr(uint index, ulong offset);

    /**
     * Use ptrace(2) to read the machine state from a process or
     * thread.
     */
    abstract void ptraceReadState(Ptrace pt);

    /**
     * Use ptrace(2) to write the machine state to a process or
     * thread.
     */
    abstract void ptraceWriteState(Ptrace pt);

    /**
     * Set the values of all the general registers. The format of the
     * register area is the one used by ptrace on the current platform.
     */
    abstract void setGRs(ubyte* regs);

    /**
     * Get the values of all the general registers.
     */
    abstract void getGRs(ubyte* regs);

    /**
     * Return the stack pointer register index.
     */
    abstract uint spregno();

    /**
     * Print a representation of the floating point state.
     */
    abstract void dumpFloat();

    /**
     * Set the values of all the floating point registers. The format of the
     * register area is the one used by ptrace on the current platform.
     */
    abstract void setFRs(ubyte* regs);

    /**
     * Get the values of all the floating point registers.
     */
    abstract void getFRs(ubyte* regs);

    /**
     * Map a dwarf register number to a MachineState register number.
     */
    abstract uint mapDwarfRegno(uint dwregno);

    /**
     * Return the number of registers
     */
    abstract uint registerCount();

    /**
     * Return the width of a register in bytes. Register index
     * corresponds to dwarf register number.
     */
    abstract TargetSize registerWidth(uint regno);

    /**
     * Return the native type of a register.
     */
    abstract Type registerType(uint regno);

    /**
     * Read an integer register value. Register index corresponds to
     * dwarf register number.
     */
    abstract MachineRegister readIntRegister(uint regno);

    /**
     * Write an integer register value. Register index corresponds to
     * dwarf register number.
     */
    abstract void writeIntRegister(uint regno, MachineRegister value);

    /**
     * Read raw register bytes in target byte order. Register index
     * corresponds to dwarf register number.
     */
    abstract ubyte[] readRegister(uint regno, TargetSize bytes);

    /**
     * Write raw register bytes in target byte order. Register index
     * corresponds to dwarf register number.
     */
    abstract void writeRegister(uint regno, ubyte[]);

    /**
     * Return a byte array containing a breakpoint instruction for
     * this architecture.
     */
    abstract ubyte[] breakpoint();

    /**
     * Called after a thread hits a breakpoint to make any adjustments
     * to the machine state so that the PC is at the breakpoint
     * address.
     */
    abstract void adjustPcAfterBreak();

    /**
     * Return the width of a pointer in bytes
     */
    abstract TargetSize pointerWidth();

    /**
     * Convert an integer in machine-native format to host format.
     */
    abstract ulong readInteger(ubyte[] bytes);

    /**
     * Convert an address in machine-native format to host format.
     */
    TargetAddress readAddress(ubyte[] bytes)
    {
        return cast(TargetAddress) readInteger(bytes);
    }

    /**
     * Convert a size in machine-native format to host format.
     */
    TargetSize readSize(ubyte[] bytes)
    {
        return cast(TargetSize) readInteger(bytes);
    }

    /**
     * Convert an integer in host format to machine-native format.
     */
    abstract void writeInteger(ulong val, ubyte[] bytes);

    /**
     * Convert a floating point value in machine-native format to host format.
     */
    abstract real readFloat(ubyte[] bytes);

    /**
     * Convert a floating point value in host format to machine-native format.
     */
    abstract void writeFloat(real val, ubyte[] bytes);

    /**
     * Read from the machine's memory.
     */
    abstract ubyte[] readMemory(TargetAddress address, TargetSize bytes);

    /**
     * Write to the machine's memory.
     */
    abstract void writeMemory(TargetAddress address, ubyte[] toWrite);

    /**
     * Call a function in the target.
     */
    abstract Value call(TargetAddress address, Type returnType, Value[] args);

    /**
     * Return a value which represents a function return value of the
     * given type.
     */
    abstract Value returnValue(Type returnType);

    /**
     * Parse function prologue and generate corresponding unwind records.
     */
    abstract FDE parsePrologue(TargetAddress func);

    /**
     * Scan the interval [start..end) and return the address of
     * any flow control instructions in the range. If there are none,
     * return end.
     */
    abstract TargetAddress findFlowControl(TargetAddress start,
					   TargetAddress end);

    /**
     * Scan the interval [start..end) and return the target address of
     * the first unconditional jump in the range or end if there are none.
     */
    abstract TargetAddress findJump(TargetAddress start, TargetAddress end);

    /**
     * Disassemble the instruction at 'address' advancing the value of
     * 'address' to point at the next instruction in sequence. The
     * delegate 'lookupAddress' is used to translate machine addresses
     * to a symbolic equivalent.
     */
    abstract string disassemble(ref TargetAddress address,
				string delegate(TargetAddress) lookupAddress);

    /**
     * Make a copy of the machine state
     */
    abstract MachineState dup();

    // Scope
    abstract string[] contents(MachineState);
    abstract bool lookup(string, MachineState, out DebugItem);
    abstract bool lookupStruct(string, out Type);
    abstract bool lookupUnion(string, out Type);
    abstract bool lookupTypedef(string, out Type);
}

/**
 * A partial implementation of MachineState that manages register
 * values. This is a template rather than a base class because we need
 * to have different static class variables for each derived class.
 */
template MachineRegisters()
{
    void initRegisters()
    {
	bytes_.length = size_;
	dirty_.length = regCount_;
    }

    /**
     * Call this to add a register. Call once for each physical
     * register in the order defined by the machine's debugger ABI.
     */
    static void addRegister(Type ty, string name, bool subregOk = true)
    {
	debug (registers)
	    writefln("%s[0..%d] -> %d", name, ty.byteWidth, regs_.length);
	assert(regs_.length == regCount_);
	reg r;
	r.type_ = ty;
	r.name_ = name;
	r.size_ = ty.byteWidth;
	r.offset_ = size_;
	r.subregOk_ = subregOk;
	size_ += r.size_;
	regMap_[name] = regs_.length;
	regs_ ~= r;
	regCount_ = regs_.length;
    }

    /**
     * Add an alias to another physical register. Calls to
     * addRegisterAlias and addRegister cannot be mixed - add all the
     * physical registers first followed by any aliases.
     */
    static void addRegisterAlias(Type ty, string name, uint regno,
				 bool subregOk = true)
    {
	debug (registers)
	    writefln("%s[0..%d] -> %s[0..%d]",
		     name, ty.byteWidth,
		     regs_[regno].name_, regs_[regno].size_);
	assert(ty.byteWidth <= regs_[regno].size_);
	reg r;
	r.type_ = ty;
	r.name_ = name;
	r.size_ = ty.byteWidth;
	r.offset_ = regs_[regno].offset_;
	r.aliasReg_ = regno;
	r.subregOk_ = subregOk;
	regMap_[name] = regs_.length;
	regs_ ~= r;
    }

    uint registerCount()
    {
	return regCount_;
    }

    TargetSize registerWidth(uint regno)
    {
	if (regno >= regs_.length)
	    throw new TargetException(
		format("Unsupported register index %d", regno));
	return regs_[regno].size_;
    }

    Type registerType(uint regno)
    {
	if (regno >= regs_.length)
	    throw new TargetException(
		format("Unsupported register index %d", regno));
	return regs_[regno].type_;
    }

    MachineRegister readIntRegister(uint regno)
    {
	if (regno >= regs_.length)
	    throw new TargetException(
		format("Unsupported register index %d", regno));
	reg r = regs_[regno];
	return cast(MachineRegister)
	    readInteger(bytes_[r.offset_ .. r.offset_ + r.size_]);
    }

    void writeIntRegister(uint regno, MachineRegister value)
    {
	if (regno >= regs_.length)
	    throw new TargetException(
		format("Unsupported register index %d", regno));
	reg r = regs_[regno];
	ubyte[] v;
	v.length = r.size_;
	writeInteger(value, v);
	writeRegister(regno, v);
    }

    ubyte[] readRegister(uint regno, TargetSize bytes)
    {
	if (regno >= regs_.length)
	    throw new TargetException(
		format("Unsupported register index %d", regno));
	reg r = regs_[regno];
	if (bytes > r.size_)
	    throw new TargetException(
		format("Unsupported size %d for register index %d",
		       bytes, regno));
	if (bytes < r.size_ && !r.subregOk_)
	    bytes = r.size_;
	return bytes_[r.offset_ .. r.offset_ + bytes];
    }

    void writeRegister(uint regno, ubyte[] v)
    {
	if (regno >= regs_.length)
	    throw new TargetException(
		format("Unsupported register index %d", regno));
	reg r = regs_[regno];
	if (v.length < r.size_ && !r.subregOk_)
	    throw new TargetException(
		format("Unsupported size %d for register index %d",
		       v.length, regno));
	if (v.length > r.size_)
	    throw new TargetException(
		format("Unsupported size %d for register index %d",
		       v.length, regno));
	if (regno < regCount_)
	    dirty_[regno] = true;
	else
	    dirty_[r.aliasReg_] = true;
	bytes_[r.offset_ .. r.offset_ + v.length] = v[];
    }

    // Scope
    string[] contents(MachineState)
    {
	return regMap_.keys;
    }

    bool lookup(string name, MachineState, out DebugItem val)
    {
	if (name in regMap_) {
	    uint regno = regMap_[name];
	    reg r = regs_[regno];
	    auto loc = new RegisterLocation(regno, r.size_);
	    val = new Value(loc, r.type_);
	    return true;
	}
	return false;
    }

    bool lookupStruct(string, out Type)
    {
	return false;
    }

    bool lookupUnion(string, out Type)
    {
	return false;
    }

    bool lookupTypedef(string, out Type)
    {
	return false;
    }

private:
    struct reg {
	Type		type_;
	string		name_;
	TargetSize	size_;
	uint		offset_;
	uint		aliasReg_;
	bool		subregOk_;
    };

    /**
     * Map register name to register number
     */
    static uint[string]	regMap_;

    /**
     * Describe the type, name, size and location of a register within
     * our storage area.
     */
    static reg[]	regs_;

    /**
     * The actual (non-alias) register count
     */
    static uint		regCount_ = 0;

    /**
     * The size in bytes required to store a set of registers.
     */
    static uint		size_ = 0;

protected:
    /**
     * The register state area for this object.
     */
    ubyte[]		bytes_;

    /**
     * A map of which registers have been modified by calling
     * writeRegister or writeIntRegister.
     */
    std.bitarray.BitArray dirty_;
}
