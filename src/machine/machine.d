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
import debuginfo.types;
version(tangobos) import std.compat;

/**
 * A structure used to decribe how to use ptrace(2) to update the
 * machine state.
 */
struct PtraceCommand
{
    uint	req;
    ubyte*	addr;
    uint	data;
}

/**
 * An integer register value.
 */
typedef ulong MachineRegister;

/**
 * A representation of the target machine. Registers are indexed by
 * dwarf register number.
 */
class MachineState: Scope
{
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
     * Return a set of ptrace commands to read the machine state from
     * a process or thread.
     */
    abstract PtraceCommand[] ptraceReadCommands();

    /**
     * Return a set of ptrace commands to write the machine state back
     * to a process or thread.
     */
    abstract PtraceCommand[] ptraceWriteCommands();

    /**
     * Set the values of all the general registers.
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
     * Set the values of all the floating point registers.
     */
    abstract void setFRs(ubyte* regs);

    /**
     * Get the values of all the floating point registers.
     */
    abstract void getFRs(ubyte* regs);

    /**
     * Map a dwarf register number to a MachineState register number.
     */
    abstract uint mapDwarfRegno(int dwregno);

    /**
     * Return the number of registers
     */
    abstract uint registerCount();

    /**
     * Return the width of a register in bytes. Register index
     * corresponds to dwarf register number.
     */
    abstract TargetSize registerWidth(int regno);

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
