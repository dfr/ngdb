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

module target.target;
import debuginfo.debuginfo;
import debuginfo.dwarf;
import debuginfo.types;
import objfile.objfile;
import objfile.elf;
import machine.machine;
version(tangobos) import std.compat;

typedef ulong TargetAddress;
typedef ulong TargetSize;

enum : TargetSize
{
    TS0 = cast(TargetSize) 0,
    TS1 = cast(TargetSize) 1,
    TS2 = cast(TargetSize) 2,
    TS4 = cast(TargetSize) 4,
    TS8 = cast(TargetSize) 8,
    TS10 = cast(TargetSize) 10,
    TS12 = cast(TargetSize) 12,
    TS16 = cast(TargetSize) 16,
}

enum : TargetAddress
{
    TA0 = cast(TargetAddress) 0,
    TAmax = cast(TargetAddress) ~0UL
}

class TargetException: Exception
{
    this(string msg)
    {
	super(msg);
    }
}

/**
 * This interface is used to allow a target to notify a user when
 * a breakpoint is hit.
 */
interface TargetBreakpointListener
{
    /**
     * Called when a thread hits a breakpoint. Return true to stop
     * execution or false to keep running.
     */
    bool onBreakpoint(Target, TargetThread);
}

/**
 * This interface is used to allow a target to notify a user of
 * changes in the target state.
 */
interface TargetListener
{
    /**
     * Called when a new target is started or attached.
     */
    void onTargetStarted(Target);

    /**
     * Called when a new thread is created in the target.
     */
    void onThreadCreate(Target, TargetThread);

    /**
     * Called when a thread is destroyed.
     */
    void onThreadDestroy(Target, TargetThread);

    /**
     * Called when a new module is mapped in the target.
     */
    void onModuleAdd(Target, TargetModule);

    /**
     * Called when a module is unmapped in the target.
     */
    void onModuleDelete(Target, TargetModule);

    /**
     * Called when the target stops because of a signal
     */
    void onSignal(Target, TargetThread, int sig, string sigName);

    /**
     * Called when the target exits
     */
    void onExit(Target);
}

/**
 * This interface is used to manipulate a single thread (program counter and
 * register set) within a target.
 */
interface TargetThread
{
    /**
     * Return the target that contains this thread.
     */
    Target target();

    /**
     * Return the machine state for this thread
     */
    MachineState state();

    /**
     * The identifiers of this thread. Identifiers start at one for
     * the main thread and increase by one for each new
     * thread. Identifiers are not re-used withing a target.
     */
    uint id();
}

struct TargetSymbol
{
    string name;
    TargetAddress value;
    TargetSize size;
}

/**
 * Describe a mapping of part of the target address space to a
 * file. Top-level modules represent loaded files. Sub-modules of
 * top-level modules are individual compilation units within a file.
 */
interface TargetModule: Scope
{
    /**
     * Return the object filename of the module that occupies this address
     * range.
     */
    string filename();

    /**
     * Return the start address in the target address space for this
     * module.
     */
    TargetAddress start();

    /**
     * Return the end address for this module
     */
    TargetAddress end();

    /**
     * Return true if the given address is within this module.
     */
    bool contains(TargetAddress);

    /**
     * Find debug information for thie module, if any.
     */
    DebugInfo debugInfo();

    /**
     * Lookup a low-level symbol in thie module.
     */
    bool lookupSymbol(string name, out TargetSymbol);

    /**
     * Ditto
     */
    bool lookupSymbol(TargetAddress addr, out TargetSymbol);

    /**
     * Return true of the address is within the Program Linkage Table for
     * this module.
     */
    bool inPLT(TargetAddress addr);
}

class TargetModuleBase: TargetModule
{
    this(string filename, TargetAddress start, TargetAddress end)
    {
	filename_ = filename;
	start_ = start;
	end_ = end;
    }

    TargetAddress entry()
    {
	if (obj_)
	    return obj_.entry;
	return cast(TargetAddress) 0;
    }

    void init()
    {
	if (!obj_) {
	    //writefln("Opening %s at %#x", filename_, start_);
	    obj_ = Objfile.open(filename_, start_);
	    if (obj_) {
		if (DwarfFile.hasDebug(obj_)) {
		    //writefln("Offset is %#x", obj_.offset);
		    //writefln("Reading debug info for %s", filename_);
		    dwarf_ = new DwarfFile(obj_);
		}
		auto elf = cast(Elffile) obj_;
	    }
	}
    }

    TargetAddress findSharedLibraryBreakpoint(Target target)
    {
	if (obj_) {
	    auto elf = cast(Elffile) obj_;
	    if (!elf)
		return cast(TargetAddress) 0;
	    return elf.findSharedLibraryBreakpoint(target);
	}
	return cast(TargetAddress) 0;
    }

    uint sharedLibraryState(Target target)
    {
	if (obj_) {
	    auto elf = cast(Elffile) obj_;
	    if (!elf)
		return 0;
	    return elf.sharedLibraryState(target);
	}
	return 0;
    }

    void enumerateLinkMap(Target target,
			  void delegate(string, TargetAddress, TargetAddress) dg)
    {
	if (obj_) {
	    auto elf = cast(Elffile) obj_;
	    if (!elf)
		return;
	    return elf.enumerateLinkMap(target, dg);
	}
	return;
    }

    MachineState getState(Target target)
    {
	if (obj_)
	    return obj_.getState(target);
	return null;
    }

    int opEquals(TargetModuleBase mod)
    {
	return filename_ == mod.filename_
	    && start_ == mod.start_;
    }

    override {
	string filename()
	{
	    return filename_;
	}

	TargetAddress start()
	{
	    return start_;
	}

	TargetAddress end()
	{
	    return end_;
	}

	bool contains(TargetAddress addr)
	{
	    return addr >= start && addr < end_;
	}

	DebugInfo debugInfo()
	{
	    return dwarf_;
	}

	bool lookupSymbol(string name, out TargetSymbol ts)
	{
	    if (obj_) {
		Symbol* s = obj_.lookupSymbol(name);
		if (s) {
		    ts.name = s.name;
		    ts.value = s.value;
		    ts.size = s.size;
		    return true;
		}
	    }
	    return false;
	}	

	bool lookupSymbol(TargetAddress addr, out TargetSymbol ts)
	{
	    if (obj_) {
		Symbol* s = obj_.lookupSymbol(addr);
		if (s) {
		    ts = TargetSymbol(s.name, s.value, s.size);
		    return true;
		}
	    }
	    return false;
	}

	bool inPLT(TargetAddress pc)
	{
	    if (obj_) {
		auto elf = cast(Elffile) obj_;
		if (!elf)
		    return false;
		return elf.inPLT(pc);
	    }
	    return false;
	}

	string[] contents(MachineState state)
	{
	    if (dwarf_)
		return dwarf_.contents(state);
	    return null;
	}

	bool lookup(string name, MachineState state, out DebugItem val)
	{
	    if (dwarf_)
		return dwarf_.lookup(name, state, val);
	    return false;
	}

	bool lookupStruct(string name, out Type ty)
	{
	    if (dwarf_)
		return dwarf_.lookupStruct(name, ty);
	    return false;
	}

	bool lookupUnion(string name, out Type ty)
	{
	    if (dwarf_)
		return dwarf_.lookupUnion(name, ty);
	    return false;
	}

	bool lookupTypedef(string name, out Type ty)
	{
	    if (dwarf_)
		return dwarf_.lookupTypedef(name, ty);
	    return false;
	}
    }

protected:
    string filename_;
    TargetAddress start_;
    TargetAddress end_;
    Objfile obj_;
    DwarfFile dwarf_;
}

/**
 * Target state
 */
enum TargetState {
    STOPPED,
    RUNNING,
    EXIT
}

/**
 * This interface represents a debugging target.
 */
interface Target
{
    /**
     * Return the current target state.
     */
    TargetState state();

    /**
     * Return the target's entry point.
     */
    TargetAddress entry();

    /**
     * Read from the target's memory.
     */
    ubyte[] readMemory(TargetAddress targetAddress, TargetSize bytes);

    /**
     * Write to the target's memory.
     */
    void writeMemory(TargetAddress targetAddress, ubyte[] toWrite);

    /**
     * Step the target by one instruction. After this method returns,
     * the target will be stopped again.
     */
    void step(TargetThread t);

    /**
     * Allow a target in state STOPPED to continue. The target's state
     * changes to RUNNING. Call wait() to pause until the target stops
     * again (e.g. at a breakpoint). If signo is non-zero, deliver a
     * signal to the target before resuming.
     */
    void cont(int signo = 0);

    /**
     * Wait for the target to receive an event which causes it to stop.
     */
    void wait();

    /**
     * Set a breakpoint at the given address. When the breakpoint is
     * hit, the listener's onBreakpoint method is called with the
     * given id value. To cancel the breakpoint, call clearBreakpoint
     * with the same id value as that used to set it. Many breakpoints
     * can be created with the same id value.
     */
    void setBreakpoint(TargetAddress addr, TargetBreakpointListener tbl);

    /**
     * Clear any breakpoints set with the given id.
     */
    void clearBreakpoint(TargetBreakpointListener tbl);
}

/**
 * An abstraction to allow creating
 * targets or attaching to existing targets.
 */
class TargetFactory
{
    /**
     * Return the name of the target factory (e.g. "process", "core" etc.).
     */
    abstract string		name();

    /**
     * Create a new target instance with the given arguments.
     */
    abstract Target		connect(TargetListener listener, char[][] args);
    /**
     * Register a target factory
     */
    static void register(TargetFactory tf)
    {
        factories_ ~= tf;
    }

    /**
     * Create a new target.
     */
    static Target               connect(string type,
                                        TargetListener listener,
                                        string[] args)
    {
        foreach (tf; factories_)
            if (tf.name == type)
                return tf.connect(listener, args);
        throw new TargetException("Target type not found");
    }

private:
    static TargetFactory[]      factories_;
}
