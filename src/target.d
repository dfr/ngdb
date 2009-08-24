/*-
 * Copyright (c) 2009 Doug Rabson
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

module target;
import objfile.debuginfo;
import machine.machine;
version(tangobos) import std.compat;

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
     * Called when a thread hits a breakpoint.
     */
    void onBreakpoint(Target, TargetThread, Breakpoint);
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
     * Return the thread's current program counter.
     */
    ulong pc();

    /**
     * Return the machine state for this thread
     */
    MachineState state();
}

struct TargetSymbol
{
    string name;
    ulong value;
    ulong size;
}

/**
 * Describe a mapping of part of the target address space to a
 * file. Top-level modules represent loaded files. Sub-modules of
 * top-level modules are individual compilation units within a file.
 */
interface TargetModule
{
    /**
     * Return the object filename of the module that occupies this address
     * range.
     */
    char[] filename();

    /**
     * Return the start address in the target address space for this
     * module.
     */
    ulong start();

    /**
     * Return the end address for this module
     */
    ulong end();

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
    bool lookupSymbol(ulong addr, out TargetSymbol);
}

/**
 * Target state
 */
enum TargetState {
    STOPPED,
    RUNNING,
}

/**
 * A breakpoint in a target
 */
interface Breakpoint
{
    /**
     * Set enabled/disabled state
     */
    void enabled(bool);

    /**
     * Get enabled/disabled state
     */
    bool enabled();

    /**
     * Remove a breakpoint
     */
    void clear();

    /**
     * Return the machine address of the breakpoint
     */
    ulong address();
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
     * Return the thread which caused the target to stop.
     */
    TargetThread focusThread();

    /**
     * Return a set of all the threads in the target.
     */
    TargetThread[] threads();

    /**
     * Return a set of all the modules in the target.
     */
    TargetModule[] modules();

    /**
     * Read from the target's memory.
     */
    ubyte[] readMemory(ulong targetAddress, size_t bytes);

    /**
     * Write to the target's memory.
     */
    void writeMemory(ulong targetAddress, ubyte[] toWrite);

    /**
     * Step the target by one instruction. After this method returns,
     * the target will be stopped again.
     */
    void step(TargetThread t);

    /**
     * Allow a target in state STOPPED to continue. The target's state
     * changes to RUNNING. Call wait() to pause until the target stops
     * again (e.g. at a breakpoint).
     */
    void cont();

    /**
     * Wait for the target to receive an event which causes it to stop.
     */
    void wait();

    /**
     * Set a breakpoint at the given address. Return an object that
     * represents the breakpoint and which can be used to cancel it.
     */
    Breakpoint setBreakpoint(ulong addr);

    /**
     * Set a breakpoint at address associated with the given
     * expression (if any). Return an object that represents the
     * breakpoint and which can be used to cancel it.
     */
    Breakpoint setBreakpoint(string expr);
}

/**
 * This interface provides an abstraction to allow creating
 * targets or attaching to existing targets.
 */
interface TargetFactory
{
    /**
     * Return the name of the target factory (e.g. "process", "core" etc.).
     */
    char[]			name();

    /**
     * Create a new target instance with the given arguments.
     */
    Target			connect(TargetListener listener, char[][] args);
}
