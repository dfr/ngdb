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

module target.coldtarget;

import target.target;
import objfile.objfile;
import objfile.elf;
import debuginfo.debuginfo;
import debuginfo.dwarf;
import debuginfo.types;
import machine.machine;
import machine.x86;

import std.stdint;
import std.stdio;
import std.string;
import std.c.stdlib;
version (DigitalMars)
import std.c.posix.posix;
else
import std.c.unix.unix;

static import std.file;

class ColdModule: TargetModuleBase
{
    this(string filename, TargetAddress addr)
    {
	TargetAddress start, end;

	void setLimits(uint tag, TargetAddress s, TargetAddress e)
	{
	    if (tag != PT_LOAD)
		return;
	    if (s < start)
		start = s;
	    if (e > end)
		end = e;
	}

	start = cast(TargetAddress) TargetAddress.max;
	end = cast(TargetAddress) 0;
	auto obj = cast(Elffile) Objfile.open(filename, addr);
	if (!obj)
	    throw new TargetException("Can't open file");
	obj.enumerateProgramHeaders(&setLimits);

	super(filename, start, end);
	init;
    }

    string interpreter()
    {
	if (obj_)
	    return obj_.interpreter;
	return null;
    }

    void enumerateNeededLibraries(Target target,
				  void delegate(string) dg)
    {
	if (obj_)
	    obj_.enumerateNeededLibraries(target, dg);
    }

    void digestDynamic(Target target)
    {
	if (obj_) {
	    auto elf = cast(Elffile) obj_;
	    if (!elf)
		return;
	    elf.digestDynamic(target);
	}
    }

    ubyte[] readMemory(TargetAddress targetAddress, TargetSize bytes)
    {
	if (obj_) {
	    auto elf = cast(Elffile) obj_;
	    if (!elf)
		return null;
	    return elf.readProgram(targetAddress, bytes);
	}
	return null;
    }
}

class ColdThread: TargetThread
{
    this(ColdTarget target, ubyte* p)
    {
	target_ = target;
	id_ = target.nextTid_++;
	state_ = target.modules_[0].getState(target);
	if (p)
	    setGRs(p);
	else if (target.modules_[0].obj_)
	    this.pc = target.modules_[0].obj_.entry;
    }

    override {
	Target target()
	{
	    return target_;
	}
	uint id()
	{
	    return id_;
	}
    }

    mixin TargetThreadBase;

    ColdTarget target_;
    uint id_;
}

struct prstatus32
{
    int32_t pr_version;		// must be 1
    uint32_t pr_statussz;
    uint32_t pr_gregsetsz;
    uint32_t pr_fpregsetsz;
    int32_t pr_osreldate;
    int32_t pr_cursig;
    int32_t pr_pid;
}

private string pathSearch(string path, string name)
{
    string execpath = "";

    execpath = name;
    if (find(execpath, "/") < 0) {
	string[] paths = split(path, ":");
	foreach (p; paths) {
	    string s = p ~ "/" ~ execpath;
	    if (std.file.exists(s) && std.file.isfile(s)) {
		execpath = s;
		break;
	    }
	}
    } else {
	if (!std.file.exists(execpath) || !std.file.isfile(execpath))
	    execpath = "";
    }
    return execpath;
}

class ColdTarget: Target
{
    this(TargetListener listener, string execname, string corename)
    {
	listener_ = listener;
	execname_ = execname;
	corename_ = corename;
	if (corename_)
            core_ = cast(Elffile) Objfile.open(corename_,
                                               cast(TargetAddress) 0);

	listener.onTargetStarted(this);

	try {
	    modules_ ~= new ColdModule(execname_, cast(TargetAddress) 0);
	    listener_.onModuleAdd(this, modules_[0]);
	} catch (TargetException e) {
	    return;
	}

	if (core_) {
	    void getThread(uint type, string name, ubyte* desc)
	    {
		if (type != NT_PRSTATUS)
		    return;
		prstatus32* pr = cast(prstatus32*) desc;
		auto t = new ColdThread(this, desc + prstatus32.sizeof);
		threads_ ~= t;
		listener_.onThreadCreate(this, t);
		static if (false)
		    if (pr.pr_cursig)
			listener_.onSignal(this, t, pr.pr_cursig,
					   signame(pr.pr_cursig));
	    }

	    void findCoreModules(string name, TargetAddress lm, TargetAddress addr)
	    {
		foreach (mod; modules_)
		    if (mod.filename == name)
			return;
		auto mod = new ColdModule(name, addr);
		modules_ ~= mod;
		listener_.onModuleAdd(this, mod);
	    }

	    modules_[0].digestDynamic(this);
	    modules_[0].enumerateLinkMap(this, &findCoreModules);

	    core_.enumerateNotes(&getThread);
	    if (threads_.length == 0) {
		threads_ ~= new ColdThread(this, null);
		listener_.onThreadCreate(this, threads_[0]);
	    }
	} else {
	    size_t i = 0;
	    TargetAddress addr = cast(TargetAddress) 0x28070000;
	    string interp = modules_[0].interpreter;
	    if (interp) {
		auto mod = new ColdModule(interp, addr);
		addr = cast(TargetAddress)
                    ((mod.end + 0xfff) & ~0xfff); // XXX pagesize
		modules_ ~= mod;
		listener_.onModuleAdd(this, mod);
	    }
	    while (i < modules_.length) {
		void neededLib(string name)
		{
		    name = pathSearch("/lib:/usr/lib", name);
		    foreach (mod; modules_)
			if (mod.filename == name)
			    return;
		    auto mod = new ColdModule(name, addr);
		    addr = cast(TargetAddress)
                        ((mod.end + 0xfff) & ~0xfff); // XXX pagesize
		    modules_ ~= mod;
		    listener_.onModuleAdd(this, mod);
		}

		modules_[i].enumerateNeededLibraries(this, &neededLib);
		i++;
	    }

	    threads_ ~= new ColdThread(this, null);
	    listener_.onThreadCreate(this, threads_[0]);
	}
    }

    ~this()
    {
	modules_ = null;
	threads_ = null;
	listener_ = null;
    }

    override
    {
	TargetState state()
	{
	    return state_;
	}

	TargetAddress entry()
	{
	    if (modules_.length > 0)
		return modules_[0].obj_.entry;
	    else
		return cast(TargetAddress) 0;
	}

	ubyte[] readMemory(TargetAddress targetAddress, TargetSize bytes)
	{
	    if (core_) {
		bool readcore = false;
		void checkAddress(uint tag, TargetAddress s, TargetAddress e)
		{
		    if (tag != PT_LOAD)
			return;
		    if (targetAddress + bytes > s && targetAddress < e)
			readcore = true;
		}
		core_.enumerateProgramHeaders(&checkAddress);
		if (readcore)
		    return core_.readProgram(targetAddress, bytes);
	    }
	    foreach (mod; modules_) {
		if (targetAddress + bytes > mod.start
		    && targetAddress < mod.end)
		    return mod.readMemory(targetAddress, bytes);
	    }
	    throw new TargetException("Can't read memory");
	}

	void writeMemory(TargetAddress targetAddress, ubyte[] toWrite)
	{
	    throw new TargetException("Can't write memory");
	}

	void step(TargetThread t)
	{
	}

	void cont(int)
	{
	}

	void wait()
	{
	}

	void setBreakpoint(TargetAddress, TargetBreakpointListener)
	{
	}

	void clearBreakpoint(TargetBreakpointListener)
	{
	}
    }

private:
    TargetState state_ = TargetState.EXIT;
    uint nextTid_ = 1;
    ColdModule[] modules_;
    ColdThread[] threads_;
    TargetListener listener_;
    string execname_;
    string corename_;
    Elffile core_;
}

class ColdFactory: TargetFactory
{
    override
    {
        static this()
        {
            TargetFactory.register(new ColdFactory);
        }

	string name()
	{
	    return "core";
	}

	Target connect(TargetListener listener, string[] args)
	{
            string execname, corename;
            
	    if (args.length < 1)
		throw new Exception("too few arguments to target core");
	    if (args.length > 2)
		throw new Exception("too many arguments to target core");

            execname = args[0];
            if (args.length == 2)
                args[1] = corename;

            return new ColdTarget(listener, corename, execname);
	}
    }
}