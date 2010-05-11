/*-
 * Copyright (c) 2010 Doug Rabson
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

module target.remotetarget;

import target.target;
import objfile.objfile;
import objfile.elf;
import debuginfo.debuginfo;
import debuginfo.dwarf;
import debuginfo.types;
import machine.machine;
import machine.x86;

import std.ctype;
import std.socket;
import std.stdint;
import std.stdio;
import std.string;
import std.c.stdlib;
version (DigitalMars)
import std.c.posix.posix;
else
import std.c.unix.unix;

static import std.file;

class RemoteModule: TargetModuleBase
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
}

class RemoteThread: TargetThread
{
    this(RemoteTarget target, uint tid)
    {
	target_ = target;
	id_ = target.nextTid_++;
	tid_ = tid;
	state_ = target.modules_[0].getState(target);
    }

    void readState()
    {
        target_.sendReceive(std.string.format("Hg%x", tid_));
	auto regs = target_.sendReceive("g");
	uint regno = 0;
	uint off = 0;

	while (regs.length > 0) {
	    uint n;
	    try {
		n = state_.registerWidth(regno);
		off += n;
		if (regs[0] != 'x') {
		    auto regval = target_.decodeBytes(regs[0..2*n]);
		    state_.writeRegister(regno, regval);
		}
	    } catch (TargetException te) {
		break;
	    }
	    regs = regs[2*n..$];
	    regno++;
	}
    }

    void writeState()
    {
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

    RemoteTarget target_;
    uint id_;
    uint tid_;
}

class RemoteBreakpoint
{
    this(RemoteTarget target, TargetAddress addr)
    {
	target_ = target;
	addr_ = addr;
    }

    void activate()
    {
	/*
	 * Write a breakpoint instruction, saving what was there
	 * before.
	 */
	save_ = target_.readMemory(addr_,
                                   cast(TargetSize) target_.break_.length);
	target_.writeMemory(addr_, target_.break_);
    }

    void deactivate()
    {
	/*
	 * Disable by writing back our saved bytes.
	 */
	target_.writeMemory(addr_, save_);
	stoppedThreads_.length = 0;
    }

    TargetAddress address()
    {
	return addr_;
    }

    void addListener(TargetBreakpointListener tbl)
    {
	listeners_ ~= tbl;
    }

    void removeListener(TargetBreakpointListener tbl)
    {
	TargetBreakpointListener[] newListeners;

	foreach (t; listeners_)
	    if (t !is tbl)
		newListeners ~= t;
	listeners_ = newListeners;
    }

    bool matchListener(TargetBreakpointListener tbl)
    {
	foreach (t; listeners_)
	    if (t is tbl)
		return true;
	return false;
    }

    TargetBreakpointListener[] listeners()
    {
	return listeners_;
    }

private:
    RemoteTarget target_;
    TargetAddress addr_;
    TargetBreakpointListener[] listeners_;
    RemoteThread[] stoppedThreads_;
    ubyte[] save_;
}

private string signame(int sig)
{
    static string signames[] = [
	SIGHUP: "SIGHUP",
	SIGINT: "SIGINT",
	SIGQUIT: "SIGQUIT",
	SIGILL: "SIGILL",
	SIGTRAP: "SIGTRAP",
	SIGABRT: "SIGABRT",
	//SIGIOT: "SIGIOT",
	//SIGEMT: "SIGEMT",
	SIGFPE: "SIGFPE",
	SIGKILL: "SIGKILL",
	SIGBUS: "SIGBUS",
	SIGSEGV: "SIGSEGV",
	SIGSYS: "SIGSYS",
	SIGPIPE: "SIGPIPE",
	SIGALRM: "SIGALRM",
	SIGTERM: "SIGTERM",
	SIGURG: "SIGURG",
	SIGSTOP: "SIGSTOP",
	SIGTSTP: "SIGTSTP",
	SIGCONT: "SIGCONT",
	SIGCHLD: "SIGCHLD",
	SIGTTIN: "SIGTTIN",
	SIGTTOU: "SIGTTOU",
	SIGIO: "SIGIO",
	SIGXCPU: "SIGXCPU",
	SIGXFSZ: "SIGXFSZ",
	SIGVTALRM: "SIGVTALRM",
	SIGPROF: "SIGPROF",
	SIGWINCH: "SIGWINCH",
	//SIGINFO: "SIGINFO",
	SIGUSR1: "SIGUSR1",
	SIGUSR2: "SIGUSR2",
	//SIGTHR: "SIGTHR",
	//SIGLWP: "SIGLWP",
	//SIGRTMIN: "SIGRTMIN",
	//SIGRTMAX: "SIGRTMAX"
	];

    if (sig >= 0 && sig < signames.length)
	return signames[sig];
    else
	return std.string.format("SIG%d", sig);
}

class RemoteTarget: Target
{
    this(TargetListener listener, string execname, string host, string port)
    {
	listener_ = listener;
	execname_ = execname;

	try {
	    Service s = new Service;
	    if (!s.getServiceByName(port))
		s.port = std.string.atoi(port);

	    address_ = new InternetAddress(host, s.port);

	    sock_ = new Socket(AddressFamily.INET, SocketType.STREAM);
	    sock_.connect(address_);
	    sock_.setOption(SocketOptionLevel.TCP,
			    SocketOption.TCP_NODELAY, 1);
	} catch (SocketException se) {
	    throw new TargetException("Can't connect to "
				      ~ host ~ ":" ~ port);
	}

	listener.onTargetStarted(this);
	modules_ ~= new RemoteModule(execname_, cast(TargetAddress) 0);
	listener_.onModuleAdd(this, modules_[0]);

	sendPacket("?");
	readState(false);
    }

    ~this()
    {
	modules_ = null;
	threads_ = null;
	listener_ = null;
    }

    uint fromhex(char c)
    {
	if (c >= '0' && c <= '9')
	    return c - '0';
	else if (c >= 'A' && c <= 'F')
	    return c - 'A' + 10;
	else if (c >= 'a' && c <= 'f')
	    return c - 'a' + 10;
	else
	    throw new TargetException("Invalid hex digit");
    }

    ulong fromhex(string s)
    {
	ulong v = 0;
	foreach (c; s)
	    v = v * 16 + fromhex(c);
	return v;
    }

    ubyte[] decodeBytes(string s)
    {
	if ((s.length % 2) != 0)
	    throw new TargetException("expected even number of hex digits");
	ubyte[] res;
	res.length = s.length / 2;
	for (auto i = 0; i < res.length; i++)
	    res[i] = fromhex(s[2*i..2*i+2]);
	return res;
    }

    string encodeBytes(ubyte[] ba)
    {
	static string hexdigits = "0123456789abcdef";
    	string res;
	res.length = ba.length * 2;
	foreach (i, b; ba) {
	    res[2*i] = hexdigits[ba[i] >> 4];
	    res[2*i+1] = hexdigits[ba[i] & 0x0f]; 
	}
	return res;
    }

    void sendPacket(string packet)
    {
	debug (remote)
	    writef("sent: '%s', ", packet);

	int csum = 0;
	foreach (c; packet)
	    csum += c;
	string p = std.string.format("$%s#%02x", packet, csum & 0xff);

	char ack;
	do {
	    if (send(p) != p.length)
		throw new TargetException("Can't send packet");
	    ack = receiveChar;
	    if (ack != '+' && ack != '-')
		throw new TargetException("Protocol error reading packet status");
	    //writefln("sent: '%s', received: '%c'", p, ack);
	} while (ack != '+');
    }

    string receivePacket()
    {
	string p;
	string rxcsum;
	ubyte csum;
	char ch;

	for (;;) {
	    p = null;
	    rxcsum = null;
	    csum = 0;
	    do
		ch = receiveChar;
	    while (ch != '$');
	    for (;;) {
		ch = receiveChar;
		if (ch == '#')
		    break;
		if (ch == '*') {
		    /*
		     * Run length encoding
		     */
		    csum += ch;
		    ch = receiveChar;
		    csum += ch;
		    uint repeat = ch - 29;
		    if (repeat > 0 && p.length > 0) {
			char rep = p[p.length - 1];
			auto off = p.length;
			p.length = p.length + repeat;
			while (repeat > 0) {
			    p[off++] = rep;
			    repeat--;
			}
		    }
		} else {
		    csum += ch;
		    p ~= ch;
		}
	    }
	    ch = receiveChar;
	    if (!isxdigit(ch))
		throw new TargetException("Can't read packet csum");
	    rxcsum ~= ch;
	    ch = receiveChar;
	    if (!isxdigit(ch))
		throw new TargetException("Can't read packet csum");
	    rxcsum ~= ch;

	    if (fromhex(rxcsum) == csum) {
		send("+");
		debug (remote)
		    writefln("received: '%s'", p);
		return p;
	    } else {
		send("-");
		continue;
	    }
	}
    }

    string sendReceive(string packet)
    {
	sendPacket(packet);
	return receivePacket;
    }

    bool readState(bool checkBreakpoints)
    {
	uint sig = 0;
	uint thread = 0;
	bool ret = true;
    outer:
	for (;;) {
	    string p = receivePacket;
	    //writefln("status: '%s'", p);

	    if (p.length < 1)
		throw new TargetException("Protocol error receiving status");

	    switch (p[0]) {
	    case 'O':
		writef("%s", decodeBytes(p[1..$]));
		continue;
		       
	    case 'W':
		state_ = TargetState.EXIT;
		listener_.onExit(this);
		return true;

	    case 'X':
		state_ = TargetState.EXIT;
		listener_.onExit(this);
		return true;

	    case 'S':
		state_ = TargetState.STOPPED;
		sig = fromhex(p[1..$]);
		break outer;

	    case 'T':
		state_ = TargetState.STOPPED;
		sig = fromhex(p[1..3]);
		p = p[3..$];
		while (p.length > 0) {
		    int i1 = p.find(':');
		    int i2 = p.find(';');
		    if (i1 < 0 || i2 < 0 || i1 > i2)
			throw new TargetException(
			    "Protocol error receiving status");

		    string regname = p[0..i1];
		    string regval = p[i1+1..i2];

		    if (regname == "thread")
			thread = fromhex(regval);

		    p = p[i2+1..$];
		}
		break outer;

	    default:
		throw new TargetException("Protocol error receiving status");
	    }
	}

	uint[] newThreads;

	RemoteThread[uint] oldThreads;
	foreach (tid, t; threads_)
	    oldThreads[tid] = t;

	bool first = true;
	for (;;) {
	    string res;
	    if (first)
		res = sendReceive("qfThreadInfo");
	    else
		res = sendReceive("qsThreadInfo");
	    first = false;
	    if (res == "l")
		break;
	    res = res[1..$];
	    auto tids = split(res, ",");
	    foreach (s; tids) {
		uint tid = fromhex(s);
		newThreads ~= tid;
	    }
	}

	foreach (ntid; newThreads) {
	    if (ntid in threads_) {
		oldThreads.remove(ntid);
		continue;
	    }
	    if (currentThread_ == 0)
		currentThread_ = ntid;
	    RemoteThread t = new RemoteThread(this, ntid);
	    if (break_.length == 0)
		break_ = t.state_.breakpoint;
	    listener_.onThreadCreate(this, t);
	    threads_[ntid] = t;
	}
	foreach (otid, t; oldThreads) {
	    listener_.onThreadDestroy(this, t);
	    threads_.remove(otid);
	}

	foreach (t; threads_.values)
	    t.readState;

	if (thread)
	    currentThread_ = thread;

	if (breakpointsActive_) {
	    foreach (bp; breakpoints_)
		bp.deactivate;
	    breakpointsActive_ = false;
	}
	auto t = threads_[currentThread_];

	if (sig == SIGTRAP) {
	    if (checkBreakpoints) {
		/*
		 * A thread stopped at a breakpoint. Adjust its PC
		 * accordingly and find out what stopped it,
		 * informing our listener as appropriate.
		 */
		t.adjustPcAfterBreak;
		foreach (bp; breakpoints_.values) {
		    if (t.pc == bp.address) {
			bp.stoppedThreads_ ~= t;
			ret = false;
			foreach (tbl; bp.listeners) {
			    debug(breakpoints)
				writefln("hit breakpoint at 0x%x for 0x%x",
					 t.pc,
					 cast(TargetAddress) cast(void*) tbl);
			    if (tbl.onBreakpoint(this, t))
				ret = true;
			}
		    }
		}
	    }
	} else {
	    listener_.onSignal(this, t, sig, signame(sig));
	}
	return ret;
    }

    size_t send(string buf)
    {
	return sock_.send(buf);
    }

    char receiveChar()
    {
	if (receivePtr_ == receiveLen_) {
	    int n;
	    if ((n = sock_.receive(receiveBuf_)) <= 0)
		throw new TargetException("Can't receive from socket");
	    receiveLen_ = n;
	    receivePtr_ = 0;
	}
	return receiveBuf_[receivePtr_++];
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
	    ubyte[] doReadMemory(TargetAddress targetAddress, TargetSize bytes)
	    {
		ubyte[] mem;

		while (bytes > 0) {
		    int n;
		    if (bytes > 200)
			n = 200;
		    else
			n = bytes;
		    string cmd = std.string.format("m%x,%x", targetAddress, n);
		    auto res = sendReceive(cmd);
		    if (res == "error" || res[0] == 'E')
			throw new TargetException("Can't read memory");
		    mem ~= decodeBytes(res);
		    n = res.length / 2;
		    targetAddress += n;
		    bytes -= n;
		}
		return mem;
	    }

	    /*
	     * Make sure we have cache pages for the region being read
	     * and paste together the result.
	     */
	    auto start = cast(TargetAddress) (targetAddress & ~CACHE_PAGEMASK);
	    auto end = cast(TargetAddress) ((targetAddress + bytes
					     + CACHE_PAGEMASK)
					    & ~CACHE_PAGEMASK);
	    ubyte[] res;

	    auto addr = start;
	    while (addr < end) {
		if (!(addr in cache_)) {
		    auto mem = doReadMemory(addr, CACHE_PAGESIZE);
		    cache_[addr] = mem;
		}
		res ~= cache_[addr];
		addr += CACHE_PAGESIZE;
	    }

	    /*
	     * Trim the result to the actual range requested.
	     */
	    auto si = targetAddress - start;
	    auto ei = si + bytes;
	    return res[si..ei];
	}

	void writeMemory(TargetAddress targetAddress, ubyte[] toWrite)
	{
	    auto start = targetAddress;
	    auto end = cast(TargetAddress) (start + toWrite.length);
	    auto addr = start;

	    /*
	     * Update any cache pages that overlap the area we are
	     * writing.
	     */
	    while (addr < end) {
		auto next = cast(TargetAddress)
		    ((start + CACHE_PAGESIZE) & ~CACHE_PAGEMASK);
		auto addrMasked = cast(TargetAddress)
		    (addr & ~CACHE_PAGEMASK);
		if (next > end)
		    next = end;

		if (addrMasked in cache_) {
		    auto si = addr - addrMasked;
		    auto ei = next - addrMasked;
		    auto n = ei - si;
		    debug (cache)
			writefln("setting [%#x][%d..%d] = toWrite[%d..%d]",
				 addrMasked, si, ei,
				 addr - start, next - start);
		    cache_[addrMasked][si..ei] =
			toWrite[addr - start..next - start];
		}
		addr = next;
	    }

	    auto s = sendReceive(std.string.format("M%x,%x:%s",
			targetAddress, toWrite.length,
			encodeBytes(toWrite)));
	    if (s[0] == 'E')
		throw new TargetException("Can't write memory");
	}

	void step(TargetThread t)
	{
	    cache_ = null;
	    auto rt = cast(RemoteThread) t;
	    rt.writeState;
	    state_ = TargetState.RUNNING;
            sendReceive(std.string.format("Hs%x", rt.tid_));
	    sendPacket("s");
	    wait;
	}

	void cont(int sig)
	{
	    cache_ = null;

	    foreach (t; threads_)
		t.writeState;
	    foreach (bp; breakpoints_) {
		foreach (t; bp.stoppedThreads_) {
			debug(breakpoints)
			    writefln("stepping thread %d over breakpoint at 0x%x",
				     t.id, t.pc);
			step(t);
			debug(breakpoints)
			    writefln("after step, thread %d pc is 0x%x",
				     t.id, t.pc);
		    }
		bp.stoppedThreads_.length = 0;
	    }

	    foreach (bp; breakpoints_)
		bp.activate;
	    breakpointsActive_ = true;

	    state_ = TargetState.RUNNING;
	    if (sig)
		sendPacket(std.string.format("c%02x", sig));
	    else
		sendPacket("c");
	}

	void wait()
	{
	    while (!readState(true)) {}
	}

	void setBreakpoint(TargetAddress addr, TargetBreakpointListener tbl)
	{
	    debug(breakpoints)
		writefln("setting breakpoint at 0x%x for 0x%x", addr,
			 cast(TargetAddress) cast(void*) tbl);
	    if (addr in breakpoints_) {
		breakpoints_[addr].addListener(tbl);
	    } else {
		auto  bp = new RemoteBreakpoint(this, addr);
		bp.addListener(tbl);
		breakpoints_[addr] = bp;
	    }
	}

	void clearBreakpoint(TargetBreakpointListener tbl)
	{
	    debug(breakpoints)
		writefln("clearing breakpoints for 0x%x",
			 cast(TargetAddress) cast(void*) tbl);
	    RemoteBreakpoint[TargetAddress] newBreakpoints;
	    foreach (addr, bp; breakpoints_) {
		if (bp.matchListener(tbl)) {
		    bp.removeListener(tbl);
		}
		if (bp.listeners.length > 0)
		    newBreakpoints[addr] = bp;
	    }
	    breakpoints_ = newBreakpoints;
	}
    }

private:
    /*
     * To reduce wire traffic, we cache memory read from the
     * target. The cache page size is chosen to fit easily within the
     * typical 400 byte maximum buffer size found in some remote
     * debugger stubs.
     */
    const TargetSize CACHE_PAGESIZE = cast(TargetSize) 128;
    const TargetSize CACHE_PAGEMASK = cast(TargetSize) (CACHE_PAGESIZE - 1);

    TargetState state_ = TargetState.EXIT;
    uint nextTid_ = 1;
    RemoteModule[] modules_;
    RemoteThread[uint] threads_;
    RemoteBreakpoint[TargetAddress] breakpoints_;
    uint currentThread_ = 0;
    TargetListener listener_;
    string execname_;
    bool breakpointsActive_ = false;
    InternetAddress address_;
    Socket sock_;
    char[512] receiveBuf_;
    size_t receivePtr_ = 0;
    size_t receiveLen_ = 0;
    ubyte[][TargetAddress] cache_;
    ubyte[] break_;		// breakpoint instruction
}

class RemoteFactory: TargetFactory
{
    override
    {
        static this()
        {
            TargetFactory.register(new RemoteFactory);
        }

	string name()
	{
	    return "remote";
	}

	Target connect(TargetListener listener, string[] args)
	{
            string execname;
	    string address;
            
	    if (args.length < 2)
		throw new Exception("too few arguments to target remote");
	    if (args.length > 2)
		throw new Exception("too many arguments to target remote");

            execname = args[0];
	    address = args[1];

	    int i = find(address, ':');
	    if (i < 0)
		throw new Exception("colon expected in address");

	    string port = address[i+1..$];
	    string host = address[0..i];
	    if (host == null)
		host = "localhost";

            return new RemoteTarget(listener, execname, host, port);
	}
    }
}
