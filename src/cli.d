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

module cli;

//debug = step;

version = editline;

version (editline)
	import editline;
import target.target;
import target.ptracetarget;
import target.coldtarget;
import debuginfo.debuginfo;
import debuginfo.expr;
import debuginfo.language;
import debuginfo.types;
import machine.machine;

version (DigitalMars)
import std.c.posix.posix;
else
import std.c.unix.unix;
import std.c.stdlib;
import std.conv;
import std.ctype;
static import std.path;
import std.string;
import std.stdio;
import std.file;
import std.c.stdio;
import std.cstream;

extern (C) char* readline(char*);
extern (C) void add_history(char*);
extern (C) void free(void*);

/**
 * A CLI command
 */
class Command
{
    /**
     * Return the command name.
     */
    abstract string name();

    /**
     * Return the command short name, if any.
     */
    string shortName()
    {
	return null;
    }

    /**
     * Return the command description.
     */
    abstract string description();

    /**
     * Execute the command
     */
    abstract void run(Debugger db, string args);

    /**
     * Called when an action which sets the current source file and
     * line happens.
     */
    void onSourceLine(Debugger db, SourceFile sf, uint line)
    {
    }

    /**
     * Called for command line completion.
     */
    string[] complete(Debugger db, string args)
    {
	return null;
    }

    /**
     * Return true if this is a builtin command
     */
    bool builtin()
    {
	return true;
    }

    /**
     * Support for .sort.
     */
    int opCmp(Object obj)
    {
        Command c = cast(Command) obj;
        if (c) {
            return std.string.cmp(name, c.name);
        } else {
            return -1;
        }
    }
}

class CommandTable
{
    /**
     * Return command name, set args to command arguments.
     */
    string parse(string cmd, out string args)
    {
	string name;

        int i = -1;
	int i1 = find(cmd, '/');
        if (i1 >= 0)
            i = i1;
	int i2 = find(cmd, ' ');
        if (i2 >= 0)
            i = i < 0 ? i2 : (i2 < i ? i2 : i);

	if (i >= 0) {
	    name = strip(cmd[0..i]);
	    args = strip(cmd[i..$]);
	} else {
	    name = cmd;
	    args = "";
	}

	return name;
    }

    void run(Debugger db, string cmd, string prefix)
    {
	string message;
	string name, args;

	name = parse(cmd, args);
	Command c = lookup(name, message);
	if (c)
	    c.run(db, args);
	else
	    writefln("Command %s%s is %s", prefix, name, message);
    }

    void add(Command c)
    {
	if (c.name in list_) {
	    auto s = list_[c.name].shortName;
	    list_.remove(c.name);
	    if (s)
		shortNames_.remove(s);
	}
	list_[c.name] = c;
	auto s = c.shortName;
	if (s)
	    shortNames_[s] = c.name;
    }

    Command lookup(string name, out string message)
    {
	if (name in shortNames_)
	    name = shortNames_[name];
	auto cp = (name in list_);
	if (cp) {
	    return *cp;
	} else {
	    /*
	     * Try to match a prefix of some command. If nothing
	     * matches or the given prefix is ambiguous, throw an
	     * exception.
	     */
	    Command[] matches;

	    foreach (c; list_) {
		string s = c.name;
		if (s.length > name.length)
		    if (s[0..name.length] == name)
			matches ~= c;
	    }
	    if (matches.length == 0) {
		message = "unrecognised";
		return null;
	    }
	    if (matches.length > 1) {
		message = "ambiguous";
		return null;
	    }
	    return matches[0];
	}
    }

    string[] complete(Debugger db, string cmd)
    {
	string name, args;

	name = parse(cmd, args);
	if (args.length == 0) {
	    string[] matches;
	    foreach (c; list_) {
		string s = c.name;
		if (s.length >= name.length)
		    if (s[0..name.length] == name)
			matches ~= s[name.length..$];
	    }
	    return matches;
	}

	string message;
	Command c = lookup(name, message);
	if (c)
	    return c.complete(db, args);
	else
	    return null;
    }

    void onSourceLine(Debugger db, SourceFile sf, uint line)
    {
	foreach (c; list_)
	    c.onSourceLine(db, sf, line);
    }

    Command[string] list_;
    string[string] shortNames_;
}

private class Breakpoint: TargetBreakpointListener
{
    this(Debugger db, SourceFile sf, uint line)
    {
	db_ = db;
	sf_ = sf;
	line_ = line;
    }

    this(Debugger db, string func)
    {
	db_ = db;
	func_ = func;
    }

    bool onBreakpoint(Target, TargetThread t)
    {
	db_.currentThread = t;
	if (condition_) {
	    db_.setCurrentFrame;
	    auto f = db_.currentFrame;
	    auto sc = f.scope_;
	    try {
		auto v = expr_.eval(sc, t).toValue;
		if (v.type.isIntegerType)
		    if (!t.readInteger(v.loc.readValue(t)))
			return false;
	    } catch (EvalException ex) {
		db_.pagefln("Error evaluating breakpoint condition: %s", ex.msg);
		return true;
	    }
	}
	writefln("Stopped at breakpoint %d", id);
	if (commands_) {
	    db_.stopped();
	    db_.executeMacro(commands);
	}
	return true;
    }

    string condition()
    {
	return condition_;
    }

    void condition(string s)
    {
	if (s == null)
	    writefln("Breakpoint %d is now unconditional", id);

	/*
	 * Try to guess a source language for parsing the expression.
	 */
	Language lang;
	gotLang: foreach (address; addresses_) {
	    foreach (mod; db_.modules_) {
		auto di = mod.debugInfo;
		if (di)
		    lang = di.findLanguage(address);
		if (lang)
		    break gotLang;
	    }
	}
	if (!lang)
	    lang = CLikeLanguage.instance;
	try {
	    auto e = lang.parseExpr(s, db_);
	    condition_ = s;
	    expr_ = e;
	} catch (EvalException ex) {
	    db_.pagefln("Error parsing breakpoint condition: %s", ex.msg);
	}
    }

    string[] commands()
    {
	return commands_;
    }

    void commands(string[] cmds)
    {
	commands_ = cmds;
    }

    void activate(TargetModule mod)
    {
	DebugInfo di = mod.debugInfo;
	int pos;

	LineEntry[] lines;
	bool found;
	if (sf_ !is null) {
	    if (di)
		found = di.findLineByName(sf_.filename, line_, lines);
	} else {
	    if (di)
		found = di.findLineByFunction(func_, lines);
	    if (!found) {
		TargetSymbol sym;
		if (mod.lookupSymbol(func_, sym) && sym.value) {
		    LineEntry le;
		    le.address = sym.value;
		    lines ~= le;
		    found = true;
		}
	    }
	}
	if (found) {
	    Function func = null;
	    foreach (le; lines) {
		/*
		 * In optimised code we can get several line entries for
		 * the same source line - take only the first one.
		 * XXX possibly remove this if it causes problems with
		 * inlines.
		 */
		if (di) {
		    Function f = di.findFunction(le.address);
		    if (func && f == func)
			continue;
		    func = f;
		}
		db_.target_.setBreakpoint(le.address, this);
		addresses_ ~= le.address;
	    }
	}
    }

    void deactivate(TargetModule mod)
    {
	TargetAddress[] newAddresses;

	foreach (addr; addresses_)
	    if (!mod.contains(addr))
		newAddresses ~= addr;
	addresses_ = newAddresses;
    }

    void disable()
    {
	if (enabled_) {
	    if (addresses_.length > 0)
		db_.target_.clearBreakpoint(this);
	    enabled_ = false;
	}
    }

    void enable()
    {
	if (!enabled_) {
	    foreach (address; addresses_)
		db_.target_.setBreakpoint(address, this);
	    enabled_ = true;
	}
    }

    void onExit()
    {
	addresses_.length = 0;
    }

    bool active()
    {
	return addresses_.length > 0;
    }

    uint id()
    {
	return id_;
    }

    bool enabled()
    {
	return enabled_;
    }

    TargetAddress[] addresses()
    {
	return addresses_;
    }

    string expr()
    {
	if (sf_)
	    return format("%s:%d", sf_.filename, line_);
	else
	    return func_;
    }

    bool matches(ulong pc)
    {
	foreach (addr; addresses_)
	    if (pc == addr)
		return true;
	return false;
    }

    static void printHeader()
    {
	writefln("%-3s %-3s %-18s %s",
		 "Id", "Enb", "Address", "Where");
    }

    void print()
    {
	if (addresses_.length > 0) {
	    bool first = true;
	    foreach (addr; addresses_) {
		if (first)
		    writef("%-3d %-3s %#-18x ",
			   id, enabled ? "y" : "n", addr);
		else
		    writef("        %#-18x ", addr);
		first = false;
		writefln("%s", db_.describeAddress(addr, null));
	    }
	} else {
	    writefln("%-3d %-3s %-18s %s",
		     id,  enabled ? "y" : "n", " ", expr);
	}
	if (condition_)
	    writefln("\tstop only if %s", condition_);
        foreach (cmd; commands_)
	    writefln("\t%s", cmd);
    }

    SourceFile sf_;
    uint line_;
    string func_;
    string condition_;
    string[] commands_;
    Expr expr_;
    bool enabled_ = true;
    Debugger db_;
    uint id_;
    TargetAddress[] addresses_;
}

private class SourceFile
{
    this(string filename)
    {
	filename_ = filename;
	long ftc, fta;
    }

    string opIndex(uint lineno)
    {
	long ftc, fta, ftm;
	if (lines_.length == 0 && !error_) {
	    try {
		string file = cast(string) std.file.read(filename);
		std.file.getTimes(filename_, ftc, fta, lastModifiedTime_);
		lines_ = splitlines(file);
	    } catch {
		writefln("Can't open file %s", filename);
		error_ = true;
	    }
	}
	if (lineno < 1 || lineno > lines_.length)
	    return null;
	std.file.getTimes(filename_, ftc, fta, ftm);
	if (ftm != lastModifiedTime_) {
	    lines_ = null;
	    return opIndex(lineno);
	}
	return lines_[lineno - 1];
    }

    size_t length()
    {
        return lines_.length;
    }

    string filename()
    {
	return filename_;
    }

    string filename_;
    long lastModifiedTime_;
    string[] lines_;
    bool error_;
}

private class Frame
{
    this(Debugger db, uint index, Frame inner,
	 DebugInfo di, Function func, MachineState state)
    {
	db_ = db;
	index_ = index;
	inner_ = inner;
	if (inner_)
	    inner_.outer_ = this;
	di_ = di;
	func_ = func;
	state_ = state;
	Location loc;
	if (di) {
	    di.findFrameBase(state, loc);
	    addr_ = loc.address(state);
	    lang_ = di.findLanguage(state.pc);
	} else {
	    addr_ = 0;
	    lang_ = CLikeLanguage.instance;
	}

	auto sc = new UnionScope;
	Value thisvar;
	if (func_ && func_.thisArgument(thisvar)) {
	    PointerType ptrTy =
		cast (PointerType) thisvar.type.underlyingType;
	    if (ptrTy) {
		Value v = ptrTy.dereference(state_, thisvar.loc);
		CompoundType cTy = cast (CompoundType) v.type;
		sc.addScope(new CompoundScope(cTy, v.loc, state_));
	    }
	}
	if (func_)
		sc.addScope(func_);
	sc.addScope(db_);
	sc.addScope(state_);
	scope_ = sc;
    }
    string toString()
    {
	return format("#%-2d %s", index_,
		      db_.describeAddress(state_.pc, state_));
    }

    /**
     * Return the index of this frame.
     */
    uint index()
    {
	return index_;
    }

    /**
     * Return the next outer stack frame, if any
     */
    Frame outer()
    {
	if (outer_)
	    return outer_;

	if (!di_)
	    return null;

	auto s = di_.unwind(state_);
	if (!s)
	    return null;
	DebugInfo di;
	if (!db_.findDebugInfo(s, di))
	    return null;
	auto func = di.findFunction(s.pc);
	if (!func)
	    return null;
	return new Frame(db_, index_ + 1, this, di, func, s);
    }

    /**
     * Return the next inner stack frame, if any
     */
    Frame inner()
    {
	return inner_;
    }

    Debugger db_;
    uint index_;
    Frame inner_;
    Frame outer_;
    DebugInfo di_;
    Function func_;
    Language lang_;
    Scope scope_;
    MachineState state_;
    ulong addr_;
}

class PagerQuit: Exception
{
    this()
    {
	super("Quit");
    }
}

class DebuggerException: Exception
{
    this(string msg)
    {
        super(msg);
    }
}

/**
 * Return a copy of list with all duplicates removed.
 */
private string[] uniq(string[] list)
{
    bool[string] map;

    foreach (s; list)
	map[s] = true;
    return map.keys;
}

/**
 * Implement a command line interface to the debugger.
 */
class Debugger: TargetListener, TargetBreakpointListener, Scope
{
    this(string prog, string core)
    {
	prog_ = prog;
	core_ = core;
	prompt_ = "(ngdb)";

	version (editline) {
	    HistEvent ev;
	    hist_ = history_init();
	    history(hist_, &ev, H_SETSIZE, 100);

	    el_ = el_init(toStringz("ngdb"), stdin, stdout, stderr);
	    el_set(el_, EL_CLIENTDATA, cast(void*) this);
	    el_set(el_, EL_EDITOR, toStringz("emacs"));
	    el_set(el_, EL_SIGNAL, 1);
	    el_set(el_, EL_PROMPT, &_prompt);
	    el_set(el_, EL_HIST, &history, hist_);
	    el_set(el_, EL_ADDFN, toStringz("ed-complete"), toStringz("Complete argument"), &_complete);
	    el_set(el_, EL_BIND, toStringz("^I"), toStringz("ed-complete"), null);
	}

	nextBPID_ = 1;
    }

    ~this()
    {
	version (editline) {
	    history_end(hist_);
	    el_end(el_);
	}
    }

    static extern(C) void ignoreSig(int)
    {
    }

    bool interactive()
    {
	return interactive_;
    }

    void sourceFile(string filename)
    {
	string file = cast(string) std.file.read(filename);
	executeMacro(splitlines(file));
    }

    void executeMacro(string[] lines)
    {
	bool oldInteractive = interactive_;
	string[] oldSourceLines = sourceLines_;
	sourceLines_ = lines;
	interactive_ = false;
	while (sourceLines_.length > 0) {
	    string cmd = inputline("");
	    if (cmd.length > 0)
		executeCommand(cmd);
	}
	interactive_ = oldInteractive;
	sourceLines_ = oldSourceLines;
    }

    void prompt(string s)
    {
	prompt_ = s;
    }

    string inputline(string prompt)
    {
	if (!interactive_) {
	    if (sourceLines_.length > 0) {
		string line = sourceLines_[0];
		sourceLines_ = sourceLines_[1..$];
		return line;
	    }
	    return "";
	}
	
	version (editline) {
	    int num;
	    elPrompt_ = prompt;
	    return .toString(el_gets(el_, &num)).dup;
	} else {
	    writef("%s ", prompt_);
	    return chomp(readln());
	}
    }

    /**
     * Read the body of a compound statement (define, if, while etc.).
     * If optEnd is non-null, it can finish the statement as well as
     * "end". The value of the keyword that finishes the statement is
     * returned in endString.
     */
    string[] readStatementBody(string optEnd, out string endString)
    {
	string[] cmds;
	uint level = 1;
	for (;;) {
	    string line = strip(inputline(">"));

	    /*
	     * Only check for optEnd at the outermost level so that we
	     * don't get confused by nested if statements.
	     */
	    if (line == "end"
		|| (level == 1 && optEnd && line == optEnd)) {
		level--;
		if (level == 0) {
		    endString = line;
		    break;
		}
	    }
	    int i = find(line, ' ');
	    if (i >= 0) {
		if (line[0..i] == "if" || line[0..i] == "while")
		    level++;
	    }
	    cmds ~= line;
	}
	return cmds;
    }

    string[] readStatementBody()
    {
        string s;
        return readStatementBody(null, s);
    }

    void run()
    {
	string buf;
	string cmd;

	target_ = new ColdTarget(this, prog_, core_);

	try
	    sourceFile(".ngdbinit");
	catch {}

	try
	    sourceFile(.toString(getenv("HOME")) ~ "/.ngdbinit");
	catch {}

	sigaction_t sa;
	sa.sa_handler = &ignoreSig;
	sa.sa_flags = 0;
	sigaction(SIGINT, &sa, null);

	if (core_) {
	    stopped();
	} else {
	    /*
	     * Try to set source line at main().
	     */
	    auto di = modules_[0].debugInfo;
	    if (di) {
		LineEntry[] lines;
		if (di.findLineByFunction("_Dmain", lines)
		    && di.findLanguage(lines[0].address)
		   	 == DLanguage.instance) {
		    SourceFile sf = findFile(lines[0].fullname);
		    setCurrentSourceLine(sf, lines[0].line);
		} else if (di.findLineByFunction("main", lines)) {
		    SourceFile sf = findFile(lines[0].fullname);
		    setCurrentSourceLine(sf, lines[0].line);
		}
	    }
	}

	while (!quit_ && (buf = inputline(prompt_)) != null) {
	    int ac;
	    char** av;

	    /*
	     * If we don't have a target (e.g. the active target
	     * exitted or we disconnected), switch back to a cold
	     * target.
	     */
	    if (!target_) {
		target_ = new ColdTarget(this, prog_, core_);
		if (core_)
		    stopped();
	    }

	    version (editline) {
		HistEvent ev;
		if (buf.length > 1) {
		    history(hist_, &ev, H_ENTER, toStringz(buf));
		    cmd = strip(buf);
		}
	    } else {
		cmd = strip(buf);
	    }

	    if (cmd.length == 0)
		continue;

	    pageline_ = 0;
	    try {
		executeCommand(cmd);
	    } catch (PagerQuit pq) {
	    }
	}
    }

    void executeCommand(string cmd)
    {
	if (cmd[0] == '#')
	    return;
	if (cmd == "history") {
	    version (editline) {
		HistEvent ev;
		for (int rv = history(hist_, &ev, H_LAST);
		     rv != -1;
		     rv = history(hist_, &ev, H_PREV))
		    writef("%d %s", ev.num, .toString(ev.str));
	    }
	} else {
	    try {
		commands_.run(this, cmd, "");
	    } catch (TargetException te) {
		writefln("%s", te.msg);
	    }
	}
    }

    Command lookupCommand(string cmd)
    {
	string msg;
	return commands_.lookup(cmd, msg);
    }

    bool yesOrNo(...)
    {
	if (!interactive_)
	    return true;

	string prompt;

	void putc(dchar c)
	{
	    std.utf.encode(prompt, c);
	}

	std.format.doFormat(&putc, _arguments, _argptr);
	prompt ~= " (y or n)";
	string s;
	do {
	    s = std.string.tolower(strip(inputline(prompt)));
	} while (s.length == 0 || (s[0] != 'y' && s[0] != 'n'));
	if (s[0] == 'y')
	    return true;
	return false;
    }

    void pagefln(...)
    {
	char[] s;

	void putc(dchar c)
	{
	    std.utf.encode(s, c);
	}

	std.format.doFormat(&putc, _arguments, _argptr);
	s = expandtabs(s);
	while (s.length) {
	    uint n = s.length;
	    if (n > 80) n = 80;
	    writefln("%s", s[0..n]);
	    s = s[n..$];
	    if (pagemaxline_) {
		pageline_++;
		if (pageline_ >= pagemaxline_) {
		    writef("--Press return to continue or type 'q' to quit--");
		    auto t = din.readLine;
		    if (t.length > 0 && (t[0] == 'q' || t[0] == 'Q'))
			throw new PagerQuit;
		    pageline_ = 0;
		}
	    }
	}
    }

    SourceFile findFile(string filename)
    {
	auto tab = &sourceFiles_;
	if (!std.path.isabs(filename))
	    tab = &sourceFilesBasename_;
	if (filename in *tab)
	    return (*tab)[filename];
	SourceFile sf = new SourceFile(filename);
	sourceFiles_[filename] = sf;
	sourceFilesBasename_[std.path.getBaseName(filename)] = sf;
	return sf;
    }

    bool parseFormat(ref string args,
		     out uint count, out TargetSize width, out string f)
    {
	assert(args[0] == '/');
	int i = find(args, ' ');
	string fmt;
	if (i >= 0) {
	    fmt = args[1..i];
	    args = strip(args[i..$]);
	} else {
	    fmt = args[1..$];
	    args = "";
	}
	if (fmt.length == 0)
	    return false;
	if (isdigit(fmt[0])) {
	    count = 0;
	    while (fmt.length > 0 && isdigit(fmt[0])) {
		count = count * 10 + (fmt[0] - '0');
		fmt = fmt[1..$];
	    }
	    if (count == 0) {
		writefln("Count field in format string should be non-zero");
		return false;
	    }
	} else {
	    count = 1;
	}
	width = TS4;
	f = "d";
	while (fmt.length > 0) {
	    switch (fmt[0]) {
	    case 'b':
		width = TS1;
		break;
	    case 'w':
		width = TS2;
		break;
	    case 'l':
		width = TS4;
		break;
	    case 'q':
		width = TS8;
		break;
	    case 'd':
	    case 'o':
	    case 'x':
	    case 'i':
		f = fmt[0..1];
		break;
	    default:
		writefln("Unsupported format character %s", fmt[0..1]);
		return false;
	    }
	    fmt = fmt[1..$];
	}
	return true;
    }

    bool parseSourceLine(string s, out SourceFile sf, out uint line)
    {
	auto pos = find(s, ":");
	if (pos >= 0) {
	    try {
	        line = toUint(s[pos + 1..$]);
		sf = findFile(s[0..pos]);
	    } catch (ConvError ce) {
	        return false;
	    }
	    return true;
	} else if (currentSourceFile_) {
	    try {
	        line = toUint(s);
	    } catch (ConvError ce) {
	        return false;
	    }
	    sf = currentSourceFile_;
	    return true;
	}
	return false;
    }

    bool setCurrentFrame()
    {
	if (!target_)
	    return false;

	TargetThread t = currentThread;
	DebugInfo di;

	if (findDebugInfo(t, di)) {
	    Location loc;
	    Function func;
	    if (di.findFrameBase(t, loc) && (func = di.findFunction(t.pc)) !is null) {
		if (!topFrame_ || topFrame_.func_ !is func
		    || topFrame_.addr_ != loc.address(t)) {
		    currentFrame_ = topFrame_ =
			new Frame(this, 0, null, di, func, t);
		    return true;
		}
	    }
	} else {
	    currentFrame_ = topFrame_ =
		new Frame(this, 0, null, null, null, t);
	    ulong tpc = t.pc;
	    return true;
	}
	return false;
    }

    void started()
    {
	stopped_ = false;
    }

    void stopped()
    {
	if (!target_ || stopped_)
	    return;

	stopped_ = true;

	auto t = currentThread;
	auto newFrame = setCurrentFrame;
	auto di = currentFrame.di_;

	if (di) {
	    if (newFrame)
		writefln("%s", describeAddress(t.pc, t));
	    LineEntry[] le;
	    if (di.findLineByAddress(t.pc, le)) {
		SourceFile sf = findFile(le[0].fullname);
		currentSourceFile_ = stoppedSourceFile_ = sf;
		currentSourceLine_ = stoppedSourceLine_ = le[0].line;
		displaySourceLine(sf, currentSourceLine_);
		commands_.onSourceLine(this, sf, le[0].line);
		infoCommands_.onSourceLine(this, sf, le[0].line);
	    }
	} else {
	    currentFrame_ = topFrame_ =
		new Frame(this, 0, null, null, null, t);
	    TargetAddress tpc = t.pc;
	    writefln("%s:\t%s", lookupAddress(t.pc),
		     t.disassemble(tpc, &lookupAddress));
	}
	executeMacro(stopCommands_);
    }

    void displaySourceLine(MachineState s)
    {
	DebugInfo di;
	LineEntry[] le;

	if (findDebugInfo(s, di)) {
	    if (di.findLineByAddress(s.pc, le)) {
		SourceFile sf = findFile(le[0].fullname);
		displaySourceLine(sf, le[0].line);
		setCurrentSourceLine(sf, le[0].line);
	    }
	}
    }

    void displaySourceLine(SourceFile sf, uint line)
    {
	string bpmark = " ";
	showline: foreach (mod; modules_) {
	    DebugInfo di = mod.debugInfo;
	    if (!di)
		continue;
	    LineEntry[] lines;
	    if (di.findLineByName(sf.filename, line, lines)) {
		foreach (li; lines)
		    foreach (bp; breakpoints_)
			if (bp.matches(li.address))  {
			    bpmark = "*";
			    break showline;
			}
	    }
	}
	auto s = sf[line];
	if (s) {
	    string a = "  ";
	    if (sf == stoppedSourceFile_ && line == stoppedSourceLine_)
		a = "=>";
	    writefln("%s%4d%s%s", a, line, bpmark, expandtabs(s));
	}
    }

    void setCurrentSourceLine(SourceFile sf, int line)
    {
	currentSourceFile_ = sf;
	currentSourceLine_ = line;
	commands_.onSourceLine(this, sf, line);
	infoCommands_.onSourceLine(this, sf, line);
    }

    string describeAddress(TargetAddress pc, MachineState state)
    {
	LineEntry[] le;
	foreach (mod; modules_) {
	    DebugInfo di = mod.debugInfo;
	    if (di && di.findLineByAddress(pc, le)) {
		string s = "";

		Function func = di.findFunction(pc);
		if (func) {
		    s = func.toString(null, state) ~ ": ";
		}

		s ~= le[0].name ~ ":" ~ .toString(le[0].line);
		return s;
	    }
	}
	return lookupAddress(pc);
    }

    string lookupAddress(TargetAddress addr)
    {
	TargetSymbol bestSym;
	bool found = false;
	foreach (mod; modules_) {
	    TargetSymbol sym;
	    if (mod.lookupSymbol(addr, sym)) {
		if (!found || addr - sym.value < addr - bestSym.value) {
		    bestSym = sym;
		    found = true;
		}
	    }
	}
	if (found) {
	    string s;
	    if (addr != bestSym.value)
		s = bestSym.name ~ "+" ~ .toString(cast(int)(addr - bestSym.value));
	    else
		s = bestSym.name;
	    if (s.length > 33)
		s = s[0..15] ~ "..." ~ s[$-15..$];
	    return std.string.format("%#x <%s>", addr, s);
	}
	return std.string.format("%#x", addr);
    }

    void setStepBreakpoint(TargetAddress pc)
    {
	debug (step)
	    writefln("step breakpoint at %#x", pc);
	if (target_)
	    target_.setBreakpoint(pc, this);
    }

    void clearStepBreakpoints()
    {
	debug (step)
	    writefln("clearing step breakpoints");
	if (target_)
	    target_.clearBreakpoint(this);
    }

    void stepProgram(bool stepOverCalls)
    {
	if (!target_) {
	    writefln("Program is not being debugged");
	    return;
	}

	TargetThread t = currentThread;
	DebugInfo di;

	started();
	if (findDebugInfo(t, di)) {
	    Location frameLoc;
	    di.findFrameBase(t, frameLoc);
	    auto frameFunc = di.findFunction(t.pc);

	    TargetAddress frame = frameLoc.address(t);
	    TargetAddress startpc = t.pc;
	    TargetAddress stoppc, flowpc;

	    LineEntry[] le;
	    if (di.findLineByAddress(t.pc, le))
		stoppc = le[1].address;
	    else {
		target_.step(t);
		stopped();
		return;
	    }
	    setStepBreakpoint(stoppc);
	    flowpc = t.findFlowControl(t.pc, stoppc);
	    if (flowpc < stoppc)
		setStepBreakpoint(flowpc);
	    else
		flowpc = TA0;

	    bool resetStep = false;
	    do {
		/*
		 * Run up to the next flow control instruction or the
		 * next statement, whichever comes first. Be careful if
		 * we are sitting on a flow control instruction.
		 */
		if (t.pc != flowpc) {
		    target_.cont();
		    target_.wait();
		}
		debug (step) {
		    void stoppedAt(string msg, TargetAddress pc)
		    {
			writefln("%s %#x (%s)", msg, pc,
				replace(t.disassemble(pc, &lookupAddress), "\t", " "));
		    }
		}
		if (t.pc == flowpc) {
		    /*
		     * Stopped at a flow control instruction - single step
		     * it and see if we change frame or go out of our step
		     * range.
		     */
		    debug (step)
			stoppedAt("stopped at flow control", t.pc);
		    target_.step(t);
		    debug (step)
			stoppedAt("single stepped to", t.pc);

		    bool inPLT(TargetAddress pc) {
			foreach (mod; modules_)
			    if (mod.inPLT(pc))
				return true;
			return false;
		    }

		    while (inPLT(t.pc)) {
			debug (step)
			    writefln("single stepping over PLT entry");
			target_.step(t);
		    }
		    resetStep = true;
		} else {
		    debug (step)
			stoppedAt("stopped at", t.pc);
		}
		if (!findDebugInfo(t, di)) {
		    /*
		     * See if the machine state can unwind and if so,
		     * we can set a return breakpoint.
		     */
		    auto fde = t.parsePrologue(t.pc);
		    if (fde) {
			debug (step)
			    writefln("stepping over call to function with no debug info at %#x",t.pc);
			MachineState ns = fde.unwind(t);
			clearStepBreakpoints();
			TargetAddress retpc = ns.pc;
			debug (step)
			    writefln("return breakpoint at %#x", retpc);
			setStepBreakpoint(retpc);
			target_.cont();
			target_.wait();
			debug (step)
			    stoppedAt("stopped at", t.pc);
			resetStep = true;
			goto nextStep;
		    }
		    /*
		     * If we step into something without debug info,
		     * just continue until we hit the step breakpoint.
		     */
		    debug (step)
			writefln("no debug info at %#x - continue", t.pc);
		    target_.cont();
		    target_.wait();
		    break;
		}
		di.findFrameBase(t, frameLoc);
		auto func = di.findFunction(t.pc);
		if (frameLoc.address(t) != frame || func !is frameFunc) {
		    debug (step)
			writefln("new frame address %#x", frameLoc.address(t));
		    if (frameLoc.address(t) > frame) {
			debug (step)
			    writefln("returning to outer frame");
			break;
		    }
		    if (stepOverCalls) {
			/*
			 * We are stepping over calls - run up to the return
			 * address
			 */
			debug (step)
			    writefln("stepping over call");
			MachineState ns = di.unwind(t);
			clearStepBreakpoints();
			TargetAddress retpc = ns.pc;
			debug (step)
			    writefln("return breakpoint at %#x", retpc);
			setStepBreakpoint(retpc);
			do {
			    target_.cont();
			    target_.wait();
			    debug (step)
				stoppedAt("stopped at", t.pc);
			    if (t.pc != retpc
				|| !di.findFrameBase(t, frameLoc))
				break;
			    debug (step)
				if (frameLoc.address(t) < frame)
				    writefln("stopped at inner frame %#x - continuing", frameLoc.address(t));
			} while (target_ && frameLoc.address(t) != frame);
			resetStep = true;
		    } else {
			clearStepBreakpoints();
			break;
		    }
		}
nextStep:
		if (t.pc < startpc || t.pc >= stoppc) {
		    debug (step)
			writefln("stepped outside range %#x..%#x", startpc, stoppc);
		    break;
		}
		if (resetStep) {
		    clearStepBreakpoints();
		    setStepBreakpoint(stoppc);
		    flowpc = t.findFlowControl(t.pc, stoppc);
		    if (flowpc < stoppc)
			setStepBreakpoint(flowpc);
		    else
			flowpc = TA0;
		}
	    } while (t.pc < stoppc);
	    clearStepBreakpoints();
	    stopped();
	} else {
	    target_.step(t);
	    stopped();
	}
    }

    void stepInstruction(bool stepOverCalls)
    {
	if (!target_) {
	    writefln("Program is not being debugged");
	    return;
	}

	started();

	TargetThread t = currentThread;

	TargetAddress frame;
	DebugInfo di;

	if (findDebugInfo(t, di)) {
	    Location frameLoc;
	    di.findFrameBase(t, frameLoc);
	    frame = frameLoc.address(t);
	}

	target_.step(t);
	
	if (findDebugInfo(t, di)) {
	    Location frameLoc;
	    di.findFrameBase(t, frameLoc);
	    if (frameLoc.address(t) != frame) {
		debug (step)
		    writefln("new frame address %#x", frameLoc.address(t));
		if (frameLoc.address(t) > frame) {
		    debug (step)
			writefln("returning to outer frame");
		    stopped();
		    return;
		}
		if (stepOverCalls) {
		    /*
		     * We are stepping over calls - run up to the return
		     * address
		     */
		    debug (step)
			writefln("stepping over call");
		    MachineState ns = di.unwind(t);
		    clearStepBreakpoints();
		    TargetAddress retpc = ns.pc;
		    debug (step)
			writefln("return breakpoint at %#x", retpc);
		    setStepBreakpoint(retpc);
		    do {
			target_.cont();
			target_.wait();
			clearStepBreakpoints();
			if (t.pc != retpc
			    || !di.findFrameBase(t, frameLoc))
			    break;
			debug (step)
			    if (frameLoc.address(t) < frame)
				writefln("stopped at inner frame %#x - continuing", frameLoc.address(t));
		    } while (frameLoc.address(t) != frame);
		}
	    }
	}
	stopped();
	if (currentFrame.func_) {
	    TargetAddress tpc = t.pc;
	    pagefln("%s:\t%s", lookupAddress(t.pc),
		    t.disassemble(tpc, &lookupAddress));
	}
    }

    void setBreakpoint(string bploc)
    {
	SourceFile sf;
	string func;
	uint line;
	if (bploc) {
	    string file;
	    if (!parseSourceLine(bploc, sf, line))
		func = bploc;
	} else {
	    sf = currentSourceFile_;
	    line = currentSourceLine_;
	    if (!sf) {
		writefln("no current source file");
		return;
	    }
	}
	Breakpoint bp;
	if (sf)
	    bp = new Breakpoint(this, sf, line);
	else
	    bp = new Breakpoint(this, func);
	if (target_)
	    foreach (mod; modules_)
		bp.activate(mod);
	if (bp.active) {
	    bp.id_ = nextBPID_++;
	    breakpoints_ ~= bp;
	    bp.printHeader;
	    bp.print;
	} else {
	    writefln("Can't set breakpoint %s", bploc);
	}
    }

    Breakpoint findBreakpoint(uint bpid)
    {
	foreach (bp; breakpoints_)
	    if (bp.id == bpid)
                return bp;
        throw new DebuggerException("No such breakpoint");
    }

    Breakpoint findBreakpoint(string bpid)
    {
        if (bpid.length == 0)
            return lastBreakpoint;

        uint num;
        try {
            num = toUint(bpid);
        } catch (ConvError ce) {
            throw new DebuggerException("Can't parse breakpoint ID");
        }
        return findBreakpoint(num);
    }

    Breakpoint lastBreakpoint()
    {
        if (breakpoints_.length > 0)
            return breakpoints_[$ - 1];
        throw new DebuggerException("No breakpoints");
    }

    void deleteBreakpoint(Breakpoint bp)
    {
	Breakpoint[] newBreakpoints;
	foreach (tbp; breakpoints_)
	    if (tbp == bp)
		bp.disable;
	    else
		newBreakpoints ~= tbp;
	breakpoints_ = newBreakpoints;
    }

    Frame topFrame()
    {
	return topFrame_;
    }

    void setStopCommands(string[] cmds)
    {
	stopCommands_ = cmds;
    }

    Frame currentFrame()
    {
	return currentFrame_;
    }

    Frame getFrame(uint frameIndex)
    {
	Frame f;
	for (f = topFrame_; f; f = f.outer)
	    if (f.index == frameIndex)
		break;
	return f;
    }

    TargetThread currentThread()
    {
	return currentThread_;
    }

    void currentThread(TargetThread t)
    {
	if (t != currentThread_) {
	    foreach (i, tt; threads_) {
		if (t == tt) {
		    pagefln("Switched to thread %d", i + 1);
		}
	    }
	    currentThread_ = t;
	}
    }

    bool findDebugInfo(MachineState s, out DebugInfo di)
    {
	Location loc;
	foreach (mod; modules_) {
	    di = mod.debugInfo;
	    if (di && di.findFrameBase(s, loc)) {
		di = mod.debugInfo;
		return true;
	    }
	}
	return false;
    }

    static void registerCommand(Command c)
    {
	if (!commands_)
	    commands_ = new CommandTable;
	commands_.add(c);
    }

    static void registerInfoCommand(Command c)
    {
	if (!infoCommands_)
	    infoCommands_ = new CommandTable;
	infoCommands_.add(c);
    }

    Language currentLanguage()
    {
	auto f = currentFrame;
	if (f)
	    return f.lang_;
	else
	    return CLikeLanguage.instance;
    }

    Value evaluateExpr(string expr, out MachineState state)
    {
	MachineState s;
	DebugInfo di;
	string fmt = null;

	auto f = currentFrame;
	if (f)
	    s = f.state_;
	else
	    s = currentThread;

	Scope sc;
	Language lang;
	if (f) {
	    sc = f.scope_;
	    lang = f.lang_;
	} else {
	    sc = this;
	    lang = CLikeLanguage.instance;
	}

	try {
	    auto e = lang.parseExpr(expr, sc);
	    auto v = e.eval(sc, s).toValue;
	    state = s;
	    return v;
	} catch (EvalException ex) {
	    pagefln("%s", ex.msg);
	    return null;
	}
    }

    Value evaluateExpr(string expr)
    {
	MachineState s;
	return evaluateExpr(expr, s);
    }

    override
    {
	// TargetListener
	void onTargetStarted(Target target)
	{
	    stopped_ = false;
	    target_ = target;
	}
	void onThreadCreate(Target target, TargetThread thread)
	{
	    foreach (t; threads_)
		if (t == thread)
		    return;
	    threads_ ~= thread;
	    if (!currentThread_)
		currentThread_ = thread;
	}
	void onThreadDestroy(Target target, TargetThread thread)
	{
	    TargetThread[] newThreads;
	    foreach (t; threads_)
		if (t != thread)
		    newThreads ~= t;
	    threads_ = newThreads;
	}
	void onModuleAdd(Target, TargetModule mod)
	{
	    modules_ ~= mod;

	    auto di = mod.debugInfo;
	    if (di) {
		foreach (s; di.findSourceFiles)
		    findFile(s);
	    }
	    foreach (bp; breakpoints_)
		bp.activate(mod);
	}
	void onModuleDelete(Target, TargetModule mod)
	{
	    TargetModule[] newModules;
	    foreach (omod; modules_)
		if (omod !is mod)
		    newModules ~= omod;
	    modules_ = newModules;
	    foreach (bp; breakpoints_)
		bp.deactivate(mod);
	}
	bool onBreakpoint(Target, TargetThread t)
	{
	    /*
	     * We use this as listener for the step breakpoints.
	     */
	    currentThread = t;
	    return true;
	}
	void onSignal(Target, TargetThread t, int sig, string sigName)
	{
	    currentThread = t;
	    writefln("Thread %d received signal %d (%s)", t.id, sig, sigName);
	}
	void onExit(Target)
	{
	    if (target_ && target_.state != TargetState.EXIT)
		writefln("Target program has exited.");

	    target_ = null;
	    threads_.length = 0;
	    currentThread_ = null;
	    modules_.length = 0;
	    topFrame_ = currentFrame_ = null;
	    foreach (bp; breakpoints_)
		bp.onExit;
	}
	string[] contents(MachineState state)
	{
	    string[] res;
	    foreach (mod; modules_)
		res ~= mod.contents(state);
	    for (int i = 0; i < valueHistory_.length; i++)
		res ~= "$" ~ .toString(i);

	    return uniq(res);
	}
	bool lookup(string name, MachineState state, out DebugItem val)
	{
	    foreach (mod; modules_)
		if (mod.lookup(name, state, val))
		    return true;

	    if (name.length == 0 || name[0] != '$')
		return false;
	    name = name[1..$];
	    if (name.length == 0 || isdigit(name[0])) {
		try {
		    uint num = name.length > 0
			? toUint(name) : valueHistory_.length - 1;
		    if (num >= valueHistory_.length)
			return false;
		    val = valueHistory_[num];
		    return true;
		} catch (ConvError ce) {
		    return false;
		}
	    } else if (isalpha(name[0]) || name[0] == '_') {
		auto vp = name in userVars_;
		if (vp) {
		    val = *vp;
		    return true;
		}
		auto lang = currentLanguage;
		Value var = new Value(new UserLocation,
				      new UserType(lang));
		userVars_[name] = var;
		val = var;
		return true;
	    } else {
		return false;
	    }
	}
	bool lookupStruct(string name, out Type ty)
	{
	    foreach (mod; modules_)
		if (mod.lookupStruct(name, ty))
		    return true;
	    return false;
	}
	bool lookupUnion(string name, out Type ty)
	{
	    foreach (mod; modules_)
		if (mod.lookupTypedef(name, ty))
		    return true;
	    return false;
	}
	bool lookupTypedef(string name, out Type ty)
	{
	    foreach (mod; modules_)
		if (mod.lookupTypedef(name, ty))
		    return true;
	    return false;
	}
    }

private:
version (editline) {
    string elPrompt_;

    extern(C) static char* _prompt(EditLine *el)
    {
	void* p;
	el_get(el, EL_CLIENTDATA, &p);
	Debugger db = cast(Debugger) p;
	assert(db);
	return toStringz(db.prompt(el));
    }
    extern(C) static char _complete(EditLine *el, int ch)
    {
	void* p;
	el_get(el, EL_CLIENTDATA, &p);
	Debugger db = cast(Debugger) p;
	assert(db);
	return db.complete(el, ch);
    }

    string prompt(EditLine *el)
    {
	return elPrompt_ ~ " ";
    }

    char complete(EditLine *el, int ch)
    {
	LineInfo* li = el_line(el);

	size_t n = li.cursor - li.buffer;
	string args = chomp(li.buffer[0..n].dup);
	string[] matches = commands_.complete(this, args);

	if (matches.length == 1) {
	    string s = matches[0] ~ " ";
	    if (el_insertstr(el, toStringz(s)) == -1)
		return CC_ERROR;
	    return CC_REFRESH;
	} else {
	    /*
	     * Find the longest common prefix of all the matches
	     * and try to insert from that. If we can't insert any
	     * more, display the match list.
	     */
	    if (matches.length == 0)
		return CC_ERROR;
	    int i;
	    string m0 = matches[0];
	    gotPrefix: for (i = 0; i < m0.length; i++) {
		foreach (m; matches[1..$]) {
		    if (i >= m.length || m[i] != m0[i])
			break gotPrefix;
		}
	    }
	    if (i > 0) {
		string s = m0[0..i];
		if (el_insertstr(el, toStringz(s)) == -1)
		    return CC_ERROR;
		return CC_REFRESH;
	    }
	    return CC_ERROR;
	}

	return CC_ERROR;
    }
    History* hist_;
    EditLine* el_;
}

    static CommandTable commands_;
    static CommandTable infoCommands_;

    bool interactive_ = true;
    string[] sourceLines_;
    bool quit_ = false;
    string prog_;
    string core_;
    string prompt_;
    uint pageline_;
    uint pagemaxline_ = 23;
    Target target_;
    TargetModule[] modules_;
    TargetThread[] threads_;
    TargetThread currentThread_;
    Frame topFrame_;
    Frame currentFrame_;
    Breakpoint[] breakpoints_;
    SourceFile[string] sourceFiles_;
    SourceFile[string] sourceFilesBasename_;
    SourceFile stoppedSourceFile_;
    uint stoppedSourceLine_;
    SourceFile currentSourceFile_;
    uint currentSourceLine_;
    string[] stopCommands_;
    uint nextBPID_;
    Value[] valueHistory_;
    Value[string] userVars_;
    bool stopped_;
}

class QuitCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new QuitCommand);
    }

    override {
	string name()
	{
	    return "quit";
	}

	string shortName()
	{
	    return "q";
	}

	string description()
	{
	    return "Exit the debugger";
	}

	void run(Debugger db, string args)
	{
	    db.quit_ = true;
	}
    }
}

class HelpCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new HelpCommand);
    }

    override {
	string name()
	{
	    return "help";
	}

	string description()
	{
	    return "Print this message";
	}

	void run(Debugger db, string args)
	{
	    foreach (c; db.commands_.list_.values.sort)
		db.pagefln("%-16s%s", c.name, c.description);
	}
    }
}

class InfoCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new InfoCommand);
    }

    override {
	string name()
	{
	    return "info";
	}

        string shortName()
        {
            return "i";
        }

	string description()
	{
	    return "Print information";
	}

	void run(Debugger db, string args)
	{
	    if (args.length == 0) {
		db.pagefln("usage: info subcommand [args ...]");
		return;
	    }
	    db.infoCommands_.run(db, args, "info ");
	}
	string[] complete(Debugger db, string args)
	{
	    if (args.length == 0)
		return null;
	    return db.infoCommands_.complete(db, args);
	}
    }
}

class RunCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new RunCommand);
    }

    override {
	string name()
	{
	    return "run";
	}

	string shortName()
	{
	    return "r";
	}

	string description()
	{
	    return "run the program being debugged";
	}

	void run(Debugger db, string args)
	{
	    if (db.target_ && db.target_.state != TargetState.EXIT) {
		db.pagefln("Program is already being debugged");
		return;
	    }
	    if (db.target_) {
		auto target = db.target_;
		db.onExit(target);
		//delete target;
	    }

	    PtraceRun pt = new PtraceRun;
	    if (args.length > 0 || runArgs_.length == 0) {
		runArgs_ = db.prog_ ~ split(args, " ");
	    }
	    pt.connect(db, runArgs_);
	    if (db.target_)
		db.stopped();
	}
    }
    string[] runArgs_;
}

class TargetCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new TargetCommand);
    }

    override {
	string name()
	{
	    return "target";
	}

	string description()
	{
	    return "Attach to a target";
	}

	void run(Debugger db, string args)
	{
            int i = find(args, ' ');
            if (i < 0) {
                db.pagefln("usage: target <type> [<args>]");
                return;
            }

            string type = args[0..i];
            args = strip(args[i..$]);

	    if (db.target_ && db.target_.state != TargetState.EXIT) {
		db.pagefln("Program is already being debugged");
		return;
	    }
	    if (db.target_) {
		auto target = db.target_;
		db.onExit(target);
		//delete target;
	    }

            TargetFactory.connect(type, db, db.prog_ ~ split(args, " "));
	    if (db.target_)
		db.stopped();
	}
    }
    string[] runArgs_;
}

class KillCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new KillCommand);
    }

    override {
	string name()
	{
	    return "kill";
	}

	string description()
	{
	    return "kill the program being debugged";
	}

	void run(Debugger db, string args)
	{
	    if (db.target_ && db.target_.state == TargetState.EXIT) {
		db.pagefln("Program is not running");
		return;
	    }
	    
	    db.target_.cont(SIGKILL);
	    db.target_.wait;
	}
    }
    string[] runArgs_;
}

class NextCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new NextCommand);
    }

    override {
	string name()
	{
	    return "next";
	}

	string shortName()
	{
	    return "n";
	}

	string description()
	{
	    return "step the program being debugged, stepping over function calls";
	}

	void run(Debugger db, string args)
	{
	    db.stepProgram(true);
	}
    }
}

class StepCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new StepCommand);
    }

    override {
	string name()
	{
	    return "step";
	}

	string shortName()
	{
	    return "s";
	}

	string description()
	{
	    return "step the program being debugged, stepping into function calls";
	}

	void run(Debugger db, string args)
	{
	    db.stepProgram(false);
	}
    }
}

class StepICommand: Command
{
    static this()
    {
	Debugger.registerCommand(new StepICommand);
    }

    override {
	string name()
	{
	    return "stepi";
	}

	string shortName()
	{
	    return "si";
	}

	string description()
	{
	    return "Step the program one instruction, stepping into function calls";
	}

	void run(Debugger db, string args)
	{
	    db.stepInstruction(false);
	}
    }
}

class NextICommand: Command
{
    static this()
    {
	Debugger.registerCommand(new NextICommand);
    }

    override {
	string name()
	{
	    return "nexti";
	}

	string shortName()
	{
	    return "ni";
	}

	string description()
	{
	    return "Step the program one instruction, stepping over function calls";
	}

	void run(Debugger db, string args)
	{
	    db.stepInstruction(true);
	}
    }
}

class ContinueCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new ContinueCommand);
    }

    override {
	string name()
	{
	    return "continue";
	}

	string shortName()
	{
	    return "c";
	}

	string description()
	{
	    return "continue the program being debugged";
	}

	void run(Debugger db, string args)
	{
	    if (db.target_.state == TargetState.EXIT) {
		db.pagefln("Program is not being debugged");
		return;
	    }

	    db.started();
	    db.target_.cont();
	    db.target_.wait();
	    db.stopped();
	}
    }
}

class FinishCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new FinishCommand);
    }

    override {
	string name()
	{
	    return "finish";
	}

	string description()
	{
	    return "Continue to calling stack frame";
	}

	void run(Debugger db, string args)
	{
	    auto f = db.topFrame;
	    if (!f) {
		db.pagefln("No current frame");
		return;
	    }
	    if (!f.outer) {
		db.pagefln("Already in outermost stack frame");
		return;
	    }
	    auto fromFrame = f;
	    auto toFrame = f.outer;

	    Type rTy = fromFrame.func_.returnType;
	    db.setStepBreakpoint(toFrame.state_.pc);
	    db.target_.cont();
	    db.target_.wait();
	    db.clearStepBreakpoints();
	    if (!db.currentThread)
		return;
	    if (rTy) {
		MachineState s = db.currentThread;
		Value val = s.returnValue(rTy);
		db.pagefln("Value returned is %s", val.toString(null, s));
	    }
	    db.stopped();
	}
    }
}

class BreakCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new BreakCommand);
    }

    override {
	string name()
	{
	    return "break";
	}

	string description()
	{
	    return "Set a breakpoint";
	}

	void run(Debugger db, string args)
	{
	    if (find(args, ' ') >= 0) {
		db.pagefln("usage: break [<function or line>]");
		return;
	    }
	    db.setBreakpoint(args.length > 0 ? args : null);
	}

	string[] complete(Debugger db, string args)
	{
	    if (args.length == 0)
		return null;

	    auto state = db.currentThread ? db.currentThread : null;
	    string[] syms = db.contents(state);
	    string[] matches;
	    foreach (sym; syms)
		if (sym.length >= args.length && sym[0..args.length] == args)
		    matches ~= sym[args.length..$];
	    return matches;
	}
    }
}

class ConditionCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new ConditionCommand);
    }

    override {
	string name()
	{
	    return "condition";
	}

	string description()
	{
	    return "Set breakpoint condition";
	}

	void run(Debugger db, string args)
	{
	    int i = find(args, ' ');
	    if (i < 0) {
		db.pagefln("usage: condition <id> [expression]");
		return;
	    }

            string num = args[0..i];
            string expr = strip(args[i..$]);
            try {
                db.findBreakpoint(num).condition = expr;
            } catch (DebuggerException de) {
                db.pagefln("%s", de.msg);
                return;
            }
	}
    }
}

class CommandsCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new CommandsCommand);
    }

    override {
	string name()
	{
	    return "commands";
	}

	string description()
	{
	    return "Set breakpoint stop commands";
	}

	void run(Debugger db, string args)
	{
	    if (find(args, ' ') >= 0) {
		db.pagefln("usage: commands [<id>]");
		return;
	    }
            
            Breakpoint bp;
            try {
                bp = db.findBreakpoint(args);
            } catch (DebuggerException de) {
                db.pagefln("%s", de.msg);
                return;
            }
            if (db.interactive)
                db.pagefln(
                    "Enter commands for breakpoint #%d, finish with \"end\"",
                    bp.id);
            string[] cmds = db.readStatementBody;
            bp.commands = cmds;
	}
    }
}

class EnableCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new EnableCommand);
    }

    override {
	string name()
	{
	    return "enable";
	}

	string description()
	{
	    return "Enable a breakpoint";
	}

	void run(Debugger db, string args)
	{
	    if (find(args, ' ') >= 0) {
		db.pagefln("usage: enable [<id>]");
		return;
	    }
	    if (args.length == 0) {
		foreach (bp; db.breakpoints_)
		    bp.enable;
	    } else {
                try {
                    db.findBreakpoint(args).enable;
                } catch (DebuggerException de) {
                    db.pagefln("%s", de.msg);
                    return;
                }
	    }
	}
    }
}

class DisableCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new DisableCommand);
    }

    override {
	string name()
	{
	    return "disable";
	}

	string description()
	{
	    return "Disable a breakpoint";
	}

	void run(Debugger db, string args)
	{
	    if (find(args, ' ') >= 0) {
		db.pagefln("usage: disable [<id>]");
		return;
	    }
	    if (args.length == 0) {
		foreach (bp; db.breakpoints_)
		    bp.disable;
	    } else {
                try {
                    db.findBreakpoint(args).disable;
                } catch (DebuggerException de) {
                    db.pagefln("%s", de.msg);
                    return;
                }
	    }
	}
    }
}

class DeleteCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new DeleteCommand);
    }

    override {
	string name()
	{
	    return "delete";
	}

	string shortName()
	{
	    return "d";
	}

	string description()
	{
	    return "Delete a breakpoint";
	}

	void run(Debugger db, string args)
	{
	    if (args.length == 0 || find(args, ' ') >= 0) {
		db.pagefln("usage: delete [<id>]");
		return;
	    }
            try {
                db.deleteBreakpoint(db.findBreakpoint(args));
            } catch (DebuggerException de) {
                db.pagefln("%s", de.msg);
                return;
            }
	}
    }
}

class InfoBreakCommand: Command
{
    static this()
    {
	Debugger.registerInfoCommand(new InfoBreakCommand);
    }

    override {
	string name()
	{
	    return "break";
	}

	string description()
	{
	    return "List breakpoints";
	}

	void run(Debugger db, string args)
	{
	    if (db.breakpoints_.length == 0) {
		db.pagefln("No breakpoints");
		return;
	    }
	    Breakpoint.printHeader;
	    foreach (b; db.breakpoints_)
		b.print;
	}
    }
}

class StopCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new StopCommand);
    }

    override {
	string name()
	{
	    return "stop";
	}

	string description()
	{
	    return "Set commands to execute when program stops";
	}

	void run(Debugger db, string args)
	{
	    if (find(args, ' ') >= 0) {
		db.pagefln("usage: stop");
		return;
	    }
            
            if (db.interactive)
                db.pagefln(
	"Enter commands to execute when program stops, finish with \"end\"");
            string[] cmds = db.readStatementBody;
            db.setStopCommands(cmds);
	}
    }
}

class ThreadCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new ThreadCommand);
    }

    override {
	string name()
	{
	    return "thread";
	}

	string description()
	{
	    return "Select a thread";
	}

	void run(Debugger db, string args)
	{
	    if (args.length == 0) {
		db.pagefln("usage: thread <number>");
		return;
	    }
	    uint n = ~0;
	    try {
		n = toUint(args);
	    } catch (ConvError ce) {
	    }
	    foreach (t; db.threads_) {
		if (t.id == n) {
		    db.currentThread = t;
		    db.stopped();
		    return;
		}
	    }
	    db.pagefln("Invalid thread %s", args[0]);
	}
    }
}

class InfoModulesCommand: Command
{
    static this()
    {
	Debugger.registerInfoCommand(new InfoModulesCommand);
    }

    override {
	string name()
	{
	    return "modules";
	}

	string description()
	{
	    return "List moduless";
	}

	void run(Debugger db, string args)
	{
	    TargetAddress pc;
	    if (db.currentThread)
		pc = db.currentThread.pc;
	    foreach (i, mod; db.modules_) {
		string addrs = format("%#x .. %#x", mod.start, mod.end);
		bool active = false;
		if (pc >= mod.start && pc < mod.end)
		    active = true;
		db.pagefln("%s%2d: %-32s %s",
			   active ? "*" : " ", i + 1, addrs, mod.filename);
	    }
	}
    }
}

class InfoThreadCommand: Command
{
    static this()
    {
	Debugger.registerInfoCommand(new InfoThreadCommand);
    }

    override {
	string name()
	{
	    return "thread";
	}

	string description()
	{
	    return "List threads";
	}

	void run(Debugger db, string args)
	{
	    foreach (i, t; db.threads_) {
		db.pagefln("%s %-2d: %s",
			   t == db.currentThread ? "*" : " ",
			   t.id,
			   db.describeAddress(t.pc, t));
	    }
	}
    }
}

class InfoRegistersCommand: Command
{
    static this()
    {
	Debugger.registerInfoCommand(new InfoRegistersCommand);
    }

    override {
	string name()
	{
	    return "registers";
	}

	string description()
	{
	    return "List registerss";
	}

	void run(Debugger db, string args)
	{
	    auto f = db.currentFrame;
	    if (!f) {
		db.pagefln("No current stack frame");
		return;
	    }
	    db.pagefln("%s", f.toString);
	    auto s = f.state_;
	    s.dumpState;
	    TargetAddress pc = s.pc;
	    TargetAddress tpc = pc;
	    db.pagefln("%s:\t%s", db.lookupAddress(pc),
		     s.disassemble(tpc, &db.lookupAddress));
	}
    }
}

class InfoFloatCommand: Command
{
    static this()
    {
	Debugger.registerInfoCommand(new InfoFloatCommand);
    }

    override {
	string name()
	{
	    return "float";
	}

	string description()
	{
	    return "Display floating point state";
	}

	void run(Debugger db, string args)
	{
	    auto f = db.currentFrame;
	    if (!f) {
		db.pagefln("No current stack frame");
		return;
	    }
	    f.state_.dumpFloat;
	}
    }
}

class InfoVariablesCommand: Command
{
    static this()
    {
	Debugger.registerInfoCommand(new InfoVariablesCommand);
    }

    override {
	string name()
	{
	    return "variables";
	}

	string description()
	{
	    return "List variables";
	}

	void run(Debugger db, string args)
	{
	    string fmt = null;

	    if (!db.target_) {
		db.pagefln("target is not running");
		return;
	    }

	    if (args.length > 0 && args[0] == '/') {
		uint count;
                TargetSize width;
		if (!db.parseFormat(args, count, width, fmt))
		    return;
		if (fmt == "i") {
		    db.pagefln("Instruction format not supported");
		    return;
		}
		if (count != 1) {
		    db.pagefln("Counts greater than one not supported");
		    return;
		}
		if (width != 4) {
		    db.pagefln("Format width characters not supported");
		}
	    }

	    auto f = db.currentFrame;
	    if (!f) {
		db.pagefln("current stack frame is invalid");
		return;
	    }

	    auto  s = f.state_;
	    auto func = f.func_;
	    if (func) {
		auto names = func.contents(s);
		foreach (name; names) {
		    DebugItem d;
		    if (func.lookup(name, s, d)) {
			auto v = cast(Variable) d;
			if (!v.value.loc.valid(s))
			    continue;
			db.pagefln("%s = %s",
				   v.toString, v.valueToString(fmt, s));
		    }
		}
	    }
	}
    }
}

class FrameCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new FrameCommand);
    }

    override {
	string name()
	{
	    return "frame";
	}

	string description()
	{
	    return "Manipulate stack frame";
	}

	void run(Debugger db, string args)
	{
	    if (find(args, ' ') >= 0) {
		db.pagefln("usage: frame [frame index]");
		return;
	    }
	    if (args.length > 0) {
		uint frameIndex;
		try {
		    frameIndex = toUint(args);
		} catch (ConvError ce) {
		    frameIndex = ~0;
		}
		Frame f = db.getFrame(frameIndex);
		if (!f) {
		    db.pagefln("Invalid frame number %s", args[1]);
		    return;
		}
		db.currentFrame_ = f;
	    }
	    auto f = db.currentFrame;
	    if (!f) {
		db.pagefln("stack frame information unavailable");
		return;
	    }
	    db.pagefln("%s", f.toString);
	    db.displaySourceLine(f.state_);
	}
    }
}

class UpCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new UpCommand);
    }

    override {
	string name()
	{
	    return "up";
	}

	string description()
	{
	    return "Select next outer stack frame";
	}

	void run(Debugger db, string args)
	{
	    if (args.length != 0) {
		db.pagefln("usage: up");
		return;
	    }
	    auto f = db.currentFrame;
	    if (!f) {
		db.pagefln("stack frame information unavailable");
		return;
	    }
	    if (f.outer)
		db.currentFrame_ = f = f.outer;
	    db.pagefln("%s", f.toString);
	    db.displaySourceLine(f.state_);
	}
    }
}

class DownCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new DownCommand);
    }

    override {
	string name()
	{
	    return "down";
	}

	string description()
	{
	    return "Select next inner stack frame";
	}

	void run(Debugger db, string args)
	{
	    if (args.length != 0) {
		db.pagefln("usage: down");
		return;
	    }
	    auto f = db.currentFrame;
	    if (!f) {
		db.pagefln("stack frame information unavailable");
		return;
	    }
	    if (f.inner)
		db.currentFrame_ = f = f.inner;
	    db.pagefln("%s", f.toString);
	    db.displaySourceLine(f.state_);
	}
    }
}

class WhereCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new WhereCommand);
    }

    override {
	string name()
	{
	    return "where";
	}

	string description()
	{
	    return "Stack backtrace";
	}

	void run(Debugger db, string args)
	{
	    for (Frame f = db.topFrame; f; f = f.outer)
		db.pagefln("%d: %s", f.index_,
		    db.describeAddress(f.state_.pc, f.state_));
	}
    }
}

class PrintCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new PrintCommand);
    }

    override {
	string name()
	{
	    return "print";
	}

	string shortName()
	{
	    return "p";
	}

	string description()
	{
	    return "evaluate and print expressio";
	}

	void run(Debugger db, string args)
	{
	    string fmt = null;

	    if (args.length > 0
		&& args[0] == '/') {
		uint count;
                TargetSize width;
		if (!db.parseFormat(args, count, width, fmt))
		    return;
		if (fmt == "i") {
		    db.pagefln("Instruction format not supported");
		    return;
		}
		if (count != 1) {
		    db.pagefln("Counts greater than one not supported");
		    return;
		}
		if (width != 4) {
		    db.pagefln("Format width characters not supported");
		}
	    }

	    string expr;
	    if (args.length == 0) {
		if (!lastExpr_) {
		    db.pagefln("No previous expression to print");
		    return;
		}
		expr = lastExpr_;
	    } else {
		expr = args;
		lastExpr_ = expr;
	    }

	    MachineState s;
	    auto v = db.evaluateExpr(expr, s);
	    if (v) {
		db.pagefln("$%s = (%s) %s",
			   db.valueHistory_.length,
			   v.type.toString,
			   v.toString(fmt, s));
		db.valueHistory_ ~= v;
	    }
	}
    }
private:
    string lastExpr_;
}

class SetCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new SetCommand);
    }

    override {
	string name()
	{
	    return "set";
	}

	string description()
	{
	    return "evaluate expressio";
	}

	void run(Debugger db, string args)
	{
	    if (args.length == 0) {
		db.pagefln("usage: set expr");
		return;
	    }
	    db.evaluateExpr(args);
	}
    }
}

class ExamineCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new ExamineCommand);
    }

    override {
	string name()
	{
	    return "examine";
	}

	string shortName()
	{
	    return "x";
	}

	string description()
	{
	    return "Examine memory";
	}

	void run(Debugger db, string args)
	{
	    MachineState s;
	    DebugInfo di;

	    if (!db.target_) {
		db.pagefln("Target is not running");
		return;
	    }
	    auto f = db.currentFrame;
	    if (f)
		s = f.state_;
	    else if (db.currentThread)
		s = db.currentThread;

	    if (args.length > 0 && args[0] == '/') {
		if (!db.parseFormat(args, count_, width_, fmt_))
		    return;
	    }

	    TargetAddress addr;
	    if (args.length == 0) {
		if (!lastAddrValid_) {
		    db.pagefln("No previous address to examine");
		    return;
		}
		addr = lastAddr_;
	    } else {
		string expr = args;
		Scope sc;
		Language lang;
		if (f) {
		    sc = f.scope_;
		    lang = f.lang_;
		} else {
		    sc = db;
		    lang = CLikeLanguage.instance;
		}

		try {
		    auto e = lang.parseExpr(expr, sc);
		    auto v = e.eval(sc, s).toValue;
		    auto pTy = cast(PointerType) v.type;
		    auto fTy = cast(FunctionType) v.type;
		    if (pTy || v.type.isIntegerType)
			addr = s.readAddress(v.loc.readValue(s));
		    else if (fTy)
			addr = v.loc.address(s);
		    else
			throw new EvalException("Not an address");
		} catch (EvalException ex) {
		    db.pagefln("%s", ex.msg);
		    return;
		}
	    }

	    uint count = count_;
	    if (fmt_ == "i") {
		while (count > 0) {
		    string addrString = db.lookupAddress(addr);
		    db.pagefln("%-31s %s", addrString,
			       s.disassemble(addr, &db.lookupAddress));
		    count--;
		}
	    } else {
		string line = format("%#-15x ", addr);
		while (count > 0) {
		    ubyte[] mem = db.target_.readMemory(addr, width_);
		    addr += width_;
		    TargetAddress val = s.readAddress(mem);
		    if (width_ < 8)
			val &= (1UL << width_ * 8) - 1;
		    string fmt = format("%%0%d%s ", 2*width_, fmt_);
		    string vs = format(fmt, val);
		    if (line.length + vs.length > 79) {
			db.pagefln("%s", line);
			line = format("%#-15x ", addr);
		    }
		    line ~= vs;
		    count--;
		}
		db.pagefln("%s", line);
	    }
	    lastAddrValid_ = true;
	    lastAddr_ = addr;
	}
    }
private:
    bool lastAddrValid_;
    TargetAddress lastAddr_;
    uint count_ = 1;
    TargetSize width_ = TS4;
    string fmt_ = "x";
}

class ListCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new ListCommand);
    }

    override {
	string name()
	{
	    return "list";
	}

	string description()
	{
	    return "list source file contents";
	}

	void run(Debugger db, string args)
	{
	    uint line = 0;
	    SourceFile sf = null;
	    if (find(args, ' ') >= 0) {
		db.pagefln("usage: list [- | <file:line>]");
		return;
	    }
	    if (args.length == 0) {
		sf = sourceFile_;
		line = sourceLine_;
	    } else if (args == "-") {
		sf = sourceFile_;
		line = sourceLine_;
		if (line > 20)
		    line -= 20;
		else
		    line = 1;
	    } else  {
		if (!db.parseSourceLine(args, sf, line)) {
		    line = 0;
		    sf = db.findFile(args);
		}
	    }
	    if (sf) {
		if (line == 0) {
		    if (sf == sourceFile_)
			line = sourceLine_;
		    else
			line = 1;
		}
	    } else {
		db.pagefln("no source file");
		return;
	    }
	    uint sl, el;
	    if (line > 5)
		sl = line - 5;
	    else
		sl = 1;
	    el = sl + 10;
	    for (uint ln = sl; ln < el; ln++)
		db.displaySourceLine(sf, ln);
	    db.setCurrentSourceLine(sf, line);
	    sourceFile_ = sf;
	    sourceLine_ = el + 5;
	}
	void onSourceLine(Debugger db, SourceFile sf, uint line)
	{
	    sourceFile_ = sf;
	    sourceLine_ = line;
	}
    }

    SourceFile sourceFile_;
    uint sourceLine_;
}

class RESearchCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new RESearchCommand);
    }

    override {
	string name()
	{
	    return "re-search";
	}

	string description()
	{
	    return "Search source file contents using regexp";
	}

	void run(Debugger db, string args)
	{
	    SourceFile sf = sourceFile_;
	    uint line = sourceLine_ + 1;
	    if (find(args, ' ') >= 0) {
		db.pagefln("usage: search [regexp]");
		return;
	    }
	    if (args.length == 0) {
                if (regexp_.length == 0) {
                    db.pagefln("No previous search expression");
                    return;
                }
                args = regexp_;
            }

	    if (!sf) {
		db.pagefln("No current source file");
		return;
	    }

	    try {
		while (line < sf.length) {
		    if (std.regexp.find(sf[line], args) >= 0)
			break;
		    line++;
		}
	    } catch (std.regexp.RegExpException ree) {
		db.pagefln("Regular expresson syntax error: %s", ree.msg);
		return;
	    }
            if (line == sf.length) {
                db.pagefln("Not found");
                return;
            }
            db.displaySourceLine(sf, line);
	    db.setCurrentSourceLine(sf, line);
	    regexp_ = args;
	}
	void onSourceLine(Debugger db, SourceFile sf, uint line)
	{
	    sourceFile_ = sf;
	    sourceLine_ = line;
	}
    }

    SourceFile sourceFile_;
    uint sourceLine_;
    string regexp_;
}

class SearchCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new SearchCommand);
    }

    override {
	string name()
	{
	    return "search";
	}

	string description()
	{
	    return "Search source file contents";
	}

	void run(Debugger db, string args)
	{
	    SourceFile sf = sourceFile_;
	    uint line = sourceLine_ + 1;
	    if (find(args, ' ') >= 0) {
		db.pagefln("usage: search [string]");
		return;
	    }
	    if (args.length == 0) {
                if (prevSearch_.length == 0) {
                    db.pagefln("No previous search expression");
                    return;
                }
                args = prevSearch_;
	    }

	    if (!sf) {
		db.pagefln("No current source file");
		return;
	    }

	    while (line < sf.length) {
		if (std.string.find(sf[line], args) >= 0)
		    break;
		line++;
	    }
            if (line == sf.length) {
                db.pagefln("Not found");
                return;
            }
            db.displaySourceLine(sf, line);
	    db.setCurrentSourceLine(sf, line);
	    prevSearch_ = args;
	}
	void onSourceLine(Debugger db, SourceFile sf, uint line)
	{
	    sourceFile_ = sf;
	    sourceLine_ = line;
	}
    }

    SourceFile sourceFile_;
    uint sourceLine_;
    string prevSearch_;
}

class DefineCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new DefineCommand);
    }

    override {
	string name()
	{
	    return "define";
	}

	string description()
	{
	    return "define a macro";
	}

	void run(Debugger db, string args)
	{
	    if (args.length == 0 || find(args, ' ') >= 0) {
		db.pagefln("usage: define name");
		return;
	    }		

	    Command c = db.lookupCommand(args);
	    if (c) {
		if (c.builtin) {
		    db.pagefln("Can't redefine built-in command \"%s\"",
			       args);
		    return;
		}
		if (!db.yesOrNo("Redefine command \"%s\"?", args))
		    return;
	    }

	    if (db.interactive)
		db.pagefln("Enter commands for \"%s\", finish with \"end\"",
			   args);
	    string[] cmds = db.readStatementBody;
	    Debugger.registerCommand(new MacroCommand(args, cmds));
	}
    }
}

class MacroCommand: Command
{
    this(string name, string[] cmds)
    {
	name_ = name;
	cmds_ = cmds;
    }

    override {
	string name()
	{
	    return name_;
	}

	string description()
	{
	    return name_;
	}

	void run(Debugger db, string args)
	{
	    if (depth_ > 1000) {
		db.pagefln("Recursion too deep");
		depth_ = 0;
		throw new PagerQuit;
	    }
	    string[] arglist = split(args, " ");
	    string[] cmds;
	    foreach (cmd; cmds_) {
		foreach (i, arg; arglist)
		    cmd = replace(cmd, "$arg" ~ std.string.toString(i), arg);
		cmds ~= cmd;
	    }
	    depth_++;
	    db.executeMacro(cmds);
	    depth_--;
	}

	bool builtin()
	{
	    return false;
	}
    }
private:
    string name_;
    string[] cmds_;
    static uint depth_ = 0;
}

class SourceCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new SourceCommand);
    }

    override {
	string name()
	{
	    return "source";
	}

	string description()
	{
	    return "Read commands from a file";
	}

	void run(Debugger db, string args)
	{
	    if (args.length == 0 || find(args, ' ') >= 0) {
		db.pagefln("usage: source filename");
		return;
	    }		

	    try
		db.sourceFile(args);
	    catch {
		writefln("Can't open file %s", args);
	    }
	}
    }
}

class IfCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new IfCommand);
    }

    override {
	string name()
	{
	    return "if";
	}

	string description()
	{
	    return "Conditionally execute commands";
	}

	void run(Debugger db, string args)
	{
	    if (args.length == 0 || find(args, ' ') >= 0) {
		db.pagefln("usage: if expr");
		return;
	    }		

	    bool cond = false;
	    MachineState s;
	    auto v = db.evaluateExpr(args, s);
	    if (v.type.isIntegerType)
		cond = s.readInteger(v.loc.readValue(s)) != 0;

	    string endString;
	    string[] ifCmds = db.readStatementBody("else", endString);
	    string[] elseCmds;
	    if (endString == "else")
		elseCmds = db.readStatementBody;

	    if (cond)
		db.executeMacro(ifCmds);
	    else
		db.executeMacro(elseCmds);
	}
    }
}

class WhileCommand: Command
{
    static this()
    {
	Debugger.registerCommand(new WhileCommand);
    }

    override {
	string name()
	{
	    return "while";
	}

	string description()
	{
	    return "Conditionally execute commands";
	}

	void run(Debugger db, string args)
	{
	    if (args.length == 0 || find(args, ' ') >= 0) {
		db.pagefln("usage: while expr");
		return;
	    }		

	    string[] cmds = db.readStatementBody;

	    for (;;) {
		bool cond = false;
		MachineState s;
		auto v = db.evaluateExpr(args, s);
		if (v.type.isIntegerType)
		    cond = s.readInteger(v.loc.readValue(s)) != 0;
		if (!cond)
		    break;
		db.executeMacro(cmds);
	    }
	}
    }
}
