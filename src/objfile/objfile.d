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

module objfile.objfile;
version (tangobos) import std.compat;
import endian;
import target.target;
import machine.machine;

struct Symbol
{
    string	name;
    TargetAddress value;
    TargetSize	size;
    int		type;
    int		binding;
    int		section;
}

class Objfile: Endian
{
    abstract bool isExecutable();

    abstract bool is64();

    abstract MachineState getState(Target);

    abstract ulong read(ubyte[] bytes);

    abstract ushort read(ushort v);

    abstract uint read(uint v);

    abstract ulong read(ulong v);

    abstract void write(ulong val, ubyte[] bytes);

    abstract void write(ushort v, out ushort res);

    abstract void write(uint v, out uint res);

    abstract void write(ulong v, out ulong res);

    abstract Symbol* lookupSymbol(TargetAddress addr);

    abstract Symbol* lookupSymbol(string name);

    abstract TargetAddress entry();

    abstract TargetAddress offset();

    abstract uint tlsindex();

    abstract bool hasSection(string name);

    abstract char[] readSection(string name);

    abstract string interpreter();

    abstract void enumerateNeededLibraries(Target target,
					   void delegate(string) dg);

    static Objfile open(string file, TargetAddress base)
    {
	Objfile obj;
	foreach (f; factories_) {
	    obj = f(file, base);
	    if (obj)
		return obj;
	}
	return null;
    }

    static void addFileType(Objfile function(string, TargetAddress) fn)
    {
	factories_ ~= fn;
    }

    static Objfile function(string, TargetAddress) factories_[];
}
