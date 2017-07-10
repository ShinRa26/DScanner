module source.launch;

import std.stdio;
import source.pscanner;

void main(string[] args)
{
	auto cla = args[1..$];
	if(cla.length == 0)
	{
		writeln("You must pass a target!\nExitting...");
		return;
	}

	PScanner ps = new PScanner(cla);
	ps.scan();
}