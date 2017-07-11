module source.scans;

import core.thread;
import std.stdio, std.socket;

/***
Class for conducting TCP/UDP scans of the target.
A target is supplied and will perform a TCP and/or UDP scan for the port ranges supplied.
Each scan takes a range of ports to scan and a flag for verbose output.
*/
class Scans
{
public:
    this(string target)
    {
        this.target = target;
    }
    ~this(){}

    /// TCP Scan
    void TCPScan(ushort[] ranges, bool verbose)
    {
        for(int i; i < ranges.length; i++)
        {
            Socket client;
            Address[] addr;

            try
            {
                client = new Socket(AddressFamily.INET, SocketType.STREAM, ProtocolType.TCP);
                addr = getAddress(this.target, ranges[i]);
            }
            catch(SocketOSException e)
            {
                writefln("Error creating socket!\nCheck host address is valid.");
                return;
            }

            try
            {
                if(verbose)
                    writefln("Attempting connection on port %d/TCP...", ranges[i]);
                client.connect(addr[0]);
            }
            catch(Exception e)
            {
                if(verbose)
                    writefln("Port %d/TCP is closed.\n", ranges[i]);

                client.close();
                continue;
            }

            writefln("Discovered open port %d/TCP!\n", ranges[i]);
            client.close();
            destroy(client);
        }
    }

    /// UDP Scan - Does not work on Linux! (Need to fix - Protocol not supported)
    /// Pretty much a TCP scan but with the UDP flag set in the socket instead of TCP...
    void UDPScan(ushort[] ranges, bool verbose)
    {
        for(int i; i < ranges.length; i++)
        {
            Socket client;
            Address[] addr;

            try
            {
                client = new Socket(AddressFamily.INET, SocketType.DGRAM, ProtocolType.UDP);
                addr = getAddress(this.target, ranges[i]);
            }
            catch(SocketOSException e)
            {
                writefln("Error creating socket!\nCheck the Host address is valid.");
                return;
            }

            try
            {
                if(verbose)
                    writefln("Attempting connection on port %d/UDP...", ranges[i]);
                client.connect(addr[0]);
            }
            catch(Exception e)
            {
                if(verbose)
                    writefln("Port %d/UDP is closed.\n", ranges[i]);

                client.close();
                continue;
            }

            writefln("Discovered open port %d/UDP!\n", ranges[i]);
            client.close();
            destroy(client); 
        }
    }

private:
    string target;
}