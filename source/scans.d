module source.scans;

import core.thread;
import std.stdio, std.socket;

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

            try
            {
                client = new Socket(AddressFamily.INET, SocketType.STREAM, ProtocolType.TCP);
            }
            catch(SocketOSException e)
            {
                writefln("Error creating socket!\n%s", e);
                return;
            }
            auto addr = getAddress(this.target, ranges[i]);

            try
            {
                if(verbose)
                    writefln("Attempting port %d...", ranges[i]);
                client.connect(addr[0]);
                Thread.sleep(dur!("seconds")(1));
            }
            catch(Exception e)
            {
                if(verbose)
                    writefln("Port %d is closed.", ranges[i]);

                client.close();
                continue;
            }

            writefln("Port %d is open!", ranges[i]);
            client.close();
            destroy(client);
        }
    }

    /// UDP Scan - FUCK THE DRY PRINCIPLE
    void UDPScan(ushort[] ranges, bool verbose)
    {
        for(int i; i < ranges.length; i++)
        {
            Socket client;

            try
            {
                client = new Socket(AddressFamily.INET, SocketType.STREAM, ProtocolType.UDP);
            }
            catch(SocketOSException e)
            {
                writefln("Error creating socket!\n%s", e);
                return;
            }
            auto addr = getAddress(this.target, ranges[i]);

            try
            {
                if(verbose)
                    writefln("Attempting port %d...", ranges[i]);
                client.connect(addr[0]);
                Thread.sleep(dur!("seconds")(1));
            }
            catch(Exception e)
            {
                if(verbose)
                    writefln("Port %d is closed.", ranges[i]);
            }

            writefln("Port %d is open!", ranges[i]);
            client.close();
            destroy(client); 
        }
    }

private:
    string target;
}