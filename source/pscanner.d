module source.pscanner;

import core.thread;
import std.string, std.stdio, std.socket;

import source.scans;

/***
Struct for setting flags passed in by the user.

NoFlags: No flags have been sent, just the target address. Performs a default TCP scan of the default port ranges. 
Verbose: "-v" flag has been passed; Performs verbose output of the scan
PRange: "-p [min-max]" has been passed; performs a scan on the range of ports provided
SinglePort: "-p [port]" has been passed; performs a scan on the specific port.

*/
struct PFlags
{
    bool NoFlags = false;
    bool Verbose = false;
    bool PRange = false;
    bool SinglePort = false;
    bool TCP = false;
    bool UDP = false;
};

/***
Class for scanning a set of ports based on parsed arguments passed to the program.
Users can scan a set of default port ranges, set a custom range, or a single port to scan on.
These scans can be TCP, UDP, or both.
Defaults to a TCP scan.
*/
class PScanner
{
public:
    this(string[] args)
    {
        this.target = args[0];
        this.scanFlags = args[1..$];
    }
    ~this(){}

    /// Processes the arguments and sets the approriate flags
    void processFlags()
    {
        if(this.scanFlags.length == 0)
        {
            Flags.NoFlags = true;
            Flags.TCP= true;
            setDefaultPortRange();
            return;
        }

        for(int i; i < this.scanFlags.length; i++)
        {
            switch(this.scanFlags[i])
            {
                case "-v":
                    Flags.Verbose = true;
                    setDefaultPortRange();
                    break;

                case "-p":
                    determinePortRange(this.scanFlags[i+1]);
                    break;

                case "tcp":
                    Flags.TCP = true;
                    break;
                
                case "udp":
                    Flags.UDP = true;
                    break;

                default:
                    break;
            }
        }
    }

    /// Public wrapper for scanning
    void scan()
    {
        processFlags();
        printInfo();
        performScan();
    }

private:
    PFlags Flags;
    string target;
    string[] scanFlags;
    ushort[] defaultPorts;
    ushort[] customPortRange;
    ushort DEFAULT_PORT_RANGE = 1023;

    /// Prints the info before scan
    void printInfo()
    {
        if(Flags.SinglePort)
            writefln("Initialising port scan on %s...\nScanning port %d...\n", this.target, this.customPortRange[0]);
        else if(Flags.PRange)
            writefln("Initialising port scan on %s...\nScanning ports %d to %d...\n", this.target, this.customPortRange[0], this.customPortRange[this.customPortRange.length-1]);
        else
            writefln("Initialising port scan on %s...\nScanning ports %d to %d...\n", this.target, this.defaultPorts[0], this.defaultPorts[this.defaultPorts.length-1]);
    }

    /// Sets the default port ranges to scan.
    void setDefaultPortRange()
    {
        this.defaultPorts = new ushort[DEFAULT_PORT_RANGE];
        for(ushort i = 1; i <= DEFAULT_PORT_RANGE; i++)
            this.defaultPorts[i-1] = i;
    }


    /// Sets the custom port range 
    void setCustomPortRange(ushort min, ushort max)
    {
        ushort range = cast(ushort)(max - min);
        this.customPortRange = new ushort[range+1];

        int count;
        for(ushort i = min; i <= max; i++)
        {
            this.customPortRange[count] = i;
            count++;
        }
    }

    /// Sets the custom port to scan.
    void setCustomSinglePort(ushort port)
    {
        this.customPortRange = new ushort[1];
        this.customPortRange[0] = port;
    }

    /// Determines the port ranges from the parsed argument and sets appropriate flags
    void determinePortRange(string ports)
    {
        import std.c.stdlib, std.conv;

        auto split = ports.split("-");
        
        if(split.length == 1)
        {
            try
            {
                ushort port = parse!ushort(split[0]);
                setCustomSinglePort(port);
                Flags.SinglePort  = true;
                return;
            }
            catch(Exception e)
            {
                writeln("That is not a valid port!");
                exit(-1);
            }
        }

        try
        {
            auto min = parse!ushort(split[0]);
            auto max = parse!ushort(split[1]);
            setCustomPortRange(min, max);
            Flags.PRange = true;
        }
        catch(Exception e)
        {
            writeln("That is not a valid port range!");
            exit(-1);
        }
    }

    /// Performs a scan
    // TODO: Find out what combos are missing...
    void performScan()
    {
        Scans scan = new Scans(this.target);

        // Default TCP Scan
        if(Flags.NoFlags)
        {
            defaultScan(scan);
            return;
        }

        // Defaualt TCP San Verbose only
        if(Flags.Verbose && !(Flags.UDP) && !(Flags.TCP) && !(Flags.PRange) && !(Flags.SinglePort))
        {
            writeln("HEre!!!");
            defaultScan(scan);
            return;
        }

        // Default UDP Scan
        if(Flags.UDP && (!Flags.PRange) && (!Flags.SinglePort))
        {
            defaultScanUDP(scan);
            return;
        }

        // Custom Range TCP Scan
        if((Flags.PRange || Flags.SinglePort) && Flags.TCP && !Flags.UDP)
        {
            customTCPScan(scan);
            return;
        }

        // Custom Range UDP Scan
        if((Flags.PRange || Flags.SinglePort) && !Flags.TCP && Flags.UDP)
        {
            customUDPScan(scan);
            return;
        }

        // Custom Range Scan (defaults to TCP)
        if((Flags.PRange || Flags.SinglePort) && !Flags.TCP && !Flags.UDP)
        {
            customTCPScan(scan);
            return;
        }

        // Concurrent custom scan of TCP and UDP ports
        if((Flags.PRange || Flags.SinglePort) && Flags.TCP && Flags.UDP)
        {
            // Starts the TCP Thread
            auto tcpThread = new Thread(
                {
                    customTCPScan(scan);
                }
            ).start();

            // Starts the UDP Thread
            auto udpThread = new Thread(
                {
                    customUDPScan(scan);
                }
            ).start();
            return;
        }

        // Concurrent default scan of TCP and UDP ports
        if(Flags.TCP && Flags.UDP)
        {
            auto tcpThread = new Thread(
                {
                    defaultScan(scan);
                }
            ).start();

            auto udpThread = new Thread(
                {
                    defaultScanUDP(scan);
                }
            ).start();
            return;
        }

        writefln("Error initialising scan");
    }

    /// Default Scan
    void defaultScan(Scans s)
    {
        if(Flags.Verbose)
        {
            s.TCPScan(this.defaultPorts, true);
            return;
        }

        s.TCPScan(this.defaultPorts, false);
    }

    /// Default UDP Scan
    void defaultScanUDP(Scans s)
    {
        if(Flags.Verbose)
        {
            s.UDPScan(this.defaultPorts, true);
            return;
        }

        s.UDPScan(this.defaultPorts, false);
    }       

    /// TCP Scan Custom ports
    void customTCPScan(Scans s)
    {
        if(Flags.Verbose)
        {
            s.TCPScan(this.customPortRange, true);
            return;
        }
        s.TCPScan(this.customPortRange, false);
    }

    /// UDP Scan Custom ports
    void customUDPScan(Scans s)
    {
        if(Flags.Verbose)
        {
            s.UDPScan(this.customPortRange, true);
            return;
        }

        s.UDPScan(this.customPortRange, false);
    }
}