
package inet.applications.myadhoc;

import inet.applications.contract.IApp;

simple MyAdhocApp like IApp
{
    parameters:
        string interfaceTableModule;   // The path to the InterfaceTable module
        int localPort = default(-1);  // local port (-1: use ephemeral port)
        string destAddresses = default(""); // list of IP addresses, separated by spaces ("": don't send)
        string localAddress = default("");	// local address
        string packetName = default("MyAdhocAppData");	// packet name
        int destPort;	// dest port number
        volatile int messageLength @unit(B); // length of messages to generate, in bytes
        double startTime @unit(s) = default(0s); // application start time (start of the first packet)
        double stopTime @unit(s) = default(-1s);  // time of finishing sending, -1s means forever
        bool createMessage = default(false);
        @display("i=block/app");
    gates:
        input socketIn @labels(UdpControlInfo/up);
        output socketOut @labels(UdpControlInfo/down);
}
