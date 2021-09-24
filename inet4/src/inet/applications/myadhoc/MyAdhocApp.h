#ifndef __INET_MYADHOCAPP_H
#define __INET_MYADHOCAPP_H

#include <vector>
#include <set>

#include "inet/common/INETDefs.h"

#include "inet/applications/base/ApplicationBase.h"
#include "inet/transportlayer/contract/udp/UdpSocket.h"

namespace inet {

class INET_API MyAdhocApp: public ApplicationBase, public UdpSocket::ICallback {
protected:
    enum SelfMsgKinds {
        START = 1, SEND, STOP, FORWARD
    };

    enum HostType {
        NORMAL, MALICIOUS
    };

    enum PacketType {
        BROADCAST, ACK
    };

    // parameters
    int localPort = -1, destPort = -1;
    simtime_t startTime;
    simtime_t stopTime;
    const char *packetName = nullptr;

    // state
    UdpSocket socket;
    cMessage *selfMsg = nullptr;
    cMessage *waitMsg = nullptr;
    cMessage *resendMsg = nullptr;
    cMessage *malicisouMsg = nullptr;

    // statistics
    int numSent = 0;
    int numReceived = 0;
    int numAck = 0;
    int numRetransmit = 0;
    int index = 0;
    int maliciousMode = 0;

    // variables for protocol
    int hostType = 0;   // host type MORMAL or MALICIOUS
    std::map<L3Address, cModule*> neighbourHosts; // neighbor host list
    std::set<L3Address> receivedSources;
    std::vector<L3Address> resendHosts;

    bool receivedAck, resendFlag;   // flags for ack & resend
    double oneHopLatency, resendTime; // one-hope latency & resend time (T = (N - 1) * latency)
    Packet *curPacket = nullptr;    // packet for resent
    L3Address myAddress;    // self address

protected:
    virtual int numInitStages() const override {
        return NUM_INIT_STAGES;
    }

    virtual void initialize(int stage) override;
    virtual void handleMessageWhenUp(cMessage *msg) override;
    virtual void finish() override;
    virtual void refreshDisplay() const override;

    virtual void sendAckPacket(L3Address destAddr); // send the ack packet
    virtual void forwardPacket(Packet *msg);    // forward the packet
    virtual void processPacket(Packet *msg);    // process the received packet
    virtual void setSocketOptions();    // set the socket

    virtual void processStart();    // process when starting
    virtual void processSend(); // broadcast the packet
    virtual void processReSend();   // resent the packet
    virtual void processStop(); // process when stop

    // handler functions
    virtual bool handleNodeStart(IDoneCallback *doneCallback) override;
    virtual bool handleNodeShutdown(IDoneCallback *doneCallback) override;
    virtual void handleNodeCrash() override;
    virtual void socketDataArrived(UdpSocket *socket, Packet *packet) override;
    virtual void socketErrorArrived(UdpSocket *socket, Indication *indication)
            override;
    void UpdateNeighborNodeList();
    void SendForwardPacket(Packet *msg);

public:
    MyAdhocApp() {
    }
    ~MyAdhocApp();

    bool IsReceived(L3Address addr);
};

} // namespace inet

#endif // ifndef __INET_MYADHOCAPP_H

