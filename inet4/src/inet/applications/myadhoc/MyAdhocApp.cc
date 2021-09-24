#include "inet/applications/base/ApplicationPacket_m.h"
#include "inet/applications/myadhoc/MyAdhocApp.h"
#include "inet/applications/myadhoc/MyAdhocMsg_m.h"
#include "inet/common/lifecycle/NodeOperations.h"
#include "inet/common/ModuleAccess.h"
#include "inet/common/packet/Packet.h"
#include "inet/common/TagBase_m.h"
#include "inet/common/TimeTag_m.h"
#include "inet/networklayer/common/L3AddressResolver.h"
#include "inet/transportlayer/contract/udp/UdpControlInfo_m.h"
#include "inet/mobility/static/StationaryMobility.h"

namespace inet {

Define_Module(MyAdhocApp);

/*
 * de-construct the class
 */
MyAdhocApp::~MyAdhocApp() {
    cancelAndDelete(selfMsg);
    cancelAndDelete(waitMsg);
    cancelAndDelete(resendMsg);
}

/*
 * initialize the module
 */
void MyAdhocApp::initialize(int stage) {
    ApplicationBase::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {

        // initialize the variables
        numSent = 0;
        numReceived = 0;
        numAck = 0;
        numRetransmit = 0;
        index = 0;
        maliciousMode = 0;

        WATCH(numSent);
        WATCH(numReceived);
        WATCH(numAck);
        WATCH(numRetransmit);

        resendFlag = true;
        receivedAck = false;
        oneHopLatency = 0.0;
        resendTime = 0.0;

        // get the parameters
        localPort = par("localPort");
        destPort = par("destPort");
        startTime = par("startTime");
        stopTime = par("stopTime");
        packetName = par("packetName");
        if (stopTime >= SIMTIME_ZERO&& stopTime < startTime)
        throw cRuntimeError("Invalid startTime/stopTime parameters");

        // create the self messages
        selfMsg = new cMessage("sendTimer");
        waitMsg = new cMessage("waitTimer");
        resendMsg = new cMessage("resendTimer");
        malicisouMsg = new cMessage("maliciousTimer");

        // check the host type whether normal or malicious
        if (!strcmp(getParentModule()->getName(), "NormalHost")) {
            hostType = NORMAL;
        } else {
            hostType = MALICIOUS;
        }
    }
}

/*
 * finish handler function
 */
void MyAdhocApp::finish() {

    // output the result if NORMAL Host
    if (hostType == NORMAL) {
        recordScalar("Packets sent", numSent);
        recordScalar("Packets received", numReceived);
        recordScalar("Overhead of Ack", numAck);
        recordScalar("Overhead of retransmit", numRetransmit);
    }

    std::cout << "----------- " << getParentModule()->getFullName()
            << " -----------" << std::endl;
    for (std::map<L3Address, cModule*>::iterator it = neighbourHosts.begin();
            it != neighbourHosts.end(); it++) {
        std::cout << "\t" << it->first.str() << " ---> "
                << it->second->getFullName() << std::endl;
    }

    ApplicationBase::finish();
}

/*
 * set the socket
 */
void MyAdhocApp::setSocketOptions() {
    // set the broadcast mode
    socket.setBroadcast(false);

    // set the callback
    socket.setCallback(this);
}

/*
 * send the ack packet
 */
void MyAdhocApp::sendAckPacket(L3Address destAddr) {
    // create the ack packet
    MyAdhocMsg *m_MyMsg = new MyAdhocMsg();
    m_MyMsg->setPacketType(ACK);    // set the packet type with ack
    m_MyMsg->setSenderAddr(myAddress);  // set the sender address
    m_MyMsg->setCreationTime(simTime().dbl());  // set the packet creating time
    const auto& payload = makeShared<ApplicationPacket>(); // create the packet payload
    payload->setChunkLength(B(16)); // set the payload size
    payload->setSequenceNumber(numSent);    // set the sequence number
    m_MyMsg->insertAtBack(payload); // add the payload to packet

    socket.sendTo(m_MyMsg, destAddr, destPort); // send the packet
    numSent++;
}

/*
 * Forward the packet
 */
void MyAdhocApp::forwardPacket(Packet* msg) {
    MyAdhocMsg *m_ForwardMsg = dynamic_cast<MyAdhocMsg*>(msg);
    m_ForwardMsg->setPacketType(BROADCAST);
    m_ForwardMsg->setSenderAddr(myAddress); // update the sender address
    m_ForwardMsg->setCreationTime(simTime().dbl()); // update the packet creating time

    MyAdhocMsg *m_MyMsg = new MyAdhocMsg(packetName);
    m_MyMsg->setPacketType(BROADCAST);  // set the packet type with BROADCAST
    m_MyMsg->setSrcAddr(m_ForwardMsg->getSrcAddr());
    m_MyMsg->setSenderAddr(myAddress);  // set the sender address
    m_MyMsg->setCreationTime(simTime().dbl());  // set the creating time
    const auto& payload = makeShared<ApplicationPacket>(); // create the payload
    payload->setChunkLength(B(par("messageLength")));   // set the payload size
    payload->setSequenceNumber(numSent);    // set the packet sequeuce number
    m_MyMsg->insertAtBack(payload); // add the payload to packet

    receivedAck = false;

    curPacket = m_ForwardMsg->dup();    // save the packet to resend

    // broadcast the packet
    index = 0;
    resendHosts.clear();
    scheduleAt(simTime() + 0.001, m_MyMsg);

    numSent++;
}

/*
 * Process when starting
 */
void MyAdhocApp::processStart() {

    if (hostType == MALICIOUS || !par("createMessage").boolValue())
        return;

    getParentModule()->getDisplayString().updateWith("r=24,red");

    // send processing
    processSend();
}

/*
 * Broadcast the packet
 */
void MyAdhocApp::processSend() {
    // create the packet
    MyAdhocMsg *m_MyMsg = new MyAdhocMsg(packetName);
    m_MyMsg->setPacketType(BROADCAST);  // set the packet type with BROADCAST
    m_MyMsg->setSrcAddr(myAddress);
    m_MyMsg->setSenderAddr(myAddress);  // set the sender address
    m_MyMsg->setCreationTime(simTime().dbl());  // set the creating time
    const auto& payload = makeShared<ApplicationPacket>(); // create the payload
    payload->setChunkLength(B(par("messageLength")));   // set the payload size
    payload->setSequenceNumber(numSent);    // set the packet sequeuce number
    m_MyMsg->insertAtBack(payload); // add the payload to packet

    curPacket = m_MyMsg->dup(); // save the packet to resend
    receivedAck = false;

    receivedSources.insert(myAddress);

    // broadcast the packet
    index = 0;
    resendHosts.clear();
    for (std::map<L3Address, cModule*>::iterator it = neighbourHosts.begin();
            it != neighbourHosts.end(); it++) {
        resendHosts.push_back(it->first);
        socket.sendTo(m_MyMsg->dup(), it->first, destPort);
    }

    // start the timer to check the receiving ack
//    oneHopLatency == 0.0 ? oneHopLatency = 0.001 : oneHopLatency;
//    resendTime =
//            (double) (getParentModule()->getParentModule()->par("numHosts").intValue()
//                    - 1) * oneHopLatency;
//    scheduleAt(simTime() + oneHopLatency, waitMsg);
    resendFlag = true;

    numSent++;
}

/*
 * resent the packet
 */
void MyAdhocApp::processReSend() {
    // check the receiving ack and resent time
    if (receivedAck || !resendFlag) {
        receivedAck = false;
        resendFlag = true;
        return;
    }

    // update the creating time
    ((MyAdhocMsg*) curPacket)->setCreationTime(simTime().dbl());

    // resent the packet
    for (std::vector<L3Address>::iterator it = resendHosts.begin();
            it != resendHosts.end(); it++) {
        socket.sendTo(curPacket->dup(), *it, destPort);
    }

    curPacket = curPacket->dup();
    scheduleAt(simTime() + oneHopLatency, waitMsg);

    resendFlag = true;
    receivedAck = false;

    numRetransmit++;
    numSent++;
}

/*
 * process when stop
 */
void MyAdhocApp::processStop() {
    socket.close();
}

/*
 * Process the received packet
 */
void MyAdhocApp::processPacket(Packet *pk) {
    EV_INFO << "Received packet: " << UdpSocket::getReceivedPacketInfo(pk)
                   << endl;

    // if host type is malicious, return
    if (hostType == MALICIOUS && maliciousMode % 2 == 1)
        return;

    MyAdhocMsg *m_MyMsg = dynamic_cast<MyAdhocMsg*>(pk);

    if (m_MyMsg == NULL) {
        delete pk;
        return;
    }

#ifdef _DEBUG_
    std::cout << getParentModule()->getFullName() << " --- Received packet: "
    << UdpSocket::getReceivedPacketInfo(pk) << endl;
#endif

    L3Address m_Sender = m_MyMsg->getSenderAddr();
    L3Address m_Src = m_MyMsg->getSrcAddr();

    oneHopLatency = simTime().dbl() - m_MyMsg->getCreationTime();

    oneHopLatency == 0.0 ? oneHopLatency = 0.1 : oneHopLatency;

    if (m_Sender == myAddress)
        return;

    // process the packet
    if (m_MyMsg->getPacketType() == BROADCAST) {

        getParentModule()->getDisplayString().updateWith("r=16,blue");

        if (receivedSources.find(m_Src) == receivedSources.end()) {
            receivedSources.insert(m_Src);
        }

        forwardPacket(pk);

        // send the ack packet
        sendAckPacket(m_Sender);
        numReceived++;
    } else if (m_MyMsg->getPacketType() == ACK) {
        receivedAck = true;
        numAck++;
    }

    delete pk;
}

/*
 * Message handler
 */
void MyAdhocApp::handleMessageWhenUp(cMessage *msg) {
    if (msg->isSelfMessage()) {
        if (msg == selfMsg) {
            switch (selfMsg->getKind()) {
            case START: // start
                processStart();
                break;

            case SEND:  // send
                processSend();
                break;

            case STOP:  // stop
                processStop();
                break;

            default:
                throw cRuntimeError("Invalid kind %d in self message",
                        (int) selfMsg->getKind());
            }
        } else if (msg == waitMsg) {    // ack waiting timer

            if (!resendMsg->isScheduled()) {
                scheduleAt(simTime() + resendTime, resendMsg);
            }

            processReSend();
        } else if (msg == resendMsg) {  // resent waiting timer
            resendFlag = false;
        } else if (msg == malicisouMsg) {
            maliciousMode++;
            scheduleAt(simTime() + 3.0, malicisouMsg);
        } else {
            SendForwardPacket((Packet*) msg);
        }
    } else
        socket.processMessage(msg);
}

/*
 * Packet receiving Handler
 */
void MyAdhocApp::socketDataArrived(UdpSocket *socket, Packet *packet) {
    // process incoming packet
    processPacket(packet);
}

/*
 * Error Handler
 */
void MyAdhocApp::socketErrorArrived(UdpSocket *socket, Indication *indication) {
    EV_WARN << "Ignoring UDP error report " << indication->getName() << endl;
    delete indication;
}

void MyAdhocApp::refreshDisplay() const {
    char buf[100];
    sprintf(buf, "rcvd: %d pks\nsent: %d pks", numReceived, numSent);
    getDisplayString().setTagArg("t", 0, buf);
}

/*
 * Node start handler
 */
bool MyAdhocApp::handleNodeStart(IDoneCallback *doneCallback) {
    // set the socket
    socket.setOutputGate(gate("socketOut"));
    const char *localAddress = par("localAddress");
    socket.bind(
            *localAddress ?
                    L3AddressResolver().resolve(localAddress) : L3Address(),
            localPort);
    setSocketOptions();

    selfMsg->setKind(SEND);

    myAddress = L3AddressResolver().resolve(getParentModule()->getFullName());
    UpdateNeighborNodeList();

    if (hostType == MALICIOUS) {
        scheduleAt(simTime() + 3.0, malicisouMsg);
    }

    simtime_t start = std::max(startTime, simTime());
    if ((stopTime < SIMTIME_ZERO) || (start < stopTime) || (start == stopTime && startTime == stopTime)) {
        selfMsg->setKind(START);
        scheduleAt(start, selfMsg);
    }

    return true;
}

/*
 * Node shutdown Handler
 */
bool MyAdhocApp::handleNodeShutdown(IDoneCallback *doneCallback) {
    if (selfMsg)
        cancelEvent(selfMsg);
    return true;
}

/*
 * Node crash handler
 */
void MyAdhocApp::handleNodeCrash() {
    if (selfMsg)
        cancelEvent(selfMsg);
}

void MyAdhocApp::UpdateNeighborNodeList() {
    int m_NumNormalHosts = getContainingNode(this)->getParentModule()->par(
            "numHosts");
    int m_NumNaliciousHosts = getContainingNode(this)->getParentModule()->par(
            "numMalHosts");

    StationaryMobility *m_CurMobility = check_and_cast<StationaryMobility *>(
            getContainingNode(this)->getSubmodule("mobility"));

    char buf[127] = { 0 };
    for (int i = 0; i < m_NumNormalHosts; i++) {
        cModule* m_module =
                getContainingNode(this)->getParentModule()->getSubmodule(
                        "NormalHost", i);
        StationaryMobility *m_Mobility = check_and_cast<StationaryMobility*>(
                m_module->getSubmodule("mobility"));

        if (m_CurMobility->getCurrentPosition().distance(
                m_Mobility->getCurrentPosition()) < 300.0) {
            memset(buf, 0, 127);
            sprintf(buf, "NormalHost[%d]", i);
            L3Address m_addr = L3AddressResolver().resolve(buf);
            if (m_addr != myAddress)
                neighbourHosts[m_addr] = m_module;
        }
    }

    for (int i = 0; i < m_NumNaliciousHosts; i++) {
        cModule* m_Module =
                getContainingNode(this)->getParentModule()->getSubmodule(
                        "MalHost", i);
        StationaryMobility *m_Mobility = check_and_cast<StationaryMobility*>(
                m_Module->getSubmodule("mobility"));

        if (m_CurMobility->getCurrentPosition().distance(
                m_Mobility->getCurrentPosition()) < 300.0) {
            memset(buf, 0, 127);
            sprintf(buf, "MalHost[%d]", i);
            L3Address m_addr = L3AddressResolver().resolve(buf);

            if (m_addr != myAddress)
                neighbourHosts[m_addr] = m_Module;
        }
    }
}

void MyAdhocApp::SendForwardPacket(Packet *msg) {
    if (index >= neighbourHosts.size()) {
        resendTime = (double) (getParentModule()->getParentModule()->par(
                "numHosts").intValue() - 1) * oneHopLatency;
        resendFlag = true;

        if (!waitMsg->isScheduled())
            scheduleAt(simTime() + oneHopLatency, waitMsg);
        return;
    }

    std::map<L3Address, cModule*>::iterator it = neighbourHosts.begin();
    std::advance(it, index);

    L3Address m_Src = dynamic_cast<MyAdhocMsg*>(msg)->getSrcAddr();
    dynamic_cast<MyAdhocMsg*>(msg)->setCreationTime(simTime().dbl());

    MyAdhocApp* m_MyApp = dynamic_cast<MyAdhocApp*>(it->second->getSubmodule(
            "app", 0));
    if (!(m_MyApp->IsReceived(m_Src))) {

#ifdef _DEBUG_
        std::cout << getParentModule()->getFullName()
        << " : forword the packet " << it->second->getFullName()
        << " : " << m_Src.str() << " : " << it->first.str()
        << std::endl;
#endif

        resendHosts.push_back(it->first);
        socket.sendTo(msg, it->first, destPort);
    }

    index++;

    scheduleAt(simTime(), msg->dup());
}

bool MyAdhocApp::IsReceived(L3Address addr) {
    return (receivedSources.find(addr) != receivedSources.end());
}

} // namespace inet

