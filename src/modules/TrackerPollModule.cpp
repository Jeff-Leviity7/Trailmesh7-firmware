#include "TrackerPollModule.h"

#include "FSCommon.h"
#include "HardwareRNG.h"
#include "MeshService.h"
#include "NodeDB.h"
#include "Router.h"
#include "SPILock.h"
#include "SafeFile.h"
#include "gps/RTC.h"
#include "meshUtils.h"
#include "modules/RoutingModule.h"
#include <pb_encode.h>

TrackerPollModule *trackerPollModule = nullptr;

static constexpr const char *kTrackerPollFile = "/prefs/tm7poll.bin";

TrackerPollModule::TrackerPollModule()
    : SinglePortModule("trackerpoll", static_cast<meshtastic_PortNum>(trailmesh::kTrackerPollPort))
{
    loadFromDisk();
}

ProcessMessage TrackerPollModule::handleReceived(const meshtastic_MeshPacket &mp)
{
    trailmesh::TrackerPollOp op;
    if (!trailmesh::trackerPollOp(mp.decoded.payload.bytes, mp.decoded.payload.size, op)) {
        LOG_DEBUG("TRAILMESH: tracker-poll frame from 0x%08x with no valid header; dropped", getFrom(&mp));
        return ProcessMessage::STOP;
    }

    switch (op) {
    case trailmesh::TrackerPollOp::SetSecret:
    case trailmesh::TrackerPollOp::Get:
    case trailmesh::TrackerPollOp::Clear:
        handleSetup(op, mp);
        break;
    case trailmesh::TrackerPollOp::Poll:
        handlePoll(mp);
        break;
    case trailmesh::TrackerPollOp::Current:
    case trailmesh::TrackerPollOp::Answer:
        // Ours to send, not to receive. An Answer addressed to a member is
        // delivered to that member's phone by the normal path regardless.
        break;
    }
    return ProcessMessage::STOP;
}

void TrackerPollModule::handleSetup(trailmesh::TrackerPollOp op, const meshtastic_MeshPacket &mp)
{
    // From the attached phone, and nowhere else. isFromUs alone is not enough:
    // `from` is just a field, and a packet off the air can carry ours. The
    // transport is what says it came over the API - the same guard
    // PositionModule::handleReceivedProtobuf uses against spoofed self-positions.
    if (!isFromUs(&mp) || !IS_ONE_OF(mp.transport_mechanism, meshtastic_MeshPacket_TransportMechanism_TRANSPORT_INTERNAL,
                                     meshtastic_MeshPacket_TransportMechanism_TRANSPORT_API)) {
        LOG_WARN("TRAILMESH: tracker-poll setup from 0x%08x over transport %d refused; phone only", getFrom(&mp),
                 mp.transport_mechanism);
        return;
    }

    if (op == trailmesh::TrackerPollOp::SetSecret) {
        trailmesh::TrackerPollConfig config;
        if (!trailmesh::decodeSetSecret(mp.decoded.payload.bytes, mp.decoded.payload.size, config)) {
            // Refused whole; the stored secret is untouched. The phone still
            // gets Current, so a bad write reads back as "not what you sent"
            // rather than as silence.
            LOG_WARN("TRAILMESH: tracker-poll secret refused (%u bytes)", (unsigned)mp.decoded.payload.size);
        } else {
            pollPolicy.setConfig(config);
            if (saveToDisk(mp.decoded.payload.bytes, mp.decoded.payload.size)) {
                LOG_INFO("TRAILMESH: tracker-poll secret set, %u s gap", config.gapSecs);
            } else {
                // Held in RAM for this boot regardless. Said, because the
                // phone's read-back cannot tell a secret that will survive a
                // reboot from one that will not.
                LOG_ERROR("TRAILMESH: tracker-poll secret set but not saved; it will be lost on reboot");
            }
        }
    } else if (op == trailmesh::TrackerPollOp::Clear) {
        pollPolicy.clear();
        removeFromDisk();
        LOG_INFO("TRAILMESH: tracker-poll secret cleared; this tag answers no polls");
    }
    reportToPhone();
}

void TrackerPollModule::handlePoll(const meshtastic_MeshPacket &mp)
{
    const uint32_t requester = getFrom(&mp);
    const uint32_t tracker = nodeDB->getNodeNum();
    // Over the air, and to us by name. A broadcast poll would have every
    // tracker in range answer at once.
    if (isFromUs(&mp) || !isToUs(&mp)) {
        LOG_DEBUG("TRAILMESH: tracker poll from 0x%08x not addressed to us over the air; ignored", requester);
        return;
    }

    uint32_t ts = 0;
    uint8_t tag[trailmesh::kTrackerPollTagBytes];
    if (!trailmesh::decodePoll(mp.decoded.payload.bytes, mp.decoded.payload.size, ts, tag)) {
        LOG_DEBUG("TRAILMESH: malformed tracker poll from 0x%08x; dropped", requester);
        return;
    }

    const uint32_t nowMs = millis();
    const auto verdict = pollPolicy.verdict(tracker, requester, ts, tag, getValidTime(RTCQualityDevice), nowMs);
    if (verdict != trailmesh::TrackerPollVerdict::Answer) {
        // Silent on the air, said here: the one place someone debugging a
        // tracker that will not answer can find out why.
        LOG_INFO("TRAILMESH: tracker poll from 0x%08x not answered: %s", requester, trailmesh::trackerPollVerdictName(verdict));
        return;
    }

    // The fix, or nothing - an empty plaintext tells the member the tracker
    // heard them and has no position, which is different from not hearing.
    uint8_t plain[meshtastic_Position_size];
    size_t plainLen = 0;
    if (nodeDB->hasLocalPositionSinceBoot() && (localPosition.latitude_i != 0 || localPosition.longitude_i != 0)) {
        meshtastic_Position pos = meshtastic_Position_init_default;
        pos.has_latitude_i = true;
        pos.latitude_i = localPosition.latitude_i;
        pos.has_longitude_i = true;
        pos.longitude_i = localPosition.longitude_i;
        if (localPosition.has_altitude) {
            pos.has_altitude = true;
            pos.altitude = localPosition.altitude;
        }
        pos.time = localPosition.time;
        pos.sats_in_view = localPosition.sats_in_view;
        pos.precision_bits = 32;
        plainLen = pb_encode_to_bytes(plain, sizeof(plain), &meshtastic_Position_msg, &pos);
    }

    meshtastic_MeshPacket *p = allocDataPacket();
    if (!p)
        return;
    uint8_t nonce[trailmesh::kTrackerPollNonceBytes];
    HardwareRNG::fill(nonce, sizeof(nonce));
    p->decoded.payload.size = trailmesh::encodeAnswer(pollPolicy.config().secret, tracker, requester, ts, nonce, plain, plainLen,
                                                      p->decoded.payload.bytes, sizeof(p->decoded.payload.bytes));
    if (p->decoded.payload.size == 0) {
        LOG_ERROR("TRAILMESH: tracker answer did not fit; not sent");
        packetPool.release(p);
        return;
    }
    p->to = requester;
    p->channel = mp.channel;
    p->want_ack = true;
    p->priority = meshtastic_MeshPacket_Priority_RELIABLE;
    p->hop_limit = routingModule->getHopLimitForResponse(mp);
    p->decoded.request_id = mp.id;
    pollPolicy.noteAnswer(requester, ts, nowMs);
    LOG_INFO("TRAILMESH: answering tracker poll from 0x%08x (%s)", requester, plainLen ? "with fix" : "no fix");
    service->sendToMesh(p);
}

void TrackerPollModule::reportToPhone()
{
    meshtastic_MeshPacket *p = router->allocForSending();
    if (!p)
        return;
    p->to = nodeDB->getNodeNum(); // addressed at ourselves; never transmitted
    p->decoded.portnum = static_cast<meshtastic_PortNum>(trailmesh::kTrackerPollPort);
    p->decoded.payload.size =
        trailmesh::encodeCurrent(pollPolicy.config(), p->decoded.payload.bytes, sizeof(p->decoded.payload.bytes));
    service->sendToPhone(p);
}

#ifdef FSCom

void TrackerPollModule::loadFromDisk()
{
    uint8_t buf[trailmesh::kTrackerPollSetSecretBytes + 1];
    size_t len = 0;
    {
        concurrency::LockGuard g(spiLock);
        auto f = FSCom.open(kTrackerPollFile, FILE_O_READ);
        if (!f) {
            LOG_DEBUG("TRAILMESH: no tracker-poll secret stored");
            return;
        }
        len = f.read(buf, sizeof(buf));
        f.close();
    }
    trailmesh::TrackerPollConfig config;
    if (trailmesh::decodeSetSecret(buf, len, config)) {
        pollPolicy.setConfig(config);
        LOG_INFO("TRAILMESH: tracker-poll secret loaded");
    } else {
        // No secret is the safe failure: nobody gets an exact answer.
        LOG_WARN("TRAILMESH: tracker-poll file unreadable (%u bytes); answering no polls", (unsigned)len);
    }
}

bool TrackerPollModule::saveToDisk(const uint8_t *frame, size_t len)
{
    {
        concurrency::LockGuard g(spiLock);
        FSCom.mkdir("/prefs");
    }
    SafeFile f(kTrackerPollFile, true);
    {
        concurrency::LockGuard g(spiLock);
        f.write(frame, len);
    }
    return f.close();
}

void TrackerPollModule::removeFromDisk()
{
    concurrency::LockGuard g(spiLock);
    FSCom.remove(kTrackerPollFile);
}

#else

void TrackerPollModule::loadFromDisk() {}
bool TrackerPollModule::saveToDisk(const uint8_t *, size_t)
{
    return false;
}
void TrackerPollModule::removeFromDisk() {}

#endif
