#include "TrackerPollPolicy.h"

#include <AES.h>
#include <CTR.h>
#include <SHA256.h>
#include <cstring>

namespace trailmesh
{

namespace
{
const char kKeyIdLabel[] = "trailmesh-poll-id";
const char kReplyKeyLabel[] = "trailmesh-poll-reply";
const char kPollLabel[] = "poll";
const char kAnswerLabel[] = "answer";

void putU32(uint8_t *p, uint32_t v)
{
    p[0] = static_cast<uint8_t>(v);
    p[1] = static_cast<uint8_t>(v >> 8);
    p[2] = static_cast<uint8_t>(v >> 16);
    p[3] = static_cast<uint8_t>(v >> 24);
}

uint32_t getU32(const uint8_t *p)
{
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) | (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

void putHeader(uint8_t *buf, TrackerPollOp op)
{
    buf[0] = kTrackerPollMagic;
    buf[1] = kTrackerPollVersion;
    buf[2] = static_cast<uint8_t>(op);
}

bool allZero(const uint8_t *bytes, size_t len)
{
    uint8_t acc = 0;
    for (size_t i = 0; i < len; i++)
        acc |= bytes[i];
    return acc == 0;
}

/// Compares without an early exit, so the time taken says nothing about how
/// much of a forged tag was right.
bool sameBytes(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++)
        diff |= a[i] ^ b[i];
    return diff == 0;
}

void hmacLabel(const uint8_t secret[kTrackerPollSecretBytes], const char *label, uint8_t *out, size_t outLen)
{
    SHA256 h;
    h.resetHMAC(secret, kTrackerPollSecretBytes);
    h.update(label, strlen(label));
    h.finalizeHMAC(secret, kTrackerPollSecretBytes, out, outLen);
}

void answerTag(const uint8_t secret[kTrackerPollSecretBytes], uint32_t tracker, uint32_t requester, uint32_t ts,
               const uint8_t *nonce, const uint8_t *ct, size_t ctLen, uint8_t out[kTrackerPollTagBytes])
{
    uint8_t ids[12];
    putU32(ids, tracker);
    putU32(ids + 4, requester);
    putU32(ids + 8, ts);
    SHA256 h;
    h.resetHMAC(secret, kTrackerPollSecretBytes);
    h.update(kAnswerLabel, strlen(kAnswerLabel));
    h.update(ids, sizeof(ids));
    h.update(nonce, kTrackerPollNonceBytes);
    h.update(ct, ctLen);
    h.finalizeHMAC(secret, kTrackerPollSecretBytes, out, kTrackerPollTagBytes);
}

/// AES-256-CTR with the counter block `nonce | 00 00 00 00`, the same layout
/// room frames use, so the app has one CTR construction to get right.
void replyCipher(const uint8_t secret[kTrackerPollSecretBytes], const uint8_t *nonce, const uint8_t *in, uint8_t *out,
                 size_t len)
{
    uint8_t key[32];
    hmacLabel(secret, kReplyKeyLabel, key, sizeof(key));
    uint8_t iv[16] = {};
    memcpy(iv, nonce, kTrackerPollNonceBytes);
    CTR<AES256> ctr;
    ctr.setKey(key, sizeof(key));
    ctr.setIV(iv, sizeof(iv));
    ctr.setCounterSize(4);
    ctr.encrypt(out, in, len);
    memset(key, 0, sizeof(key));
}
} // namespace

bool trackerPollOp(const uint8_t *buf, size_t len, TrackerPollOp &op)
{
    if (!buf || len < kTrackerPollHeaderBytes)
        return false;
    if (buf[0] != kTrackerPollMagic || buf[1] != kTrackerPollVersion)
        return false;
    if (buf[2] < static_cast<uint8_t>(TrackerPollOp::SetSecret) || buf[2] > static_cast<uint8_t>(TrackerPollOp::Clear))
        return false;
    op = static_cast<TrackerPollOp>(buf[2]);
    return true;
}

size_t encodeHeaderOnly(TrackerPollOp op, uint8_t *buf, size_t cap)
{
    if (!buf || cap < kTrackerPollHeaderBytes)
        return 0;
    putHeader(buf, op);
    return kTrackerPollHeaderBytes;
}

size_t encodeSetSecret(uint16_t gapSecs, const uint8_t secret[kTrackerPollSecretBytes], uint8_t *buf, size_t cap)
{
    if (!buf || cap < kTrackerPollSetSecretBytes)
        return 0;
    putHeader(buf, TrackerPollOp::SetSecret);
    buf[3] = static_cast<uint8_t>(gapSecs);
    buf[4] = static_cast<uint8_t>(gapSecs >> 8);
    memcpy(buf + 5, secret, kTrackerPollSecretBytes);
    return kTrackerPollSetSecretBytes;
}

bool decodeSetSecret(const uint8_t *buf, size_t len, TrackerPollConfig &out)
{
    TrackerPollOp op;
    if (!trackerPollOp(buf, len, op) || op != TrackerPollOp::SetSecret || len != kTrackerPollSetSecretBytes)
        return false;
    const uint16_t gap = static_cast<uint16_t>(buf[3] | (buf[4] << 8));
    if (gap < kTrackerPollMinGapSecs || gap > kTrackerPollMaxGapSecs)
        return false;
    if (allZero(buf + 5, kTrackerPollSecretBytes))
        return false;
    TrackerPollConfig c;
    c.hasSecret = true;
    c.gapSecs = gap;
    memcpy(c.secret, buf + 5, kTrackerPollSecretBytes);
    out = c;
    return true;
}

void trackerPollKeyId(const uint8_t secret[kTrackerPollSecretBytes], uint8_t out[kTrackerPollKeyIdBytes])
{
    hmacLabel(secret, kKeyIdLabel, out, kTrackerPollKeyIdBytes);
}

size_t encodeCurrent(const TrackerPollConfig &config, uint8_t *buf, size_t cap)
{
    if (!buf || cap < kTrackerPollCurrentBytes)
        return 0;
    putHeader(buf, TrackerPollOp::Current);
    buf[3] = static_cast<uint8_t>(config.gapSecs);
    buf[4] = static_cast<uint8_t>(config.gapSecs >> 8);
    buf[5] = config.hasSecret ? 1 : 0;
    if (config.hasSecret)
        trackerPollKeyId(config.secret, buf + 6);
    else
        memset(buf + 6, 0, kTrackerPollKeyIdBytes);
    return kTrackerPollCurrentBytes;
}

void trackerPollTag(const uint8_t secret[kTrackerPollSecretBytes], uint32_t tracker, uint32_t requester, uint32_t ts,
                    uint8_t out[kTrackerPollTagBytes])
{
    uint8_t ids[12];
    putU32(ids, tracker);
    putU32(ids + 4, requester);
    putU32(ids + 8, ts);
    SHA256 h;
    h.resetHMAC(secret, kTrackerPollSecretBytes);
    h.update(kPollLabel, strlen(kPollLabel));
    h.update(ids, sizeof(ids));
    h.finalizeHMAC(secret, kTrackerPollSecretBytes, out, kTrackerPollTagBytes);
}

size_t encodePoll(const uint8_t secret[kTrackerPollSecretBytes], uint32_t tracker, uint32_t requester, uint32_t ts,
                  uint8_t *buf, size_t cap)
{
    if (!buf || cap < kTrackerPollPollBytes)
        return 0;
    putHeader(buf, TrackerPollOp::Poll);
    putU32(buf + 3, ts);
    trackerPollTag(secret, tracker, requester, ts, buf + 7);
    return kTrackerPollPollBytes;
}

bool decodePoll(const uint8_t *buf, size_t len, uint32_t &ts, uint8_t tag[kTrackerPollTagBytes])
{
    TrackerPollOp op;
    if (!trackerPollOp(buf, len, op) || op != TrackerPollOp::Poll || len != kTrackerPollPollBytes)
        return false;
    ts = getU32(buf + 3);
    memcpy(tag, buf + 7, kTrackerPollTagBytes);
    return true;
}

size_t encodeAnswer(const uint8_t secret[kTrackerPollSecretBytes], uint32_t tracker, uint32_t requester, uint32_t ts,
                    const uint8_t nonce[kTrackerPollNonceBytes], const uint8_t *plaintext, size_t plaintextLen,
                    uint8_t *buf, size_t cap)
{
    const size_t len = kTrackerPollAnswerOverhead + plaintextLen;
    if (!buf || cap < len || (plaintextLen > 0 && !plaintext))
        return 0;
    putHeader(buf, TrackerPollOp::Answer);
    putU32(buf + 3, ts);
    memcpy(buf + 7, nonce, kTrackerPollNonceBytes);
    uint8_t *ct = buf + 7 + kTrackerPollNonceBytes;
    if (plaintextLen > 0)
        replyCipher(secret, nonce, plaintext, ct, plaintextLen);
    answerTag(secret, tracker, requester, ts, nonce, ct, plaintextLen, ct + plaintextLen);
    return len;
}

bool decodeAnswer(const uint8_t secret[kTrackerPollSecretBytes], uint32_t tracker, uint32_t requester, uint32_t expectTs,
                  const uint8_t *buf, size_t len, uint8_t *plaintext, size_t cap, size_t &plaintextLen)
{
    TrackerPollOp op;
    if (!trackerPollOp(buf, len, op) || op != TrackerPollOp::Answer || len < kTrackerPollAnswerOverhead)
        return false;
    const uint32_t ts = getU32(buf + 3);
    if (ts != expectTs)
        return false;
    const uint8_t *nonce = buf + 7;
    const uint8_t *ct = nonce + kTrackerPollNonceBytes;
    const size_t ctLen = len - kTrackerPollAnswerOverhead;
    uint8_t want[kTrackerPollTagBytes];
    answerTag(secret, tracker, requester, ts, nonce, ct, ctLen, want);
    if (!sameBytes(want, ct + ctLen, kTrackerPollTagBytes))
        return false;
    if (ctLen > cap || (ctLen > 0 && !plaintext))
        return false;
    if (ctLen > 0)
        replyCipher(secret, nonce, ct, plaintext, ctLen);
    plaintextLen = ctLen;
    return true;
}

const char *trackerPollVerdictName(TrackerPollVerdict v)
{
    switch (v) {
    case TrackerPollVerdict::NoSecret:
        return "no secret";
    case TrackerPollVerdict::NoClock:
        return "no clock";
    case TrackerPollVerdict::Stale:
        return "stale";
    case TrackerPollVerdict::BadTag:
        return "bad tag";
    case TrackerPollVerdict::Replayed:
        return "replayed";
    case TrackerPollVerdict::Throttled:
        return "throttled";
    case TrackerPollVerdict::Answer:
        return "answer";
    }
    return "?";
}

void TrackerPollPolicy::setConfig(const TrackerPollConfig &config)
{
    cfg = config;
    for (auto &r : requesters)
        r = Requester{};
}

void TrackerPollPolicy::clear()
{
    setConfig(TrackerPollConfig{});
}

const TrackerPollPolicy::Requester *TrackerPollPolicy::find(uint32_t node) const
{
    for (const auto &r : requesters) {
        if (r.used && r.node == node)
            return &r;
    }
    return nullptr;
}

TrackerPollVerdict TrackerPollPolicy::verdict(uint32_t tracker, uint32_t requester, uint32_t ts,
                                              const uint8_t tag[kTrackerPollTagBytes], uint32_t nowSecs, uint32_t nowMs) const
{
    if (!cfg.hasSecret)
        return TrackerPollVerdict::NoSecret;
    if (nowSecs == 0)
        return TrackerPollVerdict::NoClock;
    const uint32_t skew = ts > nowSecs ? ts - nowSecs : nowSecs - ts;
    if (skew > kTrackerPollClockWindowSecs)
        return TrackerPollVerdict::Stale;
    uint8_t want[kTrackerPollTagBytes];
    trackerPollTag(cfg.secret, tracker, requester, ts, want);
    if (!sameBytes(want, tag, kTrackerPollTagBytes))
        return TrackerPollVerdict::BadTag;
    if (const Requester *r = find(requester)) {
        if (ts <= r->lastTs)
            return TrackerPollVerdict::Replayed;
        // Unsigned subtraction, so a millis() wrap still measures the gap.
        if (static_cast<uint32_t>(nowMs - r->lastAnswerMs) < static_cast<uint32_t>(cfg.gapSecs) * 1000U)
            return TrackerPollVerdict::Throttled;
    }
    return TrackerPollVerdict::Answer;
}

void TrackerPollPolicy::noteAnswer(uint32_t requester, uint32_t ts, uint32_t nowMs)
{
    Requester *slot = nullptr;
    for (auto &r : requesters) {
        if (r.used && r.node == requester) {
            slot = &r;
            break;
        }
    }
    if (!slot) {
        // A free slot, else the one answered longest ago.
        for (auto &r : requesters) {
            if (!r.used) {
                slot = &r;
                break;
            }
        }
    }
    if (!slot) {
        slot = &requesters[0];
        for (auto &r : requesters) {
            if (static_cast<uint32_t>(nowMs - r.lastAnswerMs) > static_cast<uint32_t>(nowMs - slot->lastAnswerMs))
                slot = &r;
        }
    }
    slot->used = true;
    slot->node = requester;
    slot->lastTs = ts;
    slot->lastAnswerMs = nowMs;
}

} // namespace trailmesh
