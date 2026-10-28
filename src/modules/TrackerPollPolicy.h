#pragma once

#include <cstddef>
#include <cstdint>

/**
 * TRAILMESH: who may poll this tracker for its exact position, and how often.
 *
 * A TrailMesh7 tracker broadcasts no position - its primary channel is opted
 * out of position sharing. It answers a poll instead, from anyone in its room,
 * and from no one else.
 *
 * **Membership is the authorisation.** At setup the app writes one secret to
 * the tracker, derived from the room key:
 *
 *     pollSecret = HMAC-SHA256(roomKey, "trailmesh-tracker-poll")
 *
 * Every member's app can derive the same secret, so a member added later can
 * poll at once and nothing on the tracker changes. The tracker never holds
 * the room key itself, so one left on a fence post exposes only its own
 * position, not the room's messages. A kick rotates the room key, which
 * changes the secret, so a tracker must be given the new one before members
 * can poll it again - see `docs/tracker-polling.md` in the app repo.
 *
 * This replaced a per-member allowlist of public keys (2026-10-28), which
 * needed the tracker rewritten every time someone joined. Stock
 * `POSITION_APP` requests are untouched: they still get stock behaviour.
 *
 * Wire format, all on private port `kTrackerPollPort`, every frame starting
 * `[0x54 'T'][version 2][op]`, integers little-endian:
 *
 *   SetSecret 1  phone->own tag  [gap u16][secret 32]
 *   Get       2  phone->own tag  (header only)
 *   Current   3  own tag->phone  [gap u16][has secret u8][key id 4]
 *   Poll      4  member->tracker [ts u32][tag 8]
 *   Answer    5  tracker->member [ts u32][nonce 12][ciphertext][tag 8]
 *   Clear     6  phone->own tag  (header only)
 *
 *   key id     = HMAC(pollSecret, "trailmesh-poll-id")[0..4)
 *   poll tag   = HMAC(pollSecret, "poll" | tracker u32 | requester u32 | ts u32)[0..8)
 *   reply key  = HMAC(pollSecret, "trailmesh-poll-reply")
 *   ciphertext = AES-256-CTR(reply key, counter block nonce | 00 00 00 00,
 *                            meshtastic Position protobuf; empty means no fix)
 *   answer tag = HMAC(pollSecret, "answer" | tracker u32 | requester u32 | ts u32
 *                                 | nonce | ciphertext)[0..8)
 *
 * `tracker` and `requester` are node numbers, so a poll recorded from one
 * requester cannot be replayed as another's, and `ts` (the requester's clock,
 * epoch seconds) must fall within `kTrackerPollClockWindowSecs` of the
 * tracker's and beat the last one answered for that requester. The answer is
 * tagged as well as encrypted: room frames are AES-CTR without integrity, and
 * a forged answer here would be a wrong position a member walks towards.
 *
 * Pure apart from the Crypto library: no radio, no filesystem, no globals, so
 * the rule and the bytes are tested natively. `TrackerPollModule` is the thin
 * layer that stores the secret and talks to the phone and the mesh.
 */
namespace trailmesh
{

/// Private-app port for every tracker-poll frame.
constexpr uint16_t kTrackerPollPort = 300;

constexpr uint8_t kTrackerPollMagic = 0x54; // 'T'
constexpr uint8_t kTrackerPollVersion = 2;
constexpr size_t kTrackerPollHeaderBytes = 3;

constexpr size_t kTrackerPollSecretBytes = 32;
constexpr size_t kTrackerPollKeyIdBytes = 4;
constexpr size_t kTrackerPollTagBytes = 8;
constexpr size_t kTrackerPollNonceBytes = 12;

/// How far a poll's timestamp may sit from the tracker's clock, either way.
/// Wide enough for a phone and a GPS clock to disagree and for a few hops of
/// relaying; narrow enough that a recorded poll stops working quickly.
constexpr uint32_t kTrackerPollClockWindowSecs = 120;

/// Per-requester gap. Below the floor a compass open on several phones would
/// keep the tracker talking; above the ceiling "find it" stops being usable.
constexpr uint16_t kTrackerPollDefaultGapSecs = 10;
constexpr uint16_t kTrackerPollMinGapSecs = 5;
constexpr uint16_t kTrackerPollMaxGapSecs = 3600;

/// Requesters remembered for replay and throttle. Above the room ceiling of
/// twelve members, so a full room never evicts one of its own.
constexpr size_t kTrackerPollMaxRequesters = 16;

constexpr size_t kTrackerPollSetSecretBytes = kTrackerPollHeaderBytes + 2 + kTrackerPollSecretBytes;
constexpr size_t kTrackerPollCurrentBytes = kTrackerPollHeaderBytes + 2 + 1 + kTrackerPollKeyIdBytes;
constexpr size_t kTrackerPollPollBytes = kTrackerPollHeaderBytes + 4 + kTrackerPollTagBytes;
constexpr size_t kTrackerPollAnswerOverhead = kTrackerPollHeaderBytes + 4 + kTrackerPollNonceBytes + kTrackerPollTagBytes;

enum class TrackerPollOp : uint8_t {
    SetSecret = 1,
    Get = 2,
    Current = 3,
    Poll = 4,
    Answer = 5,
    Clear = 6,
};

struct TrackerPollConfig {
    bool hasSecret = false;
    uint16_t gapSecs = kTrackerPollDefaultGapSecs;
    uint8_t secret[kTrackerPollSecretBytes] = {};
};

/// The op of a frame, or false when the buffer does not start with a valid
/// header. Says nothing about whether the rest of the frame is valid.
bool trackerPollOp(const uint8_t *buf, size_t len, TrackerPollOp &op);

// ---- phone <-> own tag ------------------------------------------------------

size_t encodeSetSecret(uint16_t gapSecs, const uint8_t secret[kTrackerPollSecretBytes], uint8_t *buf, size_t cap);

/// Reads a SetSecret frame into `out`, or returns false - leaving `out`
/// untouched - when it is not a whole, valid one. A gap outside the bounds is
/// refused, not clamped, and an all-zero secret is refused as unset.
bool decodeSetSecret(const uint8_t *buf, size_t len, TrackerPollConfig &out);

/// The Current report for `config`. Carries a key id, never the secret.
size_t encodeCurrent(const TrackerPollConfig &config, uint8_t *buf, size_t cap);

size_t encodeHeaderOnly(TrackerPollOp op, uint8_t *buf, size_t cap);

void trackerPollKeyId(const uint8_t secret[kTrackerPollSecretBytes], uint8_t out[kTrackerPollKeyIdBytes]);

// ---- member <-> tracker -----------------------------------------------------

void trackerPollTag(const uint8_t secret[kTrackerPollSecretBytes], uint32_t tracker, uint32_t requester, uint32_t ts,
                    uint8_t out[kTrackerPollTagBytes]);

size_t encodePoll(const uint8_t secret[kTrackerPollSecretBytes], uint32_t tracker, uint32_t requester, uint32_t ts,
                  uint8_t *buf, size_t cap);

bool decodePoll(const uint8_t *buf, size_t len, uint32_t &ts, uint8_t tag[kTrackerPollTagBytes]);

/// Encrypts and tags `plaintext` (a Position protobuf, possibly empty) as an
/// Answer. Returns the byte count, or 0 when `cap` is too small.
size_t encodeAnswer(const uint8_t secret[kTrackerPollSecretBytes], uint32_t tracker, uint32_t requester, uint32_t ts,
                    const uint8_t nonce[kTrackerPollNonceBytes], const uint8_t *plaintext, size_t plaintextLen,
                    uint8_t *buf, size_t cap);

/// Checks and decrypts an Answer. Returns false on a bad header, a wrong tag,
/// or a mismatched `ts`; on success writes the plaintext and its length.
bool decodeAnswer(const uint8_t secret[kTrackerPollSecretBytes], uint32_t tracker, uint32_t requester, uint32_t expectTs,
                  const uint8_t *buf, size_t len, uint8_t *plaintext, size_t cap, size_t &plaintextLen);

// ---- the rule ---------------------------------------------------------------

enum class TrackerPollVerdict {
    NoSecret,  ///< not set up for polling
    NoClock,   ///< the tracker does not know the time, so cannot judge freshness
    Stale,     ///< timestamp outside the clock window
    BadTag,    ///< not from a holder of the room's secret
    Replayed,  ///< not newer than the last answered poll from this requester
    Throttled, ///< answered this requester under `gapSecs` ago
    Answer,
};

const char *trackerPollVerdictName(TrackerPollVerdict v);

class TrackerPollPolicy
{
  public:
    /// Replaces the stored secret. Forgets every requester, because their
    /// timestamps and throttles were judged against the old one.
    void setConfig(const TrackerPollConfig &config);
    void clear();
    const TrackerPollConfig &config() const { return cfg; }

    /// What to do with a poll. `nowSecs` is the tracker's epoch time, 0 when
    /// unknown; `nowMs` its millisecond clock for throttling.
    TrackerPollVerdict verdict(uint32_t tracker, uint32_t requester, uint32_t ts, const uint8_t tag[kTrackerPollTagBytes],
                               uint32_t nowSecs, uint32_t nowMs) const;

    /// Records an answer to `requester` for its poll at `ts`.
    void noteAnswer(uint32_t requester, uint32_t ts, uint32_t nowMs);

  private:
    struct Requester {
        uint32_t node = 0;
        uint32_t lastTs = 0;
        uint32_t lastAnswerMs = 0;
        bool used = false;
    };

    TrackerPollConfig cfg;
    Requester requesters[kTrackerPollMaxRequesters];

    const Requester *find(uint32_t node) const;
};

} // namespace trailmesh
