// TRAILMESH: tracker polling by room membership - the rule and the bytes.
//
// Pure: TrackerPollPolicy touches no radio, filesystem or global, so this suite
// constructs no NodeDB and writes no persisted state.
//
// The expected bytes were computed outside C++ (Python hmac, `openssl enc
// -aes-256-ctr`), because the app has to produce exactly these too:
//
//   room key   = 00 01 .. 1f
//   pollSecret = HMAC-SHA256(room key, "trailmesh-tracker-poll")
//   tracker !eb569f95, requester !46ab6fab, ts 1793201941, nonce 0a 0b .. 15

#include "TestUtil.h"
#include "modules/TrackerPollPolicy.h"
#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <unity.h>

using namespace trailmesh;

#define ASSERT_ENUM(expected, actual) TEST_ASSERT_EQUAL_INT(static_cast<int>(expected), static_cast<int>(actual))

static const uint32_t kTracker = 0xeb569f95;
static const uint32_t kRequester = 0x46ab6fab;
static const uint32_t kTs = 1793201941;

static uint8_t secret[kTrackerPollSecretBytes];
static uint8_t otherSecret[kTrackerPollSecretBytes];
static uint8_t nonce[kTrackerPollNonceBytes];

static void hex(const char *s, uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        char b[3] = {s[2 * i], s[2 * i + 1], 0};
        out[i] = static_cast<uint8_t>(strtoul(b, nullptr, 16));
    }
}

static TrackerPollConfig configWith(const uint8_t *s, uint16_t gap = 10)
{
    TrackerPollConfig c;
    c.hasSecret = true;
    c.gapSecs = gap;
    memcpy(c.secret, s, kTrackerPollSecretBytes);
    return c;
}

static void pollTagFor(const uint8_t *s, uint32_t requester, uint32_t ts, uint8_t *tag)
{
    trackerPollTag(s, kTracker, requester, ts, tag);
}

void setUp(void)
{
    hex("e2f8f8bf4ef563c985a84bf6865aa8f2f39d33ad9008681c897d5ab23ea12d7e", secret, sizeof(secret));
    for (size_t i = 0; i < sizeof(otherSecret); i++)
        otherSecret[i] = static_cast<uint8_t>(0xA0 + i);
    for (size_t i = 0; i < sizeof(nonce); i++)
        nonce[i] = static_cast<uint8_t>(10 + i);
}

void tearDown(void) {}

// ---- the bytes, against values computed outside C++ -------------------------

static void test_keyIdMatchesReference()
{
    uint8_t id[kTrackerPollKeyIdBytes], want[kTrackerPollKeyIdBytes];
    trackerPollKeyId(secret, id);
    hex("8bdc6b7a", want, sizeof(want));
    TEST_ASSERT_EQUAL_MEMORY(want, id, sizeof(want));
}

static void test_pollTagMatchesReference()
{
    uint8_t tag[kTrackerPollTagBytes], want[kTrackerPollTagBytes];
    trackerPollTag(secret, kTracker, kRequester, kTs, tag);
    hex("52bf5395474d35f0", want, sizeof(want));
    TEST_ASSERT_EQUAL_MEMORY(want, tag, sizeof(want));
}

static void test_answerMatchesReference()
{
    const char *pt = "hello position!";
    uint8_t buf[64];
    const size_t len = encodeAnswer(secret, kTracker, kRequester, kTs, nonce, reinterpret_cast<const uint8_t *>(pt), 15,
                                    buf, sizeof(buf));
    TEST_ASSERT_EQUAL(kTrackerPollAnswerOverhead + 15, len);
    uint8_t wantCt[15], wantTag[kTrackerPollTagBytes];
    hex("359263dd2fb652b3016e334b5c0ebc", wantCt, sizeof(wantCt));
    hex("009ad434c6ac8b56", wantTag, sizeof(wantTag));
    TEST_ASSERT_EQUAL_MEMORY(nonce, buf + 7, kTrackerPollNonceBytes);
    TEST_ASSERT_EQUAL_MEMORY(wantCt, buf + 7 + kTrackerPollNonceBytes, sizeof(wantCt));
    TEST_ASSERT_EQUAL_MEMORY(wantTag, buf + len - kTrackerPollTagBytes, sizeof(wantTag));
}

// ---- answers ------------------------------------------------------------------

static void test_answerRoundTrips()
{
    const uint8_t pt[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21};
    uint8_t buf[80], out[40];
    const size_t len = encodeAnswer(secret, kTracker, kRequester, kTs, nonce, pt, sizeof(pt), buf, sizeof(buf));
    size_t outLen = 0;
    TEST_ASSERT_TRUE(decodeAnswer(secret, kTracker, kRequester, kTs, buf, len, out, sizeof(out), outLen));
    TEST_ASSERT_EQUAL(sizeof(pt), outLen);
    TEST_ASSERT_EQUAL_MEMORY(pt, out, sizeof(pt));
}

static void test_emptyAnswerMeansNoFix()
{
    uint8_t buf[40], out[8];
    const size_t len = encodeAnswer(secret, kTracker, kRequester, kTs, nonce, nullptr, 0, buf, sizeof(buf));
    TEST_ASSERT_EQUAL(kTrackerPollAnswerOverhead, len);
    size_t outLen = 99;
    TEST_ASSERT_TRUE(decodeAnswer(secret, kTracker, kRequester, kTs, buf, len, out, sizeof(out), outLen));
    TEST_ASSERT_EQUAL(0, outLen);
}

static void test_answerIsRefusedIfAltered()
{
    const uint8_t pt[] = {9, 9, 9, 9};
    uint8_t buf[40], out[8];
    size_t outLen = 0;
    const size_t len = encodeAnswer(secret, kTracker, kRequester, kTs, nonce, pt, sizeof(pt), buf, sizeof(buf));

    for (size_t at : {size_t(7), size_t(7 + kTrackerPollNonceBytes), len - 1}) {
        uint8_t bad[40];
        memcpy(bad, buf, len);
        bad[at] ^= 0x01; // nonce, ciphertext, tag
        TEST_ASSERT_FALSE(decodeAnswer(secret, kTracker, kRequester, kTs, bad, len, out, sizeof(out), outLen));
    }
    TEST_ASSERT_FALSE(decodeAnswer(otherSecret, kTracker, kRequester, kTs, buf, len, out, sizeof(out), outLen));
    TEST_ASSERT_FALSE(decodeAnswer(secret, kTracker, kRequester + 1, kTs, buf, len, out, sizeof(out), outLen));
    TEST_ASSERT_FALSE(decodeAnswer(secret, kTracker, kRequester, kTs + 1, buf, len, out, sizeof(out), outLen));
}

// ---- the rule -----------------------------------------------------------------

static void test_validPollFromAMemberIsAnswered()
{
    TrackerPollPolicy p;
    p.setConfig(configWith(secret));
    uint8_t tag[kTrackerPollTagBytes];
    pollTagFor(secret, kRequester, kTs, tag);
    ASSERT_ENUM(TrackerPollVerdict::Answer, p.verdict(kTracker, kRequester, kTs, tag, kTs + 3, 1000));
}

static void test_anyMemberCanPollWithNothingChangedOnTheTracker()
{
    // The point of option 2: a member who joined after setup derives the same
    // secret from the room key, so a node the tracker has never heard of is
    // answered.
    TrackerPollPolicy p;
    p.setConfig(configWith(secret));
    uint8_t tag[kTrackerPollTagBytes];
    pollTagFor(secret, 0x11223344, kTs, tag);
    ASSERT_ENUM(TrackerPollVerdict::Answer, p.verdict(kTracker, 0x11223344, kTs, tag, kTs, 1000));
}

static void test_nonMemberIsRefused()
{
    TrackerPollPolicy p;
    p.setConfig(configWith(secret));
    uint8_t tag[kTrackerPollTagBytes];
    pollTagFor(otherSecret, kRequester, kTs, tag);
    ASSERT_ENUM(TrackerPollVerdict::BadTag, p.verdict(kTracker, kRequester, kTs, tag, kTs, 1000));
}

static void test_pollCannotBeReplayedAsAnotherNode()
{
    TrackerPollPolicy p;
    p.setConfig(configWith(secret));
    uint8_t tag[kTrackerPollTagBytes];
    pollTagFor(secret, kRequester, kTs, tag);
    ASSERT_ENUM(TrackerPollVerdict::BadTag, p.verdict(kTracker, kRequester + 1, kTs, tag, kTs, 1000));
    ASSERT_ENUM(TrackerPollVerdict::BadTag, p.verdict(kTracker + 1, kRequester, kTs, tag, kTs, 1000));
}

static void test_noSecretAnswersNobody()
{
    TrackerPollPolicy p;
    uint8_t tag[kTrackerPollTagBytes];
    pollTagFor(secret, kRequester, kTs, tag);
    ASSERT_ENUM(TrackerPollVerdict::NoSecret, p.verdict(kTracker, kRequester, kTs, tag, kTs, 1000));
    p.setConfig(configWith(secret));
    p.clear();
    ASSERT_ENUM(TrackerPollVerdict::NoSecret, p.verdict(kTracker, kRequester, kTs, tag, kTs, 1000));
}

static void test_trackerWithoutAClockAnswersNobody()
{
    TrackerPollPolicy p;
    p.setConfig(configWith(secret));
    uint8_t tag[kTrackerPollTagBytes];
    pollTagFor(secret, kRequester, kTs, tag);
    ASSERT_ENUM(TrackerPollVerdict::NoClock, p.verdict(kTracker, kRequester, kTs, tag, 0, 1000));
}

static void test_clockWindowBothWays()
{
    TrackerPollPolicy p;
    p.setConfig(configWith(secret));
    uint8_t tag[kTrackerPollTagBytes];
    pollTagFor(secret, kRequester, kTs, tag);
    const uint32_t w = kTrackerPollClockWindowSecs;
    ASSERT_ENUM(TrackerPollVerdict::Answer, p.verdict(kTracker, kRequester, kTs, tag, kTs + w, 1000));
    ASSERT_ENUM(TrackerPollVerdict::Answer, p.verdict(kTracker, kRequester, kTs, tag, kTs - w, 1000));
    ASSERT_ENUM(TrackerPollVerdict::Stale, p.verdict(kTracker, kRequester, kTs, tag, kTs + w + 1, 1000));
    ASSERT_ENUM(TrackerPollVerdict::Stale, p.verdict(kTracker, kRequester, kTs, tag, kTs - w - 1, 1000));
}

static void test_answeredPollCannotBeReplayed()
{
    TrackerPollPolicy p;
    p.setConfig(configWith(secret, 10));
    uint8_t tag[kTrackerPollTagBytes];
    pollTagFor(secret, kRequester, kTs, tag);
    p.noteAnswer(kRequester, kTs, 1000);
    // Long after the throttle, still refused: same timestamp.
    ASSERT_ENUM(TrackerPollVerdict::Replayed, p.verdict(kTracker, kRequester, kTs, tag, kTs + 30, 60000));
}

static void test_throttleIsPerRequester()
{
    TrackerPollPolicy p;
    p.setConfig(configWith(secret, 10));
    p.noteAnswer(kRequester, kTs, 1000);
    uint8_t tag[kTrackerPollTagBytes];
    pollTagFor(secret, kRequester, kTs + 5, tag);
    ASSERT_ENUM(TrackerPollVerdict::Throttled, p.verdict(kTracker, kRequester, kTs + 5, tag, kTs + 5, 6000));
    pollTagFor(secret, kRequester, kTs + 11, tag);
    ASSERT_ENUM(TrackerPollVerdict::Answer, p.verdict(kTracker, kRequester, kTs + 11, tag, kTs + 11, 11000));

    uint8_t other[kTrackerPollTagBytes];
    pollTagFor(secret, 0x11223344, kTs + 5, other);
    ASSERT_ENUM(TrackerPollVerdict::Answer, p.verdict(kTracker, 0x11223344, kTs + 5, other, kTs + 5, 6000));
}

static void test_throttleSurvivesMillisWrap()
{
    TrackerPollPolicy p;
    p.setConfig(configWith(secret, 10));
    p.noteAnswer(kRequester, kTs, 0xFFFFF000u);
    uint8_t tag[kTrackerPollTagBytes];
    pollTagFor(secret, kRequester, kTs + 1, tag);
    ASSERT_ENUM(TrackerPollVerdict::Throttled, p.verdict(kTracker, kRequester, kTs + 1, tag, kTs + 1, 0x00000100u));
    ASSERT_ENUM(TrackerPollVerdict::Answer, p.verdict(kTracker, kRequester, kTs + 1, tag, kTs + 1, 0x00003000u));
}

static void test_newSecretForgetsRequesters()
{
    TrackerPollPolicy p;
    p.setConfig(configWith(secret, 10));
    p.noteAnswer(kRequester, kTs, 1000);
    p.setConfig(configWith(otherSecret, 10));
    uint8_t tag[kTrackerPollTagBytes];
    pollTagFor(otherSecret, kRequester, kTs, tag);
    ASSERT_ENUM(TrackerPollVerdict::Answer, p.verdict(kTracker, kRequester, kTs, tag, kTs, 1500));
}

static void test_fullTableEvictsTheOldestNotAMember()
{
    TrackerPollPolicy p;
    p.setConfig(configWith(secret, 10));
    for (uint32_t i = 0; i < kTrackerPollMaxRequesters; i++)
        p.noteAnswer(0x1000 + i, kTs, 1000 + i * 100);
    p.noteAnswer(0x9999, kTs, 5000); // evicts 0x1000, answered longest ago
    uint8_t tag[kTrackerPollTagBytes];
    pollTagFor(secret, 0x1001, kTs, tag);
    ASSERT_ENUM(TrackerPollVerdict::Replayed, p.verdict(kTracker, 0x1001, kTs, tag, kTs, 90000));
    pollTagFor(secret, 0x1000, kTs, tag);
    ASSERT_ENUM(TrackerPollVerdict::Answer, p.verdict(kTracker, 0x1000, kTs, tag, kTs, 90000));
}

// ---- setup frames ---------------------------------------------------------------

static void test_setSecretRoundTrips()
{
    uint8_t buf[kTrackerPollSetSecretBytes];
    TEST_ASSERT_EQUAL(kTrackerPollSetSecretBytes, encodeSetSecret(15, secret, buf, sizeof(buf)));
    TrackerPollConfig c;
    TEST_ASSERT_TRUE(decodeSetSecret(buf, sizeof(buf), c));
    TEST_ASSERT_TRUE(c.hasSecret);
    TEST_ASSERT_EQUAL_UINT16(15, c.gapSecs);
    TEST_ASSERT_EQUAL_MEMORY(secret, c.secret, kTrackerPollSecretBytes);
}

static void test_badSetSecretIsRefusedWhole()
{
    uint8_t buf[kTrackerPollSetSecretBytes];
    encodeSetSecret(15, secret, buf, sizeof(buf));
    TrackerPollConfig c = configWith(otherSecret, 30);

    TEST_ASSERT_FALSE(decodeSetSecret(buf, sizeof(buf) - 1, c)); // truncated
    uint8_t bad[kTrackerPollSetSecretBytes];
    memcpy(bad, buf, sizeof(bad));
    bad[1] = 1; // the allowlist version
    TEST_ASSERT_FALSE(decodeSetSecret(bad, sizeof(bad), c));

    encodeSetSecret(kTrackerPollMinGapSecs - 1, secret, bad, sizeof(bad));
    TEST_ASSERT_FALSE(decodeSetSecret(bad, sizeof(bad), c)); // gap refused, not clamped
    encodeSetSecret(kTrackerPollMaxGapSecs + 1, secret, bad, sizeof(bad));
    TEST_ASSERT_FALSE(decodeSetSecret(bad, sizeof(bad), c));

    const uint8_t zero[kTrackerPollSecretBytes] = {};
    encodeSetSecret(15, zero, bad, sizeof(bad));
    TEST_ASSERT_FALSE(decodeSetSecret(bad, sizeof(bad), c)); // unset secret

    // Every refusal left the output as it was.
    TEST_ASSERT_EQUAL_UINT16(30, c.gapSecs);
    TEST_ASSERT_EQUAL_MEMORY(otherSecret, c.secret, kTrackerPollSecretBytes);
}

static void test_currentCarriesAKeyIdNeverTheSecret()
{
    uint8_t buf[kTrackerPollCurrentBytes];
    TEST_ASSERT_EQUAL(kTrackerPollCurrentBytes, encodeCurrent(configWith(secret, 15), buf, sizeof(buf)));
    TEST_ASSERT_EQUAL_UINT8(15, buf[3]);
    TEST_ASSERT_EQUAL_UINT8(1, buf[5]);
    uint8_t id[kTrackerPollKeyIdBytes];
    trackerPollKeyId(secret, id);
    TEST_ASSERT_EQUAL_MEMORY(id, buf + 6, sizeof(id));

    encodeCurrent(TrackerPollConfig{}, buf, sizeof(buf));
    TEST_ASSERT_EQUAL_UINT8(0, buf[5]);
}

static void test_pollFrameRoundTrips()
{
    uint8_t buf[kTrackerPollPollBytes];
    TEST_ASSERT_EQUAL(kTrackerPollPollBytes, encodePoll(secret, kTracker, kRequester, kTs, buf, sizeof(buf)));
    uint32_t ts = 0;
    uint8_t tag[kTrackerPollTagBytes];
    TEST_ASSERT_TRUE(decodePoll(buf, sizeof(buf), ts, tag));
    TEST_ASSERT_EQUAL_UINT32(kTs, ts);
    TrackerPollPolicy p;
    p.setConfig(configWith(secret));
    ASSERT_ENUM(TrackerPollVerdict::Answer, p.verdict(kTracker, kRequester, ts, tag, kTs, 1000));
    TEST_ASSERT_FALSE(decodePoll(buf, sizeof(buf) - 1, ts, tag));
}

static void test_framesFitOnePayload()
{
    // 233 is Meshtastic's Data.payload ceiling. A Position protobuf is well
    // under 100 bytes, so an answer always fits.
    TEST_ASSERT_TRUE(kTrackerPollAnswerOverhead + 100 <= 233);
    TEST_ASSERT_TRUE(kTrackerPollSetSecretBytes <= 233);
}

extern "C" {
void setup()
{
    initializeTestEnvironment();
    UNITY_BEGIN();
    RUN_TEST(test_keyIdMatchesReference);
    RUN_TEST(test_pollTagMatchesReference);
    RUN_TEST(test_answerMatchesReference);
    RUN_TEST(test_answerRoundTrips);
    RUN_TEST(test_emptyAnswerMeansNoFix);
    RUN_TEST(test_answerIsRefusedIfAltered);
    RUN_TEST(test_validPollFromAMemberIsAnswered);
    RUN_TEST(test_anyMemberCanPollWithNothingChangedOnTheTracker);
    RUN_TEST(test_nonMemberIsRefused);
    RUN_TEST(test_pollCannotBeReplayedAsAnotherNode);
    RUN_TEST(test_noSecretAnswersNobody);
    RUN_TEST(test_trackerWithoutAClockAnswersNobody);
    RUN_TEST(test_clockWindowBothWays);
    RUN_TEST(test_answeredPollCannotBeReplayed);
    RUN_TEST(test_throttleIsPerRequester);
    RUN_TEST(test_throttleSurvivesMillisWrap);
    RUN_TEST(test_newSecretForgetsRequesters);
    RUN_TEST(test_fullTableEvictsTheOldestNotAMember);
    RUN_TEST(test_setSecretRoundTrips);
    RUN_TEST(test_badSetSecretIsRefusedWhole);
    RUN_TEST(test_currentCarriesAKeyIdNeverTheSecret);
    RUN_TEST(test_pollFrameRoundTrips);
    RUN_TEST(test_framesFitOnePayload);
    exit(UNITY_END());
}

void loop() {}
}
