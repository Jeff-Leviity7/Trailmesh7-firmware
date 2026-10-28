#pragma once

#include "SinglePortModule.h"
#include "TrackerPollPolicy.h"

/**
 * TRAILMESH: lets a room's members poll this tracker for its exact position.
 * See `TrackerPollPolicy.h` for the rule and the wire format.
 *
 * Two kinds of traffic share `trailmesh::kTrackerPollPort`:
 *
 *  - **Setup, from the attached phone only.** SetSecret, Get and Clear. After
 *    each the tag answers the phone with Current - a key id, never the secret
 *    - so the app verifies a write instead of assuming it landed. Whoever can
 *    set the secret decides who may locate the tracker, so a setup frame from
 *    the mesh is refused.
 *  - **Polls, from the mesh only.** A valid Poll addressed to this node gets
 *    an Answer addressed to the requester. Everything else - a bad tag, a
 *    stale or replayed poll, one inside the throttle - is dropped silently: a
 *    reply would tell a stranger the tracker is here.
 *
 * The secret is stored in `/prefs/tm7poll.bin` as the SetSecret frame itself,
 * so the file and the wire share one decoder and one set of checks.
 */
class TrackerPollModule : public SinglePortModule
{
  public:
    TrackerPollModule();

  protected:
    ProcessMessage handleReceived(const meshtastic_MeshPacket &mp) override;

  private:
    trailmesh::TrackerPollPolicy pollPolicy;

    void handleSetup(trailmesh::TrackerPollOp op, const meshtastic_MeshPacket &mp);
    void handlePoll(const meshtastic_MeshPacket &mp);
    void loadFromDisk();
    bool saveToDisk(const uint8_t *frame, size_t len);
    void removeFromDisk();
    void reportToPhone();
};

extern TrackerPollModule *trackerPollModule;
