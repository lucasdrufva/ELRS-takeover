#include "tx_takeover.h"

#if defined(ELRS_TX_TAKEOVER) && ELRS_TX_TAKEOVER

extern TxConfig config;
extern volatile bool busyTransmitting;
extern TxTlmRcvPhase_e TelemetryRcvPhase;
extern volatile uint32_t LastTLMpacketRecvMillis;
#if defined(PLATFORM_ESP32) || defined(PLATFORM_ESP8266)
extern bool webserverPreventAutoStart;
#endif

void SetRFLinkRate(uint8_t index);

namespace TxTakeover
{
namespace
{
enum RecoverSubState : uint8_t
{
    RECOVER_WAIT_SYNC = 0,
    RECOVER_WAIT_REFERENCE_PACKET
};

enum RecoveryPointStatus : uint8_t
{
    RecoveryPointAdded = 0,
    RecoveryPointNotReady,
    RecoveryPointOutOfWindow,
    RecoveryPointStorageFull,
    RecoveryPointInvalidConfig
};

struct SyncObservation
{
    uint8_t rateIndex;
    uint8_t switchEncMode;
    uint8_t newTlmRatio;
    uint8_t nonce;
    uint8_t fhssIndex;
    uint8_t uid3;
    uint8_t uid4;
    uint8_t uid5Wire;
    uint32_t timestampUs;
    bool valid;
};

struct RecoveryPoint
{
    uint8_t startIndex;
    uint8_t distanceHops;
    uint8_t referenceChannel;
};

static constexpr uint8_t UID_LOCK_COUNT = 3;
static constexpr uint8_t RECOVERY_MIN_POINTS = 3;
static constexpr uint8_t RECOVERY_SWITCH_TO_ALT_REF_POINTS = 8;
static constexpr uint8_t RECOVERY_POINTS_PER_REFERENCE = 4;
static constexpr uint8_t RECOVERY_MAX_POINTS = 24;
static constexpr uint8_t RECOVERY_REJECT_LIMIT = 10;
static constexpr uint32_t RATE_SCAN_DWELL_MS = 1200;
static constexpr uint32_t RECOVER_SYNC_TIMEOUT_MS = 1500;
static constexpr uint32_t RECOVER_REFERENCE_TIMEOUT_MS = 300;
static constexpr uint32_t SYNC_WAIT_GUARD_MS = 300;
static constexpr uint32_t WAIT_HOP_TIMEOUT_MS = 1000;
static constexpr uint32_t POST_TAKEOVER_STABILIZE_MS = 4000;
static constexpr uint32_t POST_TAKEOVER_LOSS_MS = 5000;
static constexpr uint32_t MIRROR_COMPAT_MS = 5000;
static constexpr uint32_t RETRY_BACKOFF_BASE_MS = 400;
static constexpr uint32_t RETRY_BACKOFF_STEP_MS = 350;
static constexpr uint32_t RETRY_BACKOFF_MAX_MS = 4000;

static volatile State g_state = SCAN_RATE;
static volatile RecoverSubState g_recoverSubState = RECOVER_WAIT_SYNC;
static volatile uint32_t g_stateDeadlineMs = 0;
static volatile uint32_t g_backoffUntilMs = 0;
static volatile uint32_t g_waitHopStartMs = 0;
static volatile bool g_txRunning = false;
static volatile bool g_pendingIndexShift = false;
static volatile uint8_t g_burstRemaining = 0;
static volatile bool g_mirrorCompatSync = false;
static volatile uint32_t g_mirrorCompatUntilMs = 0;
static volatile uint32_t g_takeoverNormalStartMs = 0;
static volatile uint32_t g_lastTlmSeenAtStateStart = 0;
static volatile bool g_linkSeen = false;
static volatile uint8_t g_retryCount = 0;
static volatile bool g_havePendingRecoverySync = false;
static volatile uint8_t g_pendingSyncNonce = 0;
static volatile uint8_t g_pendingSyncIndex = 0;
static volatile uint32_t g_pendingSyncTimestampUs = 0;
static volatile uint8_t g_recoveryRejectedPoints = 0;
static volatile uint8_t g_recoveryReferenceSwitchCount = 0;
static volatile uint8_t g_recoveryNextReferenceSwitchAtPoints = RECOVERY_SWITCH_TO_ALT_REF_POINTS;
static volatile uint8_t g_uidLockCount = 0;
static volatile bool g_scanAltIq = false;
static volatile bool g_takeoverStartPending = false;
static uint8_t g_computedFhssOffset = TAKEOVER_FHSS_OFFSET;

static volatile uint16_t g_sniffIrqOk = 0;
static volatile uint16_t g_sniffIrqErr = 0;
static volatile uint16_t g_sniffSyncPackets = 0;
static volatile uint16_t g_sniffNonSyncPackets = 0;
static volatile uint16_t g_sniffRateMismatch = 0;
static volatile uint16_t g_sniffCrcOk = 0;
static volatile uint16_t g_sniffCrcFail = 0;

static bool g_initialized = false;
static uint8_t g_scanRates[RATE_MAX] = {0};
static uint8_t g_scanRateCount = 0;
static uint8_t g_scanRatePos = 0;
static uint8_t g_referenceChannel = 0;
static uint8_t g_recoveryPointCount = 0;
static RecoveryPoint g_recoveryPoints[RECOVERY_MAX_POINTS] = {};
static bool g_recoveryReferenceChannelUsed[FHSS_SEQUENCE_LEN] = {false};
static SyncObservation g_lastSync = {};
static uint32_t g_sniffStatsLastLogMs = 0;

static uint8_t getCurrentRateIndexForSyncWait()
{
    if (ExpressLRS_currAirRate_Modparams != nullptr)
    {
        return ExpressLRS_currAirRate_Modparams->index;
    }

    if (g_scanRateCount > 0)
    {
        return g_scanRates[g_scanRatePos % g_scanRateCount];
    }

    return 0;
}

static uint32_t computeSyncWaitTimeoutMs(uint8_t rateIndex, uint32_t minimumMs)
{
    uint32_t timeoutMs = minimumMs;
    expresslrs_rf_pref_params_s const *const rfPerf = get_elrs_RFperfParams(rateIndex);
    if (rfPerf != nullptr)
    {
        uint32_t syncIntervalMs = rfPerf->SyncPktIntervalDisconnected;
        if (rfPerf->SyncPktIntervalConnected > syncIntervalMs)
        {
            syncIntervalMs = rfPerf->SyncPktIntervalConnected;
        }

        syncIntervalMs += SYNC_WAIT_GUARD_MS;
        if (syncIntervalMs > timeoutMs)
        {
            timeoutMs = syncIntervalMs;
        }
    }

    return timeoutMs;
}

static uint32_t computeCurrentRateSyncWaitTimeoutMs(uint32_t minimumMs)
{
    return computeSyncWaitTimeoutMs(getCurrentRateIndexForSyncWait(), minimumMs);
}

static inline OTA_Sync_s const *getSyncPacket(OTA_Packet_s *pkt)
{
    return OtaIsFullRes ? &pkt->full.sync.sync : &pkt->std.sync;
}

static inline uint_fast8_t getActiveSyncChannel()
{
    if (!FHSSusePrimaryFreqBand && FHSSconfigDualBand != nullptr)
    {
        return sync_channel_DualBand;
    }
    return sync_channel;
}

static bool isSubGHzRate(uint8_t rateIndex)
{
#if defined(RADIO_LR1121)
    expresslrs_mod_settings_s const *const params = get_elrs_airRateConfig(rateIndex);
    return params->radio_type == RADIO_TYPE_LR1121_LORA_900 ||
           params->radio_type == RADIO_TYPE_LR1121_GFSK_900 ||
           params->radio_type == RADIO_TYPE_LR1121_LORA_DUAL;
#else
    (void)rateIndex;
    return true;
#endif
}

static bool shouldScanRate(uint8_t rateIndex)
{
    return isSupportedRFRate(rateIndex) && isSubGHzRate(rateIndex);
}

static void buildScanRateOrder()
{
    bool used[RATE_MAX] = {false};
    g_scanRateCount = 0;

    uint8_t preferred = config.GetRate();
    if (preferred >= RATE_MAX)
    {
        preferred = 0;
    }

    if (shouldScanRate(preferred))
    {
        g_scanRates[g_scanRateCount++] = preferred;
        used[preferred] = true;
    }

    for (uint8_t idx = 0; idx < RATE_MAX; idx++)
    {
        if (used[idx] || !shouldScanRate(idx))
        {
            continue;
        }
        g_scanRates[g_scanRateCount++] = idx;
        used[idx] = true;
    }
}

static uint32_t channelToFreq(uint8_t channel)
{
    if (FHSSusePrimaryFreqBand || FHSSconfigDualBand == nullptr)
    {
        const int64_t base = (int64_t)FHSSconfig->freq_start;
        const int64_t spread = ((int64_t)freq_spread * channel) / FREQ_SPREAD_SCALE;
        const int64_t freq = base + spread - (int64_t)FreqCorrection;
        return freq > 0 ? (uint32_t)freq : 0U;
    }

    return FHSSconfigDualBand->freq_start + (freq_spread_DualBand * channel / FREQ_SPREAD_SCALE);
}

static uint32_t freqForSequenceIndex(uint8_t sequenceIndex)
{
    const uint16_t sequenceCount = FHSSgetSequenceCount();
    if (sequenceCount == 0)
    {
        return FHSSgetInitialFreq();
    }

    const uint8_t idx = sequenceIndex % sequenceCount;
    if (FHSSusePrimaryFreqBand || FHSSconfigDualBand == nullptr)
    {
        return channelToFreq(FHSSsequence[idx]);
    }

    return FHSSconfigDualBand->freq_start + (freq_spread_DualBand * FHSSsequence_DualBand[idx] / FREQ_SPREAD_SCALE);
}

static void setRadioToCurrentTxFrequency()
{
    Radio.SetFrequencyReg(freqForSequenceIndex(FHSSgetCurrIndex()));
    if ((isDualRadio() && config.GetAntennaMode() == TX_RADIO_MODE_GEMINI) || FHSSuseDualBand)
    {
        Radio.SetFrequencyReg(FHSSgetGeminiFreq(), SX12XX_Radio_2);
    }
}

static void setRadioSyncListen()
{
    Radio.SetTxIdleMode();
    Radio.SetFrequencyReg(FHSSgetInitialFreq());
    Radio.RXnb();
}

static void setRadioReferenceListen(uint8_t channel)
{
    Radio.SetTxIdleMode();
    Radio.SetFrequencyReg(channelToFreq(channel));
    Radio.RXnb();
}

static void setSniffRxContinuous()
{
    Radio.SetRxTimeoutUs(0);
    DBGLN("Takeover sniff RX timeout=0 (continuous)");
}

static void restoreRateRxTimeout()
{
    if (ExpressLRS_currAirRate_Modparams != nullptr)
    {
        Radio.SetRxTimeoutUs(ExpressLRS_currAirRate_Modparams->interval);
    }
}

static void stopTxForSniff()
{
    hwTimer::stop();
    while (busyTransmitting)
    {
        // Wait for TX ISR completion before switching to sniff mode.
    }
    g_txRunning = false;
    TelemetryRcvPhase = ttrpTransmitting;
    Radio.SetTxIdleMode();
}

static void beginRetryBackoff(char const *reason)
{
    DBGLN("Takeover retry: %s", reason);

    stopTxForSniff();

    g_pendingIndexShift = false;
    g_burstRemaining = 0;
    g_havePendingRecoverySync = false;
    g_uidLockCount = 0;
    g_recoveryPointCount = 0;
    g_recoveryRejectedPoints = 0;
    g_recoveryReferenceSwitchCount = 0;
    g_recoveryNextReferenceSwitchAtPoints = RECOVERY_SWITCH_TO_ALT_REF_POINTS;
    g_takeoverStartPending = false;
    g_mirrorCompatSync = false;
    g_lastSync.valid = false;
    g_sniffIrqOk = 0;
    g_sniffIrqErr = 0;
    g_sniffSyncPackets = 0;
    g_sniffNonSyncPackets = 0;
    g_sniffRateMismatch = 0;
    g_sniffCrcOk = 0;
    g_sniffCrcFail = 0;

    uint32_t backoffMs = RETRY_BACKOFF_BASE_MS + (uint32_t)g_retryCount * RETRY_BACKOFF_STEP_MS;
    if (backoffMs > RETRY_BACKOFF_MAX_MS)
    {
        backoffMs = RETRY_BACKOFF_MAX_MS;
    }

    g_backoffUntilMs = millis() + backoffMs;
    g_retryCount++;
    g_state = RETRY_BACKOFF;
}

static void enterScanRate(uint8_t ratePos)
{
    if (g_scanRateCount == 0)
    {
        g_state = RETRY_BACKOFF;
        g_backoffUntilMs = millis() + RETRY_BACKOFF_MAX_MS;
        return;
    }

    uint8_t const nextPos = ratePos % g_scanRateCount;
    if (nextPos == 0 && g_state == LOCK_UID_TAIL)
    {
        g_scanAltIq = !g_scanAltIq;
        DBGLN("Takeover scan IQ polarity %s", g_scanAltIq ? "alt" : "base");
    }

    g_scanRatePos = nextPos;
    g_state = SCAN_RATE;
}

static void startSniffOnRate(uint8_t rateIndex)
{
    stopTxForSniff();
    uint8_t const uid5BeforeRateConfig = UID[5];
    if (g_scanAltIq)
    {
        UID[5] ^= 0x01;
    }
    SetRFLinkRate(rateIndex);
    setSniffRxContinuous();
    UID[5] = uid5BeforeRateConfig;
    connectionState = disconnected;

    g_uidLockCount = 0;
    g_lastSync.valid = false;
    g_state = LOCK_UID_TAIL;
    g_stateDeadlineMs = millis() + RATE_SCAN_DWELL_MS;
    g_sniffStatsLastLogMs = millis();
    g_sniffIrqOk = 0;
    g_sniffIrqErr = 0;
    g_sniffSyncPackets = 0;
    g_sniffNonSyncPackets = 0;
    g_sniffRateMismatch = 0;
    g_sniffCrcOk = 0;
    g_sniffCrcFail = 0;

    uint32_t const syncFreq = FHSSgetInitialFreq();
    setRadioSyncListen();
    DBGLN("Takeover scan rate=%u iqAlt=%u syncFreq=%u", rateIndex, g_scanAltIq ? 1 : 0, (unsigned)syncFreq);
}

static void captureSync(OTA_Sync_s const *sync, uint32_t timestampUs)
{
    g_lastSync.rateIndex = sync->rateIndex;
    g_lastSync.switchEncMode = sync->switchEncMode;
    g_lastSync.newTlmRatio = sync->newTlmRatio;
    g_lastSync.nonce = sync->nonce;
    g_lastSync.fhssIndex = sync->fhssIndex;
    g_lastSync.uid3 = sync->UID3;
    g_lastSync.uid4 = sync->UID4;
    g_lastSync.uid5Wire = sync->UID5;
    g_lastSync.timestampUs = timestampUs;
    g_lastSync.valid = true;
}

static uint16_t calcStdPacketCrcForTakeover(OTA_Packet_s *pkt, uint8_t crcHighForCalc)
{
    static Crc2Byte crc14;
    static bool crc14Ready = false;
    if (!crc14Ready)
    {
        crc14.init(14, ELRS_CRC14_POLY);
        crc14Ready = true;
    }

    uint8_t const backupCrcHigh = pkt->std.crcHigh;
    pkt->std.crcHigh = crcHighForCalc;
    uint16_t const calc = crc14.calc((uint8_t *)pkt, OTA4_CRC_CALC_LEN, OtaCrcInitializer);
    pkt->std.crcHigh = backupCrcHigh;
    return calc;
}

// Returns matched nonceMod (0..hopInterval-1) for wide-mode packets, or -1 if
// nonceMod could not be determined (non-wide, full-res, or validation failure).
static int8_t validateTakeoverPacketCrcEx(OTA_Packet_s *pkt)
{
    if (pkt == nullptr)
    {
        return -2;
    }

    if (OtaIsFullRes)
    {
        return OtaValidatePacketCrc(pkt) ? -1 : -2;
    }

    bool const isWideRcPacket =
        pkt->std.type == PACKET_TYPE_RCDATA &&
        g_lastSync.valid &&
        g_lastSync.switchEncMode == smWideOr8ch &&
        ExpressLRS_currAirRate_Modparams != nullptr;

    if (!isWideRcPacket)
    {
        return OtaValidatePacketCrc(pkt) ? -1 : -2;
    }

    uint16_t const inCRC = ((uint16_t)pkt->std.crcHigh << 8) | pkt->std.crcLow;
    uint8_t const hopInterval = ExpressLRS_currAirRate_Modparams->FHSShopInterval;
    if (hopInterval == 0)
    {
        return -2;
    }

    for (uint8_t nonceMod = 0; nonceMod < hopInterval; nonceMod++)
    {
        uint8_t const injectedCrcHigh = nonceMod + 1;
        if (calcStdPacketCrcForTakeover(pkt, injectedCrcHigh) == inCRC)
        {
            return (int8_t)nonceMod;
        }
    }

    return -2;
}

static bool validateTakeoverPacketCrc(OTA_Packet_s *pkt)
{
    return validateTakeoverPacketCrcEx(pkt) >= -1;
}

static bool resolveSyncUidTailAndCheckCrc(OTA_Packet_s *pkt, OTA_Sync_s const *sync, uint8_t *resolvedUid5)
{
    if (pkt == nullptr || sync == nullptr || resolvedUid5 == nullptr)
    {
        return false;
    }

    uint8_t const prevUid4 = UID[4];
    uint8_t const prevUid5 = UID[5];

    UID[4] = sync->UID4;
    UID[5] = sync->UID5;
    OtaUpdateCrcInitFromUid();

    if (!validateTakeoverPacketCrc(pkt))
    {
        UID[4] = prevUid4;
        UID[5] = prevUid5;
        OtaUpdateCrcInitFromUid();
        return false;
    }

    *resolvedUid5 = sync->UID5;
    return true;
}

static void emitSniffStats(uint32_t nowMs)
{
    if ((nowMs - g_sniffStatsLastLogMs) < 1000U)
    {
        return;
    }
    g_sniffStatsLastLogMs = nowMs;

    uint16_t const irqOk = g_sniffIrqOk;
    uint16_t const irqErr = g_sniffIrqErr;
    uint16_t const syncPkts = g_sniffSyncPackets;
    uint16_t const nonSyncPkts = g_sniffNonSyncPackets;
    uint16_t const rateMiss = g_sniffRateMismatch;
    uint16_t const crcOk = g_sniffCrcOk;
    uint16_t const crcFail = g_sniffCrcFail;

    g_sniffIrqOk = 0;
    g_sniffIrqErr = 0;
    g_sniffSyncPackets = 0;
    g_sniffNonSyncPackets = 0;
    g_sniffRateMismatch = 0;
    g_sniffCrcOk = 0;
    g_sniffCrcFail = 0;

    DBGLN("Takeover sniff stats rate=%u iqAlt=%u irqOk=%u irqErr=%u sync=%u nonSync=%u rateMiss=%u crcOk=%u crcFail=%u",
          g_scanRates[g_scanRatePos], g_scanAltIq ? 1 : 0, irqOk, irqErr, syncPkts, nonSyncPkts, rateMiss, crcOk, crcFail);
}

static void startUid2Recovery()
{
    g_state = RECOVER_UID2;
    g_recoverSubState = RECOVER_WAIT_SYNC;
    g_recoveryPointCount = 0;
    g_recoveryRejectedPoints = 0;
    g_recoveryReferenceSwitchCount = 0;
    g_recoveryNextReferenceSwitchAtPoints = RECOVERY_SWITCH_TO_ALT_REF_POINTS;
    g_takeoverStartPending = false;
    g_havePendingRecoverySync = false;
    g_stateDeadlineMs = millis() + computeCurrentRateSyncWaitTimeoutMs(RECOVER_SYNC_TIMEOUT_MS);

    const uint32_t channelCount = FHSSgetChannelCount();
    uint_fast8_t const activeSyncChannel = getActiveSyncChannel();
    if (channelCount == 0)
    {
        beginRetryBackoff("invalid FHSS config");
        return;
    }

    g_referenceChannel = (uint8_t)((activeSyncChannel + 7) % channelCount);
    if (g_referenceChannel == activeSyncChannel)
    {
        g_referenceChannel = (uint8_t)((g_referenceChannel + 1) % channelCount);
    }
    for (uint16_t idx = 0; idx < FHSS_SEQUENCE_LEN; idx++)
    {
        g_recoveryReferenceChannelUsed[idx] = false;
    }
    g_recoveryReferenceChannelUsed[g_referenceChannel] = true;

    setRadioSyncListen();
    DBGLN("Takeover locked UID tail, recovering UID2 using ref channel %u", g_referenceChannel);
}

static bool chooseAlternativeReferenceChannel()
{
    uint32_t const channelCount = FHSSgetChannelCount();
    if (channelCount < 3)
    {
        return false;
    }

    uint8_t const currentRef = g_referenceChannel;
    uint8_t const activeSyncChannel = (uint8_t)getActiveSyncChannel();
    for (uint32_t step = 1; step < channelCount; step++)
    {
        uint8_t const candidate = (uint8_t)((currentRef + step) % channelCount);
        if (candidate == activeSyncChannel || candidate == currentRef)
        {
            continue;
        }
        if (g_recoveryReferenceChannelUsed[candidate])
        {
            continue;
        }

        g_referenceChannel = candidate;
        g_recoveryReferenceChannelUsed[candidate] = true;
        g_recoveryReferenceSwitchCount++;
        uint8_t nextSwitchAt = (uint8_t)(g_recoveryPointCount + RECOVERY_POINTS_PER_REFERENCE);
        if (nextSwitchAt > RECOVERY_MAX_POINTS)
        {
            nextSwitchAt = RECOVERY_MAX_POINTS;
        }
        g_recoveryNextReferenceSwitchAtPoints = nextSwitchAt;
        return true;
    }

    return false;
}

static uint32_t computeRecoveryReferenceTimeoutMs(uint8_t syncNonce)
{
    if (ExpressLRS_currAirRate_Modparams == nullptr)
    {
        return RECOVER_REFERENCE_TIMEOUT_MS;
    }

    uint32_t const channelCount = FHSSgetChannelCount();
    uint8_t const hopInterval = ExpressLRS_currAirRate_Modparams->FHSShopInterval;
    uint32_t const packetIntervalUs = ExpressLRS_currAirRate_Modparams->interval;
    if (channelCount == 0 || hopInterval == 0 || packetIntervalUs == 0)
    {
        return RECOVER_REFERENCE_TIMEOUT_MS;
    }

    uint8_t const nonceMod = syncNonce % hopInterval;
    uint32_t const hopsToNextHop = (uint32_t)(hopInterval - nonceMod);
    uint32_t const maxHopsUntilReference = hopsToNextHop + (channelCount - 1U) * hopInterval;
    uint32_t const marginUs = packetIntervalUs + 3000U;
    uint32_t const timeoutUs = maxHopsUntilReference * packetIntervalUs + marginUs;
    uint32_t timeoutMs = (timeoutUs + 999U) / 1000U;
    if (timeoutMs < RECOVER_REFERENCE_TIMEOUT_MS)
    {
        timeoutMs = RECOVER_REFERENCE_TIMEOUT_MS;
    }
    return timeoutMs;
}

static void resetUidRecoveryToWaitSync(uint32_t nowMs)
{
    g_havePendingRecoverySync = false;
    g_recoverSubState = RECOVER_WAIT_SYNC;
    g_stateDeadlineMs = nowMs + computeCurrentRateSyncWaitTimeoutMs(RECOVER_SYNC_TIMEOUT_MS);
    setRadioSyncListen();
}

static uint16_t rngFromSeed(uint32_t &seed)
{
    const uint32_t a = 214013UL;
    const uint32_t c = 2531011UL;
    seed = (uint32_t)(((uint64_t)a * seed + c) & 0x7FFFFFFFUL);
    return seed >> 16;
}

static uint8_t rngNFromSeed(uint32_t &seed, uint8_t max)
{
    if (max == 0)
    {
        return 0;
    }
    return rngFromSeed(seed) % max;
}

static void buildSequenceForSeed(uint32_t seed, uint32_t freqCount, uint_fast8_t syncChannel, uint16_t sequenceCount, uint8_t *sequenceOut)
{
    if (sequenceOut == nullptr || freqCount == 0 || sequenceCount == 0)
    {
        return;
    }

    for (uint16_t i = 0; i < sequenceCount; i++)
    {
        uint32_t posInBlock = i % freqCount;
        if (posInBlock == 0)
        {
            sequenceOut[i] = syncChannel;
        }
        else if (posInBlock == syncChannel)
        {
            sequenceOut[i] = 0;
        }
        else
        {
            sequenceOut[i] = posInBlock;
        }
    }

    if (freqCount <= 1)
    {
        return;
    }

    uint32_t localSeed = seed;
    for (uint16_t i = 0; i < sequenceCount; i++)
    {
        if (i % freqCount == 0)
        {
            continue;
        }

        uint16_t blockOffset = (i / freqCount) * freqCount;
        uint8_t randIndex = rngNFromSeed(localSeed, freqCount - 1) + 1;
        uint8_t swapIndex = blockOffset + randIndex;

        uint8_t temp = sequenceOut[i];
        sequenceOut[i] = sequenceOut[swapIndex];
        sequenceOut[swapIndex] = temp;
    }
}

// Compute the FHSS offset that minimizes channel collisions between the
// original TX (at position i) and the takeover TX (at position i+offset).
// Returns the best offset in [1, sequenceCount-1].
static uint8_t computeOptimalFhssOffset(uint8_t const *sequence, uint16_t sequenceCount)
{
    if (sequenceCount <= 2)
    {
        return 1;
    }

    uint8_t bestOffset = TAKEOVER_FHSS_OFFSET;
    uint16_t bestCollisions = sequenceCount; // worst case

    for (uint16_t offset = 1; offset < sequenceCount; offset++)
    {
        uint16_t collisions = 0;
        for (uint16_t i = 0; i < sequenceCount; i++)
        {
            if (sequence[i] == sequence[(i + offset) % sequenceCount])
            {
                collisions++;
            }
        }
        if (collisions < bestCollisions)
        {
            bestCollisions = collisions;
            bestOffset = (uint8_t)offset;
        }
    }

    DBGLN("Takeover optimal FHSS offset=%u collisions=%u/%u (%.1f%%)",
          bestOffset, bestCollisions, sequenceCount,
          (float)bestCollisions * 100.0f / sequenceCount);
    return bestOffset;
}

static int16_t distanceFromSyncToChannel(uint8_t const *sequence, uint16_t sequenceCount, uint16_t startIndex, uint8_t targetChannel)
{
    if (sequenceCount == 0)
    {
        return -1;
    }

    uint16_t index = startIndex % sequenceCount;
    for (uint16_t step = 0; step < sequenceCount; step++)
    {
        index = (index + 1) % sequenceCount;
        if (sequence[index] == targetChannel)
        {
            return (int16_t)step;
        }
    }

    return -1;
}

static bool sequenceMatchesPoints(uint8_t const *sequence, uint16_t sequenceCount, uint_fast8_t syncChannel, uint8_t tolerance)
{
    for (uint8_t idx = 0; idx < g_recoveryPointCount; idx++)
    {
        uint16_t startIndex = g_recoveryPoints[idx].startIndex % sequenceCount;
        if (sequence[startIndex] != syncChannel)
        {
            return false;
        }

        int16_t distance = distanceFromSyncToChannel(sequence, sequenceCount, startIndex, g_recoveryPoints[idx].referenceChannel);
        if (distance < 0)
        {
            return false;
        }
        int16_t diff = distance - (int16_t)g_recoveryPoints[idx].distanceHops;
        if (diff < 0) diff = -diff;
        if (diff > (int16_t)tolerance)
        {
            return false;
        }
    }

    return true;
}

static uint8_t countUid2MatchesWithTolerance(uint8_t *matchedUid2, uint8_t tolerance)
{
    const uint32_t freqCount = FHSSgetChannelCount();
    const uint16_t sequenceCount = FHSSgetSequenceCount();
    const uint_fast8_t activeSyncChannel = getActiveSyncChannel();
    if (freqCount == 0 || sequenceCount == 0)
    {
        return 0;
    }

    uint8_t candidateSequence[FHSS_SEQUENCE_LEN] = {0};
    uint8_t matches = 0;
    uint8_t firstMatch = 0;
    uint8_t secondMatch = 0;

    for (uint16_t candidate = 0; candidate < 256; candidate++)
    {
        uint32_t candidateSeed = ((uint32_t)candidate << 24) + ((uint32_t)UID[3] << 16) +
                                 ((uint32_t)UID[4] << 8) + (UID[5] ^ OTA_VERSION_ID);
        buildSequenceForSeed(candidateSeed, freqCount, activeSyncChannel, sequenceCount, candidateSequence);

        if (!sequenceMatchesPoints(candidateSequence, sequenceCount, activeSyncChannel, tolerance))
        {
            continue;
        }

        if (matches == 0)
        {
            firstMatch = (uint8_t)candidate;
            if (matchedUid2 != nullptr)
            {
                *matchedUid2 = firstMatch;
            }
        }
        else if (matches == 1)
        {
            secondMatch = (uint8_t)candidate;
        }
        matches++;
    }

    if (matches == 2 && ((uint8_t)(firstMatch ^ secondMatch) == 0x80))
    {
        if (matchedUid2 != nullptr)
        {
            *matchedUid2 = firstMatch < secondMatch ? firstMatch : secondMatch;
        }
        return 1;
    }

    return matches;
}

static uint8_t countUid2Matches(uint8_t *matchedUid2)
{
    // Try exact matching first
    uint8_t count = countUid2MatchesWithTolerance(matchedUid2, 0);
    if (count > 0)
    {
        return count;
    }
    // Fall back to ±1 hop tolerance for timing-edge cases
    return countUid2MatchesWithTolerance(matchedUid2, 1);
}

// refNonceMod: nonceMod extracted from wide-mode CRC (>=0), or -1 if unknown
static RecoveryPointStatus addRecoveryPoint(uint32_t nowUs, int8_t refNonceMod, uint8_t *distanceHopsOut, uint32_t *elapsedUsOut)
{
    if (!g_havePendingRecoverySync || ExpressLRS_currAirRate_Modparams == nullptr)
    {
        return RecoveryPointNotReady;
    }

    uint32_t const channelCount = FHSSgetChannelCount();
    const uint8_t hopInterval = ExpressLRS_currAirRate_Modparams->FHSShopInterval;
    const uint32_t packetIntervalUs = ExpressLRS_currAirRate_Modparams->interval;
    if (hopInterval == 0 || packetIntervalUs == 0 || channelCount == 0)
    {
        return RecoveryPointInvalidConfig;
    }

    const uint32_t elapsedUs = nowUs - g_pendingSyncTimestampUs;
    if (elapsedUsOut != nullptr)
    {
        *elapsedUsOut = elapsedUs;
    }
    const uint8_t syncNonceMod = g_pendingSyncNonce % hopInterval;
    const uint32_t toNextHopUs = (uint32_t)(hopInterval - syncNonceMod) * packetIntervalUs;
    if (elapsedUs < toNextHopUs)
    {
        return RecoveryPointNotReady;
    }

    const uint32_t hopDurationUs = packetIntervalUs * hopInterval;
    uint32_t distanceHops;

    if (refNonceMod >= 0)
    {
        // Wide mode: use nonceMod from CRC for precise hop distance.
        // Compute approximate delta-nonce from timing, then snap to
        // the exact value consistent with the known nonceMod.
        uint32_t approxDeltaNonce = (elapsedUs + packetIntervalUs / 2U) / packetIntervalUs;
        uint32_t receivedNonce = (uint32_t)g_pendingSyncNonce + approxDeltaNonce;
        // Snap to nearest nonce that satisfies receivedNonce % hopInterval == refNonceMod
        uint8_t currentMod = receivedNonce % hopInterval;
        int8_t correction = (int8_t)refNonceMod - (int8_t)currentMod;
        if (correction > (int8_t)(hopInterval / 2))
        {
            correction -= hopInterval;
        }
        else if (correction < -(int8_t)(hopInterval / 2))
        {
            correction += hopInterval;
        }
        receivedNonce = (uint32_t)((int32_t)receivedNonce + correction);
        if (receivedNonce <= g_pendingSyncNonce)
        {
            return RecoveryPointNotReady;
        }
        // Compute exact hop count from nonce values
        uint32_t syncHopSlot = g_pendingSyncNonce / hopInterval;
        uint32_t refHopSlot = receivedNonce / hopInterval;
        distanceHops = refHopSlot - syncHopSlot;
    }
    else
    {
        // Non-wide mode: use rounded timing quantization.
        const uint32_t adjustedUs = elapsedUs - toNextHopUs;
        distanceHops = (adjustedUs + hopDurationUs / 2U) / hopDurationUs;
    }

    if (distanceHopsOut != nullptr)
    {
        *distanceHopsOut = (uint8_t)distanceHops;
    }

    if (distanceHops >= channelCount)
    {
        return RecoveryPointOutOfWindow;
    }

    if (distanceHops >= FHSS_SEQUENCE_LEN || g_recoveryPointCount >= RECOVERY_MAX_POINTS)
    {
        return RecoveryPointStorageFull;
    }

    g_recoveryPoints[g_recoveryPointCount].startIndex = g_pendingSyncIndex;
    g_recoveryPoints[g_recoveryPointCount].distanceHops = (uint8_t)distanceHops;
    g_recoveryPoints[g_recoveryPointCount].referenceChannel = g_referenceChannel;
    g_recoveryPointCount++;

    return RecoveryPointAdded;
}

static void configureRuntimeFromObservedSync()
{
    if (!g_lastSync.valid)
    {
        return;
    }

    if (isSupportedRFRate(g_lastSync.rateIndex) && isSubGHzRate(g_lastSync.rateIndex))
    {
        if (ExpressLRS_currAirRate_Modparams == nullptr || ExpressLRS_currAirRate_Modparams->index != g_lastSync.rateIndex)
        {
            SetRFLinkRate(g_lastSync.rateIndex);
        }
    }

    if (g_lastSync.switchEncMode <= sm12ch && ExpressLRS_currAirRate_Modparams != nullptr)
    {
        OtaUpdateSerializers((OtaSwitchMode_e)g_lastSync.switchEncMode, ExpressLRS_currAirRate_Modparams->PayloadLength);
    }

    expresslrs_tlm_ratio_e observedTlmRatio = (expresslrs_tlm_ratio_e)(g_lastSync.newTlmRatio + (uint8_t)TLM_RATIO_NO_TLM);
    if (observedTlmRatio >= TLM_RATIO_NO_TLM && observedTlmRatio <= TLM_RATIO_1_2)
    {
        ExpressLRS_currTlmDenom = TLMratioEnumToValue(observedTlmRatio);
    }
}

static void startTakeoverAttempt()
{
    if (!g_lastSync.valid || ExpressLRS_currAirRate_Modparams == nullptr)
    {
        beginRetryBackoff("no sync snapshot");
        return;
    }

    OtaUpdateCrcInitFromUid();
    FHSSrandomiseFHSSsequence(uidMacSeedGet());
    configureRuntimeFromObservedSync();

    if (ExpressLRS_currAirRate_Modparams == nullptr)
    {
        beginRetryBackoff("rate setup failed");
        return;
    }

    restoreRateRxTimeout();

    const uint16_t sequenceCount = FHSSgetSequenceCount();

    // Compute optimal offset to minimize frequency collisions with original TX
    g_computedFhssOffset = computeOptimalFhssOffset(FHSSsequence, sequenceCount);
    const uint8_t hopInterval = ExpressLRS_currAirRate_Modparams->FHSShopInterval;
    const uint32_t packetIntervalUs = ExpressLRS_currAirRate_Modparams->interval;
    if (sequenceCount == 0 || hopInterval == 0 || packetIntervalUs == 0)
    {
        beginRetryBackoff("invalid timing");
        return;
    }

    const uint32_t nowUs = micros();
    const uint32_t elapsedUs = nowUs - g_lastSync.timestampUs;
    const uint32_t packetDelta = (elapsedUs + packetIntervalUs / 2U) / packetIntervalUs;

    uint8_t predictedIndex = g_lastSync.fhssIndex % sequenceCount;
    uint16_t nonce = g_lastSync.nonce;
    for (uint32_t i = 0; i < packetDelta; i++)
    {
        nonce++;
        if ((nonce % hopInterval) == 0)
        {
            predictedIndex = (predictedIndex + 1) % sequenceCount;
        }
    }

    OtaNonce = (uint8_t)nonce;
    FHSSsetCurrIndex(predictedIndex);

    TelemetryRcvPhase = ttrpTransmitting;
    connectionState = disconnected;
    LastTLMpacketRecvMillis = 0;

    g_pendingIndexShift = false;
    g_burstRemaining = TAKEOVER_SYNC_BURST;
    g_mirrorCompatSync = true;
    g_mirrorCompatUntilMs = millis() + MIRROR_COMPAT_MS;
    g_waitHopStartMs = millis();
    g_state = WAIT_NEXT_HOP;

    setRadioToCurrentTxFrequency();
    g_txRunning = true;
    hwTimer::resume();

    DBGLN("Takeover ready nonce=%u fhss=%u uid2=%u", OtaNonce, FHSSgetCurrIndex(), UID[2]);
}

static bool processSyncLockPacket(OTA_Packet_s *pkt)
{
    if (pkt->std.type != PACKET_TYPE_SYNC || ExpressLRS_currAirRate_Modparams == nullptr)
    {
        Radio.RXnb();
        return false;
    }

    OTA_Sync_s const *const sync = getSyncPacket(pkt);
    bool const hadPreviousSync = g_lastSync.valid;
    uint8_t const prevResolvedUid5 = UID[5];
    uint8_t resolvedUid5 = 0;
    if (!resolveSyncUidTailAndCheckCrc(pkt, sync, &resolvedUid5))
    {
        g_sniffCrcFail++;
        Radio.RXnb();
        return false;
    }
    g_sniffCrcOk++;

    if (sync->rateIndex != ExpressLRS_currAirRate_Modparams->index)
    {
        g_sniffRateMismatch++;
        if (g_uidLockCount == 0)
        {
            DBGLN("Takeover sync CRC-ok rate mismatch scan=%u packet=%u",
                  ExpressLRS_currAirRate_Modparams->index, sync->rateIndex);
        }
        if (!shouldScanRate(sync->rateIndex))
        {
            Radio.RXnb();
            return false;
        }
    }

    UID[3] = sync->UID3;
    UID[4] = sync->UID4;
    UID[5] = resolvedUid5;

    uint8_t const prevUid3 = g_lastSync.uid3;
    uint8_t const prevUid4 = g_lastSync.uid4;
    uint8_t const prevUid5 = g_lastSync.uid5Wire;

    captureSync(sync, micros());

    bool const sameWireTail = prevUid3 == sync->UID3 && prevUid4 == sync->UID4 && prevUid5 == sync->UID5;
    bool const sameResolvedTail = prevResolvedUid5 == resolvedUid5;
    if (!hadPreviousSync || (sameWireTail && sameResolvedTail))
    {
        g_uidLockCount++;
    }
    else
    {
        g_uidLockCount = 1;
    }

    uint8_t const deadlineRate = shouldScanRate(sync->rateIndex) ? sync->rateIndex : ExpressLRS_currAirRate_Modparams->index;
    g_stateDeadlineMs = millis() + computeSyncWaitTimeoutMs(deadlineRate, RATE_SCAN_DWELL_MS);

    if (g_uidLockCount >= UID_LOCK_COUNT)
    {
        DBGLN("Takeover UID tail lock uid3-5=%u,%u,%u", sync->UID3, sync->UID4, sync->UID5);
        startUid2Recovery();
        return true;
    }

    Radio.RXnb();
    return true;
}

static bool processUidRecoveryPacket(OTA_Packet_s *pkt)
{
    if (g_takeoverStartPending)
    {
        return false;
    }

    if (g_recoverSubState == RECOVER_WAIT_SYNC)
    {
        if (pkt->std.type != PACKET_TYPE_SYNC)
        {
            Radio.RXnb();
            return false;
        }

        OTA_Sync_s const *const sync = getSyncPacket(pkt);
        if (g_lastSync.valid &&
            (sync->UID3 != g_lastSync.uid3 ||
             sync->UID4 != g_lastSync.uid4 ||
             sync->UID5 != g_lastSync.uid5Wire))
        {
            // Ignore sync-like packets that don't match the locked UID tail.
            Radio.RXnb();
            return false;
        }
        if (g_lastSync.valid && sync->rateIndex != g_lastSync.rateIndex)
        {
            // Recovery sync anchors must remain on the locked rate.
            Radio.RXnb();
            return false;
        }

        uint8_t resolvedUid5 = 0;
        if (!resolveSyncUidTailAndCheckCrc(pkt, sync, &resolvedUid5))
        {
            g_sniffCrcFail++;
            Radio.RXnb();
            return false;
        }
        if (UID[5] != resolvedUid5)
        {
            // Keep the previously locked UID5.
            Radio.RXnb();
            return false;
        }
        g_sniffCrcOk++;
        UID[3] = sync->UID3;
        UID[4] = sync->UID4;
        UID[5] = resolvedUid5;

        captureSync(sync, micros());
        g_pendingSyncIndex = sync->fhssIndex;
        g_pendingSyncNonce = sync->nonce;
        g_pendingSyncTimestampUs = g_lastSync.timestampUs;
        g_havePendingRecoverySync = true;

        g_recoverSubState = RECOVER_WAIT_REFERENCE_PACKET;
        g_stateDeadlineMs = millis() + computeRecoveryReferenceTimeoutMs(sync->nonce);
        setRadioReferenceListen(g_referenceChannel);
        return true;
    }

    if (pkt->std.type != PACKET_TYPE_RCDATA && pkt->std.type != PACKET_TYPE_MSPDATA)
    {
        // Use only uplink packets as reference points. Downlink telemetry/sync-like
        // packets can skew elapsed timing and poison UID2 constraints.
        Radio.RXnb();
        return false;
    }

    int8_t const refNonceMod = validateTakeoverPacketCrcEx(pkt);
    if (refNonceMod == -2)
    {
        g_sniffCrcFail++;
        Radio.RXnb();
        return false;
    }
    g_sniffCrcOk++;

    uint8_t measuredDistanceHops = 0;
    uint32_t elapsedUs = 0;
    RecoveryPointStatus const pointStatus = addRecoveryPoint(micros(), refNonceMod, &measuredDistanceHops, &elapsedUs);

    if (pointStatus == RecoveryPointNotReady)
    {
        Radio.RXnb();
        return false;
    }

    resetUidRecoveryToWaitSync(millis());

    if (pointStatus == RecoveryPointOutOfWindow)
    {
        DBGLN("Takeover UID2 point ignored (late) idx=%u elapsedUs=%u", g_pendingSyncIndex, (unsigned)elapsedUs);
        return false;
    }

    if (pointStatus != RecoveryPointAdded)
    {
        beginRetryBackoff("UID2 point capture error");
        return true;
    }

    DBGLN("Takeover UID2 point ref=%u idx=%u dist=%u points=%u elapsedUs=%u nonceMod=%d",
          g_referenceChannel, g_pendingSyncIndex, measuredDistanceHops, g_recoveryPointCount, (unsigned)elapsedUs, (int)refNonceMod);

    if (g_recoveryPointCount < RECOVERY_MIN_POINTS)
    {
        return true;
    }

    uint8_t recoveredUid2 = 0;
    uint8_t const matchCount = countUid2Matches(&recoveredUid2);
    if (matchCount == 1)
    {
        UID[2] = recoveredUid2;
        DBGLN("Takeover recovered UID2=%u", UID[2]);
        g_takeoverStartPending = true;
        return true;
    }

    if (matchCount == 0)
    {
        if (g_recoveryPointCount > 0)
        {
            g_recoveryPointCount--;
        }
        g_recoveryRejectedPoints++;
        DBGLN("Takeover UID2 point rejected, rejects=%u", g_recoveryRejectedPoints);
        if (g_recoveryRejectedPoints >= RECOVERY_REJECT_LIMIT)
        {
            beginRetryBackoff("UID2 constraints unstable");
        }
        return true;
    }

    g_recoveryRejectedPoints = 0;

    if (g_recoveryPointCount >= g_recoveryNextReferenceSwitchAtPoints &&
        g_recoveryPointCount < RECOVERY_MAX_POINTS &&
        chooseAlternativeReferenceChannel())
    {
        DBGLN("Takeover UID2 ambiguous candidates=%u; switching ref channel to %u (switch=%u)",
              matchCount, g_referenceChannel, g_recoveryReferenceSwitchCount);
        return true;
    }

    if (g_recoveryPointCount < RECOVERY_MAX_POINTS)
    {
        DBGLN("Takeover UID2 narrowing candidates=%u points=%u", matchCount, g_recoveryPointCount);
        return true;
    }

    DBGLN("Takeover UID2 ambiguous candidates=%u", matchCount);
    beginRetryBackoff("UID2 recovery ambiguous");

    return true;
}
} // namespace

void Init()
{
    if (g_initialized)
    {
        return;
    }

    g_initialized = true;
#if defined(PLATFORM_ESP32) || defined(PLATFORM_ESP8266)
    // Keep auto-WiFi from interrupting takeover while UID2 recovery is running.
    webserverPreventAutoStart = true;
#endif
    buildScanRateOrder();
    if (g_scanRateCount == 0)
    {
        DBGLN("Takeover has no eligible 900MHz rates");
        g_state = RETRY_BACKOFF;
        g_backoffUntilMs = millis() + RETRY_BACKOFF_MAX_MS;
        return;
    }

    g_retryCount = 0;
    enterScanRate(0);
    startSniffOnRate(g_scanRates[g_scanRatePos]);
}

void Update(uint32_t nowMs)
{
    if (!g_initialized)
    {
        return;
    }

    switch (g_state)
    {
    case SCAN_RATE:
        startSniffOnRate(g_scanRates[g_scanRatePos]);
        break;

    case LOCK_UID_TAIL:
        emitSniffStats(nowMs);
        if ((int32_t)(nowMs - g_stateDeadlineMs) >= 0)
        {
            enterScanRate((uint8_t)(g_scanRatePos + 1));
        }
        break;

    case RECOVER_UID2:
        if (g_takeoverStartPending)
        {
            g_takeoverStartPending = false;
            startTakeoverAttempt();
            break;
        }
        emitSniffStats(nowMs);
        if ((int32_t)(nowMs - g_stateDeadlineMs) >= 0)
        {
            if (g_recoverSubState == RECOVER_WAIT_REFERENCE_PACKET)
            {
                resetUidRecoveryToWaitSync(nowMs);
            }
            else
            {
                beginRetryBackoff("UID2 timeout");
            }
        }
        break;

    case WAIT_NEXT_HOP:
        if ((nowMs - g_waitHopStartMs) > WAIT_HOP_TIMEOUT_MS)
        {
            beginRetryBackoff("hop alignment timeout");
        }
        break;

    case BURST_SYNC4:
        break;

    case TX_OFFSET_NORMAL:
        if (g_mirrorCompatSync && (int32_t)(nowMs - g_mirrorCompatUntilMs) >= 0)
        {
            g_mirrorCompatSync = false;
        }

        if (LastTLMpacketRecvMillis > g_lastTlmSeenAtStateStart)
        {
            g_linkSeen = true;
        }

        if (!g_linkSeen)
        {
            if ((nowMs - g_takeoverNormalStartMs) > POST_TAKEOVER_STABILIZE_MS)
            {
                beginRetryBackoff("no telemetry lock");
            }
        }
        else if (LastTLMpacketRecvMillis != 0 && (nowMs - LastTLMpacketRecvMillis) > POST_TAKEOVER_LOSS_MS)
        {
            beginRetryBackoff("telemetry lost");
        }
        break;

    case RETRY_BACKOFF:
        if ((int32_t)(nowMs - g_backoffUntilMs) >= 0)
        {
            buildScanRateOrder();
            g_scanRatePos = 0;
            enterScanRate(0);
        }
        break;
    }
}

bool IsEnabled()
{
    return true;
}

bool IsSniffState()
{
    return g_state == LOCK_UID_TAIL || g_state == RECOVER_UID2;
}

State GetState()
{
    return g_state;
}

bool ICACHE_RAM_ATTR OnRxDone(SX12xxDriverCommon::rx_status status)
{
    if (!IsSniffState())
    {
        return false;
    }

    if (status != SX12xxDriverCommon::SX12XX_RX_OK)
    {
        g_sniffIrqErr++;
        Radio.RXnb();
        return false;
    }
    g_sniffIrqOk++;

    OTA_Packet_s *const pkt = (OTA_Packet_s *const)Radio.RXdataBuffer;
    if (pkt->std.type == PACKET_TYPE_SYNC)
    {
        g_sniffSyncPackets++;
    }
    else
    {
        g_sniffNonSyncPackets++;
    }

    if (g_state == LOCK_UID_TAIL)
    {
        return processSyncLockPacket(pkt);
    }

    return processUidRecoveryPacket(pkt);
}

bool ICACHE_RAM_ATTR OnTimerPostNonceAdvance()
{
    if (g_state != WAIT_NEXT_HOP || ExpressLRS_currAirRate_Modparams == nullptr)
    {
        return false;
    }

    uint8_t const hopInterval = ExpressLRS_currAirRate_Modparams->FHSShopInterval;
    if (hopInterval == 0)
    {
        return false;
    }

    if ((OtaNonce % hopInterval) == 0)
    {
        FHSSsetCurrIndex((uint8_t)(FHSSgetCurrIndex() + 1));
        setRadioToCurrentTxFrequency();
        g_state = BURST_SYNC4;
        return false;
    }

    return true;
}

bool ICACHE_RAM_ATTR ShouldForceSync()
{
    return g_state == BURST_SYNC4 && g_burstRemaining > 0;
}

void ICACHE_RAM_ATTR OverrideSyncFields(OTA_Sync_s *syncPtr, bool forcedBurst)
{
    if (syncPtr == nullptr || !g_lastSync.valid)
    {
        return;
    }

    if (forcedBurst || g_mirrorCompatSync)
    {
        syncPtr->rateIndex = g_lastSync.rateIndex;
        syncPtr->switchEncMode = g_lastSync.switchEncMode;
        syncPtr->newTlmRatio = g_lastSync.newTlmRatio;
        syncPtr->UID3 = g_lastSync.uid3;
        syncPtr->UID4 = g_lastSync.uid4;
        syncPtr->UID5 = g_lastSync.uid5Wire;
    }

    if (forcedBurst)
    {
        uint16_t const sequenceCount = FHSSgetSequenceCount();
        if (sequenceCount > 0)
        {
            syncPtr->fhssIndex = (uint8_t)((FHSSgetCurrIndex() + g_computedFhssOffset) % sequenceCount);
        }
    }
}

void ICACHE_RAM_ATTR OnForcedSyncQueued()
{
    if (g_state != BURST_SYNC4 || g_burstRemaining == 0)
    {
        return;
    }

    g_burstRemaining--;
    if (g_burstRemaining == 0)
    {
        g_pendingIndexShift = true;
    }
}

void ICACHE_RAM_ATTR OnTxDone()
{
    if (!g_pendingIndexShift)
    {
        return;
    }

    g_pendingIndexShift = false;
    FHSSsetCurrIndex((uint8_t)(FHSSgetCurrIndex() + g_computedFhssOffset));
    setRadioToCurrentTxFrequency();

    g_state = TX_OFFSET_NORMAL;
    g_takeoverNormalStartMs = millis();
    g_lastTlmSeenAtStateStart = LastTLMpacketRecvMillis;
    g_linkSeen = LastTLMpacketRecvMillis != 0;
    g_mirrorCompatSync = true;
    g_mirrorCompatUntilMs = g_takeoverNormalStartMs + MIRROR_COMPAT_MS;

    DBGLN("Takeover burst complete; applied FHSS offset %u", g_computedFhssOffset);
}
} // namespace TxTakeover

#else

namespace TxTakeover
{
void Init() {}
void Update(uint32_t) {}
bool IsEnabled() { return false; }
bool IsSniffState() { return false; }
State GetState() { return SCAN_RATE; }
bool ICACHE_RAM_ATTR OnRxDone(SX12xxDriverCommon::rx_status) { return false; }
bool ICACHE_RAM_ATTR OnTimerPostNonceAdvance() { return false; }
bool ICACHE_RAM_ATTR ShouldForceSync() { return false; }
void ICACHE_RAM_ATTR OverrideSyncFields(OTA_Sync_s *, bool) {}
void ICACHE_RAM_ATTR OnForcedSyncQueued() {}
void ICACHE_RAM_ATTR OnTxDone() {}
} // namespace TxTakeover

#endif
