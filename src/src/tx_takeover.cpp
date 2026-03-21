#include "tx_takeover.h"

#if defined(ELRS_TX_TAKEOVER) && ELRS_TX_TAKEOVER

extern TxConfig config;
extern volatile bool busyTransmitting;
extern TxTlmRcvPhase_e TelemetryRcvPhase;
extern volatile uint32_t LastTLMpacketRecvMillis;

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
};

enum UidRecoveryResult : uint8_t
{
    UidRecoveryNeedMore = 0,
    UidRecoverySuccess,
    UidRecoveryFailed
};

static constexpr uint8_t UID_LOCK_COUNT = 3;
static constexpr uint8_t RECOVERY_MIN_POINTS = 4;
static constexpr uint8_t RECOVERY_MAX_POINTS = 8;
static constexpr uint32_t RATE_SCAN_DWELL_MS = 1200;
static constexpr uint32_t RECOVER_SYNC_TIMEOUT_MS = 1500;
static constexpr uint32_t RECOVER_REFERENCE_TIMEOUT_MS = 300;
static constexpr uint32_t WAIT_HOP_TIMEOUT_MS = 1000;
static constexpr uint32_t POST_TAKEOVER_STABILIZE_MS = 2200;
static constexpr uint32_t POST_TAKEOVER_LOSS_MS = 1800;
static constexpr uint32_t MIRROR_COMPAT_MS = 2000;
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
static volatile uint8_t g_uidLockCount = 0;
static volatile bool g_scanAltIq = false;

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
static SyncObservation g_lastSync = {};
static uint32_t g_sniffStatsLastLogMs = 0;

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
    DBGLN("Takeover scan rate=%u iqAlt=%u syncFreq=%lu", rateIndex, g_scanAltIq ? 1 : 0, (unsigned long)syncFreq);
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

static bool resolveSyncUidTailAndCheckCrc(OTA_Packet_s *pkt, OTA_Sync_s const *sync, uint8_t *resolvedUid5, uint8_t *resolvedModelXor)
{
    if (pkt == nullptr || sync == nullptr || resolvedUid5 == nullptr)
    {
        return false;
    }

    uint8_t const prevUid4 = UID[4];
    uint8_t const prevUid5 = UID[5];

    UID[4] = sync->UID4;
    for (uint8_t modelXor = 0; modelXor <= MODELMATCH_MASK; modelXor++)
    {
        uint8_t const candidateUid5 = sync->UID5 ^ modelXor;
        UID[5] = candidateUid5;
        OtaUpdateCrcInitFromUid();
        if (OtaValidatePacketCrc(pkt))
        {
            *resolvedUid5 = candidateUid5;
            if (resolvedModelXor != nullptr)
            {
                *resolvedModelXor = modelXor;
            }
            return true;
        }
    }

    UID[4] = prevUid4;
    UID[5] = prevUid5;
    OtaUpdateCrcInitFromUid();
    return false;
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
    g_havePendingRecoverySync = false;
    g_stateDeadlineMs = millis() + RECOVER_SYNC_TIMEOUT_MS;

    const uint32_t channelCount = FHSSgetChannelCount();
    if (channelCount == 0)
    {
        beginRetryBackoff("invalid FHSS config");
        return;
    }

    g_referenceChannel = (uint8_t)((sync_channel + 7) % channelCount);
    if (g_referenceChannel == sync_channel)
    {
        g_referenceChannel = (uint8_t)((g_referenceChannel + 1) % channelCount);
    }

    setRadioSyncListen();
    DBGLN("Takeover locked UID tail, recovering UID2 using ref channel %u", g_referenceChannel);
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

static bool sequenceMatchesPoints(uint8_t const *sequence, uint16_t sequenceCount, uint_fast8_t syncChannel)
{
    for (uint8_t idx = 0; idx < g_recoveryPointCount; idx++)
    {
        uint16_t startIndex = g_recoveryPoints[idx].startIndex % sequenceCount;
        if (sequence[startIndex] != syncChannel)
        {
            return false;
        }

        int16_t distance = distanceFromSyncToChannel(sequence, sequenceCount, startIndex, g_referenceChannel);
        if (distance < 0 || (uint8_t)distance != g_recoveryPoints[idx].distanceHops)
        {
            return false;
        }
    }

    return true;
}

static UidRecoveryResult tryRecoverUid2()
{
    const uint32_t freqCount = FHSSgetChannelCount();
    const uint16_t sequenceCount = FHSSgetSequenceCount();
    const uint_fast8_t activeSyncChannel = getActiveSyncChannel();
    if (freqCount == 0 || sequenceCount == 0)
    {
        return UidRecoveryFailed;
    }

    uint8_t candidateSequence[FHSS_SEQUENCE_LEN] = {0};
    int16_t matchedUid2 = -1;
    uint8_t matches = 0;

    for (uint16_t candidate = 0; candidate < 256; candidate++)
    {
        uint32_t candidateSeed = ((uint32_t)candidate << 24) + ((uint32_t)UID[3] << 16) +
                                 ((uint32_t)UID[4] << 8) + (UID[5] ^ OTA_VERSION_ID);
        buildSequenceForSeed(candidateSeed, freqCount, activeSyncChannel, sequenceCount, candidateSequence);

        if (!sequenceMatchesPoints(candidateSequence, sequenceCount, activeSyncChannel))
        {
            continue;
        }

        matchedUid2 = (int16_t)candidate;
        matches++;
        if (matches > 1 && g_recoveryPointCount < RECOVERY_MAX_POINTS)
        {
            return UidRecoveryNeedMore;
        }
    }

    if (matches == 1 && matchedUid2 >= 0)
    {
        UID[2] = (uint8_t)matchedUid2;
        return UidRecoverySuccess;
    }

    return UidRecoveryFailed;
}

static bool addRecoveryPoint(uint32_t nowUs)
{
    if (!g_havePendingRecoverySync || ExpressLRS_currAirRate_Modparams == nullptr)
    {
        return false;
    }

    const uint8_t hopInterval = ExpressLRS_currAirRate_Modparams->FHSShopInterval;
    const uint32_t packetIntervalUs = ExpressLRS_currAirRate_Modparams->interval;
    if (hopInterval == 0 || packetIntervalUs == 0)
    {
        return false;
    }

    const uint32_t elapsedUs = nowUs - g_pendingSyncTimestampUs;
    const uint8_t nonceMod = g_pendingSyncNonce % hopInterval;
    const uint32_t toNextHopUs = (uint32_t)(hopInterval - nonceMod) * packetIntervalUs;
    if (elapsedUs < toNextHopUs)
    {
        return false;
    }

    const uint32_t hopDurationUs = packetIntervalUs * hopInterval;
    const uint32_t adjustedUs = elapsedUs - toNextHopUs;
    const uint32_t distanceHops = (adjustedUs + hopDurationUs / 2U) / hopDurationUs;

    if (distanceHops >= FHSS_SEQUENCE_LEN || g_recoveryPointCount >= RECOVERY_MAX_POINTS)
    {
        return false;
    }

    g_recoveryPoints[g_recoveryPointCount].startIndex = g_pendingSyncIndex;
    g_recoveryPoints[g_recoveryPointCount].distanceHops = (uint8_t)distanceHops;
    g_recoveryPointCount++;
    return true;
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
    if (sync->rateIndex != ExpressLRS_currAirRate_Modparams->index)
    {
        g_sniffRateMismatch++;
        Radio.RXnb();
        return false;
    }

    uint8_t resolvedUid5 = 0;
    uint8_t resolvedModelXor = 0;
    if (!resolveSyncUidTailAndCheckCrc(pkt, sync, &resolvedUid5, &resolvedModelXor))
    {
        g_sniffCrcFail++;
        Radio.RXnb();
        return false;
    }
    g_sniffCrcOk++;
    UID[3] = sync->UID3;
    UID[4] = sync->UID4;
    UID[5] = resolvedUid5;
    if (resolvedModelXor != 0 && g_uidLockCount == 0)
    {
        DBGLN("Takeover model match XOR=%u", resolvedModelXor);
    }

    bool const hadPreviousSync = g_lastSync.valid;
    uint8_t const prevUid3 = g_lastSync.uid3;
    uint8_t const prevUid4 = g_lastSync.uid4;
    uint8_t const prevUid5 = g_lastSync.uid5Wire;

    captureSync(sync, micros());

    if (!hadPreviousSync ||
        (prevUid3 == sync->UID3 && prevUid4 == sync->UID4 && prevUid5 == sync->UID5))
    {
        g_uidLockCount++;
    }
    else
    {
        g_uidLockCount = 1;
    }

    g_stateDeadlineMs = millis() + RATE_SCAN_DWELL_MS;

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
    (void)pkt;

    if (g_recoverSubState == RECOVER_WAIT_SYNC)
    {
        if (pkt->std.type != PACKET_TYPE_SYNC)
        {
            Radio.RXnb();
            return false;
        }

        OTA_Sync_s const *const sync = getSyncPacket(pkt);

        uint8_t resolvedUid5 = 0;
        if (!resolveSyncUidTailAndCheckCrc(pkt, sync, &resolvedUid5, nullptr))
        {
            g_sniffCrcFail++;
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
        g_stateDeadlineMs = millis() + RECOVER_REFERENCE_TIMEOUT_MS;
        setRadioReferenceListen(g_referenceChannel);
        return true;
    }

    bool pointAdded = addRecoveryPoint(micros());
    g_havePendingRecoverySync = false;
    g_recoverSubState = RECOVER_WAIT_SYNC;
    g_stateDeadlineMs = millis() + RECOVER_SYNC_TIMEOUT_MS;
    setRadioSyncListen();

    if (!pointAdded)
    {
        return false;
    }

    if (g_recoveryPointCount < RECOVERY_MIN_POINTS)
    {
        return true;
    }

    UidRecoveryResult const result = tryRecoverUid2();
    if (result == UidRecoveryNeedMore && g_recoveryPointCount < RECOVERY_MAX_POINTS)
    {
        return true;
    }

    if (result == UidRecoverySuccess)
    {
        DBGLN("Takeover recovered UID2=%u", UID[2]);
        startTakeoverAttempt();
    }
    else
    {
        beginRetryBackoff("UID2 recovery failed");
    }

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
        if ((int32_t)(nowMs - g_stateDeadlineMs) >= 0)
        {
            if (g_recoverSubState == RECOVER_WAIT_REFERENCE_PACKET)
            {
                g_havePendingRecoverySync = false;
                g_recoverSubState = RECOVER_WAIT_SYNC;
                g_stateDeadlineMs = nowMs + RECOVER_SYNC_TIMEOUT_MS;
                setRadioSyncListen();
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
            syncPtr->fhssIndex = (uint8_t)((FHSSgetCurrIndex() + TAKEOVER_FHSS_OFFSET) % sequenceCount);
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
    FHSSsetCurrIndex((uint8_t)(FHSSgetCurrIndex() + TAKEOVER_FHSS_OFFSET));
    setRadioToCurrentTxFrequency();

    g_state = TX_OFFSET_NORMAL;
    g_takeoverNormalStartMs = millis();
    g_lastTlmSeenAtStateStart = LastTLMpacketRecvMillis;
    g_linkSeen = LastTLMpacketRecvMillis != 0;
    g_mirrorCompatSync = true;
    g_mirrorCompatUntilMs = g_takeoverNormalStartMs + MIRROR_COMPAT_MS;

    DBGLN("Takeover burst complete; applied FHSS offset %u", (uint8_t)TAKEOVER_FHSS_OFFSET);
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
