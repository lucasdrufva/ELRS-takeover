#pragma once

#include "rxtx_common.h"

#ifndef ELRS_TX_TAKEOVER
#define ELRS_TX_TAKEOVER 0
#endif

#ifndef TAKEOVER_FHSS_OFFSET
#define TAKEOVER_FHSS_OFFSET 8
#endif

#ifndef TAKEOVER_SYNC_BURST
#define TAKEOVER_SYNC_BURST 8
#endif

namespace TxTakeover
{
enum State : uint8_t
{
    SCAN_RATE = 0,
    LOCK_UID_TAIL,
    RECOVER_UID2,
    WAIT_NEXT_HOP,
    BURST_SYNC4,
    TX_OFFSET_NORMAL,
    RETRY_BACKOFF
};

void Init();
void Update(uint32_t nowMs);

bool IsEnabled();
bool IsSniffState();
State GetState();

bool ICACHE_RAM_ATTR OnRxDone(SX12xxDriverCommon::rx_status status);
bool ICACHE_RAM_ATTR OnTimerPostNonceAdvance();

bool ICACHE_RAM_ATTR ShouldForceSync();
void ICACHE_RAM_ATTR OverrideSyncFields(OTA_Sync_s *syncPtr, bool forcedBurst);
void ICACHE_RAM_ATTR OnForcedSyncQueued();
void ICACHE_RAM_ATTR OnTxDone();
} // namespace TxTakeover

