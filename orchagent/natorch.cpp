/*
 * Copyright 2019 Broadcom Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <assert.h>
#include <iostream>
#include <vector>
#include <unordered_map>
#include <utility>

#include "exec.h"
#include "logger.h"
#include "tokenize.h"
#include "natorch.h"
#include "notifier.h"
#include "sai_serialize.h"
#include "crmorch.h"

extern CrmOrch            *gCrmOrch;
extern PortsOrch          *gPortsOrch;
extern sai_object_id_t     gSwitchId;
extern sai_switch_api_t   *sai_switch_api;
extern sai_object_id_t     gVirtualRouterId;
extern sai_nat_api_t      *sai_nat_api;
extern sai_hostif_api_t   *sai_hostif_api;
extern bool               gIsNatSupported;
#ifdef DEBUG_FRAMEWORK
extern DebugDumpOrch      *gDebugDumpOrch;
#endif
uint32_t  natTimerTickCntr  = 0;
bool      gNhTrackingSupported = false;

NatOrch::NatOrch(DBConnector *appDb, DBConnector *stateDb, vector<table_name_with_pri_t> &tableNames,
         RouteOrch *routeOrch, NeighOrch *neighOrch):
         Orch(appDb, tableNames),
         m_neighOrch(neighOrch),
         m_routeOrch(routeOrch),
         m_countersDb("COUNTERS_DB", 0),
         m_countersNatTable(&m_countersDb, COUNTERS_NAT_TABLE),
         m_countersNaptTable(&m_countersDb, COUNTERS_NAPT_TABLE),
         m_countersTwiceNatTable(&m_countersDb, COUNTERS_TWICE_NAT_TABLE),
         m_countersTwiceNaptTable(&m_countersDb, COUNTERS_TWICE_NAPT_TABLE),
         m_countersGlobalNatTable(&m_countersDb, COUNTERS_GLOBAL_NAT_TABLE),
         m_natQueryTable(appDb, APP_NAT_TABLE_NAME),
         m_naptQueryTable(appDb, APP_NAPT_TABLE_NAME),
         m_twiceNatQueryTable(appDb, APP_NAT_TWICE_TABLE_NAME),
         m_twiceNaptQueryTable(appDb, APP_NAPT_TWICE_TABLE_NAME),
         m_updateEventTable(appDb, APP_NAT_UPDATE_EVENT_TABLE_NAME),
         nullIpv4Addr(0)
{
    /* Set NAT admin mode to disabled */
    admin_mode = "disabled";

    /* Set NAT default timeout as 600 seconds */
    timeout = 600;

    /* Set NAT default tcp timeout as 86400 seconds (1 Day) */
    tcp_timeout = 86400;

    /* Set NAT default udp timeout as 300 seconds */
    udp_timeout = 300;

    /* Set entries count to 0 */
    totalEntries = totalSnatEntries = totalDnatEntries = 0;
    totalStaticNatEntries = totalDynamicNatEntries = 0;
    totalStaticNaptEntries = totalDynamicNaptEntries = 0;
    totalStaticTwiceNatEntries = totalDynamicTwiceNatEntries = 0;
    totalStaticTwiceNaptEntries = totalDynamicTwiceNaptEntries = 0;

    /* Add NAT notifications support from APPL_DB */
    SWSS_LOG_INFO("Add NAT notifications support from APPL_DB ");
    m_flushNotificationsConsumer = new NotificationConsumer(appDb, "FLUSHNATSTATISTICS");
    auto flushNotifier = new Notifier(m_flushNotificationsConsumer, this, "FLUSHNATSTATISTICS");
    Orch::addExecutor(flushNotifier);

    SWSS_LOG_INFO("Add REDIS DB cleanup notification support");
    m_cleanupNotificationConsumer = new NotificationConsumer(appDb, "NAT_DB_CLEANUP_NOTIFICATION");
    auto cleanupNotifier = new Notifier(m_cleanupNotificationConsumer, this, "NAT_DB_CLEANUP_NOTIFICATION");
    Orch::addExecutor(cleanupNotifier);

    /* Start the timer to query NAT entry statistics every 5 secs and hitbits every 30 secs */
    SWSS_LOG_INFO("Start the HITBIT Timer ");
    auto interval      = timespec { .tv_sec = NAT_HITBIT_N_CNTRS_QUERY_PERIOD, .tv_nsec = 0 };
    m_natQueryTimer = new SelectableTimer(interval);
    auto executor   = new ExecutableTimer(m_natQueryTimer, this, "NAT_HITBIT_N_CNTRS_QUERY_TIMER");
    Orch::addExecutor(executor);

    /* Start the timer to send notifications to set conntrack entry every 1 day */
    SWSS_LOG_INFO("Start the Timeout Timer ");
    auto timeout_interval      = timespec { .tv_sec = NAT_CONNTRACK_TIMEOUT_PERIOD, .tv_nsec = 0 };
    m_natTimeoutTimer = new SelectableTimer(timeout_interval);
    auto timeout_executor   = new ExecutableTimer(m_natTimeoutTimer, this, "NAT_CONNTRACK_TIMEOUT_TIMER");
    Orch::addExecutor(timeout_executor);

    /* Get the Maximum supported SNAT entries */
    SWSS_LOG_INFO("Get the Maximum supported SNAT entries");
    sai_status_t     status;
    sai_attribute_t  attr = {};
    attr.id = SAI_SWITCH_ATTR_AVAILABLE_SNAT_ENTRY;
    maxAllowedSNatEntries = 0;

    status = sai_switch_api->get_switch_attribute(gSwitchId, 1, &attr);
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_NOTICE("Failed to get the SNAT available entry count, rv:%d", status);
    }
    else
    {
        maxAllowedSNatEntries = attr.value.u32;
    }

    /* Set default values and Max entries to counter DB */
    std::vector<swss::FieldValueTuple> values;
    std::string key = "Values";
    swss::FieldValueTuple p("MAX_NAT_ENTRIES", to_string(maxAllowedSNatEntries));
    swss::FieldValueTuple q("TIMEOUT", to_string(timeout));
    swss::FieldValueTuple r("UDP_TIMEOUT", to_string(udp_timeout));
    swss::FieldValueTuple s("TCP_TIMEOUT", to_string(tcp_timeout));
    values.push_back(p);
    values.push_back(q);
    values.push_back(r);
    values.push_back(s);
    m_countersGlobalNatTable.set(key, values);

    m_updateEventTable.flush();

    setTimeoutNotifier = std::make_shared<NotificationProducer>(appDb, "SETTIMEOUTNAT");
#ifdef DEBUG_FRAMEWORK
    /*Register with debug framework*/
    this->m_dbgCompName = "natorch";
    gDebugDumpOrch->addDbgCompMap(m_dbgCompName, this);
#endif

    char *platform = getenv("platform");
    if (platform && strstr(platform, BRCM_PLATFORM_SUBSTRING))
    {
        gNhTrackingSupported = true;
    }
    SWSS_LOG_NOTICE("DNAT nexthop tracking is %s", ((gNhTrackingSupported == true) ? "enabled" : "disabled"));
}

/* Process notifications for changes in Neighbor entries and route entries
 * that resolve the DNAT entries's next-hop for the translated ip address.
 */
void NatOrch::update(SubjectType type, void *cntx)
{
    SWSS_LOG_ENTER();

    switch(type)
    {
        case SUBJECT_TYPE_NEXTHOP_CHANGE:
        {
            auto update = static_cast<NextHopUpdate *>(cntx);

            auto &ip = update->destination;
            if (ip.isV4())
            {
                auto key = ip.to_string() + keySeparator + keyNextHopUpdateEvent;
                m_updateEventTable.set(key, {{"ip_prefix", update->prefix.to_string()},
                                             {"vrf_id", std::to_string(update->vrf_id)}});
            }
            break;
        }
        case SUBJECT_TYPE_NEIGH_CHANGE:
        {
            auto update = static_cast<NeighborUpdate *>(cntx);

            auto &ip = update->entry.ip_address;
            if (ip.isV4())
            {
                auto key = ip.to_string() + keySeparator + keyNeighborUpdateEvent;
                m_updateEventTable.set(key, {{"change", update->add ? "add" : "del"}});
            }
            break;
        }
        default:
            /* Received update in which we are not interested
             * Ignore it
             */
            return;
    }
}

bool NatOrch::isNextHopResolved(const IpAddress &ip_address, const IpPrefix &ip_prefix,
                                const NextHopGroupKey &nexthopGroup)
{
    // Ignore default route  and subnet based routes
    if (ip_prefix.isDefaultRoute() ||
        (nexthopGroup.getSize() == 1 && nexthopGroup.hasIntfNextHop()))
    {
        SWSS_LOG_INFO("Ignore default or subnet nexthop update event for ip %s",
                      ip_address.to_string().c_str());
        return false;
    }
    if (nexthopGroup == NextHopGroupKey())
    {
        return false;
    }
    return true;
}

bool NatOrch::isNhCacheResolved(const IpAddress& private_ip)
{
    NeighborEntry neighEntry;
    MacAddress    macAddr;

    SWSS_LOG_ENTER();
    auto cIter = m_nhResolvCache.find(private_ip);

    if (cIter == m_nhResolvCache.end())
    {
        if (m_neighOrch->getNeighborEntry(private_ip, neighEntry, macAddr))
        {
            return true;
        }
    }
    else
    {
        if (cIter->second.neighResolved || (cIter->second.nextHopGroup != NextHopGroupKey()))
        {
            return true;
        }
    }

    return false;
}

// Route nexthop change notification to be processed for the DNAT entries
void NatOrch::updateNextHop(const IpAddress &ip_address,
                            const std::vector<FieldValueTuple>& fieldValues)
{
    SWSS_LOG_ENTER();

    auto ip_prefix = IpPrefix{};
    auto vrf_id = sai_object_id_t{};
    for (auto &fv : fieldValues)
    {
        auto &field = fvField(fv);
        auto &value = fvValue(fv);
        if (field == "ip_prefix")
        {
            ip_prefix = {value};
        }
        else if (field == "vrf_id")
        {
            try
            {
                vrf_id = std::stoull(value);
            }
            catch(...)
            {
                SWSS_LOG_ERROR("Invalid vrf_id: %s", value.c_str());
                return;
            }
        }
    }

    auto const nextHopGroup = m_routeOrch->getSyncdRouteNhgKey(vrf_id, ip_prefix);

    auto it = m_nhResolvCache.find(ip_address);
    if (it == m_nhResolvCache.end())
    {
        // No dnat entries to be resolved on this nexthop
        return;
    }
    auto &nhCache = it->second;

    // If the ECMP nexthop group did not change
    if (nextHopGroup == nhCache.nextHopGroup)
    {
        return;
    }

    SWSS_LOG_INFO("Nexthop update event for dnat entries with translated ip %s",
                  ip_address.to_string().c_str());

    bool isResolved = isNextHopResolved(ip_address, ip_prefix, nextHopGroup);
    if (nhCache.nextHopGroup == NextHopGroupKey{} && isResolved)
    {
        nhCache.nextHopGroup = nextHopGroup;
        if (!nhCache.neighResolved)
        {
            // Add all DNAT entries whose translated destination has nexthop resolved.
            SWSS_LOG_INFO("Nexthop resolved for dnat entries with translated ip %s, adding the entries",
                          ip_address.to_string().c_str());
            addNhCacheDnatEntries(ip_address, true);
        }
    }
    else if (nhCache.nextHopGroup != NextHopGroupKey{} && !isResolved)
    {
        nhCache.nextHopGroup = NextHopGroupKey();
        if (!nhCache.neighResolved)
        {
            // Delete all DNAT entries whose translated destination has nexthop unresolved.
            SWSS_LOG_INFO("Nexthop unresolved for dnat entries with translated ip %s, deleting the entries",
                          ip_address.to_string().c_str());
            addNhCacheDnatEntries(ip_address, false);
        }
    }
    else if (nhCache.nextHopGroup != nextHopGroup && isResolved)
    {
        nhCache.nextHopGroup = nextHopGroup;
        if (!nhCache.neighResolved)
        {
            // Add and delete all DNAT entries whose translated destination has ECMP group/NH modified.
            SWSS_LOG_INFO("Nexthop/ECMP modified for dnat entries with translated ip %s, deleting and re-adding the entries",
                          ip_address.to_string().c_str());
            addNhCacheDnatEntries(ip_address, false);
            addNhCacheDnatEntries(ip_address, true);
        }
    }
}

// Neighbor change notification to be processed for the DNAT entries
void NatOrch::updateNeighbor(const IpAddress &ip_address,
                             const std::vector<FieldValueTuple>& fieldValues)
{
    SWSS_LOG_ENTER();

    if (!(fieldValues.size() == 1 && fieldValues[0].first == "change"
          && (fieldValues[0].second == "add" || fieldValues[0].second == "del")))
    {
        auto fvsStr = std::string{};
        for (auto &fv : fieldValues)
        {
            fvsStr += "{" + fvField(fv) + ", " + fvValue(fv) + "}, ";
        }
        SWSS_LOG_ERROR("Invalid updateNeighbor event: {%s}", fvsStr.c_str());
        return;
    }

    bool add = fieldValues[0].second == "add";

    auto it = m_nhResolvCache.find(ip_address);

    // Check if the neighbor update IP matches the translated DNAT IP we are interested in
    if (it == m_nhResolvCache.end())
    {
        return;
    }
    auto &nhCache = it->second;

    SWSS_LOG_INFO("Neighbor update event for dnat entries with translated ip %s",
                  ip_address.to_string().c_str());

    if (nhCache.neighResolved && !add)
    {
        // Delete all DNAT entries whose translated destination is unresolved.
        SWSS_LOG_INFO("Neighbor unresolved for dnat entries with translated ip %s, deleting the entries",
                      ip_address.to_string().c_str());

        addNhCacheDnatEntries(ip_address, false);
        if (nhCache.nextHopGroup != NextHopGroupKey())
        {
            SWSS_LOG_INFO("Nexthop exists for dnat entries with translated ip %s, adding the entries",
                          ip_address.to_string().c_str());
            addNhCacheDnatEntries(ip_address, true);
        }
    }
    else if (!nhCache.neighResolved && add)
    {
        if (nhCache.nextHopGroup != NextHopGroupKey())
        {
            SWSS_LOG_INFO("Neighbor resolved for dnat entries with translated ip %s, deleting the entries added with route nexthop",
                          ip_address.to_string().c_str());
            addNhCacheDnatEntries(ip_address, false);
        }
        // Add all DNAT entries whose translated destination is resolved.
        SWSS_LOG_INFO("Neighbor resolved for dnat entries with translated ip %s, adding the entries",
                      ip_address.to_string().c_str());
        addNhCacheDnatEntries(ip_address, true);
    }
    nhCache.neighResolved = add;
}

/* Process all the dependent DNAT entries to handle the changes
 * in neighbor or nexthop notifications
 */
void NatOrch::addNhCacheDnatEntries(const IpAddress &nhIp, bool add)
{
    SWSS_LOG_ENTER();
    auto it = m_nhResolvCache.find(nhIp);

    if (it == m_nhResolvCache.end())
    {
        return;
    }
    auto &nhCache = it->second;

    if (nhCache.dnatIp != nullIpv4Addr)
    {
        auto natIter = m_natEntries.find(nhCache.dnatIp);
        if (natIter != m_natEntries.end())
        {
            if (add)
            {
                auto rv = addHwDnatEntry(natIter->first);
                if (rv)
                {
                    rv = addHwSnatEntry(natIter->second.translated_ip);
                    if (!rv)
                    {
                        removeHwDnatEntry(natIter->first);
                    }
                }
            }
            else
            {
                removeHwDnatEntry(natIter->first);
                removeHwSnatEntry(natIter->second.translated_ip);
            }
        }
    }
    auto cIter = nhCache.dnapt.begin();
    while (cIter != nhCache.dnapt.end())
    {
        auto naptIter = m_naptEntries.find(*cIter);
        if (naptIter != m_naptEntries.end())
        {
            NaptEntryKey pair_key;

            pair_key.ip_address = naptIter->second.translated_ip;
            pair_key.l4_port = naptIter->second.translated_l4_port;
            pair_key.prototype = naptIter->first.prototype;

            if (add)
            {
                auto rv = addHwDnaptEntry(naptIter->first);
                if (rv)
                {
                    rv = addHwSnaptEntry(pair_key);
                    if (!rv)
                    {
                        removeHwDnaptEntry(naptIter->first);
                    }
                }
            }
            else
            {
                removeHwDnaptEntry(naptIter->first);
                removeHwSnaptEntry(pair_key);
            }
        }
        cIter++;
    }
    auto tIter = nhCache.twiceNat.begin();
    while (tIter != nhCache.twiceNat.end())
    {
        auto tnatIter = m_twiceNatEntries.find(*tIter);
        if (tnatIter != m_twiceNatEntries.end())
        {
            TwiceNatEntryKey pair_key = { tnatIter->second.translated_dst_ip, tnatIter->second.translated_src_ip };

            if (add)
            {
                auto pair_nh_it = m_nhResolvCache.find(tnatIter->first.src_ip);
                if (pair_nh_it == m_nhResolvCache.end() ||
                    (pair_nh_it->second.neighResolved == false &&
                     pair_nh_it->second.nextHopGroup == NextHopGroupKey()))
                {
                    // pair entry is not ready
                    tIter++;
                    continue;
                }

                auto rv = addHwTwiceNatEntry(tnatIter->first);
                if (rv)
                {
                    rv = addHwTwiceNatEntry(pair_key);
                    if (!rv)
                    {
                        removeHwTwiceNatEntry(tnatIter->first);
                    }
                }
            }
            else
            {
                removeHwTwiceNatEntry(tnatIter->first);
                removeHwTwiceNatEntry(pair_key);
            }
        }
        tIter++;
    }
    auto tpIter = nhCache.twiceNapt.begin();
    while (tpIter != nhCache.twiceNapt.end())
    {
        auto tnaptIter = m_twiceNaptEntries.find(*tpIter);
        if (tnaptIter != m_twiceNaptEntries.end())
        {
            TwiceNaptEntryKey pair_key = { tnaptIter->second.translated_dst_ip, tnaptIter->second.translated_dst_l4_port,
                                           tnaptIter->second.translated_src_ip, tnaptIter->second.translated_src_l4_port,
                                           tnaptIter->first.prototype };

            if (add)
            {
                auto pair_nh_it = m_nhResolvCache.find(tnaptIter->first.src_ip);
                if (pair_nh_it == m_nhResolvCache.end() ||
                    (pair_nh_it->second.neighResolved == false &&
                     pair_nh_it->second.nextHopGroup == NextHopGroupKey()))
                {
                    // pair entry is not ready
                    tpIter++;
                    continue;
                }

                auto rv = addHwTwiceNaptEntry(tnaptIter->first);
                if (rv)
                {
                    rv = addHwTwiceNaptEntry(pair_key);
                    if (!rv)
                    {
                        removeHwTwiceNaptEntry(tnaptIter->first);
                    }
                }
            }
            else
            {
                removeHwTwiceNaptEntry(tnaptIter->first);
                removeHwTwiceNaptEntry(pair_key);
            }
        }
        tpIter++;
    }
}

/* Cache the DNAT entry in the NH resolution cache.
 * Only if the nexthop is resolved is the DNAT entry added to hardware.
 */
void NatOrch::addDnatToNhCache(const IpAddress &translatedIp, const IpAddress &dstIp)
{
    NeighborEntry neighEntry;
    MacAddress    macAddr;
    DnatEntries   dnatEntries;

    SWSS_LOG_ENTER();
    auto cIter = m_nhResolvCache.find(translatedIp);

    SWSS_LOG_INFO("Adding to NH cache indexed by translated ip %s, the DNAT entry with ip %s",
                   translatedIp.to_string().c_str(), dstIp.to_string().c_str());
    if (cIter == m_nhResolvCache.end())
    {
        dnatEntries.dnatIp            = dstIp;
        dnatEntries.nextHopGroup      = NextHopGroupKey();
        dnatEntries.neighResolved     = false;

        if (m_neighOrch->getNeighborEntry(translatedIp, neighEntry, macAddr))
        {
            dnatEntries.neighResolved = true;
        }
        m_nhResolvCache[translatedIp] = dnatEntries;
        m_routeOrch->attach(this, translatedIp);
    }
    else
    {
        if ((cIter->second).dnatIp != dstIp)
        {
            (cIter->second).dnatIp = dstIp;
        }
    }
}

/* Cache the Twice NAT entry in the NH resolution cache.
 * Only if the translated dst nexthop is resolved is the Twice NAT entry added to hardware.
 */
void NatOrch::addTwiceNatToNhCache(const IpAddress &translatedIp, const TwiceNatEntryKey &key)
{
    NeighborEntry neighEntry;
    MacAddress    macAddr;
    DnatEntries   dnatEntries;

    SWSS_LOG_ENTER();
    auto cIter = m_nhResolvCache.find(translatedIp);

    SWSS_LOG_INFO("Adding to NH cache indexed by translated ip %s, the Twice NAT entry with src ip %s, dst ip %s",
                   translatedIp.to_string().c_str(), key.src_ip.to_string().c_str(), key.dst_ip.to_string().c_str());
    if (cIter == m_nhResolvCache.end())
    {
        dnatEntries.dnatIp          = nullIpv4Addr;
        dnatEntries.nextHopGroup    = NextHopGroupKey();
        dnatEntries.twiceNat.insert(key);
        dnatEntries.neighResolved   = false;
        if (m_neighOrch->getNeighborEntry(translatedIp, neighEntry, macAddr))
        {
            dnatEntries.neighResolved      = true;
        }
        m_nhResolvCache[translatedIp] = dnatEntries;
        m_routeOrch->attach(this, translatedIp);
        return;
    }
    else
    {
        auto naptIter = ((cIter->second).twiceNat).find(key);
        if (naptIter == ((cIter->second).twiceNat).end())
        {
            ((cIter->second).twiceNat).insert(key);
        }
    }
}

/* Cache the Twice NAPT entry in the NH resolution cache.
 * Only if the translated dst nexthop is resolved is the Twice NAPT entry added to hardware.
 */
void NatOrch::addTwiceNaptToNhCache(const IpAddress &translatedIp, const TwiceNaptEntryKey &key)
{
    NeighborEntry neighEntry;
    MacAddress    macAddr;
    DnatEntries   dnatEntries;

    SWSS_LOG_ENTER();
    auto cIter = m_nhResolvCache.find(translatedIp);

    SWSS_LOG_INFO("Adding to NH cache indexed by translated ip %s, the Twice NAPT entry with src ip %s, src port %d, dst ip %s, dst port %d",
                   translatedIp.to_string().c_str(), key.src_ip.to_string().c_str(), key.src_l4_port, key.dst_ip.to_string().c_str(),
                   key.dst_l4_port);
    if (cIter == m_nhResolvCache.end())
    {
        dnatEntries.dnatIp          = nullIpv4Addr;
        dnatEntries.nextHopGroup    = NextHopGroupKey();
        dnatEntries.twiceNapt.insert(key);
        dnatEntries.neighResolved   = false;
        if (m_neighOrch->getNeighborEntry(translatedIp, neighEntry, macAddr))
        {
            dnatEntries.neighResolved      = true;
        }
        m_nhResolvCache[translatedIp] = dnatEntries;
        m_routeOrch->attach(this, translatedIp);
        return;
    }
    else
    {
        auto naptIter = ((cIter->second).twiceNapt).find(key);
        if (naptIter == ((cIter->second).twiceNapt).end())
        {
            ((cIter->second).twiceNapt).insert(key);
        }
    }
}

// Remove the DNAT entry from the NH resolution cache.
void NatOrch::removeDnatFromNhCache(const IpAddress &translatedIp, const IpAddress &dstIp)
{
    SWSS_LOG_ENTER();

    auto cIter = m_nhResolvCache.find(translatedIp);

    SWSS_LOG_INFO("Removing from NH cache the DNAT entry with ip %s, indexed by translated ip %s",
                   dstIp.to_string().c_str(), translatedIp.to_string().c_str());
    if (cIter == m_nhResolvCache.end())
    {
        SWSS_LOG_INFO("Translated IP %s doesn't exist in NH resolve cache, cannot delete DNAT entry %s",
                       translatedIp.to_string().c_str(), dstIp.to_string().c_str());
        return;
    }

    DnatEntries &dnatEntries = cIter->second;

    if (dnatEntries.dnatIp != dstIp)
    {
        SWSS_LOG_INFO("DNAT entry %s doesn't exist in NH resolve cache", dstIp.to_string().c_str());
        return;
    }
    dnatEntries.dnatIp = nullIpv4Addr;

    if (dnatEntries.dnapt.empty() && (dnatEntries.dnatIp == nullIpv4Addr) &&
        dnatEntries.twiceNat.empty() && dnatEntries.twiceNapt.empty())
    {
        SWSS_LOG_INFO("No NAT/NAPT entries waiting for NH resolution of translated-ip %s", translatedIp.to_string().c_str());
        m_routeOrch->detach(this, translatedIp);
        m_nhResolvCache.erase(translatedIp);
    }
}

/* Cache the DNAPT entry in the NH resolution cache.
 *  Only if the nexthop is resolved is the DNAT entry added to hardware.
 */
void NatOrch::addDnaptToNhCache(const IpAddress &translatedIp, const NaptEntryKey &key)
{
    NeighborEntry   neighEntry;
    MacAddress      macAddr;
    DnatEntries     dnatEntries;

    SWSS_LOG_ENTER();
    auto cIter = m_nhResolvCache.find(translatedIp);

    SWSS_LOG_INFO("Adding to NH cache indexed by translated ip %s, the DNAPT NAT entry with proto %s, ip %s, port %d",
                  translatedIp.to_string().c_str(), key.prototype.c_str(), key.ip_address.to_string().c_str(), key.l4_port);

    if (cIter == m_nhResolvCache.end())
    {
        dnatEntries.dnatIp          = nullIpv4Addr;
        dnatEntries.nextHopGroup    = NextHopGroupKey();
        dnatEntries.dnapt.insert(key);
        dnatEntries.neighResolved   = false;
        if (m_neighOrch->getNeighborEntry(translatedIp, neighEntry, macAddr))
        {
            dnatEntries.neighResolved      = true;
        }
        m_nhResolvCache[translatedIp] = dnatEntries;
        m_routeOrch->attach(this, translatedIp);
        return;
    }
    else
    {
        auto naptIter = ((cIter->second).dnapt).find(key);
        if (naptIter == ((cIter->second).dnapt).end())
        {
            ((cIter->second).dnapt).insert(key);
        }
    }
}

// Remove the DNAPT entry from the NH resolution cache.
void NatOrch::removeDnaptFromNhCache(const IpAddress &translatedIp, const NaptEntryKey &key)
{
    SWSS_LOG_ENTER();

    auto cIter = m_nhResolvCache.find(translatedIp);

    SWSS_LOG_INFO("Removing from NH cache the DNAPT NAT entry with proto %s, ip %s, port %d, indexed by translated ip %s",
                  key.prototype.c_str(), key.ip_address.to_string().c_str(), key.l4_port, translatedIp.to_string().c_str());

    if (cIter == m_nhResolvCache.end())
    {
        SWSS_LOG_INFO("Translated IP %s doesn't exist in NH resolve cache, cannot delete DNAPT entry with ip %s, l4port %d",
                       translatedIp.to_string().c_str(), key.ip_address.to_string().c_str(), key.l4_port);
        return;
    }
    DnatEntries &dnatEntries = cIter->second;

    if (dnatEntries.dnapt.find(key) == dnatEntries.dnapt.end())
    {
        SWSS_LOG_INFO("DNAPT entry ip %s, l4port %d doesn't exist in NH resolve cache",
                      key.ip_address.to_string().c_str(), key.l4_port);
        return;
    }

    dnatEntries.dnapt.erase(key);

    if (dnatEntries.dnapt.empty() && (dnatEntries.dnatIp == nullIpv4Addr) &&
        dnatEntries.twiceNat.empty() && dnatEntries.twiceNapt.empty())
    {
        SWSS_LOG_INFO("No NAT/NAPT entries waiting for NH resolution of translated-ip %s",
                      translatedIp.to_string().c_str());
        m_routeOrch->detach(this, translatedIp);
        m_nhResolvCache.erase(translatedIp);
    }
}

// Remove the Twice NAT entry from the NH resolution cache.
void NatOrch::removeTwiceNatFromNhCache(const IpAddress &translatedIp, const TwiceNatEntryKey &key)
{
    SWSS_LOG_ENTER();

    auto cIter = m_nhResolvCache.find(translatedIp);

    SWSS_LOG_INFO("Removing from NH cache the Twice NAT entry with src ip %s, dst ip %s, indexed by translated ip %s",
                  key.src_ip.to_string().c_str(), key.dst_ip.to_string().c_str(), translatedIp.to_string().c_str());

    if (cIter == m_nhResolvCache.end())
    {
        SWSS_LOG_INFO("Translated IP %s doesn't exist in NH resolve cache, cannot delete Twice NAT entry with src ip %s, dst ip %s",
                       translatedIp.to_string().c_str(), key.src_ip.to_string().c_str(), key.dst_ip.to_string().c_str());
        return;
    }
    DnatEntries &dnatEntries = cIter->second;

    if (dnatEntries.twiceNat.find(key) == dnatEntries.twiceNat.end())
    {
        SWSS_LOG_NOTICE("Twice NAT entry with src ip %s, dst ip %s doesn't exist in NH resolve cache",
                      key.src_ip.to_string().c_str(), key.dst_ip.to_string().c_str());
        return;
    }

    dnatEntries.twiceNat.erase(key);

    if (dnatEntries.dnapt.empty() && (dnatEntries.dnatIp == nullIpv4Addr) &&
        dnatEntries.twiceNat.empty() && dnatEntries.twiceNapt.empty())
    {
        SWSS_LOG_INFO("No NAT/NAPT/Twice NAT entries waiting for NH resolution of translated-ip %s",
                      translatedIp.to_string().c_str());
        m_routeOrch->detach(this, translatedIp);
        m_nhResolvCache.erase(translatedIp);
    }
}

// Remove the Twice NAPT entry from the NH resolution cache.
void NatOrch::removeTwiceNaptFromNhCache(const IpAddress &translatedIp, const TwiceNaptEntryKey &key)
{
    SWSS_LOG_ENTER();

    auto cIter = m_nhResolvCache.find(translatedIp);

    SWSS_LOG_INFO("Removing from NH cache the Twice NAPT entry with proto %s, src ip %s, src port %d, dst ip %s, dst port %d, indexed by translated ip %s",
                  key.prototype.c_str(), key.src_ip.to_string().c_str(), key.src_l4_port, key.dst_ip.to_string().c_str(), key.dst_l4_port,
                  translatedIp.to_string().c_str());

    if (cIter == m_nhResolvCache.end())
    {
        SWSS_LOG_INFO("Translated IP %s doesn't exist in NH resolve cache, cannot delete Twice NAPT entry with proto %s, \
                      src ip %s, src port %d, dst ip %s, dst port %d", translatedIp.to_string().c_str(),
                      key.prototype.c_str(), key.src_ip.to_string().c_str(), key.src_l4_port, key.dst_ip.to_string().c_str(), key.dst_l4_port);
        return;
    }
    DnatEntries &dnatEntries = cIter->second;

    if (dnatEntries.twiceNapt.find(key) == dnatEntries.twiceNapt.end())
    {
        SWSS_LOG_NOTICE("Twice NAPT entry with proto %s, src ip %s, src port %d, dst ip %s, dst port %d doesn't exist in NH resolve cache",
                        key.prototype.c_str(), key.src_ip.to_string().c_str(), key.src_l4_port, key.dst_ip.to_string().c_str(), key.dst_l4_port);
        return;
    }

    dnatEntries.twiceNapt.erase(key);

    if (dnatEntries.dnapt.empty() && (dnatEntries.dnatIp == nullIpv4Addr) &&
        dnatEntries.twiceNat.empty() && dnatEntries.twiceNapt.empty())
    {
        SWSS_LOG_INFO("No NAT/NAPT/Twice NAT/Twice NAPT entries waiting for NH resolution of translated-ip %s",
                      translatedIp.to_string().c_str());
        m_routeOrch->detach(this, translatedIp);
        m_nhResolvCache.erase(translatedIp);
    }
}

// Add the DNAT entry after nexthop resolution, to the hardware
bool NatOrch::addHwDnatEntry(const IpAddress &ip_address)
{
    uint32_t        attr_count;
    sai_nat_entry_t dnat_entry = {};
    sai_attribute_t nat_entry_attr[4] = {};
    sai_status_t    status;

    SWSS_LOG_ENTER();
    SWSS_LOG_INFO("Create DNAT entry for ip %s, as nexthop is resolved", ip_address.to_string().c_str());

    if (m_natEntries.find(ip_address) == m_natEntries.end())
    {
        SWSS_LOG_INFO("NAT entry isn't found for ip %s", ip_address.to_string().c_str());
        return false;
    }

    NatEntryValue entry = m_natEntries[ip_address];

    nat_entry_attr[0].id = SAI_NAT_ENTRY_ATTR_DST_IP;
    nat_entry_attr[0].value.u32 = entry.translated_ip.getV4Addr();
    nat_entry_attr[1].id = SAI_NAT_ENTRY_ATTR_DST_IP_MASK;
    nat_entry_attr[1].value.u32 = 0xffffffff;
    nat_entry_attr[2].id = SAI_NAT_ENTRY_ATTR_ENABLE_PACKET_COUNT;
    nat_entry_attr[2].value.booldata = true;
    nat_entry_attr[3].id = SAI_NAT_ENTRY_ATTR_ENABLE_BYTE_COUNT;
    nat_entry_attr[3].value.booldata = true;

    attr_count = 4;

    dnat_entry.vr_id = gVirtualRouterId;
    dnat_entry.switch_id = gSwitchId;
    dnat_entry.nat_type = SAI_NAT_TYPE_DESTINATION_NAT;
    dnat_entry.data.key.dst_ip = ip_address.getV4Addr();
    dnat_entry.data.mask.dst_ip = 0xffffffff;

    status = sai_nat_api->create_nat_entry(&dnat_entry, attr_count, nat_entry_attr);
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to create %s DNAT NAT entry with ip %s and it's translated ip %s",
                       entry.entry_type.c_str(), ip_address.to_string().c_str(), entry.translated_ip.to_string().c_str());

        task_process_status handle_status = handleSaiCreateStatus(SAI_API_NAT, status);
        if (handle_status != task_success)
        {
            return false;
        }
    }

    SWSS_LOG_NOTICE("Created %s DNAT NAT entry with ip %s and it's translated ip %s",
                    entry.entry_type.c_str(), ip_address.to_string().c_str(), entry.translated_ip.to_string().c_str());

    updateNatCounters(ip_address, 0, 0);
    m_natEntries[ip_address].addedToHw = true;
    gCrmOrch->incCrmResUsedCounter(CrmResourceType::CRM_DNAT_ENTRY);

    if (entry.entry_type == "static")
    {
        totalStaticNatEntries++;
        updateStaticNatCounters(totalStaticNatEntries);
    }
    else
    {
        totalDynamicNatEntries++;
        updateDynamicNatCounters(totalDynamicNatEntries);
    }
    totalDnatEntries++;
    updateDnatCounters(totalDnatEntries);
    totalEntries++;

    return true;
}

// Add the DNAPT entry after nexthop resolution, to the hardware
bool NatOrch::addHwDnaptEntry(const NaptEntryKey &key)
{
    uint32_t        attr_count;
    sai_nat_entry_t dnat_entry = {};
    sai_attribute_t nat_entry_attr[5] = {};
    uint8_t         ip_protocol = ((key.prototype == "TCP") ? IPPROTO_TCP : IPPROTO_UDP);
    sai_status_t    status;

    SWSS_LOG_ENTER();
    SWSS_LOG_INFO("Create DNAPT entry for proto %s, dest-ip %s, l4-port %d, as nexthop is resolved",
                   key.prototype.c_str(), key.ip_address.to_string().c_str(), key.l4_port);

    if (m_naptEntries.find(key) == m_naptEntries.end())
    {
        SWSS_LOG_INFO("NAPT entry isn't found for Prototype - %s, ip - %s and port - %d",
                       key.prototype.c_str(), key.ip_address.to_string().c_str(), key.l4_port);
        return false;
    }

    NaptEntryValue entry = m_naptEntries[key];

    nat_entry_attr[0].id = SAI_NAT_ENTRY_ATTR_DST_IP;
    nat_entry_attr[1].id = SAI_NAT_ENTRY_ATTR_DST_IP_MASK;
    nat_entry_attr[2].id = SAI_NAT_ENTRY_ATTR_L4_DST_PORT;
    nat_entry_attr[0].value.u32 = entry.translated_ip.getV4Addr();
    nat_entry_attr[1].value.u32 = 0xffffffff;
    nat_entry_attr[2].value.u16 = (uint16_t)(entry.translated_l4_port);
    nat_entry_attr[3].id = SAI_NAT_ENTRY_ATTR_ENABLE_PACKET_COUNT;
    nat_entry_attr[3].value.booldata = true;
    nat_entry_attr[4].id = SAI_NAT_ENTRY_ATTR_ENABLE_BYTE_COUNT;
    nat_entry_attr[4].value.booldata = true;

    attr_count = 5;

    dnat_entry.vr_id = gVirtualRouterId;
    dnat_entry.switch_id = gSwitchId;
    dnat_entry.nat_type = SAI_NAT_TYPE_DESTINATION_NAT;
    dnat_entry.data.key.dst_ip = key.ip_address.getV4Addr();
    dnat_entry.data.key.l4_dst_port = (uint16_t)(key.l4_port);
    dnat_entry.data.mask.dst_ip = 0xffffffff;
    dnat_entry.data.mask.l4_dst_port = 0xffff;
    dnat_entry.data.key.proto = ip_protocol;
    dnat_entry.data.mask.proto = 0xff;

    status = sai_nat_api->create_nat_entry(&dnat_entry, attr_count, nat_entry_attr);
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to create %s DNAT NAPT entry with ip %s, port %d, prototype %s and it's translated ip %s, translated port %d",
                       entry.entry_type.c_str(), key.ip_address.to_string().c_str(), key.l4_port, key.prototype.c_str(),
                       entry.translated_ip.to_string().c_str(), entry.translated_l4_port);
        task_process_status handle_status = handleSaiCreateStatus(SAI_API_NAT, status);
        if (handle_status != task_success)
        {
            return false;
        }
    }

    SWSS_LOG_NOTICE("Created %s DNAT NAPT entry with ip %s, port %d, prototype %s and it's translated ip %s, translated port %d",
                    entry.entry_type.c_str(), key.ip_address.to_string().c_str(), key.l4_port, key.prototype.c_str(),
                    entry.translated_ip.to_string().c_str(), entry.translated_l4_port);

    m_naptEntries[key].addedToHw = true;
    updateNaptCounters(key.prototype.c_str(), key.ip_address, key.l4_port, 0, 0);
    gCrmOrch->incCrmResUsedCounter(CrmResourceType::CRM_DNAT_ENTRY);

    if (entry.entry_type == "static")
    {
        totalStaticNaptEntries++;
        updateStaticNaptCounters(totalStaticNaptEntries);
    }
    else
    {
        totalDynamicNaptEntries++;
        updateDynamicNaptCounters(totalDynamicNaptEntries);
    }
    totalDnatEntries++;
    updateDnatCounters(totalDnatEntries);
    totalEntries++;

    return true;
}

// Remove the DNAT entry from the hardware
bool NatOrch::removeHwDnatEntry(const IpAddress &dstIp)
{
    sai_nat_entry_t dnat_entry = {};
    sai_status_t    status;

    SWSS_LOG_ENTER();
    SWSS_LOG_INFO("Deleting DNAT entry ip %s from hardware", dstIp.to_string().c_str());

    /* Check the entry is present in cache */
    if (m_natEntries.find(dstIp) == m_natEntries.end())
    {
        SWSS_LOG_ERROR("DNAT entry isn't found for ip %s", dstIp.to_string().c_str());

        return false;
    }

    if (m_natEntries[dstIp].addedToHw == false)
    {
        SWSS_LOG_INFO("DNAT entry isn't added to h/w, for ip %s", dstIp.to_string().c_str());

        return false;
    }

    NatEntryValue entry = m_natEntries[dstIp];

    m_natEntries[dstIp].addedToHw = false;

    dnat_entry.vr_id = gVirtualRouterId;
    dnat_entry.switch_id = gSwitchId;
    dnat_entry.nat_type = SAI_NAT_TYPE_DESTINATION_NAT;
    dnat_entry.data.key.dst_ip = dstIp.getV4Addr();
    dnat_entry.data.mask.dst_ip = 0xffffffff;

    status = sai_nat_api->remove_nat_entry(&dnat_entry);
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_INFO("Failed to remove %s DNAT NAT entry with ip %s and it's translated ip %s",
                      entry.entry_type.c_str(), dstIp.to_string().c_str(), entry.translated_ip.to_string().c_str());

        task_process_status handle_status = handleSaiRemoveStatus(SAI_API_NAT, status);
        if (handle_status != task_success)
        {
            return parseHandleSaiStatusFailure(handle_status);
        }
    }

    SWSS_LOG_NOTICE("Removed %s DNAT NAT entry with ip %s and it's translated ip %s",
                    entry.entry_type.c_str(), dstIp.to_string().c_str(), entry.translated_ip.to_string().c_str());

    deleteNatCounters(dstIp);
    gCrmOrch->decCrmResUsedCounter(CrmResourceType::CRM_DNAT_ENTRY);

    if (entry.entry_type == "static")
    {
        if (totalStaticNatEntries)
        {
            totalStaticNatEntries--;
            updateStaticNatCounters(totalStaticNatEntries);
        }
    }
    else
    {
        if (totalDynamicNatEntries)
        {
           totalDynamicNatEntries--;
           updateDynamicNatCounters(totalDynamicNatEntries);
        }
    }

    if (totalDnatEntries)
    {
        totalDnatEntries--;
        updateDnatCounters(totalDnatEntries);
    }

    if (totalEntries)
    {
        totalEntries--;
    }

    return true;
}

// Remove the Twice NAT entry from the hardware
bool NatOrch::removeHwTwiceNatEntry(const TwiceNatEntryKey &key)
{
    sai_nat_entry_t dbl_nat_entry = {};
    sai_status_t    status;

    SWSS_LOG_ENTER();
    SWSS_LOG_INFO("Deleting Twice NAT entry src ip %s, dst ip %s from the hardware",
                   key.src_ip.to_string().c_str(), key.dst_ip.to_string().c_str());

    /* Check the entry is present in cache */
    if (m_twiceNatEntries.find(key) == m_twiceNatEntries.end())
    {
        SWSS_LOG_ERROR("Twice NAT entry isn't found for src ip %s, dst ip %s",
                       key.src_ip.to_string().c_str(), key.dst_ip.to_string().c_str());

        return false;
    }

    if (m_twiceNatEntries[key].addedToHw == false)
    {
        SWSS_LOG_INFO("Twice NAT entry isn't added to hardware, for src ip %s, dst ip %s",
                       key.src_ip.to_string().c_str(), key.dst_ip.to_string().c_str());
        return false;
    }

    TwiceNatEntryValue value = m_twiceNatEntries[key];

    m_twiceNatEntries[key].addedToHw = false;

    dbl_nat_entry.vr_id = gVirtualRouterId;
    dbl_nat_entry.switch_id = gSwitchId;
    dbl_nat_entry.nat_type = SAI_NAT_TYPE_DOUBLE_NAT;
    dbl_nat_entry.data.key.src_ip = key.src_ip.getV4Addr();
    dbl_nat_entry.data.mask.src_ip = 0xffffffff;
    dbl_nat_entry.data.key.dst_ip = key.dst_ip.getV4Addr();
    dbl_nat_entry.data.mask.dst_ip = 0xffffffff;


    status = sai_nat_api->remove_nat_entry(&dbl_nat_entry);
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_INFO("Failed to remove Twice NAT entry with src-ip %s, dst-ip %s",
                      key.src_ip.to_string().c_str(), key.dst_ip.to_string().c_str());

        task_process_status handle_status = handleSaiRemoveStatus(SAI_API_NAT, status);
        if (handle_status != task_success)
        {
            return parseHandleSaiStatusFailure(handle_status);
        }
    }
    SWSS_LOG_NOTICE("Removed Twice NAT entry with src-ip %s, dst-ip %s",
                    key.src_ip.to_string().c_str(), key.dst_ip.to_string().c_str());

    deleteTwiceNatCounters(key);

    if (value.entry_type == "static")
    {
        if (totalStaticTwiceNatEntries)
        {
            totalStaticTwiceNatEntries--;
            updateStaticTwiceNatCounters(totalStaticTwiceNatEntries);
        }
    }
    else
    {
        if (totalDynamicTwiceNatEntries)
        {
           totalDynamicTwiceNatEntries--;
           updateDynamicTwiceNatCounters(totalDynamicTwiceNatEntries);
        }
    }

    if (totalSnatEntries)
    {
        totalSnatEntries--;
        updateSnatCounters(totalSnatEntries);
    }

    if (totalDnatEntries)
    {
        totalDnatEntries--;
        updateDnatCounters(totalDnatEntries);
    }

    if (totalEntries >= 2)
    {
        // Each Twice NAT entry is equivalent to 1 SNAT and 1 DNAT entry together
        totalEntries -= 2;
    }

    return true;
}

// Remove the DNAPT entry from the hardware
bool NatOrch::removeHwDnaptEntry(const NaptEntryKey &key)
{
    sai_nat_entry_t dnat_entry = {};
    sai_status_t    status;
    uint8_t         ip_protocol = ((key.prototype == "TCP") ? IPPROTO_TCP : IPPROTO_UDP);

    SWSS_LOG_ENTER();
    SWSS_LOG_INFO("Delete DNAPT entry for proto %s, dest-ip %s, l4-port %d",
                   key.prototype.c_str(), key.ip_address.to_string().c_str(), key.l4_port);

    /* Check the entry is present in cache */
    if (m_naptEntries.find(key) == m_naptEntries.end())
    {
        SWSS_LOG_ERROR("DNAPT entry isn't found for ip %s, l4-port %d", key.ip_address.to_string().c_str(), key.l4_port);

        return false;
    }

    if (m_naptEntries[key].addedToHw == false)
    {
        SWSS_LOG_INFO("DNAPT entry isn't added to hardware, for ip %s, l4-port %d", key.ip_address.to_string().c_str(), key.l4_port);

        return false;
    }

    NaptEntryValue entry = m_naptEntries[key];

    m_naptEntries[key].addedToHw = false;

    dnat_entry.vr_id = gVirtualRouterId;
    dnat_entry.switch_id = gSwitchId;
    dnat_entry.nat_type = SAI_NAT_TYPE_DESTINATION_NAT;
    dnat_entry.data.key.dst_ip = key.ip_address.getV4Addr();
    dnat_entry.data.key.l4_dst_port = (uint16_t)(key.l4_port);
    dnat_entry.data.mask.dst_ip = 0xffffffff;
    dnat_entry.data.mask.l4_dst_port = 0xffff;
    dnat_entry.data.key.proto = ip_protocol;
    dnat_entry.data.mask.proto = 0xff;

    status = sai_nat_api->remove_nat_entry(&dnat_entry);
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_INFO("Failed to remove %s DNAT NAPT entry with ip %s, port %d, prototype %s and it's translated ip %s, translated port %d",
                      entry.entry_type.c_str(), key.ip_address.to_string().c_str(), key.l4_port, key.prototype.c_str(),
                      entry.translated_ip.to_string().c_str(), entry.translated_l4_port);


        task_process_status handle_status = handleSaiRemoveStatus(SAI_API_NAT, status);
        if (handle_status != task_success)
        {
            return parseHandleSaiStatusFailure(handle_status);
        }
    }

    SWSS_LOG_NOTICE("Removed %s DNAT NAPT entry with ip %s, port %d, prototype %s and it's translated ip %s, translated port %d",
                    entry.entry_type.c_str(), key.ip_address.to_string().c_str(), key.l4_port, key.prototype.c_str(),
                    entry.translated_ip.to_string().c_str(), entry.translated_l4_port);

    deleteNaptCounters(key.prototype.c_str(), key.ip_address, key.l4_port);
    gCrmOrch->decCrmResUsedCounter(CrmResourceType::CRM_DNAT_ENTRY);

    if (entry.entry_type == "static")
    {
        if (totalStaticNaptEntries)
        {
            totalStaticNaptEntries--;
            updateStaticNaptCounters(totalStaticNaptEntries);
        }
    }
    else
    {
        if (totalDynamicNaptEntries)
        {
            totalDynamicNaptEntries--;
            updateDynamicNaptCounters(totalDynamicNaptEntries);
        }
    }

    if (totalDnatEntries)
    {
        totalDnatEntries--;
        updateDnatCounters(totalDnatEntries);
    }

    if (totalEntries)
    {
        totalEntries--;
    }

    return true;
}

// Remove the Twice NAPT entry from the hardware
bool NatOrch::removeHwTwiceNaptEntry(const TwiceNaptEntryKey &key)
{
    sai_nat_entry_t dbl_nat_entry = {};
    sai_status_t    status;
    uint8_t         protoType = ((key.prototype == "TCP") ? IPPROTO_TCP : IPPROTO_UDP);

    SWSS_LOG_ENTER();
    SWSS_LOG_INFO("Delete Twice NAPT entry for proto %s, src-ip %s, src port %d, dst-ip %s, dst port %d",
                   key.prototype.c_str(), key.src_ip.to_string().c_str(), key.src_l4_port,
                   key.dst_ip.to_string().c_str(), key.dst_l4_port);

    /* Check the entry is present in cache */
    if (m_twiceNaptEntries.find(key) == m_twiceNaptEntries.end())
    {
        SWSS_LOG_ERROR("Twice DNAPT entry isn't found for proto %s, src-ip %s, src port %d, dst-ip %s, dst port %d",
                       key.prototype.c_str(), key.src_ip.to_string().c_str(), key.src_l4_port, key.dst_ip.to_string().c_str(),
                       key.dst_l4_port);
        return false;
    }

    if (m_twiceNaptEntries[key].addedToHw == false)
    {
        SWSS_LOG_INFO("Twice DNAPT entry isn't added to hardware, for proto %s, src-ip %s, src port %d, dst-ip %s, dst port %d",
                      key.prototype.c_str(), key.src_ip.to_string().c_str(), key.src_l4_port, key.dst_ip.to_string().c_str(),
                      key.dst_l4_port);
        return false;
    }

    TwiceNaptEntryValue value = m_twiceNaptEntries[key];

    m_twiceNaptEntries[key].addedToHw = false;

    dbl_nat_entry.vr_id = gVirtualRouterId;
    dbl_nat_entry.switch_id = gSwitchId;
    dbl_nat_entry.nat_type = SAI_NAT_TYPE_DOUBLE_NAT;
    dbl_nat_entry.data.key.src_ip = key.src_ip.getV4Addr();
    dbl_nat_entry.data.mask.src_ip = 0xffffffff;
    dbl_nat_entry.data.key.l4_src_port = (uint16_t)(key.src_l4_port);
    dbl_nat_entry.data.mask.l4_src_port = 0xffff;
    dbl_nat_entry.data.key.dst_ip = key.dst_ip.getV4Addr();
    dbl_nat_entry.data.mask.dst_ip = 0xffffffff;
    dbl_nat_entry.data.key.l4_dst_port = (uint16_t)(key.dst_l4_port);
    dbl_nat_entry.data.mask.l4_dst_port = 0xffff;
    dbl_nat_entry.data.key.proto = protoType;
    dbl_nat_entry.data.mask.proto = 0xff;

    status = sai_nat_api->remove_nat_entry(&dbl_nat_entry);
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_INFO("Failed to remove Twice NAPT entry with prototype %s, src-ip %s, src port %d, dst-ip %s, dst port %d",
                       key.prototype.c_str(), key.src_ip.to_string().c_str(), key.src_l4_port,
                       key.dst_ip.to_string().c_str(), key.dst_l4_port);
        task_process_status handle_status = handleSaiRemoveStatus(SAI_API_NAT, status);
        if (handle_status != task_success)
        {
            return parseHandleSaiStatusFailure(handle_status);
        }
    }

    SWSS_LOG_NOTICE("Removed Twice NAPT entry with prototype %s, src-ip %s, src port %d, dst-ip %s, dst port %d",
                    key.prototype.c_str(), key.src_ip.to_string().c_str(), key.src_l4_port,
                    key.dst_ip.to_string().c_str(), key.dst_l4_port);

    deleteTwiceNaptCounters(key);
    m_twiceNaptEntries[key].addedToHw = false;

    if (value.entry_type == "static")
    {
        if (totalStaticTwiceNaptEntries)
        {
            totalStaticTwiceNaptEntries--;
            updateStaticTwiceNaptCounters(totalStaticTwiceNaptEntries);
        }
    }
    else
    {
        if (totalDynamicTwiceNaptEntries)
        {
            totalDynamicTwiceNaptEntries--;
            updateDynamicTwiceNaptCounters(totalDynamicTwiceNaptEntries);
        }
    }

    if (totalSnatEntries)
    {
        totalSnatEntries--;
        updateSnatCounters(totalSnatEntries);
    }

    if (totalDnatEntries)
    {
        totalDnatEntries--;
        updateDnatCounters(totalDnatEntries);
    }

    if (totalEntries >= 2)
    {
        // Each Twice NAT entry is equivalent to 1 SNAT and 1 DNAT entry together
        totalEntries -= 2;
    }

    return true;
}

// Add the SNAT entry to the hardware
bool NatOrch::addHwSnatEntry(const IpAddress &ip_address)
{
    uint32_t        attr_count;
    sai_nat_entry_t snat_entry = {};
    sai_attribute_t nat_entry_attr[4] = {};
    sai_status_t    status;
    struct timespec  time_now;

    SWSS_LOG_ENTER();
    SWSS_LOG_INFO("Create SNAT entry for ip %s", ip_address.to_string().c_str());

    if (clock_gettime (CLOCK_MONOTONIC, &time_now) < 0)
    {
        return false;
    }

    NatEntryValue entry = m_natEntries[ip_address];

    nat_entry_attr[0].id = SAI_NAT_ENTRY_ATTR_SRC_IP;
    nat_entry_attr[0].value.u32 = entry.translated_ip.getV4Addr();
    nat_entry_attr[1].id = SAI_NAT_ENTRY_ATTR_SRC_IP_MASK;
    nat_entry_attr[1].value.u32 = 0xffffffff;
    nat_entry_attr[2].id = SAI_NAT_ENTRY_ATTR_ENABLE_PACKET_COUNT;
    nat_entry_attr[2].value.booldata = true;
    nat_entry_attr[3].id = SAI_NAT_ENTRY_ATTR_ENABLE_BYTE_COUNT;
    nat_entry_attr[3].value.booldata = true;

    attr_count = 4;

    snat_entry.vr_id = gVirtualRouterId;
    snat_entry.switch_id = gSwitchId;
    snat_entry.nat_type = SAI_NAT_TYPE_SOURCE_NAT;
    snat_entry.data.key.src_ip = ip_address.getV4Addr();
    snat_entry.data.mask.src_ip = 0xffffffff;

    status = sai_nat_api->create_nat_entry(&snat_entry, attr_count, nat_entry_attr);
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to create %s SNAT NAT entry with ip %s and it's translated ip %s",
                       entry.entry_type.c_str(), ip_address.to_string().c_str(), entry.translated_ip.to_string().c_str());

        task_process_status handle_status = handleSaiCreateStatus(SAI_API_NAT, status);
        if (handle_status != task_success)
        {
            return false;
        }
    }

    SWSS_LOG_NOTICE("Created %s SNAT NAT entry with ip %s and it's translated ip %s",
                    entry.entry_type.c_str(), ip_address.to_string().c_str(), entry.translated_ip.to_string().c_str());

    updateNatCounters(ip_address, 0, 0);
    m_natEntries[ip_address].addedToHw = true;
    m_natEntries[ip_address].activeTime = time_now.tv_sec;
    gCrmOrch->incCrmResUsedCounter(CrmResourceType::CRM_SNAT_ENTRY);

    totalSnatEntries++;
    updateSnatCounters(totalSnatEntries);

    if (entry.entry_type == "static")
    {
        totalStaticNatEntries++;
        updateStaticNatCounters(totalStaticNatEntries);
    }
    else
    {
        totalDynamicNatEntries++;
        updateDynamicNatCounters(totalDynamicNatEntries);
    }
    totalEntries++;

    return true;
}

// Add the Twice NAT entry to the hardware
bool NatOrch::addHwTwiceNatEntry(const TwiceNatEntryKey &key)
{
    uint32_t        attr_count;
    sai_nat_entry_t dbl_nat_entry = {};
    sai_attribute_t nat_entry_attr[6] = {};

    sai_status_t    status;
    struct timespec  time_now;

    SWSS_LOG_ENTER();
    SWSS_LOG_INFO("Create Twice NAT entry for src ip %s, dst ip %s", key.src_ip.to_string().c_str(), key.dst_ip.to_string().c_str());

    if (clock_gettime (CLOCK_MONOTONIC, &time_now) < 0)
    {
        return false;
    }

    TwiceNatEntryValue value = m_twiceNatEntries[key];

    nat_entry_attr[0].id = SAI_NAT_ENTRY_ATTR_SRC_IP;
    nat_entry_attr[0].value.u32 = value.translated_src_ip.getV4Addr();
    nat_entry_attr[1].id = SAI_NAT_ENTRY_ATTR_SRC_IP_MASK;
    nat_entry_attr[1].value.u32 = 0xffffffff;
    nat_entry_attr[2].id = SAI_NAT_ENTRY_ATTR_DST_IP;
    nat_entry_attr[2].value.u32 = value.translated_dst_ip.getV4Addr();
    nat_entry_attr[3].id = SAI_NAT_ENTRY_ATTR_DST_IP_MASK;
    nat_entry_attr[3].value.u32 = 0xffffffff;
    nat_entry_attr[4].id = SAI_NAT_ENTRY_ATTR_ENABLE_PACKET_COUNT;
    nat_entry_attr[4].value.booldata = true;
    nat_entry_attr[5].id = SAI_NAT_ENTRY_ATTR_ENABLE_BYTE_COUNT;
    nat_entry_attr[5].value.booldata = true;

    attr_count = 6;

    dbl_nat_entry.vr_id = gVirtualRouterId;
    dbl_nat_entry.switch_id = gSwitchId;
    dbl_nat_entry.nat_type = SAI_NAT_TYPE_DOUBLE_NAT;
    dbl_nat_entry.data.key.src_ip = key.src_ip.getV4Addr();
    dbl_nat_entry.data.mask.src_ip = 0xffffffff;
    dbl_nat_entry.data.key.dst_ip = key.dst_ip.getV4Addr();
    dbl_nat_entry.data.mask.dst_ip = 0xffffffff;

    status = sai_nat_api->create_nat_entry(&dbl_nat_entry, attr_count, nat_entry_attr);

    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to create %s Twice NAT entry with src ip %s, dst ip %s, translated src ip %s, translated dst ip %s",
                       value.entry_type.c_str(), key.src_ip.to_string().c_str(), key.dst_ip.to_string().c_str(),
                       value.translated_src_ip.to_string().c_str(), value.translated_dst_ip.to_string().c_str());

        task_process_status handle_status = handleSaiCreateStatus(SAI_API_NAT, status);
        if (handle_status != task_success)
        {
            return false;
        }
    }

    SWSS_LOG_NOTICE("Created %s Twice NAT entry with src ip %s, dst ip %s, translated src ip %s, translated dst ip %s",
                    value.entry_type.c_str(), key.src_ip.to_string().c_str(), key.dst_ip.to_string().c_str(),
                    value.translated_src_ip.to_string().c_str(), value.translated_dst_ip.to_string().c_str());

    updateTwiceNatCounters(key, 0, 0);
    m_twiceNatEntries[key].addedToHw = true;
    m_twiceNatEntries[key].activeTime = time_now.tv_sec;

    totalDnatEntries++;
    updateDnatCounters(totalDnatEntries);
    totalEntries++;

    totalSnatEntries++;
    updateSnatCounters(totalSnatEntries);
    totalEntries++;

    if (value.entry_type == "static")
    {
        totalStaticTwiceNatEntries++;
        updateStaticTwiceNatCounters(totalStaticTwiceNatEntries);
    }
    else
    {
        totalDynamicTwiceNatEntries++;
        updateDynamicTwiceNatCounters(totalDynamicTwiceNatEntries);
    }

    return true;
}

// Add the SNAPT entry to the hardware
bool NatOrch::addHwSnaptEntry(const NaptEntryKey &keyEntry)
{
    uint32_t        attr_count;
    sai_nat_entry_t snat_entry = {};
    sai_attribute_t nat_entry_attr[5] = {};
    uint8_t         ip_protocol = ((keyEntry.prototype == "TCP") ? IPPROTO_TCP : IPPROTO_UDP);
    sai_status_t    status;
    struct timespec  time_now;

    SWSS_LOG_ENTER();
    SWSS_LOG_INFO("Create SNAPT entry for proto %s, src-ip %s, l4-port %d",
                   keyEntry.prototype.c_str(), keyEntry.ip_address.to_string().c_str(), keyEntry.l4_port);

    if (clock_gettime (CLOCK_MONOTONIC, &time_now) < 0)
    {
        return false;
    }

    NaptEntryValue entry = m_naptEntries[keyEntry];

    nat_entry_attr[0].id = SAI_NAT_ENTRY_ATTR_SRC_IP;
    nat_entry_attr[0].value.u32 = entry.translated_ip.getV4Addr();
    nat_entry_attr[1].id = SAI_NAT_ENTRY_ATTR_SRC_IP_MASK;
    nat_entry_attr[1].value.u32 = 0xffffffff;
    nat_entry_attr[2].id = SAI_NAT_ENTRY_ATTR_L4_SRC_PORT;
    nat_entry_attr[2].value.u16 = (uint16_t)(entry.translated_l4_port);
    nat_entry_attr[3].id = SAI_NAT_ENTRY_ATTR_ENABLE_PACKET_COUNT;
    nat_entry_attr[3].value.booldata = true;
    nat_entry_attr[4].id = SAI_NAT_ENTRY_ATTR_ENABLE_BYTE_COUNT;
    nat_entry_attr[4].value.booldata = true;

    attr_count = 5;

    snat_entry.vr_id = gVirtualRouterId;
    snat_entry.switch_id = gSwitchId;
    snat_entry.nat_type = SAI_NAT_TYPE_SOURCE_NAT;
    snat_entry.data.key.src_ip = keyEntry.ip_address.getV4Addr();
    snat_entry.data.key.l4_src_port = (uint16_t)(keyEntry.l4_port);
    snat_entry.data.mask.src_ip = 0xffffffff;
    snat_entry.data.mask.l4_src_port = 0xffff;
    snat_entry.data.key.proto = ip_protocol;
    snat_entry.data.mask.proto = 0xff;

    status = sai_nat_api->create_nat_entry(&snat_entry, attr_count, nat_entry_attr);
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to create %s SNAT NAPT entry with ip %s, port %d, prototype %s and it's translated ip %s, translated port %d",
                       entry.entry_type.c_str(), keyEntry.ip_address.to_string().c_str(), keyEntry.l4_port, keyEntry.prototype.c_str(),
                       entry.translated_ip.to_string().c_str(), entry.translated_l4_port);

        task_process_status handle_status = handleSaiCreateStatus(SAI_API_NAT, status);
        if (handle_status != task_success)
        {
            return false;
        }
     }

     SWSS_LOG_NOTICE("Created %s SNAT NAPT entry with ip %s, port %d, prototype %s and it's translated ip %s, translated port %d",
                     entry.entry_type.c_str(), keyEntry.ip_address.to_string().c_str(), keyEntry.l4_port, keyEntry.prototype.c_str(),
                     entry.translated_ip.to_string().c_str(), entry.translated_l4_port);

     m_naptEntries[keyEntry].addedToHw = true;
     m_naptEntries[keyEntry].activeTime = time_now.tv_sec;

     totalSnatEntries++;
     updateSnatCounters(totalSnatEntries);

     updateNaptCounters(keyEntry.prototype.c_str(), keyEntry.ip_address, keyEntry.l4_port, 0, 0);
     gCrmOrch->incCrmResUsedCounter(CrmResourceType::CRM_SNAT_ENTRY);

     if (entry.entry_type == "static")
     {
         totalStaticNaptEntries++;
         updateStaticNaptCounters(totalStaticNaptEntries);
     }
     else
     {
         totalDynamicNaptEntries++;
         updateDynamicNaptCounters(totalDynamicNaptEntries);
     }
     totalEntries++;

    return true;
}

// Add the Twice NAPT entry to the hardware
bool NatOrch::addHwTwiceNaptEntry(const TwiceNaptEntryKey &key)
{
    uint32_t        attr_count;
    sai_nat_entry_t dbl_nat_entry = {};
    sai_attribute_t nat_entry_attr[8] = {};
    uint8_t         protoType = ((key.prototype == "TCP") ? IPPROTO_TCP : IPPROTO_UDP);
    sai_status_t    status;
    struct timespec  time_now;

    SWSS_LOG_ENTER();
    SWSS_LOG_INFO("Create Twice SNAPT entry for proto %s, src-ip %s, src port %d, dst-ip %s, dst port %d",
                   key.prototype.c_str(), key.src_ip.to_string().c_str(), key.src_l4_port,
                   key.dst_ip.to_string().c_str(), key.dst_l4_port);

    if (clock_gettime (CLOCK_MONOTONIC, &time_now) < 0)
    {
        return false;
    }

    TwiceNaptEntryValue value = m_twiceNaptEntries[key];

    nat_entry_attr[0].id = SAI_NAT_ENTRY_ATTR_SRC_IP;
    nat_entry_attr[0].value.u32 = value.translated_src_ip.getV4Addr();
    nat_entry_attr[1].id = SAI_NAT_ENTRY_ATTR_SRC_IP_MASK;
    nat_entry_attr[1].value.u32 = 0xffffffff;
    nat_entry_attr[2].id = SAI_NAT_ENTRY_ATTR_L4_SRC_PORT;
    nat_entry_attr[2].value.u16 = (uint16_t)(value.translated_src_l4_port);
    nat_entry_attr[3].id = SAI_NAT_ENTRY_ATTR_DST_IP;
    nat_entry_attr[3].value.u32 = value.translated_dst_ip.getV4Addr();
    nat_entry_attr[4].id = SAI_NAT_ENTRY_ATTR_DST_IP_MASK;
    nat_entry_attr[4].value.u32 = 0xffffffff;
    nat_entry_attr[5].id = SAI_NAT_ENTRY_ATTR_L4_DST_PORT;
    nat_entry_attr[5].value.u16 = (uint16_t)(value.translated_dst_l4_port);
    nat_entry_attr[6].id = SAI_NAT_ENTRY_ATTR_ENABLE_PACKET_COUNT;
    nat_entry_attr[6].value.booldata = true;
    nat_entry_attr[7].id = SAI_NAT_ENTRY_ATTR_ENABLE_BYTE_COUNT;
    nat_entry_attr[7].value.booldata = true;

    attr_count = 8;

    dbl_nat_entry.vr_id = gVirtualRouterId;
    dbl_nat_entry.switch_id = gSwitchId;
    dbl_nat_entry.nat_type = SAI_NAT_TYPE_DOUBLE_NAT;
    dbl_nat_entry.data.key.src_ip = key.src_ip.getV4Addr();
    dbl_nat_entry.data.mask.src_ip = 0xffffffff;
    dbl_nat_entry.data.key.l4_src_port = (uint16_t)(key.src_l4_port);
    dbl_nat_entry.data.mask.l4_src_port = 0xffff;
    dbl_nat_entry.data.key.dst_ip = key.dst_ip.getV4Addr();
    dbl_nat_entry.data.mask.dst_ip = 0xffffffff;
    dbl_nat_entry.data.key.l4_dst_port = (uint16_t)(key.dst_l4_port);
    dbl_nat_entry.data.mask.l4_dst_port = 0xffff;
    dbl_nat_entry.data.key.proto = protoType;
    dbl_nat_entry.data.mask.proto = 0xff;

    status = sai_nat_api->create_nat_entry(&dbl_nat_entry, attr_count, nat_entry_attr);
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to create %s Twice NAPT entry with src ip %s, src port %d, dst ip %s dst port %d, prototype %s and \
                       it's translated src ip %s, translated src port %d, translated dst ip %s, translated dst port %d ",
                       value.entry_type.c_str(), key.src_ip.to_string().c_str(), key.src_l4_port, key.dst_ip.to_string().c_str(),
                       key.dst_l4_port, key.prototype.c_str(), value.translated_src_ip.to_string().c_str(), value.translated_src_l4_port,
                       value.translated_dst_ip.to_string().c_str(), value.translated_dst_l4_port);

        task_process_status handle_status = handleSaiCreateStatus(SAI_API_NAT, status);
        if (handle_status != task_success)
        {
            return false;
        }
     }


     SWSS_LOG_NOTICE("Created %s Twice NAPT entry with src ip %s, src port %d, dst ip %s dst port %d, prototype %s and \
                     it's translated src ip %s, translated src port %d, translated dst ip %s, translated dst port %d ",
                     value.entry_type.c_str(), key.src_ip.to_string().c_str(), key.src_l4_port, key.dst_ip.to_string().c_str(),
                     key.dst_l4_port, key.prototype.c_str(), value.translated_src_ip.to_string().c_str(), value.translated_src_l4_port,
                     value.translated_dst_ip.to_string().c_str(), value.translated_dst_l4_port);

     updateTwiceNaptCounters(key, 0, 0);
     m_twiceNaptEntries[key].addedToHw = true;
     m_twiceNaptEntries[key].activeTime = time_now.tv_sec;

     totalDnatEntries++;
     updateDnatCounters(totalDnatEntries);
     totalEntries++;

     totalSnatEntries++;
     updateSnatCounters(totalSnatEntries);
     totalEntries++;

     if (value.entry_type == "static")
     {
         totalStaticTwiceNaptEntries++;
         updateStaticTwiceNaptCounters(totalStaticTwiceNaptEntries);
     }
     else
     {
         totalDynamicTwiceNaptEntries++;
         updateDynamicTwiceNaptCounters(totalDynamicTwiceNaptEntries);
     }

    return true;
}

// Remove the SNAT entry from the hardware
bool NatOrch::removeHwSnatEntry(const IpAddress &ip_address)
{
    sai_nat_entry_t snat_entry = {};
    sai_status_t    status;

    SWSS_LOG_ENTER();
    SWSS_LOG_INFO("Deleting SNAT entry ip %s from hardware", ip_address.to_string().c_str());

    NatEntryValue& entry = m_natEntries[ip_address];

    if (entry.addedToHw == false)
    {
        SWSS_LOG_INFO("SNAT entry isn't added to h/w, for ip %s", ip_address.to_string().c_str());
        return true;
    }

    snat_entry.vr_id = gVirtualRouterId;
    snat_entry.switch_id = gSwitchId;
    snat_entry.nat_type = SAI_NAT_TYPE_SOURCE_NAT;
    snat_entry.data.key.src_ip = ip_address.getV4Addr();
    snat_entry.data.mask.src_ip = 0xffffffff;

    status = sai_nat_api->remove_nat_entry(&snat_entry);
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_INFO("Failed to removed %s SNAT NAT entry with ip %s and it's translated ip %s",
                      entry.entry_type.c_str(), ip_address.to_string().c_str(), entry.translated_ip.to_string().c_str());
    }
    else
    {
        SWSS_LOG_NOTICE("Removed %s SNAT NAT entry with ip %s and it's translated ip %s",
                        entry.entry_type.c_str(), ip_address.to_string().c_str(), entry.translated_ip.to_string().c_str());
    }
    deleteNatCounters(ip_address);

    entry.addedToHw = false;

    gCrmOrch->decCrmResUsedCounter(CrmResourceType::CRM_SNAT_ENTRY);

    if (entry.entry_type == "static")
    {
        if (totalStaticNatEntries)
        {
            totalStaticNatEntries--;
            updateStaticNatCounters(totalStaticNatEntries);
        }
    }
    else
    {
        if (totalDynamicNatEntries)
        {
            totalDynamicNatEntries--;
            updateDynamicNatCounters(totalDynamicNatEntries);
        }
        else
        {
            SWSS_LOG_ERROR("Found the total number dynamic nat entries to be corrupt, when removing SNAT entry with ip %s, translated ip %s!!",
                            ip_address.to_string().c_str(), entry.translated_ip.to_string().c_str());
        }
    }

    if (totalSnatEntries)
    {
        totalSnatEntries--;
        updateSnatCounters(totalSnatEntries);
    }
    else
    {
        SWSS_LOG_ERROR("Found the total number dynamic snat entries to be corrupt, when removing SNAT entry with ip %s, translated ip %s!!",
                       ip_address.to_string().c_str(), entry.translated_ip.to_string().c_str());
    }

    if (totalEntries)
    {
        totalEntries--;
    }

    return true;
}

// Remove the SNAPT entry from the hardware
bool NatOrch::removeHwSnaptEntry(const NaptEntryKey &keyEntry)
{
    sai_nat_entry_t snat_entry = {};
    sai_status_t    status;
    uint8_t         ip_protocol = ((keyEntry.prototype == "TCP") ? IPPROTO_TCP : IPPROTO_UDP);

    SWSS_LOG_ENTER();
    SWSS_LOG_INFO("Delete SNAPT entry for proto %s, src-ip %s, l4-port %d",
                   keyEntry.prototype.c_str(), keyEntry.ip_address.to_string().c_str(), keyEntry.l4_port);

    /* Check the entry is present in cache */
    auto nat_it = m_naptEntries.find(keyEntry);
    if (nat_it == m_naptEntries.end())
    {
        SWSS_LOG_ERROR("SNAPT entry isn't found for ip %s, l4-port %d", keyEntry.ip_address.to_string().c_str(), keyEntry.l4_port);

        return false;
    }

    if (nat_it->second.addedToHw == false)
    {
        SWSS_LOG_INFO("SNAPT entry isn't added to h/w for ip %s, l4-port %d", keyEntry.ip_address.to_string().c_str(), keyEntry.l4_port);
        return false;
    }

    NaptEntryValue entry = m_naptEntries[keyEntry];

    snat_entry.vr_id = gVirtualRouterId;
    snat_entry.switch_id = gSwitchId;
    snat_entry.nat_type = SAI_NAT_TYPE_SOURCE_NAT;
    snat_entry.data.key.src_ip = keyEntry.ip_address.getV4Addr();
    snat_entry.data.key.l4_src_port = (uint16_t)(keyEntry.l4_port);
    snat_entry.data.mask.src_ip = 0xffffffff;
    snat_entry.data.mask.l4_src_port = 0xffff;
    snat_entry.data.key.proto = ip_protocol;
    snat_entry.data.mask.proto = 0xff;

    status = sai_nat_api->remove_nat_entry(&snat_entry);
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_INFO("Failed to removed %s SNAT NAPT entry with ip %s, port %d, prototype %s and it's translated ip %s, translated port %d",
                      entry.entry_type.c_str(), keyEntry.ip_address.to_string().c_str(), keyEntry.l4_port, keyEntry.prototype.c_str(),
                      entry.translated_ip.to_string().c_str(), entry.translated_l4_port);
    }
    else
    {
        SWSS_LOG_NOTICE("Removed %s SNAT NAPT entry with ip %s, port %d, prototype %s and it's translated ip %s, translated port %d",
                      entry.entry_type.c_str(), keyEntry.ip_address.to_string().c_str(), keyEntry.l4_port, keyEntry.prototype.c_str(),
                      entry.translated_ip.to_string().c_str(), entry.translated_l4_port);
    }
    deleteNaptCounters(keyEntry.prototype.c_str(), keyEntry.ip_address, keyEntry.l4_port);
    m_naptEntries[keyEntry].addedToHw = false;

    gCrmOrch->decCrmResUsedCounter(CrmResourceType::CRM_SNAT_ENTRY);

    if (entry.entry_type == "static")
    {
        if (totalStaticNaptEntries)
        {
            totalStaticNaptEntries--;
            updateStaticNaptCounters(totalStaticNaptEntries);
        }
    }
    else
    {
        if (totalDynamicNaptEntries)
        {
            totalDynamicNaptEntries--;
            updateDynamicNaptCounters(totalDynamicNaptEntries);
        }
        else
        {
            SWSS_LOG_ERROR("Found the total number dynamic napt entries to be corrupt, when removing SNAPT entry with proto %s, ip %s, port %d, translated ip %s, translated port %d!!",
                            keyEntry.prototype.c_str(), keyEntry.ip_address.to_string().c_str(), keyEntry.l4_port,
                            entry.translated_ip.to_string().c_str(), entry.translated_l4_port);
        }
    }

    if (totalSnatEntries)
    {
        totalSnatEntries--;
        updateSnatCounters(totalSnatEntries);
    }
    else
    {
        SWSS_LOG_ERROR("Found the total number dynamic snat entries to be corrupt, when removing SNAPT entry with proto %s, ip %s, port %d, translated ip %s, translated port %d!!",
                       keyEntry.prototype.c_str(), keyEntry.ip_address.to_string().c_str(), keyEntry.l4_port,
                       entry.translated_ip.to_string().c_str(), entry.translated_l4_port);
    }

    if (totalEntries)
        totalEntries--;

    return true;
}

// Add the DNAT Pool entry to the hardware
bool NatOrch::addHwDnatPoolEntry(const IpAddress &ip_address)
{
    uint32_t        attr_count;
    sai_nat_entry_t dnat_pool_entry = {};
    sai_attribute_t nat_entry_attr[1] = {};
    sai_status_t    status;

    SWSS_LOG_ENTER();

    if (!isNatEnabled())
    {
        SWSS_LOG_WARN("NAT Feature is not yet enabled, skipped adding DNAT Pool entry with ip %s", ip_address.to_string().c_str());
        return true;
    }

    SWSS_LOG_INFO("Create DNAT Pool entry for ip %s", ip_address.to_string().c_str());

    attr_count = 0;

    dnat_pool_entry.vr_id = gVirtualRouterId;
    dnat_pool_entry.switch_id = gSwitchId;
    dnat_pool_entry.nat_type = SAI_NAT_TYPE_DESTINATION_NAT_POOL;
    dnat_pool_entry.data.key.dst_ip = ip_address.getV4Addr();
    dnat_pool_entry.data.mask.dst_ip = 0xffffffff;

    status = sai_nat_api->create_nat_entry(&dnat_pool_entry, attr_count, nat_entry_attr);
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to create DNAT Pool entry with ip %s", ip_address.to_string().c_str());

        task_process_status handle_status = handleSaiCreateStatus(SAI_API_NAT, status);
        if (handle_status != task_success)
        {
            return false;
        }
    }

    SWSS_LOG_NOTICE("Created DNAT Pool entry with ip %s", ip_address.to_string().c_str());

    return true;
}

// Remove the DNAT Pool entry from the hardware
bool NatOrch::removeHwDnatPoolEntry(const IpAddress &dstIp)
{
    sai_nat_entry_t dnat_pool_entry = {};
    sai_status_t    status;

    SWSS_LOG_ENTER();
    SWSS_LOG_INFO("Deleting DNAT Pool entry ip %s from hardware", dstIp.to_string().c_str());

    dnat_pool_entry.vr_id = gVirtualRouterId;
    dnat_pool_entry.switch_id = gSwitchId;
    dnat_pool_entry.nat_type = SAI_NAT_TYPE_DESTINATION_NAT_POOL;
    dnat_pool_entry.data.key.dst_ip = dstIp.getV4Addr();
    dnat_pool_entry.data.mask.dst_ip = 0xffffffff;

    status = sai_nat_api->remove_nat_entry(&dnat_pool_entry);
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_INFO("Failed to remove DNAT Pool entry with ip %s", dstIp.to_string().c_str());

        task_process_status handle_status = handleSaiRemoveStatus(SAI_API_NAT, status);
        if (handle_status != task_success)
        {
            return parseHandleSaiStatusFailure(handle_status);
        }
    }

    SWSS_LOG_NOTICE("Removed DNAT Pool entry with ip %s", dstIp.to_string().c_str());

    return true;
}

void NatOrch::addAllDnatPoolEntries()
{
    SWSS_LOG_ENTER();

    DnatPoolEntry::iterator dnatPoolIter = m_dnatPoolEntries.begin();
    while (dnatPoolIter != m_dnatPoolEntries.end())
    {
        addHwDnatPoolEntry((*dnatPoolIter));
        dnatPoolIter++;
    }
}

bool NatOrch::addPendingStaticEntry()
{
    NatEntry::iterator natIter = m_natEntries.begin();
    while (natIter != m_natEntries.end())
    {
        auto& nat_key = natIter->first;
        auto& nat_entry = natIter->second;
        if (totalSnatEntries == maxAllowedSNatEntries)
        {
            break;
        }

        if (nat_entry.nat_type != "snat" || nat_entry.addedToHw == true)
        {
            natIter++;
            continue;
        }

        auto pair_nat_it = m_natEntries.find(nat_entry.translated_ip);
        if (pair_nat_it == m_natEntries.end())
        {
            natIter++;
            continue;
        }

        const auto& snat_ip = nat_key;
        const auto& dnat_ip = pair_nat_it->first;
        const NatEntryValue& dnat = pair_nat_it->second;
        bool rv = false;

        if (gNhTrackingSupported == true)
        {
            if (!isNhCacheResolved(dnat.translated_ip))
            {
                natIter++;
                continue;
            }
        }

        rv = addHwSnatEntry(snat_ip);
        if (!rv)
        {
            return false;
        }

        /* Add DNAT entry to the hardware */
        rv = addHwDnatEntry(dnat_ip);
        if (!rv)
        {
            removeHwSnatEntry(snat_ip);
            return false;
        }

        natIter++;
    }

    NaptEntry::iterator naptIter = m_naptEntries.begin();
    while (naptIter != m_naptEntries.end())
    {
        auto& napt_key = naptIter->first;
        auto& napt_entry = naptIter->second;

        if (totalSnatEntries == maxAllowedSNatEntries)
        {
            break;
        }

        if (napt_entry.nat_type != "snat" || napt_entry.addedToHw == true)
        {
            naptIter++;
            continue;
        }

        NaptEntryKey dnapt_key{ napt_entry.translated_ip, napt_entry.translated_l4_port, napt_key.prototype };

        auto pair_nat_it = m_naptEntries.find(dnapt_key);
        if (pair_nat_it == m_naptEntries.end())
        {
            naptIter++;
            continue;
        }

        const auto& snapt_key = napt_key;;
        const NaptEntryValue& dnapt = pair_nat_it->second;
        bool rv = false;

        if (gNhTrackingSupported == true)
        {
            if (!isNhCacheResolved(dnapt.translated_ip))
            {
                naptIter++;
                continue;
            }
        }

        rv = addHwSnaptEntry(snapt_key);
        if (!rv)
        {
            return false;
        }

        /* Add DNAT entry to the hardware */
        rv = addHwDnaptEntry(dnapt_key);
        if (!rv)
        {
            removeHwSnaptEntry(snapt_key);
            return false;
        }

        naptIter++;
    }

    TwiceNatEntry::iterator twiceNatIter = m_twiceNatEntries.begin();
    while (twiceNatIter != m_twiceNatEntries.end())
    {
        auto& twice_nat_key = twiceNatIter->first;
        auto& twice_nat_entry = twiceNatIter->second;

        if ((totalSnatEntries + 2) >= maxAllowedSNatEntries)
        {
            break;
        }

        if (twice_nat_entry.addedToHw == true)
        {
            twiceNatIter++;
            continue;
        }

        TwiceNatEntryKey pair_key{ twice_nat_entry.translated_dst_ip, twice_nat_entry.translated_src_ip };

        auto pair_nat_it = m_twiceNatEntries.find(pair_key);
        if (pair_nat_it == m_twiceNatEntries.end())
        {
            twiceNatIter++;
            continue;
        }

        const auto& pair_entry = pair_nat_it->second;;
        bool rv = false;

        if (gNhTrackingSupported == true)
        {
            if (!isNhCacheResolved(twice_nat_entry.translated_dst_ip) ||
                !isNhCacheResolved(pair_entry.translated_dst_ip))
            {
                twiceNatIter++;
                continue;
            }
        }

        rv = addHwTwiceNatEntry(twice_nat_key);
        if (!rv)
        {
            return false;
        }

        rv = addHwTwiceNatEntry(pair_key);
        if (!rv)
        {
            removeHwTwiceNatEntry(twice_nat_key);
            return false;
        }

        twiceNatIter++;
    }

    TwiceNaptEntry::iterator twiceNaptIter = m_twiceNaptEntries.begin();
    while (twiceNaptIter != m_twiceNaptEntries.end())
    {
        auto& twice_napt_key = twiceNaptIter->first;
        auto& twice_napt_entry = twiceNaptIter->second;

        if ((totalSnatEntries + 2) >= maxAllowedSNatEntries)
        {
            break;
        }

        if (twice_napt_entry.addedToHw == true)
        {
            twiceNaptIter++;
            continue;
        }

        TwiceNaptEntryKey pair_key{ twice_napt_entry.translated_dst_ip, twice_napt_entry.translated_dst_l4_port,
                                    twice_napt_entry.translated_src_ip, twice_napt_entry.translated_src_l4_port,
                                    twice_napt_key.prototype };

        auto pair_nat_it = m_twiceNaptEntries.find(pair_key);
        if (pair_nat_it == m_twiceNaptEntries.end())
        {
            twiceNaptIter++;
            continue;
        }

        const auto& pair_entry = pair_nat_it->second;;
        bool rv = false;

        if (gNhTrackingSupported == true)
        {
            if (!isNhCacheResolved(twice_napt_entry.translated_dst_ip) ||
                !isNhCacheResolved(pair_entry.translated_dst_ip))
            {
                twiceNaptIter++;
                continue;
            }
        }

        rv = addHwTwiceNaptEntry(twice_napt_key);
        if (!rv)
        {
            return false;
        }

        rv = addHwTwiceNaptEntry(pair_key);
        if (!rv)
        {
            removeHwTwiceNaptEntry(twice_napt_key);
            return false;
        }

        twiceNaptIter++;
    }

    return true;
}

bool NatOrch::addNatEntry(const IpAddress &ip_address, const NatEntryValue &entry)
{
    SWSS_LOG_ENTER();

    /* Check the entry is present in cache */
    if (m_natEntries.find(ip_address) != m_natEntries.end())
    {
        SWSS_LOG_INFO("Duplicate %s %s NAT entry with ip %s and it's translated ip %s, do nothing",
                      entry.entry_type.c_str(), entry.nat_type.c_str(), ip_address.to_string().c_str(),
                      entry.translated_ip.to_string().c_str());
        return true;
    }

    if (entry.entry_type == "dynamic")
    {
       if (totalSnatEntries == maxAllowedSNatEntries)
       {
            const auto& snat_ip = (entry.nat_type == "snat") ? ip_address : entry.translated_ip;
            const auto& translated_ip = (entry.nat_type == "snat") ? entry.translated_ip : ip_address;

            SWSS_LOG_INFO("Reached the max allowed NAT entries in the hardware, dropping new SNAT translation with ip %s and translated ip %s",
                          snat_ip.to_string().c_str(), translated_ip.to_string().c_str());
            std::vector<FieldValueTuple> fvVector;
            std::string natKey = snat_ip.to_string();
            setTimeoutNotifier->send("AGEOUT-SINGLE-NAT", natKey, fvVector);
            return true;
        }
    }

    m_natEntries[ip_address] = entry;
    m_natEntries[ip_address].addedToHw = false;

    NatEntryValue pair_entry;
    {
        pair_entry.nat_type = (entry.nat_type == "snat") ? "dnat" : "snat";
        pair_entry.entry_type = entry.entry_type;
        pair_entry.translated_ip = ip_address;

        m_natEntries[entry.translated_ip] = pair_entry;
        m_natEntries[entry.translated_ip].addedToHw = false;
    }

    if (!isNatEnabled())
    {
        SWSS_LOG_WARN("NAT Feature is not yet enabled, skipped adding %s %s NAT entry with ip %s and it's translated ip %s",
                      entry.entry_type.c_str(), entry.nat_type.c_str(), ip_address.to_string().c_str(),
                      entry.translated_ip.to_string().c_str());

        return true;
    }

    const auto& snat_ip = (entry.nat_type == "snat") ? ip_address : entry.translated_ip;
    const auto& dnat_ip = (entry.nat_type == "snat") ? entry.translated_ip : ip_address;
    const auto& dnat = (entry.nat_type == "snat") ? pair_entry : entry;
    bool rv = false;

    if (gNhTrackingSupported == true)
    {
        /* Cache the DNAT entry in the nexthop resolution cache */
        addDnatToNhCache(dnat.translated_ip, dnat_ip);

        if (!isNhCacheResolved(dnat.translated_ip))
        {
            return true;
        }
    }

    rv = addHwSnatEntry(snat_ip);
    if (!rv)
    {
        if (dnat.entry_type == "dynamic")
        {
            std::vector<FieldValueTuple> fvVector;
            std::string natKey = dnat.translated_ip.to_string();
            setTimeoutNotifier->send("AGEOUT-SINGLE-NAT", natKey, fvVector);
        }

        return true;
    }

    /* Add DNAT entry to the hardware */
    rv = addHwDnatEntry(dnat_ip);
    if (!rv)
    {
        removeHwSnatEntry(snat_ip);

        if (dnat.entry_type == "dynamic")
        {
            std::vector<FieldValueTuple> fvVector;
            std::string natKey = dnat.translated_ip.to_string();
            setTimeoutNotifier->send("AGEOUT-SINGLE-NAT", natKey, fvVector);
        }

        return true; // no need retry
    }

    return true;
}

bool NatOrch::removeNatEntry(const IpAddress &ip_address)
{
    SWSS_LOG_ENTER();

    /* Check the entry is present in cache */
    if (m_natEntries.find(ip_address) == m_natEntries.end())
    {
        SWSS_LOG_INFO("NAT entry isn't found for ip %s", ip_address.to_string().c_str());

        return true;
    }

    const NatEntryValue entry = m_natEntries[ip_address];
    const NatEntryValue pair_entry = m_natEntries[entry.translated_ip];

    const auto &snat_ip = (entry.nat_type == "snat") ? ip_address : entry.translated_ip;
    const auto &dnat_ip = (entry.nat_type == "snat") ? entry.translated_ip : ip_address;
    const NatEntryValue &dnat = (entry.nat_type == "snat") ? pair_entry : entry;

    if (gNhTrackingSupported == true)
    {
        removeDnatFromNhCache(dnat.translated_ip, dnat_ip);
    }

    removeHwDnatEntry(dnat_ip);
    m_natEntries.erase(dnat_ip);

    removeHwSnatEntry(snat_ip);
    m_natEntries.erase(snat_ip);

    addPendingStaticEntry();

    return true;
}

bool NatOrch::addTwiceNatEntry(const TwiceNatEntryKey &key, const TwiceNatEntryValue &value)
{
    SWSS_LOG_ENTER();

    /* Check the entry is present in cache */
    if (m_twiceNatEntries.find(key) != m_twiceNatEntries.end())
    {
        SWSS_LOG_INFO("Duplicate %s Twice NAT entry with src ip %s, dst ip %s and it's translated src ip %s, dst ip %s, do nothing",
                      value.entry_type.c_str(), key.src_ip.to_string().c_str(), key.dst_ip.to_string().c_str(),
                      value.translated_src_ip.to_string().c_str(), value.translated_dst_ip.to_string().c_str());
        return true;
    }

    TwiceNatEntryKey pair_key = { value.translated_dst_ip, value.translated_src_ip };
    TwiceNatEntryValue pair_entry;

    if (value.entry_type == "dynamic")
    {
       if ((totalSnatEntries + 2)  >= maxAllowedSNatEntries)
       {
            SWSS_LOG_INFO("Reached the max allowed NAT entries in the hardware, dropping new Twice NAT translation with src ip %s, dst ip %s and translated src ip %s, dst ip %s",
                           key.src_ip.to_string().c_str(), key.dst_ip.to_string().c_str(), value.translated_src_ip.to_string().c_str(), value.translated_dst_ip.to_string().c_str());
            std::vector<FieldValueTuple> fvVector;
            std::string twiceNatKey = (key.src_ip.to_string() + ":" + key.dst_ip.to_string());
            setTimeoutNotifier->send("AGEOUT-TWICE-NAT", twiceNatKey, fvVector);

            std::string pairTwiceNatKey = (pair_key.src_ip.to_string() + ":" + pair_key.dst_ip.to_string());
            setTimeoutNotifier->send("AGEOUT-TWICE-NAT", pairTwiceNatKey, fvVector);

            return true;
        }
    }

    m_twiceNatEntries[key]           = value;
    m_twiceNatEntries[key].addedToHw = false;

    // Add pair entry
    {
        pair_entry.entry_type = value.entry_type;
        pair_entry.translated_src_ip = key.dst_ip;
        pair_entry.translated_dst_ip = key.src_ip;

        m_twiceNatEntries[pair_key] = pair_entry;
        m_twiceNatEntries[pair_key].addedToHw = false;
    }

    if (!isNatEnabled())
    {
        SWSS_LOG_WARN("NAT Feature is not yet enabled, skipped adding %s Twice NAT entry with src ip %s, dst ip %s and it's translated src ip %s, dst ip %s",
                      value.entry_type.c_str(), key.src_ip.to_string().c_str(), key.dst_ip.to_string().c_str(),
                      value.translated_src_ip.to_string().c_str(), value.translated_dst_ip.to_string().c_str());
        return true;
    }

    if (gNhTrackingSupported == true)
    {
        addTwiceNatToNhCache(value.translated_dst_ip, key);
        addTwiceNatToNhCache(pair_entry.translated_dst_ip, pair_key);

        if (!isNhCacheResolved(value.translated_dst_ip) || !isNhCacheResolved(pair_entry.translated_dst_ip))
        {
            return true;
        }
    }

    auto rv = addHwTwiceNatEntry(key);
    if (!rv)
    {
        if (value.entry_type == "dynamic")
        {
            SWSS_LOG_INFO("Reached the max allowed NAT entries in the hardware, dropping new Twice NAT translation with src ip %s, dst ip %s and translated src ip %s, dst ip %s",
                            key.src_ip.to_string().c_str(), key.dst_ip.to_string().c_str(), value.translated_src_ip.to_string().c_str(), value.translated_dst_ip.to_string().c_str());
            std::vector<FieldValueTuple> fvVector;
            std::string twiceNatKey = (key.src_ip.to_string() + ":" + key.dst_ip.to_string());
            setTimeoutNotifier->send("AGEOUT-TWICE-NAT", twiceNatKey, fvVector);

            std::string pairTwiceNatKey = (pair_key.src_ip.to_string() + ":" + pair_key.dst_ip.to_string());
            setTimeoutNotifier->send("AGEOUT-TWICE-NAT", pairTwiceNatKey, fvVector);
        }

        return true;
    }

    rv = addHwTwiceNatEntry(pair_key);
    if (!rv)
    {
        removeHwTwiceNatEntry(key);

        if (value.entry_type == "dynamic")
        {
            SWSS_LOG_INFO("Reached the max allowed NAT entries in the hardware, dropping new Twice NAT translation with src ip %s, dst ip %s and translated src ip %s, dst ip %s",
                          key.src_ip.to_string().c_str(), key.dst_ip.to_string().c_str(), value.translated_src_ip.to_string().c_str(), value.translated_dst_ip.to_string().c_str());
            std::vector<FieldValueTuple> fvVector;
            std::string twiceNatKey = (key.src_ip.to_string() + ":" + key.dst_ip.to_string());
            setTimeoutNotifier->send("AGEOUT-TWICE-NAT", twiceNatKey, fvVector);

            std::string pairTwiceNatKey = (pair_key.src_ip.to_string() + ":" + pair_key.dst_ip.to_string());
            setTimeoutNotifier->send("AGEOUT-TWICE-NAT", pairTwiceNatKey, fvVector);
        }

        return true;
    }

    return true;
}

bool NatOrch::removeTwiceNatEntry(const TwiceNatEntryKey &key)
{
    SWSS_LOG_ENTER();

    /* Check the entry is present in cache */
    if (m_twiceNatEntries.find(key) == m_twiceNatEntries.end())
    {
        SWSS_LOG_INFO("Twice NAT entry isn't found for src ip %s, dst ip %s", key.src_ip.to_string().c_str(), key.dst_ip.to_string().c_str());

        return true;
    }

    const TwiceNatEntryValue value = m_twiceNatEntries[key];
    TwiceNatEntryKey pair_key = { value.translated_dst_ip, value.translated_src_ip };
    const TwiceNatEntryValue pair_value = m_twiceNatEntries[pair_key];

    if (gNhTrackingSupported == true)
    {
        removeTwiceNatFromNhCache(value.translated_dst_ip, key);
        removeTwiceNatFromNhCache(pair_value.translated_dst_ip, pair_key);
    }

    removeHwTwiceNatEntry(key);
    m_twiceNatEntries.erase(key);

    removeHwTwiceNatEntry(pair_key);
    m_twiceNatEntries.erase(pair_key);

    addPendingStaticEntry();

    return true;
}

bool NatOrch::addNaptEntry(const NaptEntryKey &keyEntry, const NaptEntryValue &entry)
{
    SWSS_LOG_ENTER();

    NaptEntryKey pair_key { entry.translated_ip , entry.translated_l4_port, keyEntry.prototype };
    NaptEntryValue pair_entry;

    /* Check the entry is present in cache */
    if (m_naptEntries.find(keyEntry) != m_naptEntries.end())
    {
        NaptEntryValue oldEntry = m_naptEntries[keyEntry];

        /* Entry is exist*/
        if ((entry.translated_l4_port != oldEntry.translated_l4_port) or
            (entry.translated_ip.to_string() != oldEntry.translated_ip.to_string()) or
            (entry.nat_type != oldEntry.nat_type))
        {
            SWSS_LOG_INFO("%s %s NAPT entry already exists with ip %s, port %d, prototype %s and it's translated ip %s, translated port %d",
                          oldEntry.entry_type.c_str(), oldEntry.nat_type.c_str(), keyEntry.ip_address.to_string().c_str(), keyEntry.l4_port,
                          keyEntry.prototype.c_str(), oldEntry.translated_ip.to_string().c_str(), oldEntry.translated_l4_port);

            /* Removed the NAPT entry */
            SWSS_LOG_INFO("Removing %s %s NAPT entry with ip %s, port %d, prototype %s and it's translated ip %s, translated port %d",
                          oldEntry.entry_type.c_str(), oldEntry.nat_type.c_str(), keyEntry.ip_address.to_string().c_str(), keyEntry.l4_port,
                          keyEntry.prototype.c_str(), oldEntry.translated_ip.to_string().c_str(), oldEntry.translated_l4_port);

            removeNaptEntry(keyEntry);
        }
        else if (entry.entry_type != oldEntry.entry_type)
        {
            if (entry.entry_type == "static")
            {
                SWSS_LOG_INFO("%s %s NAPT entry already exists with ip %s, port %d, prototype %s and it's translated ip %s, translated port %d, is moved to %s NAPT",
                              oldEntry.entry_type.c_str(), entry.nat_type.c_str(), keyEntry.ip_address.to_string().c_str(), keyEntry.l4_port,
                              keyEntry.prototype.c_str(), entry.translated_ip.to_string().c_str(), entry.translated_l4_port, entry.entry_type.c_str());

                m_naptEntries[keyEntry].entry_type = entry.entry_type;
                m_naptEntries[pair_key].entry_type = entry.entry_type;

                totalStaticNaptEntries+=2;
                totalDynamicNaptEntries-=2;
                updateStaticNaptCounters(totalStaticNaptEntries);
                updateDynamicNaptCounters(totalDynamicNaptEntries);
            }

            return true;
        }
        else
        {
            SWSS_LOG_INFO("Duplicate %s %s NAPT entry already exists with ip %s, port %d, prototype %s and it's translated ip %s, translated port %d, do nothing",
                          entry.entry_type.c_str(), entry.nat_type.c_str(), keyEntry.ip_address.to_string().c_str(), keyEntry.l4_port,
                          keyEntry.prototype.c_str(), entry.translated_ip.to_string().c_str(), entry.translated_l4_port);
            return true;
        }
    }

    if (entry.entry_type == "dynamic")
    {
        if (totalSnatEntries == maxAllowedSNatEntries)
        {
            const auto& snapt_key = (entry.nat_type == "snat") ? keyEntry : pair_key;
            const auto& dnapt_key = (entry.nat_type == "snat") ? pair_key : keyEntry;

            SWSS_LOG_INFO("Reached the max allowed NAT entries in the hardware, dropping new SNAPT translation with ip %s, port %d, prototype %s, translated ip %s, translated port %d",
                            snapt_key.ip_address.to_string().c_str(), snapt_key.l4_port,
                            snapt_key.prototype.c_str(), dnapt_key.ip_address.to_string().c_str(), dnapt_key.l4_port);
            std::vector<FieldValueTuple> fvVector;
            std::string naptKey = (snapt_key.prototype + ":" + snapt_key.ip_address.to_string() + ":" + to_string(snapt_key.l4_port));
            setTimeoutNotifier->send("AGEOUT-SINGLE-NAPT", naptKey, fvVector);
            return true;
        }
    }

    m_naptEntries[keyEntry] = entry;
    m_naptEntries[keyEntry].addedToHw = false;

    // Add pair entry
    {
        pair_entry.translated_ip = keyEntry.ip_address;
        pair_entry.translated_l4_port = keyEntry.l4_port;
        pair_entry.nat_type = (entry.nat_type == "snat") ? "dnat" : "snat";
        pair_entry.entry_type = entry.entry_type;
        pair_entry.addedToHw = false;
    }
    m_naptEntries[pair_key] = pair_entry;

    if (!isNatEnabled())
    {
        SWSS_LOG_WARN("NAT feature is not yet enabled, skipped adding %s %s NAPT entry with ip %s, port %d, prototype %s and it's translated ip %s, translated port %d",
                        entry.entry_type.c_str(), entry.nat_type.c_str(), keyEntry.ip_address.to_string().c_str(), keyEntry.l4_port, keyEntry.prototype.c_str(),
                        entry.translated_ip.to_string().c_str(), entry.translated_l4_port);

        return true;
    }

    const auto& snapt_key = (entry.nat_type == "snat") ? keyEntry : pair_key;
    const auto& dnapt_key = (entry.nat_type == "snat") ? pair_key : keyEntry;
    const NaptEntryValue& dnapt = (entry.nat_type == "snat") ? pair_entry : entry;
    bool rv = false;

    if (gNhTrackingSupported == true)
    {
        /* Cache the DNAT entry in the nexthop resolution cache */
        addDnaptToNhCache(dnapt.translated_ip, dnapt_key);

        if (!isNhCacheResolved(dnapt.translated_ip))
        {
            return true;
        }
    }

    rv = addHwSnaptEntry(snapt_key);
    if (!rv)
    {
        if (entry.entry_type == "dynamic")
        {
            SWSS_LOG_INFO("Reached the max allowed NAT entries in the hardware, dropping new SNAPT translation with ip %s, port %d, prototype %s, translated ip %s, translated port %d",
                            snapt_key.ip_address.to_string().c_str(), snapt_key.l4_port,
                            snapt_key.prototype.c_str(), dnapt_key.ip_address.to_string().c_str(), dnapt_key.l4_port);
            std::vector<FieldValueTuple> fvVector;
            std::string naptKey = (snapt_key.prototype + ":" + snapt_key.ip_address.to_string() + ":" + to_string(snapt_key.l4_port));
            setTimeoutNotifier->send("AGEOUT-SINGLE-NAPT", naptKey, fvVector);
        }

        return true;
    }

    rv = addHwDnaptEntry(dnapt_key);
    if (!rv)
    {
        removeHwSnaptEntry(snapt_key);

        if (entry.entry_type == "dynamic")
        {
            SWSS_LOG_INFO("Reached the max allowed NAT entries in the hardware, dropping new SNAPT translation with ip %s, port %d, prototype %s, translated ip %s, translated port %d",
                            snapt_key.ip_address.to_string().c_str(), snapt_key.l4_port,
                            snapt_key.prototype.c_str(), dnapt_key.ip_address.to_string().c_str(), dnapt_key.l4_port);
            std::vector<FieldValueTuple> fvVector;
            std::string naptKey = (snapt_key.prototype + ":" + snapt_key.ip_address.to_string() + ":" + to_string(snapt_key.l4_port));
            setTimeoutNotifier->send("AGEOUT-SINGLE-NAPT", naptKey, fvVector);
        }

        return true;
    }

    return true;
}

bool NatOrch::removeNaptEntry(const NaptEntryKey &keyEntry)
{
    SWSS_LOG_ENTER();

    if (m_naptEntries.find(keyEntry) == m_naptEntries.end())
    {
        SWSS_LOG_INFO("NAPT entry isn't found for prototype - %s, ip - %s and port - %d",
                       keyEntry.prototype.c_str(), keyEntry.ip_address.to_string().c_str(), keyEntry.l4_port);

        return true;
    }

    const NaptEntryValue entry = m_naptEntries[keyEntry];
    const NaptEntryKey pair_key { entry.translated_ip, entry.translated_l4_port, keyEntry.prototype };
    const NaptEntryValue pair_entry = m_naptEntries[pair_key];

    const auto &snapt_key = (entry.nat_type == "snat") ? keyEntry : pair_key;
    const auto &dnapt_key = (entry.nat_type == "snat") ? pair_key : keyEntry;
    const NaptEntryValue &dnapt = (entry.nat_type == "snat") ? pair_entry : entry;

    if (gNhTrackingSupported == true)
    {
        removeDnaptFromNhCache(dnapt.translated_ip, dnapt_key);
    }

    removeHwSnaptEntry(snapt_key);
    m_naptEntries.erase(snapt_key);

    removeHwDnaptEntry(dnapt_key);
    m_naptEntries.erase(dnapt_key);

    addPendingStaticEntry();

    return true;
}

bool NatOrch::addTwiceNaptEntry(const TwiceNaptEntryKey &key, const TwiceNaptEntryValue &value)
{
    SWSS_LOG_ENTER();

    TwiceNaptEntryKey pair_key{ value.translated_dst_ip, value.translated_dst_l4_port,
                                value.translated_src_ip, value.translated_src_l4_port,
                                key.prototype};
    TwiceNaptEntryValue pair_entry;

    /* Check the entry is present in the cache */
    if (m_twiceNaptEntries.find(key) != m_twiceNaptEntries.end())
    {
        TwiceNaptEntryValue oldEntry = m_twiceNaptEntries[key];

        /* Entry exists */
        if ((value.translated_src_l4_port != oldEntry.translated_src_l4_port) or
            (value.translated_dst_l4_port != oldEntry.translated_dst_l4_port) or
            (value.translated_src_ip.to_string() != oldEntry.translated_src_ip.to_string()) or
            (value.translated_dst_ip.to_string() != oldEntry.translated_dst_ip.to_string()))
        {
            SWSS_LOG_INFO("Twice NAPT entry already exists with src ip %s, src port %d, dst ip %s, dst port %d, prototype %s and it's translated src ip %s, \
                           translated src port %d, translated dst ip %s, translated dst port %d",
                          key.src_ip.to_string().c_str(), key.src_l4_port, key.dst_ip.to_string().c_str(), key.dst_l4_port,
                          key.prototype.c_str(), oldEntry.translated_src_ip.to_string().c_str(), oldEntry.translated_src_l4_port,
                          oldEntry.translated_dst_ip.to_string().c_str(), oldEntry.translated_dst_l4_port);

            /* Removed the NAPT entry */
            SWSS_LOG_INFO("Removing %s Twice NAPT entry with src ip %s, src port %d, dst ip %s, dst port %d, prototype %s",
                          oldEntry.entry_type.c_str(), key.src_ip.to_string().c_str(), key.src_l4_port,
                          key.dst_ip.to_string().c_str(), key.dst_l4_port, key.prototype.c_str());

            removeTwiceNaptEntry(key);
        }
        else if (value.entry_type != oldEntry.entry_type)
        {
            if (value.entry_type == "static")
            {
                SWSS_LOG_INFO("Entry type change, %s Twice NAPT entry already exists with src ip %s, src port %d, dst ip %s, dst port %d, prototype %s and it's translated src ip %s, \
                               translated src port %d, translated dst ip %s, translated dst port %d",
                              oldEntry.entry_type.c_str(), key.src_ip.to_string().c_str(), key.src_l4_port, key.dst_ip.to_string().c_str(), key.dst_l4_port,
                              key.prototype.c_str(), oldEntry.translated_src_ip.to_string().c_str(), oldEntry.translated_src_l4_port,
                              oldEntry.translated_dst_ip.to_string().c_str(), oldEntry.translated_dst_l4_port);

                m_twiceNaptEntries[key].entry_type = value.entry_type;

                totalStaticTwiceNaptEntries++;
                totalDynamicTwiceNaptEntries--;
                updateStaticTwiceNaptCounters(totalStaticTwiceNaptEntries);
                updateDynamicTwiceNaptCounters(totalDynamicTwiceNaptEntries);

                auto pair_it = m_twiceNaptEntries.find(pair_key);

                if (pair_it != m_twiceNaptEntries.end() &&
                    pair_it->second.entry_type != value.entry_type)
                {
                    m_twiceNaptEntries[pair_key].entry_type = value.entry_type;

                    totalStaticTwiceNaptEntries++;
                    totalDynamicTwiceNaptEntries--;
                    updateStaticTwiceNaptCounters(totalStaticTwiceNaptEntries);
                    updateDynamicTwiceNaptCounters(totalDynamicTwiceNaptEntries);
                }
            }

            return true;
        }
        else
        {
            SWSS_LOG_INFO("Duplicate %s Twice NAPT entry already exists with src ip %s, src port %d, dst ip %s, dst port %d, prototype %s and \
                          it's translated src ip %s, translated src port %d, translated dst ip %s, translated dst port %d, do nothing",
                          value.entry_type.c_str(), key.src_ip.to_string().c_str(), key.src_l4_port, key.dst_ip.to_string().c_str(),
                          key.dst_l4_port, key.prototype.c_str(), value.translated_src_ip.to_string().c_str(),
                          value.translated_src_l4_port, value.translated_dst_ip.to_string().c_str(), value.translated_dst_l4_port);
            return true;
        }
    }

    if (value.entry_type == "dynamic")
    {
        if (totalSnatEntries == maxAllowedSNatEntries)
        {
            SWSS_LOG_INFO("Reached the max allowed NAT entries in the hardware, dropping new Twice SNAPT translation with src ip %s, src port %d, prototype %s, \
                        dst ip %s, dst port %d",
                            key.src_ip.to_string().c_str(), key.src_l4_port, key.prototype.c_str(), key.dst_ip.to_string().c_str(), key.dst_l4_port);
            std::vector<FieldValueTuple> fvVector;
            std::string twiceNaptKey = (key.prototype + ":" + key.src_ip.to_string() + ":" + to_string(key.src_l4_port) +
                                        ":" + key.dst_ip.to_string() + ":" + to_string(key.dst_l4_port));
            setTimeoutNotifier->send("AGEOUT-TWICE-NAPT", twiceNaptKey, fvVector);

            std::string pairTwiceNaptKey = (pair_key.prototype + ":" + pair_key.src_ip.to_string() + ":" + to_string(pair_key.src_l4_port) +
                                            ":" + pair_key.dst_ip.to_string() + ":" + to_string(pair_key.dst_l4_port));
            setTimeoutNotifier->send("AGEOUT-TWICE-NAPT", pairTwiceNaptKey, fvVector);
            return true;
        }
    }
    m_twiceNaptEntries[key] = value;
    m_twiceNaptEntries[key].addedToHw = false;

    {
        pair_entry.entry_type = value.entry_type;
        pair_entry.translated_src_ip = key.dst_ip;
        pair_entry.translated_src_l4_port = key.dst_l4_port;
        pair_entry.translated_dst_ip = key.src_ip;
        pair_entry.translated_dst_l4_port = key.src_l4_port;
        pair_entry.addedToHw = false;

        m_twiceNaptEntries[pair_key] = pair_entry;
    }

    if (!isNatEnabled())
    {
        SWSS_LOG_WARN("NAT feature is not yet enabled, skipped adding %s Twice NAPT entry with src ip %s, src port %d, prototype %s, dst ip %s, dst port %d",
                      value.entry_type.c_str(), key.src_ip.to_string().c_str(), key.src_l4_port, key.prototype.c_str(),
                      key.dst_ip.to_string().c_str(), key.dst_l4_port);

        return true;
    }

    if (gNhTrackingSupported == true)
    {
        addTwiceNaptToNhCache(value.translated_dst_ip, key);
        addTwiceNaptToNhCache(pair_entry.translated_dst_ip, pair_key);

        if (!isNhCacheResolved(value.translated_dst_ip) ||
            !isNhCacheResolved(pair_entry.translated_dst_ip))
        {
            return true;
        }
    }

    auto rv = addHwTwiceNaptEntry(key);
    if (!rv)
    {
        if (value.entry_type == "dynamic")
        {
            SWSS_LOG_INFO("Reached the max allowed NAT entries in the hardware, dropping new Twice SNAPT translation with src ip %s, src port %d, prototype %s, \
                    dst ip %s, dst port %d",
                            key.src_ip.to_string().c_str(), key.src_l4_port, key.prototype.c_str(), key.dst_ip.to_string().c_str(), key.dst_l4_port);
            std::vector<FieldValueTuple> fvVector;
            std::string twiceNaptKey = (key.prototype + ":" + key.src_ip.to_string() + ":" + to_string(key.src_l4_port) +
                                        ":" + key.dst_ip.to_string() + ":" + to_string(key.dst_l4_port));
            setTimeoutNotifier->send("AGEOUT-TWICE-NAPT", twiceNaptKey, fvVector);

            std::string pairTwiceNaptKey = (pair_key.prototype + ":" + pair_key.src_ip.to_string() + ":" + to_string(pair_key.src_l4_port) +
                                            ":" + pair_key.dst_ip.to_string() + ":" + to_string(pair_key.dst_l4_port));
            setTimeoutNotifier->send("AGEOUT-TWICE-NAPT", pairTwiceNaptKey, fvVector);
        }
        return true;
    }

    rv = addHwTwiceNaptEntry(pair_key);
    if (!rv)
    {
        removeHwTwiceNaptEntry(key);

        if (value.entry_type == "dynamic")
        {
            SWSS_LOG_INFO("Reached the max allowed NAT entries in the hardware, dropping new Twice SNAPT translation with src ip %s, src port %d, prototype %s, \
                    dst ip %s, dst port %d",
                            key.src_ip.to_string().c_str(), key.src_l4_port, key.prototype.c_str(), key.dst_ip.to_string().c_str(), key.dst_l4_port);
            std::vector<FieldValueTuple> fvVector;
            std::string twiceNaptKey = (key.prototype + ":" + key.src_ip.to_string() + ":" + to_string(key.src_l4_port) +
                                        ":" + key.dst_ip.to_string() + ":" + to_string(key.dst_l4_port));
            setTimeoutNotifier->send("AGEOUT-TWICE-NAPT", twiceNaptKey, fvVector);

            std::string pairTwiceNaptKey = (pair_key.prototype + ":" + pair_key.src_ip.to_string() + ":" + to_string(pair_key.src_l4_port) +
                                            ":" + pair_key.dst_ip.to_string() + ":" + to_string(pair_key.dst_l4_port));
            setTimeoutNotifier->send("AGEOUT-TWICE-NAPT", pairTwiceNaptKey, fvVector);
        }

        return true;
    }

    return true;
}

bool NatOrch::removeTwiceNaptEntry(const TwiceNaptEntryKey &key)
{
    SWSS_LOG_ENTER();

    if (m_twiceNaptEntries.find(key) == m_twiceNaptEntries.end())
    {
        SWSS_LOG_INFO("Twice NAPT entry isn't found for prototype - %s, src ip %s src port %d dst ip %s dst port %d",
                       key.prototype.c_str(), key.src_ip.to_string().c_str(), key.src_l4_port,
                       key.dst_ip.to_string().c_str(), key.dst_l4_port);
        return true;
    }

    const TwiceNaptEntryValue value = m_twiceNaptEntries[key];
    TwiceNaptEntryKey pair_key{ value.translated_dst_ip, value.translated_dst_l4_port,
                                value.translated_src_ip, value.translated_src_l4_port,
                                key.prototype };

    if (gNhTrackingSupported == true)
    {
        /* Remove Twice NAPT entry from the NH resolv cache */
        removeTwiceNaptFromNhCache(value.translated_dst_ip, key);
    }

    removeHwTwiceNaptEntry(key);
    m_twiceNaptEntries.erase(key);

    removeHwTwiceNaptEntry(pair_key);
    m_twiceNaptEntries.erase(pair_key);

    addPendingStaticEntry();

    return true;
}

bool NatOrch::isNatEnabled(void)
{
    if (admin_mode == "enabled")
    {
        return true;
    }

    return false;
}

void NatOrch::clearAllDnatEntries(void)
{
    NaptEntryKey  keyEntry;
    NatEntryValue natEntry;
    NaptEntryValue naptEntry;
    TwiceNatEntryKey twiceNatKey;
    TwiceNatEntryValue twiceNatValue;
    TwiceNaptEntryKey  twiceNaptKey;
    TwiceNaptEntryValue twiceNaptValue;

    NatEntry::iterator natIter = m_natEntries.begin();
    while (natIter != m_natEntries.end())
    {
        natEntry = (*natIter).second;
        IpAddress ip = (*natIter).first;
        natIter++;

        if (natEntry.nat_type == "dnat")
        {
            if (gNhTrackingSupported == true)
            {
                removeDnatFromNhCache(natEntry.translated_ip, ip);
            }

            removeHwDnatEntry(ip);
        }
        else
        {
            removeHwSnatEntry(ip);
        }
        m_natEntries.erase(ip);
    }

    NaptEntry::iterator naptIter = m_naptEntries.begin();
    while (naptIter != m_naptEntries.end())
    {
        naptEntry = (*naptIter).second;
        keyEntry = (*naptIter).first;
        naptIter++;

        if (naptEntry.nat_type == "dnat")
        {
            if (gNhTrackingSupported == true)
            {
                removeDnaptFromNhCache(naptEntry.translated_ip, keyEntry);
            }

            removeHwDnaptEntry(keyEntry);
        }
        else
        {
            removeHwSnaptEntry(keyEntry);
        }

        m_naptEntries.erase(keyEntry);
    }

    TwiceNatEntry::iterator twiceNatIter = m_twiceNatEntries.begin();
    while (twiceNatIter != m_twiceNatEntries.end())
    {
        twiceNatValue = (*twiceNatIter).second;
        twiceNatKey   = (*twiceNatIter).first;
        twiceNatIter++;

        if (gNhTrackingSupported == true)
        {
            removeTwiceNatFromNhCache(twiceNatValue.translated_dst_ip, twiceNatKey);
        }

        removeHwTwiceNatEntry(twiceNatKey);
        m_twiceNatEntries.erase(twiceNatKey);
    }

    TwiceNaptEntry::iterator twiceNaptIter = m_twiceNaptEntries.begin();
    while (twiceNaptIter != m_twiceNaptEntries.end())
    {
        twiceNaptValue = (*twiceNaptIter).second;
        twiceNaptKey   = (*twiceNaptIter).first;
        twiceNaptIter++;

        if (gNhTrackingSupported == true)
        {
            removeTwiceNaptFromNhCache(twiceNaptValue.translated_dst_ip, twiceNaptKey);
        }

        removeHwTwiceNaptEntry(twiceNaptKey);
        m_twiceNaptEntries.erase(twiceNaptKey);
    }
}

void NatOrch::cleanupAppDbEntries(void)
{
    /* Iterate over all the entries clean them up from the APP_DB
     * and from the hardware */
    string            appDbKey;
    IpAddress         ip;
    NaptEntryKey      keyEntry;
    TwiceNatEntryKey  twiceNatKey;
    TwiceNaptEntryKey twiceNaptKey;

    std::vector<IpAddress>          natKeys;
    std::vector<NaptEntryKey>       naptKeys;
    std::vector<TwiceNatEntryKey>   twiceNatKeys;
    std::vector<TwiceNaptEntryKey>  twiceNaptKeys;

    NatEntry::iterator natIter = m_natEntries.begin();
    while (natIter != m_natEntries.end())
    {
        ip = (*natIter).first;
        natIter++;

        /* Remove from APP_DB */
        appDbKey = ip.to_string();
        m_natQueryTable.del(appDbKey);

        natKeys.push_back(ip);

        SWSS_LOG_INFO("Removed NAT entry from APP_DB and ASIC - %s", appDbKey.c_str());
    }

    NaptEntry::iterator naptIter = m_naptEntries.begin();
    while (naptIter != m_naptEntries.end())
    {
        keyEntry = (*naptIter).first;
        naptIter++;

        /* Remove from APP_DB */
        appDbKey = keyEntry.prototype + ":" + keyEntry.ip_address.to_string() + ":" + std::to_string(keyEntry.l4_port);
        m_naptQueryTable.del(appDbKey);

        naptKeys.push_back(keyEntry);

        SWSS_LOG_INFO("Removed NAPT entry from APP_DB and ASIC - %s", appDbKey.c_str());
    }

    TwiceNatEntry::iterator twiceNatIter = m_twiceNatEntries.begin();
    while (twiceNatIter != m_twiceNatEntries.end())
    {
        twiceNatKey   = (*twiceNatIter).first;
        twiceNatIter++;

        /* Remove from APP_DB */
        appDbKey = twiceNatKey.src_ip.to_string() + ":" + twiceNatKey.dst_ip.to_string();
        m_twiceNatQueryTable.del(appDbKey);

        twiceNatKeys.push_back(twiceNatKey);

        SWSS_LOG_INFO("Removed Twice NAT entry from APP_DB and ASIC - %s", appDbKey.c_str());
    }

    TwiceNaptEntry::iterator twiceNaptIter = m_twiceNaptEntries.begin();
    while (twiceNaptIter != m_twiceNaptEntries.end())
    {
        twiceNaptKey   = (*twiceNaptIter).first;
        twiceNaptIter++;

        /* Remove from APP_DB */
        appDbKey = twiceNaptKey.prototype + ":" + twiceNaptKey.src_ip.to_string() + ":" +
                   std::to_string(twiceNaptKey.src_l4_port) + ":" + twiceNaptKey.dst_ip.to_string() +
                   ":" + std::to_string(twiceNaptKey.dst_l4_port);
        m_twiceNaptQueryTable.del(appDbKey);

        twiceNaptKeys.push_back(twiceNaptKey);

        SWSS_LOG_INFO("Removed Twice NAPT entry from APP_DB and ASIC - %s", appDbKey.c_str());
    }

    for (const auto& key : natKeys)
    {
        removeNatEntry(key);
    }

    for (const auto& key : naptKeys)
    {
        removeNaptEntry(key);
    }

    for (const auto& key : twiceNatKeys)
    {
        removeTwiceNatEntry(key);
    }

    for (const auto& key : twiceNaptKeys)
    {
        removeTwiceNaptEntry(key);
    }
}

void NatOrch::enableNatFeature(void)
{
    sai_status_t     status;
    sai_attribute_t  attr = {};

    SWSS_LOG_INFO("Verify NAT is supported or not");

    if (gIsNatSupported == false)
    {
        SWSS_LOG_NOTICE("NAT Feature is not supported in this Platform");
        return;
    }
    else
    {
        admin_mode = "enabled";
        SWSS_LOG_INFO("NAT Feature is supported with available limit : %d", maxAllowedSNatEntries);
    }

    SWSS_LOG_INFO("Enabling NAT ");

    attr.id = SAI_SWITCH_ATTR_NAT_ENABLE;
    attr.value.booldata = true;

    status = sai_switch_api->set_switch_attribute(gSwitchId, &attr);
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to enable NAT: %d", status);
        handleSaiSetStatus(SAI_API_SWITCH, status);
    }

    SWSS_LOG_INFO("NAT Query timer start ");
    m_natQueryTimer->start();

    SWSS_LOG_INFO("NAT Timeout timer start ");
    m_natTimeoutTimer->start();

    if (gNhTrackingSupported == true)
    {
        SWSS_LOG_INFO("Attach to Neighbor Orch ");
        m_neighOrch->attach(this);
    }

    SWSS_LOG_INFO("Adding DNAT Pool Entries ");
    addAllDnatPoolEntries();

    SWSS_LOG_INFO("Adding NAT Entries ");
    addAllNatEntries();
}

void NatOrch::disableNatFeature(void)
{
    sai_status_t     status;
    sai_attribute_t  attr = {};

    SWSS_LOG_INFO("Disabling NAT ");

    admin_mode = "disabled";
    attr.id = SAI_SWITCH_ATTR_NAT_ENABLE;
    attr.value.booldata = false;

    status = sai_switch_api->set_switch_attribute(gSwitchId, &attr);
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to disable NAT: %d", status);
        handleSaiSetStatus(SAI_API_SWITCH, status);
    }

    SWSS_LOG_INFO("NAT Query timer stop ");
    m_natQueryTimer->stop();

    SWSS_LOG_INFO("NAT Timeout timer stop ");
    m_natTimeoutTimer->stop();

    if (gNhTrackingSupported == true)
    {
        SWSS_LOG_INFO("Detach to Neighbor Orch ");
        m_neighOrch->detach(this);
    }

    SWSS_LOG_INFO("Clear all DNAT Entries ");
    clearAllDnatEntries();
}

void NatOrch::doUpdateTableTask(Consumer& consumer)
{
    for (auto &syncPair : consumer.m_toSync)
    {
        auto const &keyOpFV = syncPair.second;
        auto &key = kfvKey(keyOpFV);
        auto &op = kfvOp(keyOpFV);

        // only process set command
        if (op != SET_COMMAND)
        {
            continue;
        }

        // key: <ipv4>:<update event type>
        auto const keyParts = tokenize(key, keySeparator);
        if (keyParts.size() != 2)
        {
            SWSS_LOG_WARN("Invalid key: %s", key.c_str());
            continue;
        }
        auto ip = IpAddress{ keyParts[0] };
        auto &updateEvent = keyParts[1];

        if (updateEvent == keyNextHopUpdateEvent)
        {
            updateNextHop(ip, kfvFieldsValues(keyOpFV));
        }
        else if (updateEvent == keyNeighborUpdateEvent)
        {
            updateNeighbor(ip, kfvFieldsValues(keyOpFV));
        }
        else
        {
            SWSS_LOG_ERROR("Invalid update event type: %s", updateEvent.c_str());
        }
        m_updateEventTable.del(key);
    }
    consumer.m_toSync.clear();
}

void NatOrch::doNatTableTask(Consumer& consumer)
{
    auto it = consumer.m_toSync.begin();
    while (it != consumer.m_toSync.end())
    {
        KeyOpFieldsValuesTuple t = it->second;
        string key = kfvKey(t);
        string op = kfvOp(t);
        vector<string> keys = tokenize(key, ':');
        /* Example : APPL_DB
         * NAT_TABLE:65.55.45.1
         *     translated_ip: 10.0.0.1
         *     nat_type: dnat
         *     entry_type: static
         */

        /* Ensure the key size is 1 otherwise ignore */
        if (keys.size() != 1)
        {
            SWSS_LOG_ERROR("Invalid key size, skipping %s", key.c_str());
            it = consumer.m_toSync.erase(it);
            continue;
        }

        IpAddress ip_address = IpAddress(key);

        if (op == SET_COMMAND)
        {
            NatEntryValue entry;
            string type;

            for (auto i : kfvFieldsValues(t))
            {
                if (fvField(i) == "entry_type")
                    type = fvValue(i);
                else if (fvField(i) == "translated_ip")
                    entry.translated_ip = IpAddress(fvValue(i));
                else if (fvField(i) == "nat_type")
                    entry.nat_type = fvValue(i);
            }

            /* NAT type is either dynamic or static */
            assert(type == "dynamic" || type == "static");
            entry.entry_type = type;
            entry.addedToHw = false;

            if (addNatEntry(ip_address, entry))
                it = consumer.m_toSync.erase(it);
            else
                it++;
        }
        else if (op == DEL_COMMAND)
        {
            if (removeNatEntry(ip_address))
                it = consumer.m_toSync.erase(it);
            else
                it++;
        }
        else
        {
            SWSS_LOG_ERROR("Unknown operation type %s\n", op.c_str());
            it = consumer.m_toSync.erase(it);
        }
    }
}

void NatOrch::doNaptTableTask(Consumer& consumer)
{
    auto it = consumer.m_toSync.begin();
    while (it != consumer.m_toSync.end())
    {
        KeyOpFieldsValuesTuple t = it->second;
        string key = kfvKey(t);
        string op = kfvOp(t);
        vector<string> keys = tokenize(key, ':');

        /* Example : APPL_DB
         * NAPT_TABLE:TCP:65.55.42.1:1024
         *     translated_ip: 10.0.0.1
         *     translated_l4_port: 6000
         *     nat_type: snat
         *     entry_type: static
         */

        /* Ensure the key size is 5 otherwise ignore */
        if (keys.size() != 3)
        {
            SWSS_LOG_ERROR("Invalid key size, skipping %s", key.c_str());
            it = consumer.m_toSync.erase(it);
            continue;
        }

        NaptEntryKey keyEntry;

        keyEntry.ip_address = IpAddress(keys[1]);
        keyEntry.l4_port = stoi(keys[2]);
        keyEntry.prototype = keys[0];

        if (op == SET_COMMAND)
        {
            NaptEntryValue entry;
            string type;

            for (auto i : kfvFieldsValues(t))
            {
                if (fvField(i) == "entry_type")
                    type = fvValue(i);
                else if (fvField(i) == "translated_ip")
                    entry.translated_ip = IpAddress(fvValue(i));
                else if (fvField(i) == "translated_l4_port")
                    entry.translated_l4_port = stoi(fvValue(i));
                else if (fvField(i) == "nat_type")
                    entry.nat_type = fvValue(i);
            }

            /* NAT type is either dynamic or static */
            assert(type == "dynamic" || type == "static");
            entry.entry_type = type;
            entry.addedToHw = false;

            if (addNaptEntry(keyEntry, entry))
                it = consumer.m_toSync.erase(it);
            else
                it++;
        }
        else if (op == DEL_COMMAND)
        {
            if (removeNaptEntry(keyEntry))
                it = consumer.m_toSync.erase(it);
            else
                it++;
        }
        else
        {
            SWSS_LOG_ERROR("Unknown operation type %s\n", op.c_str());
            it = consumer.m_toSync.erase(it);
        }
    }
}

void NatOrch::doTwiceNatTableTask(Consumer& consumer)
{
    auto it = consumer.m_toSync.begin();
    while (it != consumer.m_toSync.end())
    {
        KeyOpFieldsValuesTuple t = it->second;
        string key = kfvKey(t);
        string op = kfvOp(t);
        vector<string> keys = tokenize(key, ':');
        /* Example : APPL_DB
         * NAT_TWICE_TABLE:91.91.91.91:65.55.45.1
         *     translated_src_ip: 14.14.14.14
         *     translated_dst_ip: 12.12.12.12
         *     entry_type: static
         */

        /* Ensure the key size is 2 otherwise ignore */
        if (keys.size() != 2)
        {
            SWSS_LOG_ERROR("Invalid key size, skipping %s", key.c_str());
            it = consumer.m_toSync.erase(it);
            continue;
        }

        TwiceNatEntryKey keyEntry;
        keyEntry.src_ip = IpAddress(keys[0]);
        keyEntry.dst_ip = IpAddress(keys[1]);

        if (op == SET_COMMAND)
        {
            TwiceNatEntryValue entry;
            string type;

            for (auto i : kfvFieldsValues(t))
            {
                if (fvField(i) == "entry_type")
                    type = fvValue(i);
                else if (fvField(i) == "translated_src_ip")
                    entry.translated_src_ip = IpAddress(fvValue(i));
                else if (fvField(i) == "translated_dst_ip")
                    entry.translated_dst_ip = IpAddress(fvValue(i));
            }

            /* NAT type is either dynamic or static */
            assert(type == "dynamic" || type == "static");
            entry.entry_type = type;
            entry.addedToHw = false;

            if (addTwiceNatEntry(keyEntry, entry))
                it = consumer.m_toSync.erase(it);
            else
                it++;
        }
        else if (op == DEL_COMMAND)
        {
            if (removeTwiceNatEntry(keyEntry))
                it = consumer.m_toSync.erase(it);
            else
                it++;
        }
        else
        {
            SWSS_LOG_ERROR("Unknown operation type %s\n", op.c_str());
            it = consumer.m_toSync.erase(it);
        }
    }
}

void NatOrch::doTwiceNaptTableTask(Consumer& consumer)
{
    auto it = consumer.m_toSync.begin();
    while (it != consumer.m_toSync.end())
    {
        KeyOpFieldsValuesTuple t = it->second;
        string key = kfvKey(t);
        string op = kfvOp(t);
        vector<string> keys = tokenize(key, ':');

        /* Example : APPL_DB
         * NAPT_TWICE_TABLE:TCP:91.91.91.91:6363:165.55.42.1:1024
         *     translated_src_ip: 14.14.14.14
         *     translated_src_l4_port: 6000
         *     translated_dst_ip: 12.12.12.12
         *     translated_dst_l4_port: 8000
         *     entry_type: static
         */

        /* Ensure the key size is 5 otherwise ignore */
        if (keys.size() != 5)
        {
            SWSS_LOG_ERROR("Invalid key size, skipping %s", key.c_str());
            it = consumer.m_toSync.erase(it);
            continue;
        }

        TwiceNaptEntryKey keyEntry;

        keyEntry.src_ip      = IpAddress(keys[1]);
        keyEntry.src_l4_port = stoi(keys[2]);
        keyEntry.dst_ip      = IpAddress(keys[3]);
        keyEntry.dst_l4_port = stoi(keys[4]);
        keyEntry.prototype   = keys[0];

        if (op == SET_COMMAND)
        {
            TwiceNaptEntryValue entry;
            string type;

            for (auto i : kfvFieldsValues(t))
            {
                if (fvField(i) == "entry_type")
                    type = fvValue(i);
                else if (fvField(i) == "translated_src_ip")
                    entry.translated_src_ip = IpAddress(fvValue(i));
                else if (fvField(i) == "translated_src_l4_port")
                    entry.translated_src_l4_port = stoi(fvValue(i));
                else if (fvField(i) == "translated_dst_ip")
                    entry.translated_dst_ip = IpAddress(fvValue(i));
                else if (fvField(i) == "translated_dst_l4_port")
                    entry.translated_dst_l4_port = stoi(fvValue(i));
            }

            /* NAT type is either dynamic or static */
            assert(type == "dynamic" || type == "static");
            entry.entry_type = type;
            entry.addedToHw = false;

            if (addTwiceNaptEntry(keyEntry, entry))
                it = consumer.m_toSync.erase(it);
            else
                it++;
        }
        else if (op == DEL_COMMAND)
        {
            if (removeTwiceNaptEntry(keyEntry))
                it = consumer.m_toSync.erase(it);
            else
                it++;
        }
        else
        {
            SWSS_LOG_ERROR("Unknown operation type %s\n", op.c_str());
            it = consumer.m_toSync.erase(it);
        }
    }
}

void NatOrch::doNatGlobalTableTask(Consumer& consumer)
{
    auto it = consumer.m_toSync.begin();
    while (it != consumer.m_toSync.end())
    {
        KeyOpFieldsValuesTuple t = it->second;
        string key = kfvKey(t);
        string op = kfvOp(t);
        string mode;
        vector<string> keys = tokenize(key, ':');

        /* Example : APPL_DB
         * NAT_GLOBAL_TABLE:Values
         *     admin_mode: disabled
         *     nat_timeout : 600
         *     nat_tcp_timeout : 100
         *     nat_udp_timeout : 500
         */

        /* Ensure the key is "Values" otherwise ignore */
        if (strcmp(key.c_str(), VALUES))
        {
            SWSS_LOG_ERROR("Invalid key format. No Values: %s", key.c_str());
            it = consumer.m_toSync.erase(it);
            continue;
        }

        for (auto i : kfvFieldsValues(t))
        {
            if (fvField(i) == "admin_mode")
            {
                mode = fvValue(i);

                /* NAT mode is either enabled or disabled */
                assert(mode == "enabled" || mode == "disabled");

                if (mode != admin_mode)
                {
                    if (mode == "enabled")
                        enableNatFeature();
                    else
                        disableNatFeature();
                }
            }
            else if (fvField(i) == "nat_tcp_timeout")
            {
                tcp_timeout = stoi(fvValue(i));
            }
            else if (fvField(i) == "nat_udp_timeout")
            {
                udp_timeout = stoi(fvValue(i));
            }
            else if (fvField(i) == "nat_timeout")
            {
                timeout = stoi(fvValue(i));
            }
        }

        SWSS_LOG_INFO("Global Values - Admin mode - %s, TCP - %d, UDP - %d and Both - %d", admin_mode.c_str(), tcp_timeout, udp_timeout, timeout);

        it = consumer.m_toSync.erase(it);
    }
}

void NatOrch::doDnatPoolTableTask(Consumer& consumer)
{
    auto it = consumer.m_toSync.begin();
    while (it != consumer.m_toSync.end())
    {
        KeyOpFieldsValuesTuple t = it->second;
        string key = kfvKey(t);
        string op = kfvOp(t);
        vector<string> keys = tokenize(key, ':');
        /* Example : APPL_DB
         * NAT_DNAT_POOL_TABLE:65.55.45.1
         *     NULL: NULL
         */

        /* Ensure the key size is 1 otherwise ignore */
        if (keys.size() != 1)
        {
            SWSS_LOG_ERROR("Invalid key size, skipping %s", key.c_str());
            it = consumer.m_toSync.erase(it);
            continue;
        }

        IpAddress ip_address = IpAddress(key);

        if (op == SET_COMMAND)
        {

            if (m_dnatPoolEntries.find(ip_address) != m_dnatPoolEntries.end())
            {
                SWSS_LOG_INFO("DNAT Pool entry found for ip %s", ip_address.to_string().c_str());
                it = consumer.m_toSync.erase(it);
                continue;
            }

            m_dnatPoolEntries.insert(ip_address);

            if (addHwDnatPoolEntry(ip_address))
                it = consumer.m_toSync.erase(it);
            else
                it++;
        }
        else if (op == DEL_COMMAND)
        {
            if (m_dnatPoolEntries.find(ip_address) == m_dnatPoolEntries.end())
            {
                SWSS_LOG_INFO("DNAT Pool entry isn't found for ip %s", ip_address.to_string().c_str());
                it = consumer.m_toSync.erase(it);
                continue;
            }

            m_dnatPoolEntries.erase(ip_address);

            if (removeHwDnatPoolEntry(ip_address))
                it = consumer.m_toSync.erase(it);
            else
                it++;
        }
        else
        {
            SWSS_LOG_ERROR("Unknown operation type %s\n", op.c_str());
            it = consumer.m_toSync.erase(it);
        }
    }
}

void NatOrch::doTask(Consumer& consumer)
{
    SWSS_LOG_ENTER();

    string table_name = consumer.getTableName();

    unique_lock<mutex> lock(m_natMutex);

    if (table_name == APP_NAT_UPDATE_EVENT_TABLE_NAME)
    {
        SWSS_LOG_INFO("Received APP_NAT_UPDATE_EVENT_TABLE_NAME update");
        doUpdateTableTask(consumer);
    }
    else if (table_name == APP_NAT_TABLE_NAME)
    {
        SWSS_LOG_INFO("Received APP_NAT_TABLE_NAME update");
        doNatTableTask(consumer);
    }
    else if (table_name == APP_NAPT_TABLE_NAME)
    {
        SWSS_LOG_INFO("Received APP_NAPT_TABLE_NAME update");
        doNaptTableTask(consumer);
    }
    if (table_name == APP_NAT_TWICE_TABLE_NAME)
    {
        SWSS_LOG_INFO("Received APP_NAT_TWICE_TABLE_NAME update");
        doTwiceNatTableTask(consumer);
    }
    else if (table_name == APP_NAPT_TWICE_TABLE_NAME)
    {
        SWSS_LOG_INFO("Received APP_NAPT_TWICE_TABLE_NAME update");
        doTwiceNaptTableTask(consumer);
    }
    else if (table_name == APP_NAT_GLOBAL_TABLE_NAME)
    {
        SWSS_LOG_INFO("Received APP_NAT_GLOBAL_TABLE_NAME update");
        doNatGlobalTableTask(consumer);
    }
    else if (table_name == APP_NAT_DNAT_POOL_TABLE_NAME)
    {
        SWSS_LOG_INFO("Received APP_NAT_DNAT_POOL_TABLE_NAME update");
        doDnatPoolTableTask(consumer);
    }
    else
    {
        SWSS_LOG_INFO("Received unknown NAT Table - %s notification", table_name.c_str());
        return;
    }
}

struct timespec getTimeDiff(const struct timespec &begin, const struct timespec &end)
{
    struct timespec diff = {0, 0};

    if (end.tv_nsec-begin.tv_nsec < 0)
    {
        diff.tv_sec  = end.tv_sec - begin.tv_sec - 1;
        diff.tv_nsec = end.tv_nsec - begin.tv_nsec + 1000000000UL;
    }
    else
    {
        diff.tv_sec  = end.tv_sec - begin.tv_sec;
        diff.tv_nsec = end.tv_nsec - begin.tv_nsec;
    }
    return diff;
}

void NatOrch::doTask(SelectableTimer &timer)
{
    SWSS_LOG_ENTER();

    if (timer.getFd() == m_natQueryTimer->getFd())
    {
        if (((natTimerTickCntr++) % NAT_HITBIT_QUERY_MULTIPLE) == 0)
        {
            queryHitBits();
        }
        queryCounters();
    }
    else if (timer.getFd() == m_natTimeoutTimer->getFd())
    {
        SWSS_LOG_INFO("Received NatTimeoutTimer");
        updateAllConntrackEntries();
    }
    else
    {
        SWSS_LOG_INFO("Received unknown timer");
    }
}

void NatOrch::queryCounters(void)
{
    SWSS_LOG_ENTER();

    uint32_t         queried_entries = 0;
    struct timespec  time_now, time_end, time_spent;

    if (clock_gettime (CLOCK_MONOTONIC, &time_now) < 0)
    {
        return;
    }

    NatEntry::iterator natIter = m_natEntries.begin();
    while (natIter != m_natEntries.end())
    {
        getNatCounters(natIter);

        queried_entries++;
        natIter++;
    }

    NaptEntry::iterator naptIter = m_naptEntries.begin();
    while (naptIter != m_naptEntries.end())
    {
        getNaptCounters(naptIter);

        queried_entries++;
        naptIter++;
    }
    TwiceNatEntry::iterator tnatIter = m_twiceNatEntries.begin();
    while (tnatIter != m_twiceNatEntries.end())
    {
        getTwiceNatCounters(tnatIter);

        queried_entries++;
        tnatIter++;
    }

    TwiceNaptEntry::iterator tnaptIter = m_twiceNaptEntries.begin();
    while (tnaptIter != m_twiceNaptEntries.end())
    {
        getTwiceNaptCounters(tnaptIter);

        queried_entries++;
        tnaptIter++;
    }

    if (clock_gettime (CLOCK_MONOTONIC, &time_end) < 0)
    {
        return;
    }
    time_spent = getTimeDiff(time_now, time_end);

    if (queried_entries)
    {
        SWSS_LOG_DEBUG("Time spent in querying counters for %u NAT/NAPT entries = %lu secs, %lu msecs",
                       queried_entries, time_spent.tv_sec, (time_spent.tv_nsec / 1000000UL));
    }
}

void NatOrch::addAllNatEntries(void)
{
    SWSS_LOG_ENTER();

    NatEntry::iterator natIter = m_natEntries.begin();
    while (natIter != m_natEntries.end())
    {
        if ((*natIter).second.addedToHw == false)
        {
            if ((*natIter).second.nat_type == "snat")
            {
                /* Add SNAT entry to the hardware */
                addHwSnatEntry((*natIter).first);
            }
            else if ((*natIter).second.nat_type == "dnat")
            {
                if (gNhTrackingSupported == true)
                {
                    addDnatToNhCache((*natIter).second.translated_ip, (*natIter).first);
                    if (isNhCacheResolved(natIter->second.translated_ip))
                    {
                        addHwDnatEntry(natIter->first);
                    }
                }
                else
                {
                    addHwDnatEntry((*natIter).first);
                }
            }
        }
        natIter++;
    }

    NaptEntry::iterator naptIter = m_naptEntries.begin();
    while (naptIter != m_naptEntries.end())
    {
        if ((*naptIter).second.addedToHw == false)
        {
            if ((*naptIter).second.nat_type == "snat")
            {
                /* Add SNAPT entry to the hardware */
                addHwSnaptEntry((*naptIter).first);
            }
            else if ((*naptIter).second.nat_type == "dnat")
            {
                if (gNhTrackingSupported == true)
                {
                    addDnaptToNhCache((*naptIter).second.translated_ip, (*naptIter).first);
                    if (isNhCacheResolved(naptIter->second.translated_ip))
                    {
                        addHwDnaptEntry(naptIter->first);
                    }
                }
                else
                {
                    addHwDnaptEntry((*naptIter).first);
                }
            }
        }
        naptIter++;
    }

    TwiceNatEntry::iterator twiceNatIter = m_twiceNatEntries.begin();
    while (twiceNatIter != m_twiceNatEntries.end())
    {
        if ((*twiceNatIter).second.addedToHw == false)
        {
            if (gNhTrackingSupported == true)
            {
                /* Cache the Twice NAT entry in the nexthop resolution cache */
                addTwiceNatToNhCache(twiceNatIter->second.translated_dst_ip, (*twiceNatIter).first);
                if (isNhCacheResolved(twiceNatIter->second.translated_dst_ip))
                {
                    addHwTwiceNatEntry(twiceNatIter->first);
                }
            }
            else
            {
                /* Add Twice NAT entry to the hardware */
                addHwTwiceNatEntry((*twiceNatIter).first);
            }
        }
        twiceNatIter++;
    }

    TwiceNaptEntry::iterator twiceNaptIter = m_twiceNaptEntries.begin();
    while (twiceNaptIter != m_twiceNaptEntries.end())
    {
        if ((*twiceNaptIter).second.addedToHw == false)
        {
            if (gNhTrackingSupported == true)
            {
                /* Cache the Twice NAPT entry in the nexthop resolution cache */
                addTwiceNaptToNhCache(twiceNaptIter->second.translated_dst_ip, twiceNaptIter->first);
                if (isNhCacheResolved(twiceNaptIter->second.translated_dst_ip))
                {
                    addHwTwiceNaptEntry(twiceNaptIter->first);
                }
            }
            else
            {
                /* Add Twice NAPT entry to the hardware */
                addHwTwiceNaptEntry((*twiceNaptIter).first);
            }
        }
        twiceNaptIter++;
    }
}

void NatOrch::clearCounters(void)
{
    SWSS_LOG_ENTER();

    NatEntry::iterator natIter = m_natEntries.begin();
    while (natIter != m_natEntries.end())
    {
        setNatCounters(natIter);
        natIter++;
    }

    NaptEntry::iterator naptIter = m_naptEntries.begin();
    while (naptIter != m_naptEntries.end())
    {
        setNaptCounters(naptIter);
        naptIter++;
    }

    TwiceNatEntry::iterator twiceNatIter = m_twiceNatEntries.begin();
    while (twiceNatIter != m_twiceNatEntries.end())
    {
        setTwiceNatCounters(twiceNatIter);
        twiceNatIter++;
    }

    TwiceNaptEntry::iterator twiceNaptIter = m_twiceNaptEntries.begin();
    while (twiceNaptIter != m_twiceNaptEntries.end())
    {
        setTwiceNaptCounters(twiceNaptIter);
        twiceNaptIter++;
    }
}

void NatOrch::queryHitBits(void)
{
    SWSS_LOG_ENTER();

    uint32_t         queried_entries = 0;
    struct timespec  time_now, time_end, time_spent;

    if (clock_gettime (CLOCK_MONOTONIC, &time_now) < 0)
    {
        return;
    }

    /* Remove the NAT entries that are aged out.
     * Query the NAT entries for their activity in the hardware
     * and update the active timeout. */
    NatEntry::iterator natIter = m_natEntries.begin();
    while (natIter != m_natEntries.end())
    {
        if (checkIfNatEntryIsActive(natIter, time_now.tv_sec))
        {
            /* Since the entry is active in the hardware, reset the active time */
            natIter->second.activeTime = time_now.tv_sec;
        }
        else
        {
            if ((natIter->second.nat_type == "snat") and (natIter->second.addedToHw == true) and
                (natIter->second.entry_type != "static"))
            {
                if (time_now.tv_sec - natIter->second.activeTime >= timeout)
                {
                    std::vector<FieldValueTuple> fvVector;
                    std::string key = natIter->first.to_string();
                    setTimeoutNotifier->send("AGEOUT-SINGLE-NAT", key, fvVector);
                }
            }
        }
        queried_entries++;
        natIter++;
    }

    /* Remove the NAPT entries that are aged out.
     * Query the NAPT entries for their activity in the hardware
     * and update the active timeout. */
    NaptEntry::iterator naptIter = m_naptEntries.begin();
    while (naptIter != m_naptEntries.end())
    {
        if (checkIfNaptEntryIsActive(naptIter, time_now.tv_sec))
        {
            /* Since the entry is active in the hardware, reset the active time */
            naptIter->second.activeTime = time_now.tv_sec;
        }
        else
        {
            if ((naptIter->second.nat_type == "snat") and (naptIter->second.addedToHw == true) and
                (naptIter->second.entry_type != "static"))
            {
                int timeout = naptIter->first.prototype == string("TCP") ? tcp_timeout : udp_timeout;
                if (time_now.tv_sec - naptIter->second.activeTime >= timeout)
                {
                    std::vector<FieldValueTuple> fvVector;
                    std::string key = (naptIter->first.prototype + ":" + naptIter->first.ip_address.to_string() + ":" + to_string(naptIter->first.l4_port));
                    setTimeoutNotifier->send("AGEOUT-SINGLE-NAPT", key, fvVector);
                }
            }
        }
        queried_entries++;
        naptIter++;
    }

    /* Remove the Twice NAT entries that are aged out.
     * Query the Twice NAT entries for their activity in the hardware
     * and update the active timeout. */
    TwiceNatEntry::iterator twiceNatIter = m_twiceNatEntries.begin();
    while (twiceNatIter != m_twiceNatEntries.end())
    {
        if (checkIfTwiceNatEntryIsActive(twiceNatIter, time_now.tv_sec))
        {
            /* Since the entry is active in the hardware, reset the active time */
            twiceNatIter->second.activeTime = time_now.tv_sec;
        }
        else
        {
            if ((twiceNatIter->second.addedToHw == true) and
                (twiceNatIter->second.entry_type != "static"))
            {
                if (time_now.tv_sec - twiceNatIter->second.activeTime >= timeout)
                {
                    std::vector<FieldValueTuple> fvVector;
                    std::string key = (twiceNatIter->first.src_ip.to_string() + ":" + twiceNatIter->first.dst_ip.to_string());
                    setTimeoutNotifier->send("AGEOUT-TWICE-NAT", key, fvVector);
                }
            }
        }
        queried_entries++;
        twiceNatIter++;
    }

    /* Remove the Twice NAPT entries that are aged out.
     * Query the Twice NAPT entries for their activity in the hardware
     * and update the active timeout. */
    TwiceNaptEntry::iterator twiceNaptIter = m_twiceNaptEntries.begin();
    while (twiceNaptIter != m_twiceNaptEntries.end())
    {
        if (checkIfTwiceNaptEntryIsActive(twiceNaptIter, time_now.tv_sec))
        {
            /* Since the entry is active in the hardware, reset the active time */
            twiceNaptIter->second.activeTime = time_now.tv_sec;
        }
        else
        {
            if ((twiceNaptIter->second.addedToHw == true) and
                (twiceNaptIter->second.entry_type != "static"))
            {
                int timeout = twiceNaptIter->first.prototype == string("TCP") ? tcp_timeout : udp_timeout;
                if (time_now.tv_sec - twiceNaptIter->second.activeTime >= timeout)
                {
                    std::vector<FieldValueTuple> fvVector;
                    std::string key = (twiceNaptIter->first.prototype + ":" + twiceNaptIter->first.src_ip.to_string() + ":" + to_string(twiceNaptIter->first.src_l4_port) +
                                       ":" + twiceNaptIter->first.dst_ip.to_string() + ":" + to_string(twiceNaptIter->first.dst_l4_port));
                    setTimeoutNotifier->send("AGEOUT-TWICE-NAPT", key, fvVector);
                }
            }
        }
        queried_entries++;
        twiceNaptIter++;
    }
    if (clock_gettime (CLOCK_MONOTONIC, &time_end) < 0)
    {
        return;
    }
    time_spent = getTimeDiff(time_now, time_end);

    if (queried_entries)
    {
        SWSS_LOG_DEBUG("Time spent in querying hardware hit-bits for %u NAT/NAPT entries = %lu secs, %lu msecs",
                       queried_entries, time_spent.tv_sec, (time_spent.tv_nsec / 1000000UL));
    }
}

void NatOrch::updateAllConntrackEntries(void)
{
    SWSS_LOG_ENTER();

    /* Send notifications for the Single NAT entries to set timeout */
    NatEntry::iterator natIter = m_natEntries.begin();
    while (natIter != m_natEntries.end())
    {

        if ((natIter->second.nat_type == "snat") and (natIter->second.addedToHw == true) and
            (natIter->second.entry_type != "static"))
        {
            SWSS_LOG_ERROR("Update %s NAT entry [ip %s]", natIter->second.nat_type.c_str(), natIter->first.to_string().c_str());
            std::vector<FieldValueTuple> fvVector;
            std::string key = natIter->first.to_string();
            setTimeoutNotifier->send("SET-SINGLE-NAT", key, fvVector);
        }
        natIter++;
    }

    /* Send notifications for the Single NAPT entries to set timeout */
    NaptEntry::iterator naptIter = m_naptEntries.begin();
    while (naptIter != m_naptEntries.end())
    {
        if ((naptIter->second.nat_type == "snat") and (naptIter->second.addedToHw == true) and
            (naptIter->second.entry_type != "static"))
        {
            std::vector<FieldValueTuple> fvVector;
            std::string key = (naptIter->first.prototype + ":" + naptIter->first.ip_address.to_string() + ":" + to_string(naptIter->first.l4_port));
            setTimeoutNotifier->send("SET-SINGLE-NAPT", key, fvVector);
        }
        naptIter++;
    }

    /* Send notifications for the Twice NAT entries to set timeout */
    TwiceNatEntry::iterator twiceNatIter = m_twiceNatEntries.begin();
    while (twiceNatIter != m_twiceNatEntries.end())
    {
        if ((twiceNatIter->second.addedToHw == true) and
            (twiceNatIter->second.entry_type != "static"))
        {
            std::vector<FieldValueTuple> fvVector;
            std::string key = (twiceNatIter->first.src_ip.to_string() + ":" + twiceNatIter->first.dst_ip.to_string());
            setTimeoutNotifier->send("SET-TWICE-NAT", key, fvVector);
        }
        twiceNatIter++;
    }

    /* Send notifications for the Twice NAPT entries to set timeout */
    TwiceNaptEntry::iterator twiceNaptIter = m_twiceNaptEntries.begin();
    while (twiceNaptIter != m_twiceNaptEntries.end())
    {
        if ((twiceNaptIter->second.addedToHw == true) and
            (twiceNaptIter->second.entry_type != "static"))
        {
            std::vector<FieldValueTuple> fvVector;
            std::string key = (twiceNaptIter->first.prototype + ":" + twiceNaptIter->first.src_ip.to_string() + ":" + to_string(twiceNaptIter->first.src_l4_port) +
                               ":" + twiceNaptIter->first.dst_ip.to_string() + ":" + to_string(twiceNaptIter->first.dst_l4_port));
            setTimeoutNotifier->send("SET-TWICE-NAPT", key, fvVector);
        }
        twiceNaptIter++;
    }
}

bool NatOrch::getNatCounters(const NatEntry::iterator &iter)
{
    const IpAddress   &ipAddr = iter->first;
    NatEntryValue     &entry  = iter->second;
    uint32_t          attr_count;
    sai_attribute_t   nat_entry_attr[4] = {};
    sai_nat_entry_t   nat_entry = {};
    sai_status_t      status;
    uint64_t          nat_translations_pkts = 0, nat_translations_bytes = 0;

    if (entry.addedToHw == false)
    {
        SWSS_LOG_DEBUG("Skip get Counters for %s NAT entry [ip %s], as not yet added to HW", entry.nat_type.c_str(), ipAddr.to_string().c_str());
        return 0;
    }

    nat_entry_attr[0].id   = SAI_NAT_ENTRY_ATTR_BYTE_COUNT;
    nat_entry_attr[1].id   = SAI_NAT_ENTRY_ATTR_PACKET_COUNT;

    attr_count = 2;


    nat_entry.vr_id       = gVirtualRouterId;
    nat_entry.switch_id   = gSwitchId;

    if (entry.nat_type == "dnat")
    {
        nat_entry.nat_type = SAI_NAT_TYPE_DESTINATION_NAT;
        nat_entry.data.key.dst_ip = ipAddr.getV4Addr();
        nat_entry.data.mask.dst_ip = 0xffffffff;
    }
    else
    {
        nat_entry.nat_type = SAI_NAT_TYPE_SOURCE_NAT;
        nat_entry.data.key.src_ip = ipAddr.getV4Addr();
        nat_entry.data.mask.src_ip = 0xffffffff;
    }

    status = sai_nat_api->get_nat_entry_attribute(&nat_entry, attr_count, nat_entry_attr);
    if (entry.nat_type == "snat")
    {
        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("Failed to get Counters for SNAT entry [src-ip %s], bytes = %" PRIu64 ", pkts = %" PRIu64 "", ipAddr.to_string().c_str(),
                           nat_entry_attr[0].value.u64, nat_entry_attr[1].value.u64);
        }
        else
        {
            nat_translations_bytes = nat_entry_attr[0].value.u64;
            nat_translations_pkts  = nat_entry_attr[1].value.u64;
        }
    }
    else if (entry.nat_type == "dnat")
    {
        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("Failed to get Counters for DNAT entry [dst-ip %s], bytes = %" PRIu64 ", pkts = %" PRIu64 "", ipAddr.to_string().c_str(),
                           nat_entry_attr[0].value.u64, nat_entry_attr[1].value.u64);
        }
        else
        {
            nat_translations_bytes = nat_entry_attr[0].value.u64;
            nat_translations_pkts  = nat_entry_attr[1].value.u64;
        }
    }

    /* Update the Counter values in the database */
    updateNatCounters(ipAddr, nat_translations_pkts, nat_translations_bytes);

    return 0;
}

bool NatOrch::getTwiceNatCounters(const TwiceNatEntry::iterator &iter)
{
    const TwiceNatEntryKey   &key = iter->first;
    TwiceNatEntryValue       &entry  = iter->second;
    uint32_t          attr_count;
    sai_attribute_t   nat_entry_attr[4] = {};
    sai_nat_entry_t   dbl_nat_entry = {};
    sai_status_t      status;
    uint64_t          nat_translations_pkts = 0, nat_translations_bytes = 0;

    if (entry.addedToHw == false)
    {
        SWSS_LOG_DEBUG("Skip get Counters for Twice NAT entry [src ip %s, dst ip %s], as not yet added to HW",
                        key.src_ip.to_string().c_str(), key.dst_ip.to_string().c_str());
        return 0;
    }

    nat_entry_attr[0].id   = SAI_NAT_ENTRY_ATTR_BYTE_COUNT;
    nat_entry_attr[1].id   = SAI_NAT_ENTRY_ATTR_PACKET_COUNT;

    attr_count = 2;

    dbl_nat_entry.vr_id = gVirtualRouterId;
    dbl_nat_entry.switch_id = gSwitchId;
    dbl_nat_entry.nat_type = SAI_NAT_TYPE_DOUBLE_NAT;
    dbl_nat_entry.data.key.src_ip = key.src_ip.getV4Addr();
    dbl_nat_entry.data.mask.src_ip = 0xffffffff;
    dbl_nat_entry.data.key.dst_ip = key.dst_ip.getV4Addr();
    dbl_nat_entry.data.mask.dst_ip = 0xffffffff;

    status = sai_nat_api->get_nat_entry_attribute(&dbl_nat_entry, attr_count, nat_entry_attr);
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to get Counters for Twice NAT entry [src-ip %s, dst-ip %s], bytes = %" PRIu64 ", pkts = %" PRIu64 "",
                        key.src_ip.to_string().c_str(), key.dst_ip.to_string().c_str(),
                        nat_entry_attr[0].value.u64, nat_entry_attr[1].value.u64);
    }
    else
    {
        nat_translations_bytes = nat_entry_attr[0].value.u64;
        nat_translations_pkts  = nat_entry_attr[1].value.u64;
    }

    /* Update the Counter values in the database */
    updateTwiceNatCounters(key, nat_translations_pkts, nat_translations_bytes);

    return 0;
}

bool NatOrch::setNatCounters(const NatEntry::iterator &iter)
{
    const IpAddress   &ipAddr = iter->first;
    NatEntryValue     &entry  = iter->second;
    sai_attribute_t   nat_entry_attr_packet = {};
    sai_attribute_t   nat_entry_attr_byte = {};
    sai_nat_entry_t   nat_entry = {};
    sai_status_t      status;
    uint64_t          nat_translations_pkts = 0, nat_translations_bytes = 0;

    if (entry.addedToHw == false)
    {
        SWSS_LOG_DEBUG("Skip set Counters for %s NAT entry [ip %s], as not yet added to HW", entry.nat_type.c_str(), ipAddr.to_string().c_str());
        return 0;
    }

    nat_entry_attr_byte.id   = SAI_NAT_ENTRY_ATTR_BYTE_COUNT;
    nat_entry_attr_packet.id   = SAI_NAT_ENTRY_ATTR_PACKET_COUNT;

    memset(&nat_entry, 0, sizeof(nat_entry));

    nat_entry.vr_id       = gVirtualRouterId;
    nat_entry.switch_id   = gSwitchId;

    if (entry.nat_type == "dnat")
    {
        nat_entry.nat_type = SAI_NAT_TYPE_DESTINATION_NAT;
        nat_entry.data.key.dst_ip = ipAddr.getV4Addr();
        nat_entry.data.mask.dst_ip = 0xffffffff;
    }
    else
    {
        nat_entry.nat_type = SAI_NAT_TYPE_SOURCE_NAT;
        nat_entry.data.key.src_ip = ipAddr.getV4Addr();
        nat_entry.data.mask.src_ip = 0xffffffff;
    }

    status = sai_nat_api->set_nat_entry_attribute(&nat_entry, &nat_entry_attr_packet);

    if (entry.nat_type == "snat")
    {
        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("Failed to clear packet counter for SNAT entry [src-ip %s]", ipAddr.to_string().c_str());
            handleSaiSetStatus(SAI_API_NAT, status);
        }
    }
    else if (entry.nat_type == "dnat")
    {
        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("Failed to clear packet counter for DNAT entry [dst-ip %s]", ipAddr.to_string().c_str());
            handleSaiSetStatus(SAI_API_NAT, status);
        }
    }

    status = sai_nat_api->set_nat_entry_attribute(&nat_entry, &nat_entry_attr_byte);

    if (entry.nat_type == "snat")
    {
        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("Failed to clear byte counter for SNAT entry [src-ip %s]", ipAddr.to_string().c_str());
            handleSaiSetStatus(SAI_API_NAT, status);
        }
    }
    else if (entry.nat_type == "dnat")
    {
        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("Failed to clear byte counter for DNAT entry [dst-ip %s]", ipAddr.to_string().c_str());
            handleSaiSetStatus(SAI_API_NAT, status);
        }
    }
    /* Update the Counter values in the database */
    updateNatCounters(ipAddr, nat_translations_pkts, nat_translations_bytes);

    return 0;
}

bool NatOrch::getNaptCounters(const NaptEntry::iterator &iter)
{
    const NaptEntryKey &naptKey    = iter->first;
    NaptEntryValue     &entry      = iter->second;
    uint8_t            protoType   = ((naptKey.prototype == "TCP") ? IPPROTO_TCP : IPPROTO_UDP);
    uint32_t           attr_count;
    sai_attribute_t    nat_entry_attr[4] = {};
    sai_nat_entry_t    nat_entry = {};
    sai_status_t       status;
    uint64_t           nat_translations_pkts = 0, nat_translations_bytes = 0;

    if (entry.addedToHw == false)
    {
        SWSS_LOG_DEBUG("Skip get Counters for %s NAPT entry for [proto %s, ip %s, port %d], as not yet added to HW",
                       entry.nat_type.c_str(), naptKey.prototype.c_str(), naptKey.ip_address.to_string().c_str(), naptKey.l4_port);
        return 0;
    }

    nat_entry_attr[0].id   = SAI_NAT_ENTRY_ATTR_BYTE_COUNT;
    nat_entry_attr[1].id   = SAI_NAT_ENTRY_ATTR_PACKET_COUNT;

    attr_count = 2;

    nat_entry.vr_id       = gVirtualRouterId;
    nat_entry.switch_id   = gSwitchId;

    if (entry.nat_type == "dnat")
    {
        nat_entry.nat_type = SAI_NAT_TYPE_DESTINATION_NAT;
        nat_entry.data.key.dst_ip      = naptKey.ip_address.getV4Addr();
        nat_entry.data.key.l4_dst_port = (uint16_t)(naptKey.l4_port);
        nat_entry.data.mask.dst_ip      = 0xffffffff;
        nat_entry.data.mask.l4_dst_port = 0xffff;
    }
    else if (entry.nat_type == "snat")
    {
        nat_entry.nat_type = SAI_NAT_TYPE_SOURCE_NAT;
        nat_entry.data.key.src_ip      = naptKey.ip_address.getV4Addr();
        nat_entry.data.key.l4_src_port = (uint16_t)(naptKey.l4_port);
        nat_entry.data.mask.src_ip      = 0xffffffff;
        nat_entry.data.mask.l4_src_port = 0xffff;
    }

    nat_entry.data.key.proto        = protoType;
    nat_entry.data.mask.proto       = 0xff;

    status = sai_nat_api->get_nat_entry_attribute(&nat_entry, attr_count, nat_entry_attr);

    if (entry.nat_type == "snat")
    {
        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("Failed to get Counters for SNAPT entry for [proto %s, src-ip %s, src-port %d], bytes = %" PRIu64 ", pkts = %" PRIu64 "",
                           naptKey.prototype.c_str(), naptKey.ip_address.to_string().c_str(), naptKey.l4_port,
                           nat_entry_attr[0].value.u64, nat_entry_attr[1].value.u64);
        }
        else
        {
            nat_translations_bytes = nat_entry_attr[0].value.u64;
            nat_translations_pkts  = nat_entry_attr[1].value.u64;
        }
    }
    else if (entry.nat_type == "dnat")
    {
        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("Failed to get Counters for DNAPT entry for [proto %s, dst-ip %s, dst-port %d], bytes = %" PRIu64 ", pkts = %" PRIu64 "",
                           naptKey.prototype.c_str(), naptKey.ip_address.to_string().c_str(), naptKey.l4_port,
                           nat_entry_attr[0].value.u64, nat_entry_attr[1].value.u64);
        }
        else
        {
            nat_translations_bytes = nat_entry_attr[0].value.u64;
            nat_translations_pkts  = nat_entry_attr[1].value.u64;
        }
    }

    /* Update the Counter values in the database */
    updateNaptCounters(naptKey.prototype, naptKey.ip_address, naptKey.l4_port,
                       nat_translations_pkts, nat_translations_bytes);
    return 0;
}

bool NatOrch::getTwiceNaptCounters(const TwiceNaptEntry::iterator &iter)
{
    const TwiceNaptEntryKey &key    = iter->first;
    TwiceNaptEntryValue     &entry      = iter->second;
    uint8_t            protoType   = ((key.prototype == "TCP") ? IPPROTO_TCP : IPPROTO_UDP);
    uint32_t           attr_count;
    sai_attribute_t    nat_entry_attr[4] = {};
    sai_nat_entry_t    dbl_nat_entry = {};
    sai_status_t       status;
    uint64_t           nat_translations_pkts = 0, nat_translations_bytes = 0;

    if (entry.addedToHw == false)
    {
        SWSS_LOG_DEBUG("Skip get Counters for Twice NAPT entry for [proto %s, src ip %s, src port %d, dst ip %s, dst port %d], as not yet added to HW",
                       key.prototype.c_str(), key.src_ip.to_string().c_str(), key.src_l4_port, key.dst_ip.to_string().c_str(),
                       key.dst_l4_port);
        return 0;
    }

    nat_entry_attr[0].id   = SAI_NAT_ENTRY_ATTR_BYTE_COUNT;
    nat_entry_attr[1].id   = SAI_NAT_ENTRY_ATTR_PACKET_COUNT;

    attr_count = 2;

    dbl_nat_entry.vr_id = gVirtualRouterId;
    dbl_nat_entry.switch_id = gSwitchId;
    dbl_nat_entry.nat_type = SAI_NAT_TYPE_DOUBLE_NAT;
    dbl_nat_entry.data.key.src_ip = key.src_ip.getV4Addr();
    dbl_nat_entry.data.mask.src_ip = 0xffffffff;
    dbl_nat_entry.data.key.l4_src_port = (uint16_t)(key.src_l4_port);
    dbl_nat_entry.data.mask.l4_src_port = 0xffff;
    dbl_nat_entry.data.key.dst_ip = key.dst_ip.getV4Addr();
    dbl_nat_entry.data.mask.dst_ip = 0xffffffff;
    dbl_nat_entry.data.key.l4_dst_port = (uint16_t)(key.dst_l4_port);
    dbl_nat_entry.data.mask.l4_dst_port = 0xffff;
    dbl_nat_entry.data.key.proto = protoType;
    dbl_nat_entry.data.mask.proto = 0xff;

    status = sai_nat_api->get_nat_entry_attribute(&dbl_nat_entry, attr_count, nat_entry_attr);

    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_DEBUG("Failed to get Counters for Twice NAPT entry for [proto %s, src ip %s, src port %d, dst ip %s, dst port %d], as not yet added to HW",
                       key.prototype.c_str(), key.src_ip.to_string().c_str(), key.src_l4_port, key.dst_ip.to_string().c_str(),
                       key.dst_l4_port);
    }
    else
    {
        nat_translations_bytes = nat_entry_attr[0].value.u64;
        nat_translations_pkts  = nat_entry_attr[1].value.u64;
    }

    /* Update the Counter values in the database */
    updateTwiceNaptCounters(key, nat_translations_pkts, nat_translations_bytes);
    return 0;
}

bool NatOrch::setNaptCounters(const NaptEntry::iterator &iter)
{
    const NaptEntryKey &naptKey    = iter->first;
    NaptEntryValue     &entry      = iter->second;
    uint8_t            protoType   = ((naptKey.prototype == "TCP") ? IPPROTO_TCP : IPPROTO_UDP);
    sai_attribute_t    nat_entry_attr_packet = {};
    sai_attribute_t    nat_entry_attr_byte = {};
    sai_nat_entry_t    nat_entry = {};
    sai_status_t       status;
    uint64_t           nat_translations_pkts = 0, nat_translations_bytes = 0;

    if (entry.addedToHw == false)
    {
        SWSS_LOG_DEBUG("Skip set Counters for %s NAPT entry for [proto %s, ip %s, port %d], as not yet added to HW",
                       entry.nat_type.c_str(), naptKey.prototype.c_str(), naptKey.ip_address.to_string().c_str(), naptKey.l4_port);
        return 0;
    }

    nat_entry_attr_packet.id = SAI_NAT_ENTRY_ATTR_PACKET_COUNT;
    nat_entry_attr_byte.id = SAI_NAT_ENTRY_ATTR_BYTE_COUNT;

    nat_entry.vr_id       = gVirtualRouterId;
    nat_entry.switch_id   = gSwitchId;

    if (entry.nat_type == "dnat")
    {
        nat_entry.nat_type = SAI_NAT_TYPE_DESTINATION_NAT;
        nat_entry.data.key.dst_ip      = naptKey.ip_address.getV4Addr();
        nat_entry.data.key.l4_dst_port = (uint16_t)(naptKey.l4_port);
        nat_entry.data.mask.dst_ip      = 0xffffffff;
        nat_entry.data.mask.l4_dst_port = 0xffff;
    }
    else if (entry.nat_type == "snat")
    {
        nat_entry.nat_type = SAI_NAT_TYPE_SOURCE_NAT;
        nat_entry.data.key.src_ip      = naptKey.ip_address.getV4Addr();
        nat_entry.data.key.l4_src_port = (uint16_t)(naptKey.l4_port);
        nat_entry.data.mask.src_ip      = 0xffffffff;
        nat_entry.data.mask.l4_src_port = 0xffff;
    }

    nat_entry.data.key.proto        = protoType;
    nat_entry.data.mask.proto       = 0xff;

    status = sai_nat_api->set_nat_entry_attribute(&nat_entry, &nat_entry_attr_packet);

    if (entry.nat_type == "snat")
    {
        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("Failed to clear packet counter for SNAPT entry for [proto %s, src-ip %s, src-port %d",
                           naptKey.prototype.c_str(), naptKey.ip_address.to_string().c_str(), naptKey.l4_port);
            handleSaiSetStatus(SAI_API_NAT, status);
        }
    }
    else if (entry.nat_type == "dnat")
    {
        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("Failed to clear packet counter for DNAPT entry for [proto %s, dst-ip %s, dst-port %d]",
                           naptKey.prototype.c_str(), naptKey.ip_address.to_string().c_str(), naptKey.l4_port);
            handleSaiSetStatus(SAI_API_NAT, status);
        }
    }

    status = sai_nat_api->set_nat_entry_attribute(&nat_entry, &nat_entry_attr_byte);

    if (entry.nat_type == "snat")
    {
        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("Failed to clear byte counter for SNAPT entry for [proto %s, src-ip %s, src-port %d",
                           naptKey.prototype.c_str(), naptKey.ip_address.to_string().c_str(), naptKey.l4_port);
            handleSaiSetStatus(SAI_API_NAT, status);
        }
    }
    else if (entry.nat_type == "dnat")
    {
        if (status != SAI_STATUS_SUCCESS)
        {
            SWSS_LOG_ERROR("Failed to clear byte counter for DNAPT entry for [proto %s, dst-ip %s, dst-port %d]",
                           naptKey.prototype.c_str(), naptKey.ip_address.to_string().c_str(), naptKey.l4_port);
            handleSaiSetStatus(SAI_API_NAT, status);
        }
    }

    /* Update the Counter values in the database */
    updateNaptCounters(naptKey.prototype, naptKey.ip_address, naptKey.l4_port,
                       nat_translations_pkts, nat_translations_bytes);
    return 0;
}

bool NatOrch::setTwiceNatCounters(const TwiceNatEntry::iterator &iter)
{
    const TwiceNatEntryKey &key    = iter->first;
    TwiceNatEntryValue     &entry  = iter->second;
    sai_attribute_t    nat_entry_attr_packet = {};
    sai_attribute_t    nat_entry_attr_byte = {};
    sai_nat_entry_t    dbl_nat_entry = {};
    sai_status_t       status;
    uint64_t           nat_translations_pkts = 0, nat_translations_bytes = 0;

    if (entry.addedToHw == false)
    {
        SWSS_LOG_DEBUG("Skip set Counters for Twice NAT entry [src ip %s, dst ip %s], as not yet added to HW",
                        key.src_ip.to_string().c_str(), key.dst_ip.to_string().c_str());
        return 0;
    }

    nat_entry_attr_packet.id = SAI_NAT_ENTRY_ATTR_PACKET_COUNT;
    nat_entry_attr_byte.id = SAI_NAT_ENTRY_ATTR_BYTE_COUNT;

    dbl_nat_entry.vr_id = gVirtualRouterId;
    dbl_nat_entry.switch_id = gSwitchId;
    dbl_nat_entry.nat_type = SAI_NAT_TYPE_DOUBLE_NAT;
    dbl_nat_entry.data.key.src_ip = key.src_ip.getV4Addr();
    dbl_nat_entry.data.mask.src_ip = 0xffffffff;
    dbl_nat_entry.data.key.dst_ip = key.dst_ip.getV4Addr();
    dbl_nat_entry.data.mask.dst_ip = 0xffffffff;

    status = sai_nat_api->set_nat_entry_attribute(&dbl_nat_entry, &nat_entry_attr_packet);

    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to clear packet counters for Twice NAT entry [src-ip %s, dst-ip %s]",
                        key.src_ip.to_string().c_str(), key.dst_ip.to_string().c_str());
        handleSaiSetStatus(SAI_API_NAT, status);
    }

    status = sai_nat_api->set_nat_entry_attribute(&dbl_nat_entry, &nat_entry_attr_byte);

    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to clear byte counters for Twice NAT entry [src-ip %s, dst-ip %s]",
                        key.src_ip.to_string().c_str(), key.dst_ip.to_string().c_str());
        handleSaiSetStatus(SAI_API_NAT, status);
    }

    /* Update the Counter values in the database */
    updateTwiceNatCounters(key, nat_translations_pkts, nat_translations_bytes);

    return 0;
}

bool NatOrch::setTwiceNaptCounters(const TwiceNaptEntry::iterator &iter)
{
    const TwiceNaptEntryKey &key    = iter->first;
    TwiceNaptEntryValue     &entry  = iter->second;
    uint8_t            protoType   = ((key.prototype == "TCP") ? IPPROTO_TCP : IPPROTO_UDP);
    sai_attribute_t    nat_entry_attr_packet = {};
    sai_attribute_t    nat_entry_attr_byte = {};
    sai_nat_entry_t    dbl_nat_entry = {};
    sai_status_t       status;
    uint64_t           nat_translations_pkts = 0, nat_translations_bytes = 0;

    if (entry.addedToHw == false)
    {
        SWSS_LOG_DEBUG("Skip set Counters for Twice NAPT entry [src ip %s, src port %d, dst ip %s, dst port %d], as not yet added to HW",
                        key.src_ip.to_string().c_str(), key.src_l4_port, key.dst_ip.to_string().c_str(), key.dst_l4_port);
        return 0;
    }

    nat_entry_attr_packet.id = SAI_NAT_ENTRY_ATTR_PACKET_COUNT;
    nat_entry_attr_byte.id = SAI_NAT_ENTRY_ATTR_BYTE_COUNT;

    dbl_nat_entry.vr_id = gVirtualRouterId;
    dbl_nat_entry.switch_id = gSwitchId;
    dbl_nat_entry.nat_type = SAI_NAT_TYPE_DOUBLE_NAT;
    dbl_nat_entry.data.key.src_ip = key.src_ip.getV4Addr();
    dbl_nat_entry.data.mask.src_ip = 0xffffffff;
    dbl_nat_entry.data.key.l4_src_port = (uint16_t)(key.src_l4_port);
    dbl_nat_entry.data.mask.l4_src_port = 0xffff;
    dbl_nat_entry.data.key.dst_ip = key.dst_ip.getV4Addr();
    dbl_nat_entry.data.mask.dst_ip = 0xffffffff;
    dbl_nat_entry.data.key.l4_dst_port = (uint16_t)(key.dst_l4_port);
    dbl_nat_entry.data.mask.l4_dst_port = 0xffff;
    dbl_nat_entry.data.key.proto = protoType;
    dbl_nat_entry.data.mask.proto = 0xff;

    status = sai_nat_api->set_nat_entry_attribute(&dbl_nat_entry, &nat_entry_attr_packet);

    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to clear packet counters for Twice NAPT entry [src-ip %s, src port %d, dst-ip %s, dst port %d]",
                        key.src_ip.to_string().c_str(), key.src_l4_port, key.dst_ip.to_string().c_str(), key.dst_l4_port);
        handleSaiSetStatus(SAI_API_NAT, status);
    }

    status = sai_nat_api->set_nat_entry_attribute(&dbl_nat_entry, &nat_entry_attr_byte);

    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to clear byte counters for Twice NAPT entry [src-ip %s, src port %d, dst-ip %s, dst port %d]",
                        key.src_ip.to_string().c_str(), key.src_l4_port, key.dst_ip.to_string().c_str(), key.dst_l4_port);
        handleSaiSetStatus(SAI_API_NAT, status);
    }

    /* Update the Counter values in the database */
    updateTwiceNaptCounters(key, nat_translations_pkts, nat_translations_bytes);

    return 0;
}

void NatOrch::updateNatCounters(const IpAddress &ipAddr,
                                uint64_t nat_translations_pkts, uint64_t nat_translations_bytes)
{
    vector<swss::FieldValueTuple> values;
    string key = ipAddr.to_string().c_str();

    swss::FieldValueTuple p("NAT_TRANSLATIONS_PKTS", std::to_string(nat_translations_pkts));
    values.push_back(p);
    swss::FieldValueTuple q("NAT_TRANSLATIONS_BYTES", std::to_string(nat_translations_bytes));
    values.push_back(q);

    m_countersNatTable.set(key, values);
}

void NatOrch::deleteNatCounters(const IpAddress &ipAddr)
{
    string key = ipAddr.to_string();

    m_countersNatTable.del(key);
}

void NatOrch::deleteTwiceNatCounters(const TwiceNatEntryKey &key)
{
    string natKey = key.src_ip.to_string() + ":" + key.dst_ip.to_string();

    m_countersTwiceNatTable.del(natKey);
}

void NatOrch::updateNaptCounters(const string &protocol, const IpAddress &ipAddr, int l4_port,
                                 uint64_t nat_translations_pkts, uint64_t nat_translations_bytes)
{
    vector<swss::FieldValueTuple> values;
    string protoStr = protocol.c_str(), ipStr = ipAddr.to_string().c_str(), portStr = std::to_string(l4_port);
    string key = (protoStr + ":" + ipStr + ":" + portStr);

    swss::FieldValueTuple p("NAT_TRANSLATIONS_PKTS", to_string(nat_translations_pkts));
    values.push_back(p);
    swss::FieldValueTuple q("NAT_TRANSLATIONS_BYTES", to_string(nat_translations_bytes));
    values.push_back(q);

    m_countersNaptTable.set(key, values);
}

void NatOrch::deleteNaptCounters(const string &protocol, const IpAddress &ipAddr, int l4_port)
{
    string protoStr = protocol.c_str(), ipStr = ipAddr.to_string().c_str(), portStr = std::to_string(l4_port);
    string key = (protoStr + ":" + ipStr + ":" + portStr);

    m_countersNaptTable.del(key);
}

void NatOrch::deleteTwiceNaptCounters(const TwiceNaptEntryKey &key)
{
    string naptKey = (key.prototype + ":" + key.src_ip.to_string() + ":" + std::to_string(key.src_l4_port) +
                      ":" + key.dst_ip.to_string() + ":" + std::to_string(key.dst_l4_port));

    m_countersTwiceNaptTable.del(naptKey);
}

void NatOrch::updateTwiceNatCounters(const TwiceNatEntryKey &key,
                                     uint64_t nat_translations_pkts, uint64_t nat_translations_bytes)
{
    vector<swss::FieldValueTuple> values;
    string natKey = key.src_ip.to_string() + ":" + key.dst_ip.to_string();

    swss::FieldValueTuple p("NAT_TRANSLATIONS_PKTS", to_string(nat_translations_pkts));
    values.push_back(p);
    swss::FieldValueTuple q("NAT_TRANSLATIONS_BYTES", to_string(nat_translations_bytes));
    values.push_back(q);

    m_countersTwiceNatTable.set(natKey, values);
}

void NatOrch::updateTwiceNaptCounters(const TwiceNaptEntryKey &key,
                                      uint64_t nat_translations_pkts, uint64_t nat_translations_bytes)
{
    vector<swss::FieldValueTuple> values;
    string naptKey = (key.prototype + ":" + key.src_ip.to_string() + ":" + std::to_string(key.src_l4_port) +
                     ":" + key.dst_ip.to_string() + ":" + std::to_string(key.dst_l4_port));

    swss::FieldValueTuple p("NAT_TRANSLATIONS_PKTS", to_string(nat_translations_pkts));
    values.push_back(p);
    swss::FieldValueTuple q("NAT_TRANSLATIONS_BYTES", to_string(nat_translations_bytes));
    values.push_back(q);

    m_countersTwiceNaptTable.set(naptKey, values);
}

bool NatOrch::checkIfNatEntryIsActive(const NatEntry::iterator &iter, time_t now)
{
    const IpAddress   &ipAddr = iter->first;
    NatEntryValue     &entry  = iter->second;
    uint32_t          attr_count;
    IpAddress         srcIp;
    sai_attribute_t   nat_entry_attr[4] = {};
    sai_nat_entry_t   snat_entry = {};
    sai_nat_entry_t   dnat_entry;
    sai_status_t      status;

    if (entry.nat_type == "dnat")
    {
        /* Hitbits are queried for both directions when SNAT entry is checked */
        return 0;
    }

    if (entry.addedToHw == false)
    {
        SWSS_LOG_DEBUG("Skip get hitbits for %s NAT entry [ip %s], as not yet added to HW", entry.nat_type.c_str(), ipAddr.to_string().c_str());
        return 0;
    }

    if (entry.entry_type == "static")
    {
        /* Static NAT entries are always treated active */
        return 1;
    }

    nat_entry_attr[0].id             = SAI_NAT_ENTRY_ATTR_HIT_BIT;  /* Get the Hit bit */
    nat_entry_attr[0].value.booldata = 0;
    nat_entry_attr[1].id             = SAI_NAT_ENTRY_ATTR_HIT_BIT_COR; /* clear the hit bit after returning the value */
    nat_entry_attr[1].value.booldata = 1;

    attr_count = 2;

    snat_entry.vr_id                 = gVirtualRouterId;
    snat_entry.switch_id             = gSwitchId;
    snat_entry.nat_type              = SAI_NAT_TYPE_SOURCE_NAT;
    srcIp     = ipAddr;
    snat_entry.data.key.src_ip   = srcIp.getV4Addr();
    snat_entry.data.mask.src_ip  = 0xffffffff;

    status = sai_nat_api->get_nat_entry_attribute(&snat_entry, attr_count, nat_entry_attr);
    if (status == SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_DEBUG("SNAT HIT BIT for src-ip %s = %d", srcIp.to_string().c_str(),
                      nat_entry_attr[0].value.booldata);

        if (nat_entry_attr[0].value.booldata)
        {
            entry.ageOutTime = now + timeout;
            return 1;
        }
        else
        {
            auto dnatIter = m_natEntries.find(entry.translated_ip);
            if (dnatIter == m_natEntries.end())
            {
                return 0;
            }
            if ((dnatIter->second).addedToHw == false)
            {
                return 0;
            }

            /* If SNAT HitBit is not set, check for the HitBit in the reverse direction */
            memset(&dnat_entry, 0, sizeof(dnat_entry));

            dnat_entry.vr_id             = gVirtualRouterId;
            dnat_entry.switch_id         = gSwitchId;
            dnat_entry.nat_type          = SAI_NAT_TYPE_DESTINATION_NAT;
            dnat_entry.data.key.dst_ip   = entry.translated_ip.getV4Addr();
            dnat_entry.data.mask.dst_ip  = 0xffffffff;

            status = sai_nat_api->get_nat_entry_attribute(&dnat_entry, attr_count, nat_entry_attr);
            if (status == SAI_STATUS_SUCCESS)
            {
                SWSS_LOG_DEBUG("DNAT HIT BIT for dst-ip %s = %d", entry.translated_ip.to_string().c_str(),
                                nat_entry_attr[0].value.booldata);
                if (nat_entry_attr[0].value.booldata)
                {
                    entry.ageOutTime = now + timeout;
                    return 1;
                }
            }
        }
    }
    return 0;
}

bool NatOrch::checkIfNaptEntryIsActive(const NaptEntry::iterator &iter, time_t now)
{
    const NaptEntryKey &naptKey    = iter->first;
    NaptEntryValue     &entry      = iter->second;
    int                protoType   = ((naptKey.prototype == "TCP") ? IPPROTO_TCP : IPPROTO_UDP);
    uint32_t           attr_count;
    IpAddress          srcIp;
    uint16_t           srcPort;
    sai_attribute_t    nat_entry_attr[4] = {};
    sai_nat_entry_t    snat_entry = {};
    sai_nat_entry_t    dnat_entry;
    sai_status_t       status;

    if (entry.nat_type == "dnat")
    {
        /* Hitbits are queried for both directions when SNAT entry is checked */
        return 0;
    }

    if (entry.addedToHw == false)
    {
        SWSS_LOG_DEBUG("Skip get hitbits for %s NAPT entry for [proto %s, ip %s, port %d], as not yet added to HW",
                       entry.nat_type.c_str(), naptKey.prototype.c_str(), naptKey.ip_address.to_string().c_str(), naptKey.l4_port);
        return 0;
    }

    if (entry.entry_type == "static")
    {
        /* Static NAPT entries are always treated active */
        return 1;
    }

    nat_entry_attr[0].id             = SAI_NAT_ENTRY_ATTR_HIT_BIT;  /* Get the Hit bit */
    nat_entry_attr[0].value.booldata = 0;
    nat_entry_attr[1].id             = SAI_NAT_ENTRY_ATTR_HIT_BIT_COR; /* clear the hit bit after returning the value */
    nat_entry_attr[1].value.booldata = 1;

    attr_count = 2;

    snat_entry.vr_id                 = gVirtualRouterId;
    snat_entry.switch_id             = gSwitchId;
    snat_entry.nat_type              = SAI_NAT_TYPE_SOURCE_NAT;

    srcIp     = naptKey.ip_address;
    srcPort   = (uint16_t)(naptKey.l4_port);
    snat_entry.data.key.src_ip       = srcIp.getV4Addr();
    snat_entry.data.key.l4_src_port  = srcPort;

    snat_entry.data.mask.src_ip      = 0xffffffff;
    snat_entry.data.mask.l4_src_port = 0xffff;
    snat_entry.data.key.proto        = (uint8_t)protoType;
    snat_entry.data.mask.proto       = 0xff;

    status = sai_nat_api->get_nat_entry_attribute(&snat_entry, attr_count, nat_entry_attr);
    if (status == SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_DEBUG("SNAPT HIT BIT for proto %s, src-ip %s, src-port %d = %d", naptKey.prototype.c_str(),
                      srcIp.to_string().c_str(), srcPort, nat_entry_attr[0].value.booldata);
        if (nat_entry_attr[0].value.booldata)
        {
            entry.ageOutTime = now + ((protoType == IPPROTO_TCP) ? tcp_timeout : udp_timeout);
            return 1;
        }
        else
        {
            NaptEntryKey dnaptKey;
            dnaptKey.ip_address = entry.translated_ip;
            dnaptKey.l4_port    = entry.translated_l4_port;
            dnaptKey.prototype  = naptKey.prototype;

            auto dnaptIter = m_naptEntries.find(dnaptKey);
            if (dnaptIter == m_naptEntries.end())
            {
                return 0;
            }
            if ((dnaptIter->second).addedToHw == false)
            {
                return 0;
            }


            /* If SNAPT HitBit is not set, check for the HitBit in the reverse direction */
            memset(&dnat_entry, 0, sizeof(dnat_entry));

            dnat_entry.vr_id                 = gVirtualRouterId;
            dnat_entry.switch_id             = gSwitchId;
            dnat_entry.nat_type              = SAI_NAT_TYPE_DESTINATION_NAT;

            dnat_entry.data.key.dst_ip       = entry.translated_ip.getV4Addr();
            dnat_entry.data.key.l4_dst_port  = (uint16_t)(entry.translated_l4_port);

            dnat_entry.data.mask.dst_ip      = 0xffffffff;
            dnat_entry.data.mask.l4_dst_port = 0xffff;
            dnat_entry.data.key.proto        = (uint8_t)protoType;
            dnat_entry.data.mask.proto       = 0xff;

            status = sai_nat_api->get_nat_entry_attribute(&dnat_entry, attr_count, nat_entry_attr);
            if (status == SAI_STATUS_SUCCESS)
            {
                SWSS_LOG_DEBUG("DNAPT HIT BIT for proto %s, dst-ip %s, dst-port %d = %d", naptKey.prototype.c_str(),
                              entry.translated_ip.to_string().c_str(), entry.translated_l4_port, nat_entry_attr[0].value.booldata);
                if (nat_entry_attr[0].value.booldata)
                {
                    entry.ageOutTime = now + ((protoType == IPPROTO_TCP) ? tcp_timeout : udp_timeout);
                    return 1;
                }
            }
        }
    }
    return 0;
}

bool NatOrch::checkIfTwiceNatEntryIsActive(const TwiceNatEntry::iterator &iter, time_t now)
{
    const TwiceNatEntryKey &key    = iter->first;
    TwiceNatEntryValue     &entry  = iter->second;
    uint32_t           attr_count;
    sai_attribute_t    nat_entry_attr[4] = {};
    sai_nat_entry_t    dbl_nat_entry = {};
    sai_status_t       status;

    if (entry.entry_type == "static")
    {
        /* Static NAPT entries are always treated active */
        return 1;
    }

    if (entry.addedToHw == false)
    {
        SWSS_LOG_DEBUG("Skip get hitbits for Twice NAPT entry for [src ip %s, dst-ip %s], as not yet added to HW",
                       key.src_ip.to_string().c_str(), key.dst_ip.to_string().c_str());
        return 0;
    }

    nat_entry_attr[0].id             = SAI_NAT_ENTRY_ATTR_HIT_BIT;  /* Get the Hit bit */
    nat_entry_attr[0].value.booldata = 0;
    nat_entry_attr[1].id             = SAI_NAT_ENTRY_ATTR_HIT_BIT_COR; /* clear the hit bit after returning the value */
    nat_entry_attr[1].value.booldata = 1;

    attr_count = 2;

    dbl_nat_entry.vr_id = gVirtualRouterId;
    dbl_nat_entry.switch_id = gSwitchId;
    dbl_nat_entry.nat_type = SAI_NAT_TYPE_DOUBLE_NAT;
    dbl_nat_entry.data.key.src_ip = key.src_ip.getV4Addr();
    dbl_nat_entry.data.mask.src_ip = 0xffffffff;
    dbl_nat_entry.data.key.dst_ip = key.dst_ip.getV4Addr();
    dbl_nat_entry.data.mask.dst_ip = 0xffffffff;

    status = sai_nat_api->get_nat_entry_attribute(&dbl_nat_entry, attr_count, nat_entry_attr);
    if (status == SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_DEBUG("Twice NAT HIT BIT for src-ip %s, dst-ip %s = %d",
                       key.src_ip.to_string().c_str(), key.dst_ip.to_string().c_str(), nat_entry_attr[0].value.booldata);
        if (nat_entry_attr[0].value.booldata)
        {
            entry.ageOutTime = now + timeout;
            return 1;
        }
    }
    return 0;
}

bool NatOrch::checkIfTwiceNaptEntryIsActive(const TwiceNaptEntry::iterator &iter, time_t now)
{
    const TwiceNaptEntryKey &key   = iter->first;
    TwiceNaptEntryValue     &entry = iter->second;
    uint8_t            protoType   = ((key.prototype == "TCP") ? IPPROTO_TCP : IPPROTO_UDP);
    uint32_t           attr_count;
    sai_attribute_t    nat_entry_attr[4] = {};
    sai_nat_entry_t    dbl_nat_entry = {};
    sai_status_t       status;

    if (entry.addedToHw == false)
    {
        SWSS_LOG_DEBUG("Skip get hitbits for Twice NAPT entry for [proto %s, src ip %s, src port %d, dst ip %s, dst port %d], as not yet added to HW",
                        key.prototype.c_str(), key.src_ip.to_string().c_str(), key.src_l4_port, key.dst_ip.to_string().c_str(), key.dst_l4_port);
        return 0;
    }

    if (entry.entry_type == "static")
    {
        /* Static NAPT entries are always treated active */
        return 1;
    }

    nat_entry_attr[0].id             = SAI_NAT_ENTRY_ATTR_HIT_BIT;  /* Get the Hit bit */
    nat_entry_attr[0].value.booldata = 0;
    nat_entry_attr[1].id             = SAI_NAT_ENTRY_ATTR_HIT_BIT_COR; /* clear the hit bit after returning the value */
    nat_entry_attr[1].value.booldata = 1;

    attr_count = 2;

    dbl_nat_entry.vr_id = gVirtualRouterId;
    dbl_nat_entry.switch_id = gSwitchId;
    dbl_nat_entry.nat_type = SAI_NAT_TYPE_DOUBLE_NAT;
    dbl_nat_entry.data.key.src_ip = key.src_ip.getV4Addr();
    dbl_nat_entry.data.mask.src_ip = 0xffffffff;
    dbl_nat_entry.data.key.l4_src_port = (uint16_t)(key.src_l4_port);
    dbl_nat_entry.data.mask.l4_src_port = 0xffff;
    dbl_nat_entry.data.key.dst_ip = key.dst_ip.getV4Addr();
    dbl_nat_entry.data.mask.dst_ip = 0xffffffff;
    dbl_nat_entry.data.key.l4_dst_port = (uint16_t)(key.dst_l4_port);
    dbl_nat_entry.data.mask.l4_dst_port = 0xffff;
    dbl_nat_entry.data.key.proto = protoType;
    dbl_nat_entry.data.mask.proto = 0xff;

    status = sai_nat_api->get_nat_entry_attribute(&dbl_nat_entry, attr_count, nat_entry_attr);
    if (status == SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_DEBUG("Twice NAPT HIT BIT for [proto %s, src ip %s, src port %d, dst ip %s, dst port %d] = %d",
                        key.prototype.c_str(), key.src_ip.to_string().c_str(), key.src_l4_port, key.dst_ip.to_string().c_str(), key.dst_l4_port,
                        nat_entry_attr[0].value.booldata);
        if (nat_entry_attr[0].value.booldata)
        {
            entry.ageOutTime = now + ((protoType == IPPROTO_TCP) ? tcp_timeout : udp_timeout);
            return 1;
        }
    }
    return 0;
}

void NatOrch::doTask(NotificationConsumer& consumer)
{
    SWSS_LOG_ENTER();

    std::string op;
    std::string data;
    std::vector<swss::FieldValueTuple> values;

    unique_lock<mutex> lock(m_natMutex);

    consumer.pop(op, data, values);

    if (&consumer == m_flushNotificationsConsumer)
    {
        if ((op == "STATISTICS") and (data == "ALL"))
        {
            SWSS_LOG_INFO("Received All Statistics notification");
            clearCounters();
        }
        else
        {
            SWSS_LOG_ERROR("Received unknown flush nat request");
        }
    }
    else if (&consumer == m_cleanupNotificationConsumer)
    {
        SWSS_LOG_NOTICE("Received RedisDB and ASIC  cleanup notification on NAT docker stop");
        cleanupAppDbEntries();
    }
}

void NatOrch::updateStaticNatCounters(int count)
{
    std::vector<swss::FieldValueTuple> values;
    std::string key = "Values";

    swss::FieldValueTuple p("STATIC_NAT_ENTRIES", to_string(count));
    values.push_back(p);

    m_countersGlobalNatTable.set(key, values);
}

void NatOrch::updateStaticNaptCounters(int count)
{
    std::vector<swss::FieldValueTuple> values;
    std::string key = "Values";

    swss::FieldValueTuple p("STATIC_NAPT_ENTRIES", to_string(count));
    values.push_back(p);

    m_countersGlobalNatTable.set(key, values);
}

void NatOrch::updateStaticTwiceNatCounters(int count)
{
    std::vector<swss::FieldValueTuple> values;
    std::string key = "Values";

    swss::FieldValueTuple p("STATIC_TWICE_NAT_ENTRIES", to_string(count));
    values.push_back(p);

    m_countersGlobalNatTable.set(key, values);
}

void NatOrch::updateStaticTwiceNaptCounters(int count)
{
    std::vector<swss::FieldValueTuple> values;
    std::string key = "Values";

    swss::FieldValueTuple p("STATIC_TWICE_NAPT_ENTRIES", to_string(count));
    values.push_back(p);

    m_countersGlobalNatTable.set(key, values);
}

void NatOrch::updateDynamicNatCounters(int count)
{
    std::vector<swss::FieldValueTuple> values;
    std::string key = "Values";

    swss::FieldValueTuple p("DYNAMIC_NAT_ENTRIES", to_string(count));
    values.push_back(p);

    m_countersGlobalNatTable.set(key, values);
}

void NatOrch::updateDynamicNaptCounters(int count)
{
    std::vector<swss::FieldValueTuple> values;
    std::string key = "Values";

    swss::FieldValueTuple p("DYNAMIC_NAPT_ENTRIES", to_string(count));
    values.push_back(p);

    m_countersGlobalNatTable.set(key, values);
}

void NatOrch::updateDynamicTwiceNatCounters(int count)
{
    std::vector<swss::FieldValueTuple> values;
    std::string key = "Values";

    swss::FieldValueTuple p("DYNAMIC_TWICE_NAT_ENTRIES", to_string(count));
    values.push_back(p);

    m_countersGlobalNatTable.set(key, values);
}

void NatOrch::updateDynamicTwiceNaptCounters(int count)
{
    std::vector<swss::FieldValueTuple> values;
    std::string key = "Values";

    swss::FieldValueTuple p("DYNAMIC_TWICE_NAPT_ENTRIES", to_string(count));
    values.push_back(p);

    m_countersGlobalNatTable.set(key, values);
}

void NatOrch::updateSnatCounters(int count)
{
    std::vector<swss::FieldValueTuple> values;
    std::string key = "Values";

    swss::FieldValueTuple p("SNAT_ENTRIES", to_string(count));
    values.push_back(p);

    m_countersGlobalNatTable.set(key, values);
}

void NatOrch::updateDnatCounters(int count)
{
    std::vector<swss::FieldValueTuple> values;
    std::string key = "Values";

    swss::FieldValueTuple p("DNAT_ENTRIES", to_string(count));
    values.push_back(p);

    m_countersGlobalNatTable.set(key, values);
}

#ifdef DEBUG_FRAMEWORK
/* Dump all internal operational information */
bool NatOrch::debugdumpCLI(KeyOpFieldsValuesTuple t)
{
    SWSS_LOG_NOTICE("debugdumpcli called");
    debugdumpALL();

    return true;
}

void NatOrch::debugdumpALL()
{
    int                 count = 0;
    IpAddress           ipAddr;
    NatEntryValue       value;
    NaptEntryKey        naptKey;
    NaptEntryValue      naptValue;
    TwiceNatEntryKey    twiceNatKey;
    TwiceNatEntryValue  twiceNatValue;
    TwiceNaptEntryKey   twiceNaptKey;
    TwiceNaptEntryValue twiceNaptValue;
    struct timespec     time_now;

    SWSS_LOG_ENTER();

    unique_lock<mutex> lock(m_natMutex);

    if (clock_gettime (CLOCK_MONOTONIC, &time_now) < 0)
    {
        return;
    }

    SWSS_LOG_NOTICE("debugdumpall called");
    SWSS_DEBUG_PRINT(m_dbgCompName, "--- NatOrch Dump All Start --->");

    SWSS_DEBUG_PRINT(m_dbgCompName, "\nNatOrch Internal values");
    SWSS_DEBUG_PRINT(m_dbgCompName, "-----------------------");
    SWSS_DEBUG_PRINT(m_dbgCompName, "    Admin Mode    : %s", admin_mode.c_str());
    SWSS_DEBUG_PRINT(m_dbgCompName, "    Timeout       : %d", timeout);
    SWSS_DEBUG_PRINT(m_dbgCompName, "    TCP timeout   : %d", tcp_timeout);
    SWSS_DEBUG_PRINT(m_dbgCompName, "    UDP timeout   : %d", udp_timeout);
    SWSS_DEBUG_PRINT(m_dbgCompName, "    Total Entries : %d", totalEntries);
    SWSS_DEBUG_PRINT(m_dbgCompName, "    Total Static Nat Entries        : %d", totalStaticNatEntries);
    SWSS_DEBUG_PRINT(m_dbgCompName, "    Total Dynamic Nat Entries       : %d", totalDynamicNatEntries);
    SWSS_DEBUG_PRINT(m_dbgCompName, "    Total Static Napt Entries       : %d", totalStaticNaptEntries);
    SWSS_DEBUG_PRINT(m_dbgCompName, "    Total Dynamic Napt Entries      : %d", totalDynamicNaptEntries);
    SWSS_DEBUG_PRINT(m_dbgCompName, "    Total Static Twice Nat Entries  : %d", totalStaticTwiceNatEntries);
    SWSS_DEBUG_PRINT(m_dbgCompName, "    Total Dynamic Twice Nat Entries : %d", totalDynamicTwiceNatEntries);
    SWSS_DEBUG_PRINT(m_dbgCompName, "    Total Static Twice Napt Entries : %d", totalStaticTwiceNaptEntries);
    SWSS_DEBUG_PRINT(m_dbgCompName, "    Total Dynamic Twice Napt Entries: %d", totalDynamicTwiceNaptEntries);
    SWSS_DEBUG_PRINT(m_dbgCompName, "    Total Snat Entries              : %d", totalSnatEntries);
    SWSS_DEBUG_PRINT(m_dbgCompName, "    Total Dnat Entries              : %d", totalDnatEntries);
    SWSS_DEBUG_PRINT(m_dbgCompName, "    Max allowed NAT entries         : %d", maxAllowedSNatEntries);

    SWSS_DEBUG_PRINT(m_dbgCompName, "\n\nNatOrch NAT entries Cache");
    SWSS_DEBUG_PRINT(m_dbgCompName, "--------------------------");

    auto natIter = m_natEntries.begin();
    while (natIter != m_natEntries.end())
    {
        ipAddr = natIter->first;
        value  = natIter->second;
        count++;
        SWSS_DEBUG_PRINT(m_dbgCompName, "%8d.  IP: %s", count, ipAddr.to_string().c_str());
        SWSS_DEBUG_PRINT(m_dbgCompName, "             Translated IP: %s, NAT Type: %s, Entry Type: %s",
                         value.translated_ip.to_string().c_str(), value.nat_type.c_str(), value.entry_type.c_str());
        SWSS_DEBUG_PRINT(m_dbgCompName, "             Age-out time: %" PRId64 " secs, Added-to-Hw: %s",
                         (value.ageOutTime - time_now.tv_sec), ((value.addedToHw) ? "Yes" : "No"));
        natIter++;
    }
    count = 0;
    SWSS_DEBUG_PRINT(m_dbgCompName, "\n\nNatOrch NAPT entries Cache");
    SWSS_DEBUG_PRINT(m_dbgCompName, "--------------------------");

    auto naptIter = m_naptEntries.begin();
    while (naptIter != m_naptEntries.end())
    {
        naptKey    = naptIter->first;
        naptValue  = naptIter->second;
        count++;
        SWSS_DEBUG_PRINT(m_dbgCompName, "%8d.  IP: %s, L4 Port: %d, Proto: %s", count,
                         naptKey.ip_address.to_string().c_str(), naptKey.l4_port, naptKey.prototype.c_str());
        SWSS_DEBUG_PRINT(m_dbgCompName, "             Translated IP: %s, L4 Port: %d, NAT Type: %s, Entry Type: %s",
                         naptValue.translated_ip.to_string().c_str(), naptValue.translated_l4_port,
                         naptValue.nat_type.c_str(), naptValue.entry_type.c_str());
        SWSS_DEBUG_PRINT(m_dbgCompName, "             Age-out time: %" PRId64 " secs, Added-to-Hw: %s",
                         (naptValue.ageOutTime - time_now.tv_sec), ((naptValue.addedToHw) ? "Yes" : "No"));
        naptIter++;
    }
    count = 0;

    SWSS_DEBUG_PRINT(m_dbgCompName, "\n\nNatOrch Twice NAT entries Cache");
    SWSS_DEBUG_PRINT(m_dbgCompName, "-------------------------------");

    auto twiceNatIter = m_twiceNatEntries.begin();
    while (twiceNatIter != m_twiceNatEntries.end())
    {
        twiceNatKey    = twiceNatIter->first;
        twiceNatValue  = twiceNatIter->second;
        count++;
        SWSS_DEBUG_PRINT(m_dbgCompName, "%8d.  Src IP: %s, Dst IP: %s", count,
                         twiceNatKey.src_ip.to_string().c_str(), twiceNatKey.dst_ip.to_string().c_str());
        SWSS_DEBUG_PRINT(m_dbgCompName, "             Translated Src IP: %s, Dst IP: %s, Entry Type: %s",
                         twiceNatValue.translated_src_ip.to_string().c_str(), twiceNatValue.translated_dst_ip.to_string().c_str(),
                         twiceNatValue.entry_type.c_str());
        SWSS_DEBUG_PRINT(m_dbgCompName, "             Age-out time: %" PRId64 " secs, Added-to-Hw: %s",
                         (twiceNatValue.ageOutTime - time_now.tv_sec), ((twiceNatValue.addedToHw) ? "Yes" : "No"));
        twiceNatIter++;
    }
    count = 0;

    SWSS_DEBUG_PRINT(m_dbgCompName, "\n\nNatOrch Twice NAPT entries Cache");
    SWSS_DEBUG_PRINT(m_dbgCompName, "--------------------------------");

    auto twiceNaptIter = m_twiceNaptEntries.begin();
    while (twiceNaptIter != m_twiceNaptEntries.end())
    {
        twiceNaptKey    = twiceNaptIter->first;
        twiceNaptValue  = twiceNaptIter->second;
        count++;
        SWSS_DEBUG_PRINT(m_dbgCompName, "%8d.  Src IP: %s, L4 Port: %d, Dst IP: %s, L4 Port: %d, Proto: %s", count,
                         twiceNaptKey.src_ip.to_string().c_str(), twiceNaptKey.src_l4_port, twiceNaptKey.dst_ip.to_string().c_str(),
                         twiceNaptKey.dst_l4_port, twiceNaptKey.prototype.c_str());
        SWSS_DEBUG_PRINT(m_dbgCompName, "             Translated Src IP: %s, L4 Port: %d, Dst IP: %s, L4 Port: %d, Entry Type: %s",
                         twiceNaptValue.translated_src_ip.to_string().c_str(), twiceNaptValue.translated_src_l4_port,
                         twiceNaptValue.translated_dst_ip.to_string().c_str(), twiceNaptValue.translated_dst_l4_port,
                         twiceNaptValue.entry_type.c_str());
        SWSS_DEBUG_PRINT(m_dbgCompName, "             Age-out time: %" PRId64 " secs, Added-to-Hw: %s",
                         (twiceNaptValue.ageOutTime - time_now.tv_sec), ((twiceNaptValue.addedToHw) ? "Yes" : "No"));
        twiceNaptIter++;
    }
    count = 0;

    if (gNhTrackingSupported == true)
    {
        SWSS_DEBUG_PRINT(m_dbgCompName, "\n\nNatOrch Dump NextHop resolution entries Cache");
        SWSS_DEBUG_PRINT(m_dbgCompName, "---------------------------------------------");

        auto dnatNhIter = m_nhResolvCache.begin();
        while (dnatNhIter != m_nhResolvCache.end())
        {
            ipAddr = dnatNhIter->first;
            DnatEntries &dnatEntries = dnatNhIter->second;
            count++;
            SWSS_DEBUG_PRINT(m_dbgCompName, "%8d. Translated DNAT IP: %s, neighResolved: %d", count,
                             ipAddr.to_string().c_str(), dnatEntries.neighResolved);
            if (dnatEntries.nextHopGroup != NextHopGroupKey())
            {
                SWSS_DEBUG_PRINT(m_dbgCompName, "          NextHop Group: %s", dnatEntries.nextHopGroup.to_string().c_str());
            }
            if (dnatEntries.dnatIp != nullIpv4Addr)
            {
                SWSS_DEBUG_PRINT(m_dbgCompName, "             DNAT Entry Key: DIP %s", dnatEntries.dnatIp.to_string().c_str());
            }
            if (! dnatEntries.dnapt.empty())
            {
                auto iter1 = dnatEntries.dnapt.begin();
                while (iter1 != dnatEntries.dnapt.end())
                {
                    SWSS_DEBUG_PRINT(m_dbgCompName, "             DNAPT entry Key: DIP %s, Port %d, Proto %s",
                                     (*iter1).ip_address.to_string().c_str(), (*iter1).l4_port, (*iter1).prototype.c_str());
                    iter1++;
                }
            }
            if (! dnatEntries.twiceNat.empty())
            {
                auto iter2 = dnatEntries.twiceNat.begin();
                while (iter2 != dnatEntries.twiceNat.end())
                {
                    SWSS_DEBUG_PRINT(m_dbgCompName, "             Twice NAT entry key: Src IP: %s, Dst IP: %s",
                                     (*iter2).src_ip.to_string().c_str(), (*iter2).dst_ip.to_string().c_str());
                    iter2++;
                }
            }
            if (! dnatEntries.twiceNapt.empty())
            {
                auto iter3 = dnatEntries.twiceNapt.begin();
                while (iter3 != dnatEntries.twiceNapt.end())
                {
                    SWSS_DEBUG_PRINT(m_dbgCompName, "             Twice NAPT entry key: Src IP: %s, L4 Port: %d, Dst IP: %s, L4 Port: %d, Proto: %s",
                                     (*iter3).src_ip.to_string().c_str(), (*iter3).src_l4_port,
                                     (*iter3).dst_ip.to_string().c_str(), (*iter3).dst_l4_port, (*iter3).prototype.c_str());
                    iter3++;
                }
            }
            dnatNhIter++;
        }
    }
}
#endif

task_process_status NatOrch::handleSaiCreateStatus(sai_api_t api, sai_status_t status, void* context)
{
    if (status == SAI_STATUS_SUCCESS)
    {
        return task_process_status::task_success;
    }

    return task_process_status::task_failed;
}

task_process_status NatOrch::handleSaiSetStatus(sai_api_t api, sai_status_t status, void* context)
{
    if (status == SAI_STATUS_SUCCESS)
    {
        return task_process_status::task_success;
    }

    return task_process_status::task_failed;
}

task_process_status NatOrch::handleSaiRemoveStatus(sai_api_t api, sai_status_t status, void* context)
{
    if (status == SAI_STATUS_SUCCESS)
    {
        return task_process_status::task_success;
    }

    return task_process_status::task_failed;
}

task_process_status NatOrch::handleSaiGetStatus(sai_api_t api, sai_status_t status, void* context)
{
    if (status == SAI_STATUS_SUCCESS)
    {
        return task_process_status::task_success;
    }

    return task_process_status::task_failed;
}
