/** @file moal_sta_cfg80211.c
  *
  * @brief This file contains the functions for STA CFG80211.
  *
  *
  * Copyright 2014-2020 NXP
  *
  * This software file (the File) is distributed by NXP
  * under the terms of the GNU General Public License Version 2, June 1991
  * (the License).  You may use, redistribute and/or modify the File in
  * accordance with the terms and conditions of the License, a copy of which
  * is available by writing to the Free Software Foundation, Inc.,
  * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA or on the
  * worldwide web at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
  *
  * THE FILE IS DISTRIBUTED AS-IS, WITHOUT WARRANTY OF ANY KIND, AND THE
  * IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE
  * ARE EXPRESSLY DISCLAIMED.  The License provides additional details about
  * this warranty disclaimer.
  *
  */

#include "moal_cfg80211.h"
#include "moal_cfgvendor.h"
#include "moal_sta_cfg80211.h"
#include "moal_eth_ioctl.h"
#ifdef UAP_SUPPORT
#include    "moal_uap.h"
#endif
#include <linux/sort.h>

extern int cfg80211_wext;

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
extern int dfs_offload;
#endif

extern int cntry_txpwr;

/* Supported crypto cipher suits to be advertised to cfg80211 */
const u32 cfg80211_cipher_suites[] = {
	WLAN_CIPHER_SUITE_WEP40,
	WLAN_CIPHER_SUITE_WEP104,
	WLAN_CIPHER_SUITE_TKIP,
	WLAN_CIPHER_SUITE_CCMP,
	WLAN_CIPHER_SUITE_SMS4,
	WLAN_CIPHER_SUITE_AES_CMAC,
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	WLAN_CIPHER_SUITE_CCMP_256,
#endif
};

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
static int woal_cfg80211_set_monitor_channel(struct wiphy *wiphy,
					     struct cfg80211_chan_def *chandef);
#endif
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
static void
#else
static int
#endif

woal_cfg80211_reg_notifier(struct wiphy *wiphy,
			   struct regulatory_request *request);

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)
static int woal_cfg80211_scan(struct wiphy *wiphy,
			      struct cfg80211_scan_request *request);
#else
static int woal_cfg80211_scan(struct wiphy *wiphy, struct net_device *dev,
			      struct cfg80211_scan_request *request);
#endif
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(4,5,0)
static void woal_cfg80211_abort_scan(struct wiphy *wiphy,
				     struct wireless_dev *wdev);
#endif
static int woal_cfg80211_connect(struct wiphy *wiphy, struct net_device *dev,
				 struct cfg80211_connect_params *sme);

static int woal_cfg80211_disconnect(struct wiphy *wiphy,
				    struct net_device *dev, t_u16 reason_code);

static int woal_cfg80211_deauthenticate(struct wiphy *wiphy,
					struct net_device *dev,
					struct cfg80211_deauth_request *req);

static int woal_cfg80211_disassociate(struct wiphy *wiphy,
				      struct net_device *dev,
				      struct cfg80211_disassoc_request *req);

static int woal_cfg80211_get_station(struct wiphy *wiphy,
				     struct net_device *dev,
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 16, 0)
				     const t_u8 *mac,
#else
				     t_u8 *mac,
#endif
				     struct station_info *sinfo);

static int woal_cfg80211_dump_station(struct wiphy *wiphy,
				      struct net_device *dev, int idx,
				      t_u8 *mac, struct station_info *sinfo);

static int woal_cfg80211_dump_survey(struct wiphy *wiphy,
				     struct net_device *dev, int idx,
				     struct survey_info *survey);
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
static int woal_cfg80211_get_channel(struct wiphy *wiphy,
				     struct wireless_dev *wdev,
				     struct cfg80211_chan_def *chandef);
#endif
static int woal_cfg80211_set_power_mgmt(struct wiphy *wiphy,
					struct net_device *dev, bool enabled,
					int timeout);
#if CFG80211_VERSION_CODE > KERNEL_VERSION(2, 6, 35)
static int woal_cfg80211_set_cqm_rssi_config(struct wiphy *wiphy,
					     struct net_device *dev,
					     s32 rssi_thold, u32 rssi_hyst);
#endif

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(2, 6, 31)
static int woal_cfg80211_get_tx_power(struct wiphy *wiphy,
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
				      struct wireless_dev *wdev,
#endif
				      int *dbm);

static int woal_cfg80211_set_tx_power(struct wiphy *wiphy,
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
				      struct wireless_dev *wdev,
#endif
#if CFG80211_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
				      enum tx_power_setting type,
#else
				      enum nl80211_tx_power_setting type,
#endif
				      int dbm);
#endif

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
static int woal_cfg80211_mgmt_tx_cancel_wait(struct wiphy *wiphy,
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)
					     struct wireless_dev *wdev,
#else
					     struct net_device *dev,
#endif
					     u64 cookie);

static int woal_cfg80211_remain_on_channel(struct wiphy *wiphy,
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)
					   struct wireless_dev *wdev,
#else
					   struct net_device *dev,
#endif
					   struct ieee80211_channel *chan,
#if CFG80211_VERSION_CODE < KERNEL_VERSION(3, 8, 0)
					   enum nl80211_channel_type
					   channel_type,
#endif
					   unsigned int duration, u64 * cookie);

static int woal_cfg80211_cancel_remain_on_channel(struct wiphy *wiphy,
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)
						  struct wireless_dev *wdev,
#else
						  struct net_device *dev,
#endif
						  u64 cookie);
#endif /* KERNEL_VERSION */

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)
int woal_cfg80211_sched_scan_start(struct wiphy *wiphy,
				   struct net_device *dev,
				   struct cfg80211_sched_scan_request *request);
int woal_cfg80211_sched_scan_stop(struct wiphy *wiphy, struct net_device *dev
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
				  , u64 reqid
#endif
	);
#endif

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)
int woal_cfg80211_resume(struct wiphy *wiphy);
int woal_cfg80211_suspend(struct wiphy *wiphy, struct cfg80211_wowlan *wow);
#endif

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
static void woal_cfg80211_set_wakeup(struct wiphy *wiphy, bool enabled);
#endif

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3,2,0)
static int
 woal_cfg80211_change_station(struct wiphy *wiphy, struct net_device *dev,
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 16, 0)
			      const u8 *mac,
#else
			      u8 *mac,
#endif
			      struct station_parameters *params);
#endif
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3,10,0)
int woal_cfg80211_update_ft_ies(struct wiphy *wiphy, struct net_device *dev,
				struct cfg80211_update_ft_ies_params *ftie);
#endif
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
static int woal_cfg80211_authenticate(struct wiphy *wiphy,
				      struct net_device *dev,
				      struct cfg80211_auth_request *req);

static int woal_cfg80211_associate(struct wiphy *wiphy,
				   struct net_device *dev,
				   struct cfg80211_assoc_request *req);

#ifdef UAP_SUPPORT
int woal_cfg80211_uap_add_station(struct wiphy *wiphy, struct net_device *dev,
				  u8 *mac, struct station_parameters *params);
#endif
#endif

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3,2,0)
static int
 woal_cfg80211_add_station(struct wiphy *wiphy, struct net_device *dev,
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 16, 0)
			   const u8 *mac,
#else
			   u8 *mac,
#endif
			   struct station_parameters *params);
#endif

/** cfg80211 operations */
static struct cfg80211_ops woal_cfg80211_ops = {
	.change_virtual_intf = woal_cfg80211_change_virtual_intf,
	.scan = woal_cfg80211_scan,
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(4,5,0)
	.abort_scan = woal_cfg80211_abort_scan,
#endif
	.connect = woal_cfg80211_connect,
	.disconnect = woal_cfg80211_disconnect,
	.deauth = woal_cfg80211_deauthenticate,
	.disassoc = woal_cfg80211_disassociate,
	.get_station = woal_cfg80211_get_station,
	.dump_station = woal_cfg80211_dump_station,
	.dump_survey = woal_cfg80211_dump_survey,
	.set_wiphy_params = woal_cfg80211_set_wiphy_params,
#if CFG80211_VERSION_CODE < KERNEL_VERSION(3, 5, 0)
	.set_channel = woal_cfg80211_set_channel,
#endif
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
	.get_channel = woal_cfg80211_get_channel,
#endif
	.add_key = woal_cfg80211_add_key,
	.del_key = woal_cfg80211_del_key,
	.set_default_key = woal_cfg80211_set_default_key,
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
	.set_default_mgmt_key = woal_cfg80211_set_default_mgmt_key,
#endif
	.set_pmksa = woal_cfg80211_set_pmksa,
	.del_pmksa = woal_cfg80211_del_pmksa,
	.flush_pmksa = woal_cfg80211_flush_pmksa,
	.set_power_mgmt = woal_cfg80211_set_power_mgmt,
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(2, 6, 31)
	.set_tx_power = woal_cfg80211_set_tx_power,
	.get_tx_power = woal_cfg80211_get_tx_power,
#endif
	.set_bitrate_mask = woal_cfg80211_set_bitrate_mask,
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)
	.sched_scan_start = woal_cfg80211_sched_scan_start,
	.sched_scan_stop = woal_cfg80211_sched_scan_stop,
#endif
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)
	.suspend = woal_cfg80211_suspend,
	.resume = woal_cfg80211_resume,
#endif
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
	.set_wakeup = woal_cfg80211_set_wakeup,
#endif
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(2, 6, 38)
	.set_antenna = woal_cfg80211_set_antenna,
	.get_antenna = woal_cfg80211_get_antenna,
#endif
#if CFG80211_VERSION_CODE > KERNEL_VERSION(2, 6, 35)
	.set_cqm_rssi_config = woal_cfg80211_set_cqm_rssi_config,
#endif
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3,2,0)
	.change_station = woal_cfg80211_change_station,
#endif
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3,10,0)
	.update_ft_ies = woal_cfg80211_update_ft_ies,
#endif
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3,14,0)
	.set_qos_map = woal_cfg80211_set_qos_map,
#endif
#ifdef UAP_CFG80211
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 12, 0)
	.set_coalesce = woal_cfg80211_set_coalesce,
#endif
	.add_virtual_intf = woal_cfg80211_add_virtual_intf,
	.del_virtual_intf = woal_cfg80211_del_virtual_intf,
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 4, 0)
	.start_ap = woal_cfg80211_add_beacon,
	.change_beacon = woal_cfg80211_set_beacon,
	.stop_ap = woal_cfg80211_del_beacon,
#else
	.add_beacon = woal_cfg80211_add_beacon,
	.set_beacon = woal_cfg80211_set_beacon,
	.del_beacon = woal_cfg80211_del_beacon,
#endif
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
	.change_bss = woal_cfg80211_change_bss,
#endif
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3,2,0)
	.add_station = woal_cfg80211_add_station,
#endif
	.del_station = woal_cfg80211_del_station,
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 1, 0)
	.set_txq_params = woal_cfg80211_set_txq_params,
#endif
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
	.set_mac_acl = woal_cfg80211_set_mac_acl,
#endif
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 12, 0)
	.start_radar_detection = woal_cfg80211_start_radar_detection,
	.channel_switch = woal_cfg80211_channel_switch,
#endif
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)
	.mgmt_frame_register = woal_cfg80211_mgmt_frame_register,
	.mgmt_tx = woal_cfg80211_mgmt_tx,
#endif
#endif

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
	.mgmt_tx_cancel_wait = woal_cfg80211_mgmt_tx_cancel_wait,
	.remain_on_channel = woal_cfg80211_remain_on_channel,
	.cancel_remain_on_channel = woal_cfg80211_cancel_remain_on_channel,
#endif

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
	.set_monitor_channel = woal_cfg80211_set_monitor_channel,
#endif
};

/** Region code mapping */
typedef struct _region_code_t {
    /** Region */
	t_u8 region[COUNTRY_CODE_LEN];
} region_code_t;

static const struct ieee80211_regdomain mrvl_regdom = {
	.n_reg_rules = 4,
	.alpha2 = "99",
	.reg_rules = {
		      /* IEEE 802.11b/g, channels 1..11 */
		      REG_RULE(2412 - 10, 2472 + 10, 40, 6, 20, 0),
		      /* If any */
		      /* IEEE 802.11 channel 14 - Only JP enables
		       * this and for 802.11b only
		       */
		      REG_RULE(2484 - 10, 2484 + 10, 20, 6, 20, 0),
		      /* IEEE 802.11a, channel 36..64 */
		      REG_RULE(5150 - 10, 5350 + 10, 80, 6, 20, 0),
		      /* IEEE 802.11a, channel 100..165 */
		      REG_RULE(5470 - 10, 5850 + 10, 80, 6, 20, 0),}
};

/********************************************************
				Local Variables
********************************************************/
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)
static const struct ieee80211_txrx_stypes
 ieee80211_mgmt_stypes[NUM_NL80211_IFTYPES] = {
	[NL80211_IFTYPE_STATION] = {
				    .tx = MBIT(IEEE80211_STYPE_ACTION >> 4) |
				    MBIT(IEEE80211_STYPE_PROBE_RESP >> 4),
				    .rx = MBIT(IEEE80211_STYPE_ACTION >> 4) |
				    MBIT(IEEE80211_STYPE_PROBE_REQ >> 4),
				    },
	[NL80211_IFTYPE_AP] = {
			       .tx = 0xffff,
			       .rx = MBIT(IEEE80211_STYPE_ASSOC_REQ >> 4) |
			       MBIT(IEEE80211_STYPE_REASSOC_REQ >> 4) |
			       MBIT(IEEE80211_STYPE_PROBE_REQ >> 4) |
			       MBIT(IEEE80211_STYPE_DISASSOC >> 4) |
			       MBIT(IEEE80211_STYPE_AUTH >> 4) |
			       MBIT(IEEE80211_STYPE_DEAUTH >> 4) |
			       MBIT(IEEE80211_STYPE_ACTION >> 4),
			       },
	[NL80211_IFTYPE_AP_VLAN] = {
				    .tx = 0x0000,
				    .rx = 0x0000,
				    },
	[NL80211_IFTYPE_MESH_POINT] = {
				       .tx = 0x0000,
				       .rx = 0x0000,
				       },

};
#endif

#if CFG80211_VERSION_CODE > KERNEL_VERSION(3, 0, 0)
/**
 * NOTE: types in all the sets must be equals to the
 * initial value of wiphy->interface_modes
 */
static const struct ieee80211_iface_limit cfg80211_ap_sta_limits[] = {
	{
	 .max = 4,
	 .types = MBIT(NL80211_IFTYPE_STATION)
#ifdef UAP_CFG80211
	 | MBIT(NL80211_IFTYPE_AP)
	 | MBIT(NL80211_IFTYPE_MONITOR)
#endif
	 }
};

static struct ieee80211_iface_combination cfg80211_iface_comb_ap_sta = {
	.limits = cfg80211_ap_sta_limits,
	.num_different_channels = 1,
	.n_limits = ARRAY_SIZE(cfg80211_ap_sta_limits),
	.max_interfaces = 4,
	.beacon_int_infra_match = MTRUE,
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 12, 0)
	.radar_detect_widths = MBIT(NL80211_CHAN_WIDTH_20_NOHT)
		| MBIT(NL80211_CHAN_WIDTH_20),
#endif
};
#endif

extern moal_handle *m_handle[];
extern int hw_test;
extern int ps_mode;
int disable_regd_by_driver = 1;
/** Region alpha2 string */
char *reg_alpha2;
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
int country_ie_ignore = 0;
int beacon_hints = 0;
#endif

/** Set configuration data of Tx power limitation */
extern char *txpwrlimit_cfg;

int cfg80211_drcs = 0;
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
int host_mlme = 0;
#endif

#ifdef CONFIG_PM
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
static const struct wiphy_wowlan_support wowlan_support = {
	.flags = WIPHY_WOWLAN_ANY | WIPHY_WOWLAN_MAGIC_PKT,
	.n_patterns = MAX_NUM_FILTERS,
	.pattern_min_len = 1,
	.pattern_max_len = WOWLAN_MAX_PATTERN_LEN,
	.max_pkt_offset = WOWLAN_MAX_OFFSET_LEN,
};
#endif
#endif

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 12, 0)
static const struct wiphy_coalesce_support coalesce_support = {
	.n_rules = COALESCE_MAX_RULES,
	.max_delay = MAX_COALESCING_DELAY,
	.n_patterns = COALESCE_MAX_FILTERS,
	.pattern_min_len = 1,
	.pattern_max_len = MAX_PATTERN_LEN,
	.max_pkt_offset = MAX_OFFSET_LEN,
};
#endif

/********************************************************
				Global Variables
********************************************************/

/********************************************************
				Local Functions
********************************************************/
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
static int
woal_cfg80211_set_monitor_channel(struct wiphy *wiphy,
				  struct cfg80211_chan_def *chandef)
{
	moal_handle *handle = (moal_handle *)woal_get_wiphy_priv(wiphy);
	moal_private *priv =
		(moal_private *)woal_get_priv(handle, MLAN_BSS_ROLE_STA);
	netmon_band_chan_cfg band_chan_cfg;
	t_u32 bandwidth = 0;
	int ret = -EFAULT;

	ENTER();

	if (handle->mon_if) {
		if (cfg80211_chandef_identical
		    (&handle->mon_if->chandef, chandef)) {
			ret = 0;
			goto done;
		}
		if (woal_is_any_interface_active(handle)) {
			PRINTM(MERROR,
			       "Cannot change monitor channel for an active"
			       " interface\n");
			goto done;
		}
		memset(&band_chan_cfg, 0x00, sizeof(band_chan_cfg));
		/* Set channel */
		band_chan_cfg.channel =
			ieee80211_frequency_to_channel(chandef->chan->
						       center_freq);
		/* Set band */
		if (chandef->chan->band == IEEE80211_BAND_2GHZ)
			band_chan_cfg.band |= (BAND_B | BAND_G);
		if (chandef->chan->band == IEEE80211_BAND_5GHZ)
			band_chan_cfg.band |= BAND_A;
		if (chandef->chan->band == IEEE80211_BAND_2GHZ)
			band_chan_cfg.band |= BAND_GN;
		if (chandef->chan->band == IEEE80211_BAND_5GHZ)
			band_chan_cfg.band |= BAND_AN;
		if (chandef->chan->band == IEEE80211_BAND_2GHZ)
			band_chan_cfg.band |= BAND_GAC;
		if (chandef->chan->band == IEEE80211_BAND_5GHZ)
			band_chan_cfg.band |= BAND_AAC;
		/* Set bandwidth */
		if (chandef->width == NL80211_CHAN_WIDTH_20)
			bandwidth = CHANNEL_BW_20MHZ;
		else if (chandef->width == NL80211_CHAN_WIDTH_40)
			bandwidth =
				chandef->center_freq1 >
				chandef->chan->
				center_freq ? CHANNEL_BW_40MHZ_ABOVE :
				CHANNEL_BW_40MHZ_BELOW;
		else if (chandef->width == NL80211_CHAN_WIDTH_80)
			bandwidth = CHANNEL_BW_80MHZ;
		band_chan_cfg.chan_bandwidth = bandwidth;

		if (MLAN_STATUS_SUCCESS !=
		    woal_set_net_monitor(priv, MOAL_IOCTL_WAIT, MTRUE, 0x7,
					 &band_chan_cfg)) {
			PRINTM(MERROR, "%s: woal_set_net_monitor fail\n",
			       __func__);
			ret = -EFAULT;
			goto done;
		}

		memcpy(&handle->mon_if->band_chan_cfg, &band_chan_cfg,
		       sizeof(handle->mon_if->band_chan_cfg));
		handle->mon_if->chandef = *chandef;

		if (handle->mon_if->chandef.chan)
			PRINTM(MINFO,
			       "set_monitor_channel+++ chan[band=%d center_freq=%d hw_value=%d] width=%d center_freq1=%d center_freq2=%d\n",
			       handle->mon_if->chandef.chan->band,
			       handle->mon_if->chandef.chan->center_freq,
			       handle->mon_if->chandef.chan->hw_value,
			       handle->mon_if->chandef.width,
			       handle->mon_if->chandef.center_freq1,
			       handle->mon_if->chandef.center_freq2);
		PRINTM(MINFO,
		       "set_monitor_channel+++ band=%x channel=%d bandwidth=%d\n",
		       handle->mon_if->band_chan_cfg.band,
		       handle->mon_if->band_chan_cfg.channel,
		       handle->mon_if->band_chan_cfg.chan_bandwidth);
		ret = 0;
	}

done:
	LEAVE();
	return ret;
}
#endif

/**
 *  @brief This function check cfg80211 special region code.
 *
 *  @param region_string         Region string
 *
 *  @return     MTRUE/MFALSE
 */
t_u8
is_cfg80211_special_region_code(char *region_string)
{
	t_u8 i;
	region_code_t cfg80211_special_region_code[] = {
		{"00 "}, {"99 "}, {"98 "}, {"97 "}
	};

	for (i = 0; i < COUNTRY_CODE_LEN && region_string[i]; i++)
		region_string[i] = toupper(region_string[i]);

	for (i = 0; i < ARRAY_SIZE(cfg80211_special_region_code); i++) {
		if (!memcmp(region_string,
			    cfg80211_special_region_code[i].region,
			    COUNTRY_CODE_LEN)) {
			PRINTM(MIOCTL, "special region code=%s\n",
			       region_string);
			return MTRUE;
		}
	}
	return MFALSE;
}

/**
 * @brief Get the encryption mode from cipher
 *
 * @param cipher        Cipher cuite
 * @param wpa_enabled   WPA enable or disable
 *
 * @return              MLAN_ENCRYPTION_MODE_*
 */
static int
woal_cfg80211_get_encryption_mode(t_u32 cipher, int *wpa_enabled)
{
	int encrypt_mode;

	ENTER();

	*wpa_enabled = 0;
	switch (cipher) {
	case MW_AUTH_CIPHER_NONE:
		encrypt_mode = MLAN_ENCRYPTION_MODE_NONE;
		break;
	case WLAN_CIPHER_SUITE_WEP40:
		encrypt_mode = MLAN_ENCRYPTION_MODE_WEP40;
		break;
	case WLAN_CIPHER_SUITE_WEP104:
		encrypt_mode = MLAN_ENCRYPTION_MODE_WEP104;
		break;
	case WLAN_CIPHER_SUITE_TKIP:
		encrypt_mode = MLAN_ENCRYPTION_MODE_TKIP;
		*wpa_enabled = 1;
		break;
	case WLAN_CIPHER_SUITE_CCMP:
		encrypt_mode = MLAN_ENCRYPTION_MODE_CCMP;
		*wpa_enabled = 1;
		break;
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	case WLAN_CIPHER_SUITE_CCMP_256:
		encrypt_mode = MLAN_ENCRYPTION_MODE_CCMP_256;
		*wpa_enabled = 1;
		break;
#endif
	default:
		encrypt_mode = -1;
	}

	LEAVE();
	return encrypt_mode;
}

/**
 *  @brief get associate failure status code
 *
 *  @param priv     Pointer to the moal_private driver data struct
 *
 *  @return         IEEE status code
 */
static int
woal_get_assoc_status(moal_private *priv)
{
	int ret = WLAN_STATUS_UNSPECIFIED_FAILURE;
	t_u16 status = (t_u16)(priv->assoc_status & 0xffff);
	t_u16 cap = (t_u16)(priv->assoc_status >> 16);

	switch (cap) {
	case 0xfffd:
	case 0xfffe:
		ret = status;
		break;
	case 0xfffc:
		ret = WLAN_STATUS_AUTH_TIMEOUT;
		break;
	default:
		break;
	}
	PRINTM(MCMND, "Assoc fail: status=%d, cap=0x%x, IEEE status=%d\n",
	       status, cap, ret);
	return ret;
}

/**
 *  @brief Check the pairwise or group cipher for
 *  WEP enabled or not
 *
 *  @param cipher       MLAN Cipher cuite
 *
 *  @return             1 -- enable or 0 -- disable
 */
static int
woal_cfg80211_is_alg_wep(t_u32 cipher)
{
	int alg = 0;
	ENTER();

	if (cipher == MLAN_ENCRYPTION_MODE_WEP40 ||
	    cipher == MLAN_ENCRYPTION_MODE_WEP104)
		alg = 1;

	LEAVE();
	return alg;
}

/**
 *  @brief Convert NL80211 interface type to MLAN_BSS_MODE_*
 *
 *  @param iftype   Interface type of NL80211
 *
 *  @return         Driver bss mode
 */
static t_u32
woal_nl80211_iftype_to_mode(enum nl80211_iftype iftype)
{
	switch (iftype) {
	case NL80211_IFTYPE_STATION:
		return MLAN_BSS_MODE_INFRA;
	case NL80211_IFTYPE_UNSPECIFIED:
	default:
		return MLAN_BSS_MODE_AUTO;
	}
}

/**
 *  @brief Control WPS Session Enable/Disable
 *
 *  @param priv     Pointer to the moal_private driver data struct
 *  @param enable   enable/disable flag
 *
 *  @return          0 --success, otherwise fail
 */
static int
woal_wps_cfg(moal_private *priv, int enable)
{
	int ret = 0;
	mlan_ds_wps_cfg *pwps = NULL;
	mlan_ioctl_req *req = NULL;
	mlan_status status = MLAN_STATUS_SUCCESS;

	ENTER();

	PRINTM(MINFO, "WOAL_WPS_SESSION\n");

	req = woal_alloc_mlan_ioctl_req(sizeof(mlan_ds_wps_cfg));
	if (req == NULL) {
		ret = -ENOMEM;
		goto done;
	}

	pwps = (mlan_ds_wps_cfg *)req->pbuf;
	req->req_id = MLAN_IOCTL_WPS_CFG;
	req->action = MLAN_ACT_SET;
	pwps->sub_command = MLAN_OID_WPS_CFG_SESSION;
	if (enable)
		pwps->param.wps_session = MLAN_WPS_CFG_SESSION_START;
	else
		pwps->param.wps_session = MLAN_WPS_CFG_SESSION_END;

	status = woal_request_ioctl(priv, req, MOAL_IOCTL_WAIT);
	if (status != MLAN_STATUS_SUCCESS) {
		ret = -EFAULT;
		goto done;
	}

done:
	if (status != MLAN_STATUS_PENDING)
		kfree(req);
	LEAVE();
	return ret;
}

/**
 * @brief configure ASSOC IE
 *
 * @param priv				A pointer to moal private structure
 * @param ie				A pointer to ie data
 * @param ie_len			The length of ie data
 * @param wait_option       wait option
 *
 * @return                  0 -- success, otherwise fail
 */
static int
woal_cfg80211_assoc_ies_cfg(moal_private *priv, t_u8 *ie, int ie_len,
			    t_u8 wait_option)
{
	int bytes_left = ie_len;
	t_u8 *pcurrent_ptr = ie;
	int total_ie_len;
	t_u8 element_len;
	int ret = MLAN_STATUS_SUCCESS;
	IEEEtypes_ElementId_e element_id;
	IEEEtypes_VendorSpecific_t *pvendor_ie;
	t_u8 wps_oui[] = { 0x00, 0x50, 0xf2, 0x04 };

	while (bytes_left >= 2) {
		element_id = (IEEEtypes_ElementId_e)(*((t_u8 *)pcurrent_ptr));
		element_len = *((t_u8 *)pcurrent_ptr + 1);
		total_ie_len = element_len + sizeof(IEEEtypes_Header_t);
		if (bytes_left < total_ie_len) {
			PRINTM(MERROR,
			       "InterpretIE: Error in processing IE, bytes left < IE length\n");
			bytes_left = 0;
			continue;
		}
		switch (element_id) {
		case RSN_IE:
			if (MLAN_STATUS_SUCCESS !=
			    woal_set_get_gen_ie(priv, MLAN_ACT_SET,
						pcurrent_ptr, &total_ie_len,
						wait_option)) {
				PRINTM(MERROR, "Fail to set RSN IE\n");
				ret = -EFAULT;
				goto done;
			}
			PRINTM(MIOCTL, "Set RSN IE\n");
			break;
		case VENDOR_SPECIFIC_221:
			pvendor_ie = (IEEEtypes_VendorSpecific_t *)pcurrent_ptr;
			if (!memcmp
			    (pvendor_ie->vend_hdr.oui, wps_oui,
			     sizeof(pvendor_ie->vend_hdr.oui)) &&
			    (pvendor_ie->vend_hdr.oui_type == wps_oui[3])) {
				PRINTM(MIOCTL, "Enable WPS session\n");
				woal_wps_cfg(priv, MTRUE);
			}
			if (MLAN_STATUS_SUCCESS !=
			    woal_set_get_gen_ie(priv, MLAN_ACT_SET,
						pcurrent_ptr, &total_ie_len,
						wait_option)) {
				PRINTM(MERROR,
				       "Fail to Set VENDOR SPECIFIC IE\n");
				ret = -EFAULT;
				goto done;
			}
			PRINTM(MIOCTL,
			       "Set VENDOR SPECIFIC IE, OUI: %02x:%02x:%02x:%02x\n",
			       pvendor_ie->vend_hdr.oui[0],
			       pvendor_ie->vend_hdr.oui[1],
			       pvendor_ie->vend_hdr.oui[2],
			       pvendor_ie->vend_hdr.oui_type);
			break;
		case MOBILITY_DOMAIN:
			break;
		case FAST_BSS_TRANSITION:
			if (MLAN_STATUS_SUCCESS !=
			    woal_set_get_gen_ie(priv, MLAN_ACT_SET,
						pcurrent_ptr, &total_ie_len,
						wait_option)) {
				PRINTM(MERROR,
				       "Fail to set"
				       "FAST_BSS_TRANSITION IE\n");
				ret = -EFAULT;
				goto done;
			}
			PRINTM(MIOCTL, "Set FAST_BSS_TRANSITION IE\n");
			break;
		case RIC:
			if (MLAN_STATUS_SUCCESS !=
			    woal_set_get_gen_ie(priv, MLAN_ACT_SET,
						pcurrent_ptr, &total_ie_len,
						wait_option)) {
				PRINTM(MERROR,
				       "Fail to set"
				       "RESOURCE INFORMATION CONTAINER IE\n");
				ret = -EFAULT;
				goto done;
			}
			PRINTM(MIOCTL,
			       "Set RESOURCE INFORMATION CONTAINER IE\n");
			break;
		case EXT_CAPABILITY:
			if (MLAN_STATUS_SUCCESS !=
			    woal_set_get_gen_ie(priv, MLAN_ACT_SET,
						pcurrent_ptr, &total_ie_len,
						wait_option)) {
				PRINTM(MERROR,
				       "Fail to set Extended Capabilites IE\n");
				ret = -EFAULT;
				goto done;
			}
			PRINTM(MIOCTL, "Set Extended Capabilities IE\n");
			break;
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
		case EXTENSION:
			if (MLAN_STATUS_SUCCESS !=
			    woal_set_get_gen_ie(priv, MLAN_ACT_SET,
						pcurrent_ptr, &total_ie_len,
						wait_option)) {
				PRINTM(MERROR, "Fail to set Extension IE\n");
				ret = -EFAULT;
				goto done;
			}
			PRINTM(MIOCTL, "Set Extension IE\n");
			break;
		case FRAGMENT:
			if (MLAN_STATUS_SUCCESS !=
			    woal_set_get_gen_ie(priv, MLAN_ACT_SET,
						pcurrent_ptr, &total_ie_len,
						wait_option)) {
				PRINTM(MERROR, "Fail to set Fragmented IE\n");
				ret = -EFAULT;
				goto done;
			}
			PRINTM(MIOCTL, "Set Fragmented IE\n");
			break;
#endif
		default:
			if (MLAN_STATUS_SUCCESS !=
			    woal_set_get_gen_ie(priv, MLAN_ACT_SET,
						pcurrent_ptr, &total_ie_len,
						wait_option)) {
				PRINTM(MERROR, "Fail to set GEN IE\n");
				ret = -EFAULT;
				goto done;
			}
			PRINTM(MIOCTL, "Set GEN IE\n");
			break;
		}
		pcurrent_ptr += element_len + 2;
		/* Need to account for IE ID and IE Len */
		bytes_left -= (element_len + 2);
	}
done:
	return ret;
}

/**
 * @brief Send domain info command to FW
 *
 * @param priv      A pointer to moal_private structure
 * @param wait_option  wait option
 *
 * @return          MLAN_STATUS_SUCCESS or MLAN_STATUS_FAILURE
 */
static mlan_status
woal_send_domain_info_cmd_fw(moal_private *priv, t_u8 wait_option)
{
	mlan_status ret = MLAN_STATUS_SUCCESS;
	enum ieee80211_band band;
	struct ieee80211_supported_band *sband = NULL;
	struct ieee80211_channel *channel = NULL;
	t_u8 no_of_sub_band = 0;
	t_u8 no_of_parsed_chan = 0;
	t_u8 first_chan = 0, next_chan = 0, max_pwr = 0;
	t_u8 i, flag = 0;
	mlan_ds_11d_cfg *cfg_11d = NULL;
	mlan_ioctl_req *req = NULL;
	mlan_status status = MLAN_STATUS_SUCCESS;

	ENTER();

	if (!priv->wdev || !priv->wdev->wiphy) {
		PRINTM(MERROR, "No wdev or wiphy in priv\n");
		ret = MLAN_STATUS_FAILURE;
		goto done;
	}
	band = priv->phandle->band;
	if (!priv->wdev->wiphy->bands[band]) {
		PRINTM(MERROR, "11D: setting domain info in FW failed band=%d",
		       band);
		ret = MLAN_STATUS_FAILURE;
		goto done;
	}

	if (MTRUE ==
	    is_cfg80211_special_region_code(priv->phandle->country_code)) {
		PRINTM(MIOCTL,
		       "skip region code config, cfg80211 special region code: %s\n",
		       priv->phandle->country_code);
		goto done;
	}
	PRINTM(MIOCTL, "Send domain info: country=%c%c band=%d\n",
	       priv->phandle->country_code[0], priv->phandle->country_code[1],
	       band);
	/* Allocate an IOCTL request buffer */
	req = woal_alloc_mlan_ioctl_req(sizeof(mlan_ds_11d_cfg));
	if (req == NULL) {
		ret = MLAN_STATUS_FAILURE;
		goto done;
	}
	cfg_11d = (mlan_ds_11d_cfg *)req->pbuf;
	cfg_11d->sub_command = MLAN_OID_11D_DOMAIN_INFO_EXT;
	req->req_id = MLAN_IOCTL_11D_CFG;
	req->action = MLAN_ACT_SET;

	/* Set country code */
	cfg_11d->param.domain_info.country_code[0] =
		priv->phandle->country_code[0];
	cfg_11d->param.domain_info.country_code[1] =
		priv->phandle->country_code[1];
	cfg_11d->param.domain_info.country_code[2] = ' ';
	cfg_11d->param.domain_info.band = band;

	sband = priv->wdev->wiphy->bands[band];
	for (i = 0; (i < sband->n_channels) &&
	     (no_of_sub_band < MRVDRV_MAX_SUBBAND_802_11D); i++) {
		channel = &sband->channels[i];
		if (channel->flags & IEEE80211_CHAN_DISABLED)
			continue;

		if (!flag) {
			flag = 1;
			next_chan = first_chan = (t_u32)channel->hw_value;
			max_pwr = channel->max_power;
			no_of_parsed_chan = 1;
			continue;
		}

		if (channel->hw_value == next_chan + 1 &&
		    channel->max_power == max_pwr) {
			next_chan++;
			no_of_parsed_chan++;
		} else {
			cfg_11d->param.domain_info.sub_band[no_of_sub_band]
				.first_chan = first_chan;
			cfg_11d->param.domain_info.sub_band[no_of_sub_band]
				.no_of_chan = no_of_parsed_chan;
			cfg_11d->param.domain_info.sub_band[no_of_sub_band]
				.max_tx_pwr = max_pwr;
			no_of_sub_band++;
			next_chan = first_chan = (t_u32)channel->hw_value;
			max_pwr = channel->max_power;
			no_of_parsed_chan = 1;
		}
	}

	if (flag && (no_of_sub_band < MRVDRV_MAX_SUBBAND_802_11D)) {
		cfg_11d->param.domain_info.sub_band[no_of_sub_band]
			.first_chan = first_chan;
		cfg_11d->param.domain_info.sub_band[no_of_sub_band]
			.no_of_chan = no_of_parsed_chan;
		cfg_11d->param.domain_info.sub_band[no_of_sub_band]
			.max_tx_pwr = max_pwr;
		no_of_sub_band++;
	}
	cfg_11d->param.domain_info.no_of_sub_band = no_of_sub_band;

	PRINTM(MCMND, "CFG80211: Country=%c%c, band=%d, no_of_sub_band=%d\n",
	       priv->phandle->country_code[0], priv->phandle->country_code[1],
	       priv->phandle->band, cfg_11d->param.domain_info.no_of_sub_band);
	/* Send domain info command to FW */
	status = woal_request_ioctl(priv, req, wait_option);
	if (status != MLAN_STATUS_SUCCESS) {
		ret = MLAN_STATUS_FAILURE;
		PRINTM(MERROR, "11D: Error setting domain info in FW\n");
		goto done;
	}

done:
	if (status != MLAN_STATUS_PENDING)
		kfree(req);
	LEAVE();
	return ret;
}

/**
 * @brief Request the driver to change the channel and
 * change domain info according to that channel
 *
 * @param priv            A pointer to moal_private structure
 * @param chan            A pointer to ieee80211_channel structure
 * @param channel_type    Channel type of nl80211_channel_type
 * @param wait_option     wait option
 *
 * @return                0 -- success, otherwise fail
 */
int
woal_set_rf_channel(moal_private *priv,
		    struct ieee80211_channel *chan,
		    enum nl80211_channel_type channel_type, t_u8 wait_option)
{
	int ret = 0;
	t_u32 mode, config_bands = 0;
	mlan_ioctl_req *req = NULL;
	mlan_ds_radio_cfg *radio_cfg = NULL;
	mlan_status status = MLAN_STATUS_SUCCESS;

	ENTER();

	if (!chan) {
		LEAVE();
		return -EINVAL;
	}
	mode = woal_nl80211_iftype_to_mode(priv->wdev->iftype);
	req = woal_alloc_mlan_ioctl_req(sizeof(mlan_ds_radio_cfg));
	if (req == NULL) {
		ret = -ENOMEM;
		goto done;
	}
	radio_cfg = (mlan_ds_radio_cfg *)req->pbuf;
	radio_cfg->sub_command = MLAN_OID_BAND_CFG;
	req->req_id = MLAN_IOCTL_RADIO_CFG;
	/* Get config_bands, adhoc_start_band and adhoc_channel values from MLAN */
	req->action = MLAN_ACT_GET;
	status = woal_request_ioctl(priv, req, wait_option);
	if (status != MLAN_STATUS_SUCCESS) {
		ret = -EFAULT;
		goto done;
	}
	req->action = MLAN_ACT_SET;
	priv->phandle->band = chan->band;
	/* Set appropriate bands */
	if (chan->band == IEEE80211_BAND_2GHZ)
		config_bands = BAND_B | BAND_G | BAND_GN;
	else {
		config_bands = BAND_AN | BAND_A;
	}
	if (mode == MLAN_BSS_MODE_IBSS) {
		radio_cfg->param.band_cfg.adhoc_start_band = config_bands;
		radio_cfg->param.band_cfg.adhoc_channel =
			ieee80211_frequency_to_channel(chan->center_freq);
	}

	status = woal_request_ioctl(priv, req, wait_option);
	if (status != MLAN_STATUS_SUCCESS) {
		ret = -EFAULT;
		goto done;
	}
	woal_send_domain_info_cmd_fw(priv, wait_option);

	PRINTM(MINFO, "Setting band %d, and mode = %d channel=%d\n",
	       config_bands, mode,
	       ieee80211_frequency_to_channel(chan->center_freq));

	if (MLAN_STATUS_SUCCESS !=
	    woal_change_adhoc_chan(priv,
				   ieee80211_frequency_to_channel(chan->
								  center_freq),
				   wait_option)) {
		ret = -EFAULT;
		goto done;
	}

done:
	if (status != MLAN_STATUS_PENDING)
		kfree(req);
	LEAVE();
	return ret;
}

/**
 *  @brief Set ewpa mode
 *
 *  @param priv                 A pointer to moal_private structure
 *  @param wait_option          Wait option
 *  @param ssid_bssid           A pointer to mlan_ssid_bssid structure
 *
 *  @return                     MLAN_STATUS_SUCCESS/MLAN_STATUS_PENDING -- success, otherwise fail
 */
mlan_status
woal_set_ewpa_mode(moal_private *priv, t_u8 wait_option,
		   mlan_ssid_bssid *ssid_bssid)
{
	int ret = 0;
	mlan_ioctl_req *req = NULL;
	mlan_ds_sec_cfg *sec = NULL;
	mlan_status status = MLAN_STATUS_SUCCESS;

	ENTER();

	/* Allocate an IOCTL request buffer */
	req = woal_alloc_mlan_ioctl_req(sizeof(mlan_ds_sec_cfg));
	if (req == NULL) {
		ret = -ENOMEM;
		goto error;
	}
	/* Fill request buffer */
	sec = (mlan_ds_sec_cfg *)req->pbuf;
	sec->sub_command = MLAN_OID_SEC_CFG_PASSPHRASE;
	req->req_id = MLAN_IOCTL_SEC_CFG;
	req->action = MLAN_ACT_GET;

	/* Try Get All */
	memset(&sec->param.passphrase, 0, sizeof(mlan_ds_passphrase));
	memcpy(&sec->param.passphrase.ssid, &ssid_bssid->ssid,
	       sizeof(sec->param.passphrase.ssid));
	memcpy(&sec->param.passphrase.bssid, &ssid_bssid->bssid,
	       MLAN_MAC_ADDR_LENGTH);
	sec->param.passphrase.psk_type = MLAN_PSK_QUERY;

	/* Send IOCTL request to MLAN */
	status = woal_request_ioctl(priv, req, wait_option);
	if (status != MLAN_STATUS_SUCCESS)
		goto error;
	sec->param.ewpa_enabled = MFALSE;
	if (sec->param.passphrase.psk_type == MLAN_PSK_PASSPHRASE) {
		if (sec->param.passphrase.psk.passphrase.passphrase_len > 0)
			sec->param.ewpa_enabled = MTRUE;
	} else if (sec->param.passphrase.psk_type == MLAN_PSK_PMK)
		sec->param.ewpa_enabled = MTRUE;

	sec->sub_command = MLAN_OID_SEC_CFG_EWPA_ENABLED;
	req->action = MLAN_ACT_SET;

	/* Send IOCTL request to MLAN */
	status = woal_request_ioctl(priv, req, wait_option);

error:
	if (status != MLAN_STATUS_PENDING)
		kfree(req);
	LEAVE();
	return status;
}

/**
 * @brief Set encryption mode and enable WPA
 *
 * @param priv          A pointer to moal_private structure
 * @param encrypt_mode  Encryption mode
 * @param wpa_enabled   WPA enable or not
 * @param wait_option   wait option
 *
 * @return              0 -- success, otherwise fail
 */
static int
woal_cfg80211_set_auth(moal_private *priv, int encrypt_mode,
		       int wpa_enabled, t_u8 wait_option)
{
	int ret = 0;

	ENTER();

	if (MLAN_STATUS_SUCCESS !=
	    woal_set_encrypt_mode(priv, wait_option, encrypt_mode))
		ret = -EFAULT;

	if (wpa_enabled) {
		if (MLAN_STATUS_SUCCESS !=
		    woal_set_wpa_enable(priv, wait_option, 1))
			ret = -EFAULT;
	}

	LEAVE();
	return ret;
}

/**
 * @brief Informs the CFG802.11 subsystem of a new BSS connection.
 *
 * The following information are sent to the CFG802.11 subsystem
 * to register the new BSS connection. If we do not register the new BSS,
 * a kernel panic will result.
 *      - MAC address
 *      - Capabilities
 *      - Beacon period
 *      - RSSI value
 *      - Channel
 *      - Supported rates IE
 *      - Extended capabilities IE
 *      - DS parameter set IE
 *      - HT Capability IE
 *      - Vendor Specific IE (221)
 *      - WPA IE
 *      - RSN IE
 *
 * @param priv            A pointer to moal_private structure
 * @param ssid_bssid      A pointer to A pointer to mlan_ssid_bssid structure
 * @param wait_option     wait_option
 *
 * @return          MLAN_STATUS_SUCCESS or MLAN_STATUS_FAILURE
 */
mlan_status
woal_inform_bss_from_scan_result(moal_private *priv,
				 mlan_ssid_bssid *ssid_bssid, t_u8 wait_option)
{
	mlan_status ret = MLAN_STATUS_SUCCESS;
	struct ieee80211_channel *chan;
	mlan_scan_resp scan_resp;
	BSSDescriptor_t *scan_table;
	t_u64 ts = 0;
	u16 cap_info = 0;
	int i = 0;
	struct cfg80211_bss *pub = NULL;

	ENTER();
	if (!priv->wdev || !priv->wdev->wiphy) {
		LEAVE();
		return MLAN_STATUS_FAILURE;
	}

	memset(&scan_resp, 0, sizeof(scan_resp));
	if (MLAN_STATUS_SUCCESS != woal_get_scan_table(priv,
						       wait_option,
						       &scan_resp)) {
		ret = MLAN_STATUS_FAILURE;
		goto done;
	}

	if (scan_resp.num_in_scan_table) {
		scan_table = (BSSDescriptor_t *)scan_resp.pscan_table;
		for (i = 0; i < scan_resp.num_in_scan_table; i++) {
			if (ssid_bssid) {
				/* Inform specific BSS only */
				if (memcmp
				    (ssid_bssid->ssid.ssid,
				     scan_table[i].ssid.ssid,
				     ssid_bssid->ssid.ssid_len) ||
				    memcmp(ssid_bssid->bssid,
					   scan_table[i].mac_address, ETH_ALEN))
					continue;
			}
			if (!scan_table[i].freq) {
				scan_table[i].freq =
					ieee80211_channel_to_frequency((int)
								       scan_table
								       [i].
								       channel
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
								       ,
								       woal_band_cfg_to_ieee_band
								       (scan_table
									[i].
									bss_band)
#endif
					);
			}
			chan = ieee80211_get_channel(priv->wdev->wiphy,
						     scan_table[i].freq);
			if (!chan) {
				PRINTM(MCMND,
				       "Fail to get chan with freq: channel=%d freq=%d\n",
				       (int)scan_table[i].channel,
				       (int)scan_table[i].freq);
				continue;
			}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
			/** Andorid's Location service is expecting timestamp to be
			* local time (in microsecond) since boot;
			* and not the TSF found in the beacon. */
			ts = ktime_to_us(ktime_get_boottime());
#else
			memcpy(&ts, scan_table[i].time_stamp, sizeof(ts));
#endif
			memcpy(&cap_info, &scan_table[i].cap_info,
			       sizeof(cap_info));
			pub = cfg80211_inform_bss(priv->wdev->wiphy, chan,
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 18, 0)
						  CFG80211_BSS_FTYPE_UNKNOWN,
#endif
						  scan_table[i].mac_address,
						  ts, cap_info,
						  scan_table[i].beacon_period,
						  scan_table[i].pbeacon_buf +
						  WLAN_802_11_FIXED_IE_SIZE,
						  scan_table[i].
						  beacon_buf_size -
						  WLAN_802_11_FIXED_IE_SIZE,
						  -RSSI_DBM_TO_MDM(scan_table
								   [i].rssi),
						  GFP_KERNEL);
			if (pub) {
#if CFG80211_VERSION_CODE < KERNEL_VERSION(3, 8, 0)
				pub->len_information_elements =
					pub->len_beacon_ies;
#endif
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
				cfg80211_put_bss(priv->wdev->wiphy, pub);
#else
				cfg80211_put_bss(pub);
#endif
			}
		}
	}
done:
	LEAVE();
	return ret;
}

/**
 * @brief Informs the CFG802.11 subsystem of a new IBSS connection.
 *
 * The following information are sent to the CFG802.11 subsystem
 * to register the new IBSS connection. If we do not register the
 * new IBSS, a kernel panic will result.
 *      - MAC address
 *      - Capabilities
 *      - Beacon period
 *      - RSSI value
 *      - Channel
 *      - Supported rates IE
 *      - Extended capabilities IE
 *      - DS parameter set IE
 *      - HT Capability IE
 *      - Vendor Specific IE (221)
 *      - WPA IE
 *      - RSN IE
 *
 * @param priv              A pointer to moal_private structure
 * @param cahn              A pointer to ieee80211_channel structure
 * @param beacon_interval   Beacon interval
 *
 * @return                  MLAN_STATUS_SUCCESS or MLAN_STATUS_FAILURE
 */
static mlan_status
woal_cfg80211_inform_ibss_bss(moal_private *priv,
			      struct ieee80211_channel *chan,
			      t_u16 beacon_interval)
{
	mlan_status ret = MLAN_STATUS_SUCCESS;
	mlan_bss_info bss_info;
	mlan_ds_get_signal signal;
	t_u8 ie_buf[MLAN_MAX_SSID_LENGTH + sizeof(IEEEtypes_Header_t)];
	int ie_len = 0;
	struct cfg80211_bss *bss = NULL;

	ENTER();

	ret = woal_get_bss_info(priv, MOAL_IOCTL_WAIT, &bss_info);
	if (ret)
		goto done;

	memset(ie_buf, 0, sizeof(ie_buf));
	ie_buf[0] = WLAN_EID_SSID;
	ie_buf[1] = bss_info.ssid.ssid_len;

	memcpy(&ie_buf[sizeof(IEEEtypes_Header_t)],
	       &bss_info.ssid.ssid, bss_info.ssid.ssid_len);
	ie_len = ie_buf[1] + sizeof(IEEEtypes_Header_t);

	/* Get signal information from the firmware */
	memset(&signal, 0, sizeof(mlan_ds_get_signal));
	if (MLAN_STATUS_SUCCESS !=
	    woal_get_signal_info(priv, MOAL_IOCTL_WAIT, &signal)) {
		PRINTM(MERROR, "Error getting signal information\n");
		ret = MLAN_STATUS_FAILURE;
		goto done;
	}

	bss = cfg80211_inform_bss(priv->wdev->wiphy, chan,
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 18, 0)
				  CFG80211_BSS_FTYPE_UNKNOWN,
#endif
				  bss_info.bssid, 0, WLAN_CAPABILITY_IBSS,
				  beacon_interval, ie_buf, ie_len,
				  signal.bcn_rssi_avg, GFP_KERNEL);
	if (bss)
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
		cfg80211_put_bss(priv->wdev->wiphy, bss);
#else
		cfg80211_put_bss(bss);
#endif
done:
	LEAVE();
	return ret;
}

/**
 * @brief Process country IE before assoicate
 *
 * @param priv            A pointer to moal_private structure
 * @param bss             A pointer to cfg80211_bss structure
 *
 * @return                0 -- success, otherwise fail
 */
static int
woal_process_country_ie(moal_private *priv, struct cfg80211_bss *bss)
{
	u8 *country_ie, country_ie_len;
	int ret = 0;
	mlan_ioctl_req *req = NULL;
	mlan_ds_11d_cfg *cfg_11d = NULL;
	mlan_status status = MLAN_STATUS_SUCCESS;

	ENTER();
	country_ie = (u8 *)ieee80211_bss_get_ie(bss, WLAN_EID_COUNTRY);
	if (!country_ie) {
		PRINTM(MIOCTL, "No country IE found!\n");
		woal_send_domain_info_cmd_fw(priv, MOAL_IOCTL_WAIT);
		LEAVE();
		return 0;
	}

	country_ie_len = country_ie[1];
	if (country_ie_len < IEEE80211_COUNTRY_IE_MIN_LEN) {
		PRINTM(MIOCTL, "Wrong Country IE length!\n");
		woal_send_domain_info_cmd_fw(priv, MOAL_IOCTL_WAIT);
		LEAVE();
		return 0;
	}
	if ((priv->phandle->country_code[0] != country_ie[2]) ||
	    (priv->phandle->country_code[1] != country_ie[3])) {
		t_u8 country_code[COUNTRY_CODE_LEN];
		memset(country_code, 0, sizeof(country_code));
		country_code[0] = country_ie[2];
		country_code[1] = country_ie[3];
		if (cntry_txpwr) {
			if (MLAN_STATUS_SUCCESS !=
			    woal_request_country_power_table(priv,
							     country_code))
				PRINTM(MERROR, "Set power table failed!\n");
		}
	}

	priv->phandle->country_code[0] = country_ie[2];
	priv->phandle->country_code[1] = country_ie[3];
	priv->phandle->country_code[2] = ' ';
	if (MLAN_STATUS_SUCCESS !=
	    woal_set_region_code(priv, priv->phandle->country_code))
		PRINTM(MERROR, "Set country code failed!\n");

	/* Allocate an IOCTL request buffer */
	req = woal_alloc_mlan_ioctl_req(sizeof(mlan_ds_11d_cfg));
	if (req == NULL) {
		PRINTM(MERROR, "Fail to allocate mlan_ds_11d_cfg buffer\n");
		ret = MLAN_STATUS_FAILURE;
		goto done;
	}

	cfg_11d = (mlan_ds_11d_cfg *)req->pbuf;
	cfg_11d->sub_command = MLAN_OID_11D_DOMAIN_INFO_EXT;
	req->req_id = MLAN_IOCTL_11D_CFG;
	req->action = MLAN_ACT_SET;

	/* Set country code */
	cfg_11d->param.domain_info.country_code[0] =
		priv->phandle->country_code[0];
	cfg_11d->param.domain_info.country_code[1] =
		priv->phandle->country_code[1];
	cfg_11d->param.domain_info.country_code[2] = ' ';

    /** IEEE80211_BAND_2GHZ or IEEE80211_BAND_5GHZ */
	cfg_11d->param.domain_info.band = priv->phandle->band;

	country_ie_len -= COUNTRY_CODE_LEN;
	cfg_11d->param.domain_info.no_of_sub_band =
		MIN(MRVDRV_MAX_SUBBAND_802_11D,
		    (country_ie_len /
		     sizeof(struct ieee80211_country_ie_triplet)));
	memcpy((u8 *)cfg_11d->param.domain_info.sub_band,
	       &country_ie[2] + COUNTRY_CODE_LEN,
	       cfg_11d->param.domain_info.no_of_sub_band *
	       sizeof(mlan_ds_subband_set_t));

	PRINTM(MCMND, "11D: Country IE: %c%c band=%d no_of_sub_band=%d\n",
	       country_ie[2], country_ie[3], priv->phandle->band,
	       cfg_11d->param.domain_info.no_of_sub_band);
	/* Send domain info command to FW */
	status = woal_request_ioctl(priv, req, MOAL_IOCTL_WAIT);
	if (status != MLAN_STATUS_SUCCESS) {
		ret = MLAN_STATUS_FAILURE;
		PRINTM(MERROR, "11D: Error setting domain info in FW\n");
		goto done;
	}
done:
	if (status != MLAN_STATUS_PENDING)
		kfree(req);
	LEAVE();
	return ret;
}

/**
 * @brief Request scan based on connect parameter
 *
 * @param priv            A pointer to moal_private structure
 * @param conn_param      A pointer to connect parameters
 * @param wait_option     wait option
 *
 * @return                0 -- success, otherwise fail
 */
int
woal_cfg80211_connect_scan(moal_private *priv,
			   struct cfg80211_connect_params *conn_param,
			   t_u8 wait_option)
{
	moal_handle *handle = priv->phandle;
	int ret = 0;
	wlan_user_scan_cfg scan_req;
	enum ieee80211_band band;
	struct ieee80211_supported_band *sband;
	struct ieee80211_channel *ch;
	int chan_idx = 0, i;
	ENTER();
	if (handle->scan_pending_on_block == MTRUE) {
		PRINTM(MINFO, "scan already in processing...\n");
		LEAVE();
		return ret;
	}
#ifdef REASSOCIATION
	if (MOAL_ACQ_SEMAPHORE_BLOCK(&handle->reassoc_sem)) {
		PRINTM(MERROR, "Acquire semaphore error, woal_do_combo_scan\n");
		LEAVE();
		return -EBUSY;
	}
#endif /* REASSOCIATION */
	priv->report_scan_result = MTRUE;
	memset(&scan_req, 0x00, sizeof(scan_req));
	memcpy(scan_req.ssid_list[0].ssid, conn_param->ssid,
	       conn_param->ssid_len);
	scan_req.ssid_list[0].max_len = 0;
	if (conn_param->channel) {
		scan_req.chan_list[0].chan_number =
			conn_param->channel->hw_value;
		scan_req.chan_list[0].radio_type = conn_param->channel->band;
		if (conn_param->channel->flags & IEEE80211_CHAN_PASSIVE_SCAN)
			scan_req.chan_list[0].scan_type =
				MLAN_SCAN_TYPE_PASSIVE;
		else if (conn_param->channel->flags & IEEE80211_CHAN_RADAR)
			scan_req.chan_list[0].scan_type =
				MLAN_SCAN_TYPE_PASSIVE_TO_ACTIVE;
		else
			scan_req.chan_list[0].scan_type = MLAN_SCAN_TYPE_ACTIVE;
		scan_req.chan_list[0].scan_time = 0;
	} else {
		for (band = 0; (band < IEEE80211_NUM_BANDS); band++) {
			if (!priv->wdev->wiphy->bands[band])
				continue;
			sband = priv->wdev->wiphy->bands[band];
			for (i = 0; (i < sband->n_channels); i++) {
				ch = &sband->channels[i];
				if (ch->flags & IEEE80211_CHAN_DISABLED)
					continue;
				scan_req.chan_list[chan_idx].radio_type = band;
				if (ch->flags & IEEE80211_CHAN_PASSIVE_SCAN)
					scan_req.chan_list[chan_idx].scan_type =
						MLAN_SCAN_TYPE_PASSIVE;
				else if (ch->flags & IEEE80211_CHAN_RADAR)
					scan_req.chan_list[chan_idx].scan_type =
						MLAN_SCAN_TYPE_PASSIVE_TO_ACTIVE;
				else
					scan_req.chan_list[chan_idx].scan_type =
						MLAN_SCAN_TYPE_ACTIVE;
				scan_req.chan_list[chan_idx].chan_number =
					(u32)ch->hw_value;
				chan_idx++;
			}
		}
	}
	ret = woal_request_userscan(priv, wait_option, &scan_req);
#ifdef REASSOCIATION
	MOAL_REL_SEMAPHORE(&handle->reassoc_sem);
#endif
	LEAVE();
	return ret;

}

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
/**
 * @brief Save assoc parameters for roaming
 *
 * @param priv            A pointer to moal_private
 * @param req             A pointer to cfg80211_assoc_request structure
 */
void
woal_save_assoc_params(moal_private *priv, struct cfg80211_assoc_request *req,
		       mlan_ssid_bssid *ssid_bssid)
{
	ENTER();

	if (req->bss->channel) {
		priv->sme_current.channel = &priv->conn_chan;
		memcpy(priv->sme_current.channel, req->bss->channel,
		       sizeof(struct ieee80211_channel));
	}
	priv->sme_current.bssid = priv->conn_bssid;
	memcpy((void *)priv->sme_current.bssid, req->bss->bssid,
	       MLAN_MAC_ADDR_LENGTH);
	if (req->ie && req->ie_len) {
		priv->sme_current.ie = kzalloc(req->ie_len, GFP_KERNEL);
		priv->sme_current.ie_len = req->ie_len;
		memcpy((void *)priv->sme_current.ie, req->ie, req->ie_len);
	}
	memcpy(&priv->sme_current.crypto, &req->crypto,
	       sizeof(struct cfg80211_crypto_settings));
	priv->sme_current.flags = req->flags;
	memcpy(&priv->sme_current.ht_capa, &req->ht_capa,
	       sizeof(struct ieee80211_ht_cap));
	memcpy(&priv->sme_current.ht_capa_mask, &req->ht_capa_mask,
	       sizeof(struct ieee80211_ht_cap));
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
	memcpy(&priv->sme_current.vht_capa, &req->vht_capa,
	       sizeof(struct ieee80211_vht_cap));
	memcpy(&priv->sme_current.vht_capa_mask, &req->vht_capa_mask,
	       sizeof(struct ieee80211_vht_cap));
#endif
	if (ssid_bssid && ssid_bssid->ssid.ssid_len) {
		priv->sme_current.ssid = priv->conn_ssid;
		memset(priv->conn_ssid, 0, MLAN_MAX_SSID_LENGTH);
		memcpy((void *)priv->sme_current.ssid, ssid_bssid->ssid.ssid,
		       ssid_bssid->ssid.ssid_len);
		priv->conn_ssid_len = ssid_bssid->ssid.ssid_len;
	}
	LEAVE();
}

/**
 * @brief Save auth parameters for roaming
 *
 * @param priv            A pointer to moal_private
 * @param req             A pointer to struct cfg80211_auth_request
 */
void
woal_save_auth_params(moal_private *priv, struct cfg80211_auth_request *req)
{
	ENTER();
	woal_clear_conn_params(priv);
	priv->sme_current.auth_type = req->auth_type;
	priv->sme_current.key_idx = req->key_idx;
	priv->sme_current.key_len = req->key_len;
	if (req->key && req->key_len && (req->key_len <= MAX_WEP_KEY_SIZE)) {
		priv->sme_current.key = priv->conn_wep_key;
		memcpy((t_u8 *)priv->sme_current.key, req->key, req->key_len);
	}
	LEAVE();
}

/**
*  @brief This function is authentication handler when host MLME
*          enable.
*          In this case driver will prepare and send Auth Req.
*
*  @param wiphy       A pointer to wiphy.
*
*  @param dev         A pointer to net_device
*
*  @param req         A pointer to cfg80211_auth_request
*
*  @return            0 -- success, otherwise fail
*/
static int
woal_cfg80211_authenticate(struct wiphy *wiphy,
			   struct net_device *dev,
			   struct cfg80211_auth_request *req)
{
	moal_private *priv = (moal_private *)woal_get_netdev_priv(dev);
	IEEE80211_MGMT *mgmt = NULL;
	mlan_status status = MLAN_STATUS_SUCCESS;
	pmlan_buffer pmbuf = NULL;
	t_u32 pkt_type, tx_control;
	t_u16 packet_len = 0, auth_alg;
	t_u8 addr[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
	int ret = 0;

	t_u8 trans = 1, status_code = 0;
	t_u8 *varptr = NULL;
	mlan_ssid_bssid *ssid_bssid;
	moal_handle *handle = priv->phandle;
	int i;

	ENTER();

	priv->cfg_disconnect = MFALSE;
#ifdef UAP_CFG80211
	if (GET_BSS_ROLE(priv) == MLAN_BSS_ROLE_UAP) {
		LEAVE();
		return -EFAULT;
	}
#endif

	if (priv->wdev->iftype != NL80211_IFTYPE_STATION) {
		PRINTM(MERROR,
		       "Received infra auth request when interface not in infra mode\n");
		LEAVE();
		return -EINVAL;
	}

	ssid_bssid = kzalloc(sizeof(mlan_ssid_bssid), GFP_ATOMIC);
	if (!ssid_bssid) {
		PRINTM(MERROR, "Fail to allocate ssid_bssid buffer\n");
		LEAVE();
		return -ENOMEM;
	}
	memcpy(ssid_bssid->bssid, req->bss->bssid, ETH_ALEN);
	/* Not allowed to connect to the same AP which is already connected
	   with other interface */
	for (i = 0; i < handle->priv_num; i++) {
		if (handle->priv[i] != priv &&
		    MTRUE == woal_is_connected(handle->priv[i], ssid_bssid)) {
			PRINTM(MMSG,
			       "wlan: already connected with other interface, bssid "
			       MACSTR "\n",
			       MAC2STR(handle->priv[i]->cfg_bssid));
			kfree(ssid_bssid);
			LEAVE();
			return -EINVAL;
		}
	}

	kfree(ssid_bssid);
	if (priv->auth_flag & HOST_MLME_AUTH_PENDING) {
		PRINTM(MERROR, "pending auth on going\n");
		LEAVE();
		return -EBUSY;
	}
	/** cancel pending scan */
	woal_cancel_scan(priv, MOAL_IOCTL_WAIT);

	/*enable auth register frame */
	woal_mgmt_frame_register(priv, IEEE80211_STYPE_AUTH, MTRUE);
	woal_mgmt_frame_register(priv, IEEE80211_STYPE_DEAUTH, MTRUE);
	woal_mgmt_frame_register(priv, IEEE80211_STYPE_DISASSOC, MTRUE);

#define HEADER_SIZE             8
	// frmctl + durationid + addr1 + addr2 + addr3 + seqctl + addr4
#define MGMT_HEADER_LEN     (2 + 2 + 6 + 6 + 6 + 2 +6)
	// 6   = auth_alg + auth_transaction +auth_status
#define AUTH_BODY_LEN 6
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(4,10,0)
	packet_len = (t_u16)req->ie_len + req->auth_data_len
		+ MGMT_HEADER_LEN + AUTH_BODY_LEN;
#else
	packet_len = (t_u16)req->ie_len + req->sae_data_len
		+ MGMT_HEADER_LEN + AUTH_BODY_LEN;
#endif
	pmbuf = woal_alloc_mlan_buffer(priv->phandle,
				       MLAN_MIN_DATA_HEADER_LEN + HEADER_SIZE +
				       packet_len + sizeof(packet_len));

	if (!pmbuf) {
		PRINTM(MERROR, "Fail to allocate mlan_buffer\n");
		ret = -ENOMEM;
		goto done;
	}

	switch (req->auth_type) {
	case NL80211_AUTHTYPE_OPEN_SYSTEM:
		auth_alg = WLAN_AUTH_OPEN;
		break;
	case NL80211_AUTHTYPE_SHARED_KEY:
		auth_alg = WLAN_AUTH_SHARED_KEY;
		break;
	case NL80211_AUTHTYPE_FT:
		auth_alg = WLAN_AUTH_FT;
		break;
	case NL80211_AUTHTYPE_NETWORK_EAP:
		auth_alg = WLAN_AUTH_LEAP;
		break;
	case NL80211_AUTHTYPE_SAE:
		auth_alg = WLAN_AUTH_SAE;
		break;
	default:
		PRINTM(MERROR, "Unsupported auth type=%d\n", req->auth_type);
		ret = -EOPNOTSUPP;
		break;
	}
	if (ret)
		goto done;
	if (MLAN_STATUS_SUCCESS !=
	    woal_set_auth_mode(priv, MOAL_IOCTL_WAIT, auth_alg)) {
		ret = -EFAULT;
		goto done;
	}

	if (req->auth_type == NL80211_AUTHTYPE_SHARED_KEY && req->key) {
		PRINTM(MINFO, "Setting wep encryption with key len %d\n",
		       req->key_len);
		/* Set the WEP key */
		if (MLAN_STATUS_SUCCESS !=
		    woal_cfg80211_set_wep_keys(priv, req->key, req->key_len,
					       req->key_idx, MOAL_IOCTL_WAIT)) {
			ret = -EFAULT;
			goto done;
		}
		/* Enable the WEP key by key index */
		if (MLAN_STATUS_SUCCESS !=
		    woal_cfg80211_set_wep_keys(priv, NULL, 0, req->key_idx,
					       MOAL_IOCTL_WAIT)) {
			ret = -EFAULT;
			goto done;
		}
	}
#define AUTH_TX_DEFAULT_WAIT_TIME  1200
	if (woal_cfg80211_remain_on_channel_cfg(priv, MOAL_IOCTL_WAIT, MFALSE,
						(t_u8 *)&status,
						req->bss->channel, 0,
						AUTH_TX_DEFAULT_WAIT_TIME)) {
		PRINTM(MERROR, "Fail to configure remain on channel\n");
		ret = -EFAULT;
		goto done;
	}
	if (status == MLAN_STATUS_SUCCESS) {
		priv->phandle->remain_on_channel = MTRUE;
		memcpy(&(priv->phandle->chan), req->bss->channel,
		       sizeof(struct ieee80211_channel));
	} else {
		PRINTM(MMSG,
		       "HostMlme %s: Set remain on Channel: with status=%d\n",
		       dev->name, status);
	}
	pmbuf->data_offset = MLAN_MIN_DATA_HEADER_LEN;
	pkt_type = MRVL_PKT_TYPE_MGMT_FRAME;
	tx_control = 0;
	/* Add pkt_type and tx_control */
	memcpy(pmbuf->pbuf + pmbuf->data_offset, &pkt_type, sizeof(pkt_type));
	memcpy(pmbuf->pbuf + pmbuf->data_offset + sizeof(pkt_type),
	       &tx_control, sizeof(tx_control));

	mgmt = (IEEE80211_MGMT *)(pmbuf->pbuf + pmbuf->data_offset
				  + HEADER_SIZE + sizeof(packet_len));
	memset(mgmt, 0, MGMT_HEADER_LEN);
    /**Authentication Frame: Frame Control*/
	mgmt->frame_control = cpu_to_le16(IEEE80211_FTYPE_MGMT |
					  IEEE80211_STYPE_AUTH);
    /**Authentication Frame: Destination Address*/
	memcpy(mgmt->da, req->bss->bssid, ETH_ALEN);
    /**Authentication Frame: Source Address*/
	memcpy(mgmt->sa, priv->current_addr, ETH_ALEN);
    /**Authentication Frame: BSSID*/
	memcpy(mgmt->bssid, req->bss->bssid, ETH_ALEN);
	memcpy(mgmt->addr4, addr, ETH_ALEN);

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(4,10,0)
	if (req->auth_data_len >= 4) {
		if (req->auth_type == NL80211_AUTHTYPE_SAE) {
			__le16 *pos = (__le16 *) req->auth_data;

			trans = le16_to_cpu(pos[0]);
			status_code = le16_to_cpu(pos[1]);
		}
		memcpy((t_u8 *)(&mgmt->u.auth.variable), req->auth_data + 4,
		       req->auth_data_len - 4);
		varptr = (t_u8 *)&mgmt->u.auth.variable + (req->auth_data_len -
							   4);
		packet_len -= 4;
	}
#else
	if (req->sae_data_len >= 4) {
		if (req->auth_type == NL80211_AUTHTYPE_SAE) {
			__le16 *pos = (__le16 *) req->sae_data;

			trans = le16_to_cpu(pos[0]);
			status_code = le16_to_cpu(pos[1]);
		}
		memcpy((t_u8 *)(&mgmt->u.auth.variable), req->sae_data + 4,
		       req->sae_data_len - 4);
		varptr = (t_u8 *)&mgmt->u.auth.variable + (req->sae_data_len -
							   4);
		packet_len -= 4;
	}
#endif
	/*Add packet len */
	memcpy(pmbuf->pbuf + pmbuf->data_offset + HEADER_SIZE, &packet_len,
	       sizeof(packet_len));

    /**Authentication Frame: Authentication Alg*/
	mgmt->u.auth.auth_alg = cpu_to_le16(auth_alg);
	mgmt->u.auth.auth_transaction = trans;
    /**Authentication Frame: Status code*/
	mgmt->u.auth.status_code = status_code;

	if (req->ie && req->ie_len) {
		if (!varptr) {
			varptr = (t_u8 *)&mgmt->u.auth.variable;
		}
		memcpy((t_u8 *)varptr, req->ie, req->ie_len);
	}

	pmbuf->data_len = HEADER_SIZE + packet_len + sizeof(packet_len);
	pmbuf->buf_type = MLAN_BUF_TYPE_RAW_DATA;
	pmbuf->bss_index = priv->bss_index;
	pmbuf->priority = 7;

	priv->host_mlme = MTRUE;
	priv->auth_flag = HOST_MLME_AUTH_PENDING;
	PRINTM(MCMND, "wlan: HostMlme %s send auth to bssid " MACSTR "\n",
	       dev->name, MAC2STR(req->bss->bssid));
	DBG_HEXDUMP(MDAT_D, "Auth:", pmbuf->pbuf + pmbuf->data_offset,
		    pmbuf->data_len);

	if (priv->bss_type == MLAN_BSS_TYPE_STA)
		woal_save_auth_params(priv, req);

	status = mlan_send_packet(priv->phandle->pmlan_adapter, pmbuf);

	switch (status) {
	case MLAN_STATUS_PENDING:
		atomic_inc(&priv->phandle->tx_pending);
		queue_work(priv->phandle->workqueue, &priv->phandle->main_work);
		break;
	case MLAN_STATUS_SUCCESS:
		woal_free_mlan_buffer(priv->phandle, pmbuf);
		break;
	case MLAN_STATUS_FAILURE:
	default:
		woal_free_mlan_buffer(priv->phandle, pmbuf);
		ret = -EFAULT;
		break;
	}
done:
	if (ret) {
		woal_mgmt_frame_register(priv, IEEE80211_STYPE_AUTH, MFALSE);
		if (priv->phandle->remain_on_channel) {
			woal_cfg80211_remain_on_channel_cfg(priv,
							    MOAL_IOCTL_WAIT,
							    MTRUE,
							    (t_u8 *)&status,
							    NULL, 0, 0);
			priv->phandle->remain_on_channel = MFALSE;
		}
	}

	LEAVE();
	return ret;

}

/**
 *  @brief This workqueue function handles association response in host mlme case
 *
 *  @param work    A pointer to work_struct
 *
 *  @return        N/A
 */
void
woal_host_mlme_work_queue(struct work_struct *work)
{
	mlan_ds_misc_assoc_rsp assoc_rsp;
	struct cfg80211_bss *bss = NULL;
	moal_handle *handle = container_of(work, moal_handle, host_mlme_work);
	moal_private *priv = (moal_private *)handle->host_mlme_priv;
	unsigned long flags;
	mlan_status status = MLAN_STATUS_SUCCESS;
	handle->host_mlme_priv = NULL;

	if (priv) {
		if (priv->auth_flag & HOST_MLME_AUTH_DONE) {
			priv->auth_flag = 0;
			woal_mgmt_frame_register(priv, IEEE80211_STYPE_AUTH,
						 MFALSE);

			if (priv->phandle->remain_on_channel) {
				woal_cfg80211_remain_on_channel_cfg(priv,
								    MOAL_IOCTL_WAIT,
								    MTRUE,
								    (t_u8 *)
								    &status,
								    NULL, 0, 0);
				priv->phandle->remain_on_channel = MFALSE;
			}
			PRINTM(MCMND, "wlan: HostMlme %s auth success\n",
			       priv->netdev->name);
		}

		if (priv->auth_flag & HOST_MLME_ASSOC_DONE) {
			priv->auth_flag = 0;
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
			bss = cfg80211_get_bss(priv->wdev->wiphy, NULL,
					       priv->conn_bssid,
					       priv->conn_ssid,
					       priv->conn_ssid_len,
					       IEEE80211_BSS_TYPE_ESS,
					       IEEE80211_PRIVACY_ANY);
#else
			bss = cfg80211_get_bss(priv->wdev->wiphy, NULL,
					       priv->conn_bssid,
					       priv->conn_ssid,
					       priv->conn_ssid_len,
					       WLAN_CAPABILITY_ESS,
					       WLAN_CAPABILITY_ESS);
#endif
			if (!bss) {
				PRINTM(MERROR, "HostMlme %s:Fail to get bss\n",
				       priv->netdev->name);
				return;
			}
			memset(&assoc_rsp, 0, sizeof(mlan_ds_misc_assoc_rsp));
			woal_get_assoc_rsp(priv, &assoc_rsp, MOAL_IOCTL_WAIT);

			if (assoc_rsp.assoc_resp_len) {
				PRINTM(MCMND,
				       "HostMlme: %s assoc_resp_len=%d, frame_control=0x%x\n",
				       priv->netdev->name,
				       assoc_rsp.assoc_resp_len,
				       ((struct ieee80211_mgmt *)assoc_rsp.
					assoc_resp_buf)->frame_control);
				if (ieee80211_is_assoc_resp
				    (((struct ieee80211_mgmt *)assoc_rsp.
				      assoc_resp_buf)->frame_control) ||
				    ieee80211_is_reassoc_resp(((struct
								ieee80211_mgmt
								*)assoc_rsp.
							       assoc_resp_buf)->
							      frame_control)) {
					spin_lock_irqsave(&priv->connect_lock,
							  flags);
					if (le16_to_cpu
					    (((struct ieee80211_mgmt *)
					      assoc_rsp.assoc_resp_buf)->u.
					     assoc_resp.status_code) !=
					    WLAN_STATUS_SUCCESS) {
						memset(priv->cfg_bssid, 0,
						       ETH_ALEN);
						if (priv->bss_type ==
						    MLAN_BSS_TYPE_STA)
							woal_clear_conn_params
								(priv);
					}
					spin_unlock_irqrestore(&priv->
							       connect_lock,
							       flags);
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
					cfg80211_rx_assoc_resp(priv->netdev,
							       bss,
							       assoc_rsp.
							       assoc_resp_buf,
							       assoc_rsp.
							       assoc_resp_len,
							       -1, NULL, 0);
#else
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 18, 0)
					cfg80211_rx_assoc_resp(priv->netdev,
							       bss,
							       assoc_rsp.
							       assoc_resp_buf,
							       assoc_rsp.
							       assoc_resp_len,
							       -1);
#else
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
					cfg80211_rx_assoc_resp(priv->netdev,
							       bss,
							       assoc_rsp.
							       assoc_resp_buf,
							       assoc_rsp.
							       assoc_resp_len);
#else
					cfg80211_send_rx_assoc(priv->netdev,
							       bss,
							       assoc_rsp.
							       assoc_resp_buf,
							       assoc_rsp.
							       assoc_resp_len);
#endif
#endif
#endif
				}
			}
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
			cfg80211_put_bss(priv->wdev->wiphy, bss);
#else
			cfg80211_put_bss(bss);
#endif
		}
	}
}

/**
*  @brief This function is association handler when host MLME
*          enable.
*          In this case driver will prepare and send Assoc Req.
*
*  @param wiphy       A pointer to wiphy.
*
*  @param dev         A pointer to net_device
*
*  @param req         A pointer to cfg80211_assoc_request
*
*  @return            0 -- success, otherwise fail
*/
static int
woal_cfg80211_associate(struct wiphy *wiphy, struct net_device *dev,
			struct cfg80211_assoc_request *req)
{
	moal_private *priv = (moal_private *)woal_get_netdev_priv(dev);
	int ret = 0;
	mlan_ssid_bssid ssid_bssid;
	unsigned long flags;
	const u8 *ssid_ie;
	int wpa_enabled = 0, group_enc_mode = 0, pairwise_enc_mode = 0;
	mlan_bss_info bss_info;

	ENTER();

	if (priv->auth_flag && !(priv->auth_flag & HOST_MLME_AUTH_DONE)) {
		LEAVE();
		return -EBUSY;
	}

	priv->cfg_connect = MTRUE;
	priv->assoc_status = 0;

	memset(&ssid_bssid, 0, sizeof(mlan_ssid_bssid));
	ssid_ie = ieee80211_bss_get_ie(req->bss, WLAN_EID_SSID);
	memcpy(ssid_bssid.bssid, req->bss->bssid, ETH_ALEN);

	if (!ssid_ie) {
		ret = -EINVAL;
		goto done;
	}

	memcpy(ssid_bssid.ssid.ssid, ssid_ie + 2, ssid_ie[1]);
	ssid_bssid.ssid.ssid_len = ssid_ie[1];

	if (ssid_bssid.ssid.ssid_len > MW_ESSID_MAX_SIZE) {
		PRINTM(MERROR, "Invalid SSID - aborting\n");
		ret = -EINVAL;
		goto done;
	}

	if (!ssid_bssid.ssid.ssid_len || ssid_bssid.ssid.ssid[0] < 0x20) {
		PRINTM(MERROR, "Invalid SSID - aborting\n");
		ret = -EINVAL;
		goto done;
	}
#ifdef STA_WEXT
	if (IS_STA_WEXT(cfg80211_wext)) {
		switch (req->crypto.wpa_versions) {
		case NL80211_WPA_VERSION_2:
			priv->wpa_version = IW_AUTH_WPA_VERSION_WPA2;
			break;
		case NL80211_WPA_VERSION_1:
			priv->wpa_version = IW_AUTH_WPA_VERSION_WPA;
			break;
		default:
			priv->wpa_version = 0;
			break;
		}
		if (req->crypto.n_akm_suites) {
			switch (req->crypto.akm_suites[0]) {
			case WLAN_AKM_SUITE_PSK:
				priv->key_mgmt = IW_AUTH_KEY_MGMT_PSK;
				break;
			case WLAN_AKM_SUITE_8021X:
				priv->key_mgmt = IW_AUTH_KEY_MGMT_802_1X;
				break;
			default:
				priv->key_mgmt = 0;
				break;
			}
		}
	}
#endif

	if (MLAN_STATUS_SUCCESS !=
	    woal_cfg80211_set_key(priv, 0, 0, NULL, 0, NULL, 0,
				  KEY_INDEX_CLEAR_ALL, NULL, 1,
				  MOAL_IOCTL_WAIT)) {
		/* Disable keys and clear all previous security settings */
		ret = -EFAULT;
		goto done;
	}

	if (req->ie && req->ie_len) {	/* Set the IE */
		if (MLAN_STATUS_SUCCESS !=
		    woal_cfg80211_assoc_ies_cfg(priv, (t_u8 *)req->ie,
						req->ie_len, MOAL_IOCTL_WAIT)) {
			ret = -EFAULT;
			goto done;
		}
	}

	if (req->crypto.n_ciphers_pairwise) {
		pairwise_enc_mode =
			woal_cfg80211_get_encryption_mode(req->
							  crypto.ciphers_pairwise
							  [0], &wpa_enabled);
		ret = woal_cfg80211_set_auth(priv, pairwise_enc_mode,
					     wpa_enabled, MOAL_IOCTL_WAIT);
		if (ret)
			goto done;
	}

	if (req->crypto.cipher_group) {
		group_enc_mode =
			woal_cfg80211_get_encryption_mode(req->
							  crypto.cipher_group,
							  &wpa_enabled);
		ret = woal_cfg80211_set_auth(priv, group_enc_mode, wpa_enabled,
					     MOAL_IOCTL_WAIT);
		if (ret)
			goto done;
	}
	ssid_bssid.host_mlme = priv->host_mlme;

	if (req->bss->channel) {
		ssid_bssid.channel_flags = req->bss->channel->flags;
		ssid_bssid.channel_flags |= CHAN_FLAGS_MAX;
		PRINTM(MCMND, "channel flags=0x%x\n", req->bss->channel->flags);
	}

	PRINTM(MCMND, "HostMlme: Associate...\n");
	if (MLAN_STATUS_SUCCESS !=
	    woal_bss_start(priv, MOAL_IOCTL_WAIT_TIMEOUT, &ssid_bssid)) {
		PRINTM(MERROR, "HostMlme: bss_start Fails\n");
		priv->host_mlme = MFALSE;
		priv->auth_flag = 0;
		ret = -EFAULT;
	}

done:

	if (!ret) {
		priv->rssi_low = DEFAULT_RSSI_LOW_THRESHOLD;
		if (priv->bss_type == MLAN_BSS_TYPE_STA)
			woal_save_assoc_params(priv, req, &ssid_bssid);
		memset(&bss_info, 0, sizeof(bss_info));
		woal_get_bss_info(priv, MOAL_IOCTL_WAIT, &bss_info);
		priv->channel = bss_info.bss_chan;
	}

	spin_lock_irqsave(&priv->connect_lock, flags);
	priv->cfg_connect = MFALSE;
	if (!ret && priv->media_connected) {
		PRINTM(MMSG,
		       "wlan: HostMlme %s Connected to bssid " MACSTR
		       " successfully\n", priv->netdev->name,
		       MAC2STR(priv->cfg_bssid));
		spin_unlock_irqrestore(&priv->connect_lock, flags);
	} else {
		PRINTM(MERROR,
		       "wlan: HostMlme %s Failed to connect to bssid " MACSTR
		       "\n", priv->netdev->name, MAC2STR(req->bss->bssid));
		if (ssid_bssid.assoc_rsp.assoc_resp_len &&
		    ssid_bssid.assoc_rsp.assoc_resp_len >=
		    sizeof(IEEEtypes_MgmtHdr_t)) {
			//save the connection param when send assoc_resp to kernel
			woal_save_assoc_params(priv, req, &ssid_bssid);
			ret = 0;
		} else {
			ssid_bssid.assoc_rsp.assoc_resp_len = 0;
			ret = -EFAULT;
			memset(priv->cfg_bssid, 0, ETH_ALEN);
			if (priv->bss_type == MLAN_BSS_TYPE_STA)
				woal_clear_conn_params(priv);
		}
		priv->host_mlme = MFALSE;
		priv->auth_flag = 0;
		spin_unlock_irqrestore(&priv->connect_lock, flags);
	}

	/*Association Response should also be send when ret is non-zero.
	   We also need to return success when we have association response
	   available */
	if (ssid_bssid.assoc_rsp.assoc_resp_len) {
		priv->auth_flag |= HOST_MLME_ASSOC_DONE;
		priv->phandle->host_mlme_priv = priv;
		queue_work(priv->phandle->rx_workqueue,
			   &priv->phandle->host_mlme_work);
	}

	LEAVE();
	return ret;
}
#endif
/*
 * @brief Request the driver for (re)association
 *
 * @param priv            A pointer to moal_private structure
 * @param sme             A pointer to connect parameters
 * @param wait_option     wait option
 * @param assoc_resp      A pointer to assoc_rsp structure;
 *
 * @return                0 -- success, otherwise fail
 */
int
woal_cfg80211_assoc(moal_private *priv, void *sme, t_u8 wait_option,
		    mlan_ds_misc_assoc_rsp *assoc_rsp)
{
	struct cfg80211_ibss_params *ibss_param = NULL;
	struct cfg80211_connect_params *conn_param = NULL;
	mlan_802_11_ssid req_ssid;
	mlan_ssid_bssid ssid_bssid;
	mlan_ioctl_req *req = NULL;
	int ret = 0;
	t_u32 auth_type = 0, mode;
	int wpa_enabled = 0;
	int group_enc_mode = 0, pairwise_enc_mode = 0;
	int alg_is_wep = 0;

	t_u8 *ssid, ssid_len = 0, *bssid;
	t_u8 *ie = NULL;
	int ie_len = 0;
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
	struct cfg80211_chan_def *chan_def = NULL;
#endif
	struct ieee80211_channel *channel = NULL;
	t_u16 beacon_interval = 0;
	bool privacy;
	struct cfg80211_bss *bss = NULL;
	mlan_status status = MLAN_STATUS_SUCCESS;

	ENTER();

	if (!sme) {
		LEAVE();
		return -EFAULT;
	}

	mode = woal_nl80211_iftype_to_mode(priv->wdev->iftype);

	if (mode == MLAN_BSS_MODE_IBSS) {
		ibss_param = (struct cfg80211_ibss_params *)sme;
		ssid = (t_u8 *)ibss_param->ssid;
		ssid_len = ibss_param->ssid_len;
		bssid = (t_u8 *)ibss_param->bssid;
#if CFG80211_VERSION_CODE < KERNEL_VERSION(3, 8, 0)
		channel = ibss_param->channel;
#else
		chan_def = &ibss_param->chandef;
		channel = ibss_param->chandef.chan;
#endif
		if (channel)
			priv->phandle->band = channel->band;
		if (ibss_param->ie_len)
			ie = (t_u8 *)ibss_param->ie;
		ie_len = ibss_param->ie_len;
		beacon_interval = ibss_param->beacon_interval;
		privacy = ibss_param->privacy;

	} else {
		conn_param = (struct cfg80211_connect_params *)sme;
		ssid = (t_u8 *)conn_param->ssid;
		ssid_len = conn_param->ssid_len;
		bssid = (t_u8 *)conn_param->bssid;
		channel = conn_param->channel;
		if (channel)
			priv->phandle->band = channel->band;
		if (conn_param->ie_len)
			ie = (t_u8 *)conn_param->ie;
		ie_len = conn_param->ie_len;
		privacy = conn_param->privacy;
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(4, 1, 0)
		bss = cfg80211_get_bss(priv->wdev->wiphy, channel, bssid, ssid,
				       ssid_len, IEEE80211_BSS_TYPE_ESS,
				       IEEE80211_PRIVACY_ANY);
#else
		bss = cfg80211_get_bss(priv->wdev->wiphy, channel, bssid, ssid,
				       ssid_len, WLAN_CAPABILITY_ESS,
				       WLAN_CAPABILITY_ESS);
#endif
		if (bss) {
			if ((!reg_alpha2 ||
			     strncmp(reg_alpha2, "99", strlen("99")))
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
			    && (!country_ie_ignore)
#endif
				)
				woal_process_country_ie(priv, bss);
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
			cfg80211_put_bss(priv->wdev->wiphy, bss);
#else
			cfg80211_put_bss(bss);
#endif
		} else
			woal_send_domain_info_cmd_fw(priv, wait_option);
#ifdef STA_WEXT
		if (IS_STA_WEXT(cfg80211_wext)) {
			switch (conn_param->crypto.wpa_versions) {
			case NL80211_WPA_VERSION_2:
				priv->wpa_version = IW_AUTH_WPA_VERSION_WPA2;
				break;
			case NL80211_WPA_VERSION_1:
				priv->wpa_version = IW_AUTH_WPA_VERSION_WPA;
				break;
			default:
				priv->wpa_version = 0;
				break;
			}
			if (conn_param->crypto.n_akm_suites) {
				switch (conn_param->crypto.akm_suites[0]) {
				case WLAN_AKM_SUITE_PSK:
					priv->key_mgmt = IW_AUTH_KEY_MGMT_PSK;
					break;
				case WLAN_AKM_SUITE_8021X:
					priv->key_mgmt =
						IW_AUTH_KEY_MGMT_802_1X;
					break;
				default:
					priv->key_mgmt = 0;
					break;
				}
			}
		}
#endif
	}

	memset(&req_ssid, 0, sizeof(mlan_802_11_ssid));
	memset(&ssid_bssid, 0, sizeof(mlan_ssid_bssid));

	req_ssid.ssid_len = ssid_len;
	if (ssid_len > MW_ESSID_MAX_SIZE) {
		PRINTM(MERROR, "Invalid SSID - aborting\n");
		ret = -EINVAL;
		goto done;
	}

	memcpy(req_ssid.ssid, ssid, ssid_len);
	if (!req_ssid.ssid_len || req_ssid.ssid[0] < 0x20) {
		PRINTM(MERROR, "Invalid SSID - aborting\n");
		ret = -EINVAL;
		goto done;
	}

	if (MLAN_STATUS_SUCCESS !=
	    woal_set_ewpa_mode(priv, wait_option, &ssid_bssid)) {
		ret = -EFAULT;
		goto done;
	}

	if (MLAN_STATUS_SUCCESS !=
	    woal_cfg80211_set_key(priv, 0, 0, NULL, 0, NULL, 0,
				  KEY_INDEX_CLEAR_ALL, NULL, 1, wait_option)) {
		/* Disable keys and clear all previous security settings */
		ret = -EFAULT;
		goto done;
	}
#ifdef STA_CFG80211
	if (IS_STA_CFG80211(cfg80211_wext)) {
		/** Check if current roaming support OKC offload roaming */
		if (conn_param && conn_param->crypto.n_akm_suites &&
		    conn_param->crypto.akm_suites[0] == WLAN_AKM_SUITE_8021X) {
			if (priv->okc_roaming_ie && priv->okc_ie_len) {
				ie = priv->okc_roaming_ie;
				ie_len = priv->okc_ie_len;
			}
		}
	}
#endif

	if ((priv->ft_pre_connect ||
	     (conn_param && conn_param->auth_type == NL80211_AUTHTYPE_FT))
	    && priv->ft_ie_len) {
		ie = priv->ft_ie;
		ie_len = priv->ft_ie_len;
		priv->ft_ie_len = 0;
	}
	if (ie && ie_len) {	/* Set the IE */
		if (MLAN_STATUS_SUCCESS !=
		    woal_cfg80211_assoc_ies_cfg(priv, ie, ie_len,
						wait_option)) {
			ret = -EFAULT;
			goto done;
		}
	}

	if (conn_param && mode != MLAN_BSS_MODE_IBSS) {
		/* These parameters are only for managed mode */
		if (conn_param->auth_type == NL80211_AUTHTYPE_OPEN_SYSTEM)
			auth_type = MLAN_AUTH_MODE_OPEN;
		else if (conn_param->auth_type == NL80211_AUTHTYPE_SHARED_KEY)
			auth_type = MLAN_AUTH_MODE_SHARED;
		else if (conn_param->auth_type == NL80211_AUTHTYPE_NETWORK_EAP)
			auth_type = MLAN_AUTH_MODE_NETWORKEAP;
		else if (conn_param->auth_type == NL80211_AUTHTYPE_FT)
			auth_type = MLAN_AUTH_MODE_FT;
		else
			auth_type = MLAN_AUTH_MODE_AUTO;
		if (priv->ft_pre_connect)
			auth_type = MLAN_AUTH_MODE_FT;
		if (MLAN_STATUS_SUCCESS !=
		    woal_set_auth_mode(priv, wait_option, auth_type)) {
			ret = -EFAULT;
			goto done;
		}

		if (conn_param->crypto.n_ciphers_pairwise) {
			pairwise_enc_mode =
				woal_cfg80211_get_encryption_mode(conn_param->
								  crypto.ciphers_pairwise
								  [0],
								  &wpa_enabled);
			ret = woal_cfg80211_set_auth(priv, pairwise_enc_mode,
						     wpa_enabled, wait_option);
			if (ret)
				goto done;
		}

		if (conn_param->crypto.cipher_group) {
			group_enc_mode =
				woal_cfg80211_get_encryption_mode(conn_param->
								  crypto.cipher_group,
								  &wpa_enabled);
			ret = woal_cfg80211_set_auth(priv, group_enc_mode,
						     wpa_enabled, wait_option);
			if (ret)
				goto done;
		}

		if (conn_param->key) {
			alg_is_wep =
				woal_cfg80211_is_alg_wep(pairwise_enc_mode) |
				woal_cfg80211_is_alg_wep(group_enc_mode);
			if (alg_is_wep) {
				PRINTM(MINFO,
				       "Setting wep encryption with key len %d\n",
				       conn_param->key_len);
				/* Set the WEP key */
				if (MLAN_STATUS_SUCCESS !=
				    woal_cfg80211_set_wep_keys(priv,
							       conn_param->key,
							       conn_param->
							       key_len,
							       conn_param->
							       key_idx,
							       wait_option)) {
					ret = -EFAULT;
					goto done;
				}
				/* Enable the WEP key by key index */
				if (MLAN_STATUS_SUCCESS !=
				    woal_cfg80211_set_wep_keys(priv, NULL, 0,
							       conn_param->
							       key_idx,
							       wait_option)) {
					ret = -EFAULT;
					goto done;
				}
			}
		}
	}

	if (mode == MLAN_BSS_MODE_IBSS) {
		mlan_ds_bss *bss = NULL;
		/* Change beacon interval */
		if ((beacon_interval < MLAN_MIN_BEACON_INTERVAL) ||
		    (beacon_interval > MLAN_MAX_BEACON_INTERVAL)) {
			ret = -EINVAL;
			goto done;
		}
		kfree(req);
		req = NULL;

		req = woal_alloc_mlan_ioctl_req(sizeof(mlan_ds_bss));
		if (req == NULL) {
			ret = -ENOMEM;
			goto done;
		}
		bss = (mlan_ds_bss *)req->pbuf;
		req->req_id = MLAN_IOCTL_BSS;
		req->action = MLAN_ACT_SET;
		bss->sub_command = MLAN_OID_IBSS_BCN_INTERVAL;
		bss->param.bcn_interval = beacon_interval;
		status = woal_request_ioctl(priv, req, wait_option);
		if (status != MLAN_STATUS_SUCCESS) {
			ret = -EFAULT;
			goto done;
		}

		/* "privacy" is set only for ad-hoc mode */
		if (privacy) {
			/*
			 * Keep MLAN_ENCRYPTION_MODE_WEP40 for now so that
			 * the firmware can find a matching network from the
			 * scan. cfg80211 does not give us the encryption
			 * mode at this stage so just setting it to wep here
			 */
			if (MLAN_STATUS_SUCCESS !=
			    woal_set_auth_mode(priv, wait_option,
					       MLAN_AUTH_MODE_OPEN)) {
				ret = -EFAULT;
				goto done;
			}

			wpa_enabled = 0;
			ret = woal_cfg80211_set_auth(priv,
						     MLAN_ENCRYPTION_MODE_WEP104,
						     wpa_enabled, wait_option);
			if (ret)
				goto done;
		}
	}
	memcpy(&ssid_bssid.ssid, &req_ssid, sizeof(mlan_802_11_ssid));
	if (bssid)
		memcpy(&ssid_bssid.bssid, bssid, ETH_ALEN);
	if (MLAN_STATUS_SUCCESS !=
	    woal_find_essid(priv, &ssid_bssid, wait_option)) {
		/* Do specific SSID scanning */
		if (mode != MLAN_BSS_MODE_IBSS)
			ret = woal_cfg80211_connect_scan(priv, conn_param,
							 wait_option);
		else
			ret = woal_request_scan(priv, wait_option, &req_ssid);
		if (ret) {
			ret = -EFAULT;
			goto done;
		}
	}

	/* Disconnect before try to associate */
	if (mode == MLAN_BSS_MODE_IBSS)
		woal_disconnect(priv, wait_option, NULL,
				DEF_DEAUTH_REASON_CODE);

	if (mode != MLAN_BSS_MODE_IBSS) {
		if (MLAN_STATUS_SUCCESS !=
		    woal_find_best_network(priv, wait_option, &ssid_bssid)) {
			ret = -EFAULT;
			goto done;
		}
		/* Inform the BSS information to kernel, otherwise
		 * kernel will give a panic after successful assoc */
		if (MLAN_STATUS_SUCCESS !=
		    woal_inform_bss_from_scan_result(priv, &ssid_bssid,
						     wait_option)) {
			ret = -EFAULT;
			goto done;
		}
	} else if (MLAN_STATUS_SUCCESS !=
		   woal_find_best_network(priv, wait_option, &ssid_bssid))
		/* Adhoc start, Check the channel command */
		woal_11h_channel_check_ioctl(priv, wait_option);

	PRINTM(MINFO, "Trying to associate to %s and bssid " MACSTR "\n",
	       (char *)req_ssid.ssid, MAC2STR(ssid_bssid.bssid));

	/* Zero SSID implies use BSSID to connect */
	if (bssid)
		memset(&ssid_bssid.ssid, 0, sizeof(mlan_802_11_ssid));
	else			/* Connect to BSS by ESSID */
		memset(&ssid_bssid.bssid, 0, MLAN_MAC_ADDR_LENGTH);
	if (channel) {
		ssid_bssid.channel_flags = channel->flags;
		ssid_bssid.channel_flags |= CHAN_FLAGS_MAX;
		PRINTM(MCMND, "channel flags=0x%x\n", channel->flags);
	}
	if (MLAN_STATUS_SUCCESS !=
	    woal_bss_start(priv, MOAL_IOCTL_WAIT_TIMEOUT, &ssid_bssid)) {
		ret = -EFAULT;
		goto done;
	}

	/* Inform the IBSS information to kernel, otherwise
	 * kernel will give a panic after successful assoc */
	if (mode == MLAN_BSS_MODE_IBSS) {
		if (MLAN_STATUS_SUCCESS !=
		    woal_cfg80211_inform_ibss_bss(priv, channel,
						  beacon_interval)) {
			ret = -EFAULT;
			goto done;
		}
	} else if (assoc_rsp) {
		memcpy(assoc_rsp, &ssid_bssid.assoc_rsp,
		       sizeof(mlan_ds_misc_assoc_rsp));
		PRINTM(MCMND, "assoc_rsp ie len=%d\n",
		       assoc_rsp->assoc_resp_len);
	}
done:
	if (ret) {
		/* clear the encryption mode */
		woal_cfg80211_set_auth(priv, MLAN_ENCRYPTION_MODE_NONE, MFALSE,
				       wait_option);
		/* clear IE */
		ie_len = 0;
		if (MLAN_STATUS_SUCCESS !=
		    woal_set_get_gen_ie(priv, MLAN_ACT_SET, NULL, &ie_len,
					wait_option)) {
			PRINTM(MERROR, "Could not clear RSN IE\n");
			ret = -EFAULT;
		}
	}
	if (status != MLAN_STATUS_PENDING)
		kfree(req);
	LEAVE();
	return ret;
}

/**
 * @brief Request the driver to dump the station information
 *
 * @param priv            A pointer to moal_private structure
 * @param sinfo           A pointer to station_info structure
 *
 * @return                0 -- success, otherwise fail
 */
static mlan_status
woal_cfg80211_dump_station_info(moal_private *priv, struct station_info *sinfo)
{
	mlan_status ret = MLAN_STATUS_SUCCESS;
	mlan_ds_get_signal signal;
	mlan_ds_get_stats stats;
	mlan_ioctl_req *req = NULL;
	mlan_ds_rate *rate = NULL;
	t_u16 Rates[12] = {
		0x02, 0x04, 0x0B, 0x16,
		0x0C, 0x12, 0x18, 0x24,
		0x30, 0x48, 0x60, 0x6c
	};
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
	mlan_bss_info bss_info;
	t_u8 dtim_period = 0;
#endif

	ENTER();
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
	sinfo->filled =
		MBIT(NL80211_STA_INFO_RX_BYTES) |
		MBIT(NL80211_STA_INFO_TX_BYTES) |
		MBIT(NL80211_STA_INFO_RX_PACKETS) |
		MBIT(NL80211_STA_INFO_TX_PACKETS) |
		MBIT(NL80211_STA_INFO_SIGNAL) |
		MBIT(NL80211_STA_INFO_TX_BITRATE);
#else
	sinfo->filled = STATION_INFO_RX_BYTES | STATION_INFO_TX_BYTES |
		STATION_INFO_RX_PACKETS | STATION_INFO_TX_PACKETS |
		STATION_INFO_SIGNAL | STATION_INFO_TX_BITRATE;
#endif

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
	sinfo->filled |= MBIT(NL80211_STA_INFO_TX_FAILED);
#else
	sinfo->filled |= STATION_INFO_TX_FAILED;
#endif
#endif

	/* Get signal information from the firmware */
	memset(&signal, 0, sizeof(mlan_ds_get_signal));
	if (MLAN_STATUS_SUCCESS !=
	    woal_get_signal_info(priv, MOAL_IOCTL_WAIT, &signal)) {
		PRINTM(MERROR, "Error getting signal information\n");
		ret = MLAN_STATUS_FAILURE;
		goto done;
	}

	/* Get stats information from the firmware */
	memset(&stats, 0, sizeof(mlan_ds_get_stats));
	if (MLAN_STATUS_SUCCESS !=
	    woal_get_stats_info(priv, MOAL_IOCTL_WAIT, &stats)) {
		PRINTM(MERROR, "Error getting stats information\n");
		ret = MLAN_STATUS_FAILURE;
		goto done;
	}

	req = woal_alloc_mlan_ioctl_req(sizeof(mlan_ds_rate));
	if (req == NULL) {
		ret = MLAN_STATUS_FAILURE;
		goto done;
	}
	rate = (mlan_ds_rate *)req->pbuf;
	rate->sub_command = MLAN_OID_GET_DATA_RATE;
	req->req_id = MLAN_IOCTL_RATE;
	req->action = MLAN_ACT_GET;
	ret = woal_request_ioctl(priv, req, MOAL_IOCTL_WAIT);
	if (ret != MLAN_STATUS_SUCCESS)
		goto done;
	if (rate->param.data_rate.tx_rate_format != MLAN_RATE_FORMAT_LG) {
		if (rate->param.data_rate.tx_rate_format == MLAN_RATE_FORMAT_HT) {
			sinfo->txrate.flags = RATE_INFO_FLAGS_MCS;
			if (rate->param.data_rate.tx_ht_bw == MLAN_HT_BW40)
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
				sinfo->txrate.bw = RATE_INFO_BW_40;
#else
				sinfo->txrate.flags |=
					RATE_INFO_FLAGS_40_MHZ_WIDTH;
#endif
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
			else
				sinfo->txrate.bw = RATE_INFO_BW_20;
#endif
		}
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
		else if (rate->param.data_rate.tx_rate_format ==
			 MLAN_RATE_FORMAT_VHT) {
			sinfo->txrate.flags = RATE_INFO_FLAGS_VHT_MCS;
			sinfo->txrate.nss = rate->param.data_rate.tx_nss + 1;
			if (rate->param.data_rate.tx_ht_bw == MLAN_VHT_BW80)
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
				sinfo->txrate.bw = RATE_INFO_BW_80;
#else
				sinfo->txrate.flags |=
					RATE_INFO_FLAGS_80_MHZ_WIDTH;
#endif
			else if (rate->param.data_rate.tx_ht_bw == MLAN_HT_BW40)
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
				sinfo->txrate.bw = RATE_INFO_BW_40;
#else
				sinfo->txrate.flags |=
					RATE_INFO_FLAGS_40_MHZ_WIDTH;
#endif
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
			else
				sinfo->txrate.bw = RATE_INFO_BW_20;
#endif
		}
#endif
		if (rate->param.data_rate.tx_ht_gi == MLAN_HT_SGI)
			sinfo->txrate.flags |= RATE_INFO_FLAGS_SHORT_GI;
		sinfo->txrate.mcs = rate->param.data_rate.tx_mcs_index;
	} else {
		/* Bit rate is in 500 kb/s units. Convert it to 100kb/s units */
		sinfo->txrate.legacy =
			Rates[rate->param.data_rate.tx_data_rate] * 5;
	}
	sinfo->rx_bytes = priv->stats.rx_bytes;
	sinfo->tx_bytes = priv->stats.tx_bytes;
	sinfo->rx_packets = priv->stats.rx_packets;
	sinfo->tx_packets = priv->stats.tx_packets;
	sinfo->signal = signal.bcn_rssi_avg;
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)
	sinfo->tx_failed = stats.failed;
#endif

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
	/* Update BSS information */
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
	sinfo->filled |= MBIT(NL80211_STA_INFO_BSS_PARAM);
#else
	sinfo->filled |= STATION_INFO_BSS_PARAM;
#endif
	sinfo->bss_param.flags = 0;
	ret = woal_get_bss_info(priv, MOAL_IOCTL_WAIT, &bss_info);
	if (ret)
		goto done;
	if (bss_info.capability_info & WLAN_CAPABILITY_SHORT_PREAMBLE)
		sinfo->bss_param.flags |= BSS_PARAM_FLAGS_SHORT_PREAMBLE;
	if (bss_info.capability_info & WLAN_CAPABILITY_SHORT_SLOT_TIME)
		sinfo->bss_param.flags |= BSS_PARAM_FLAGS_SHORT_SLOT_TIME;
	sinfo->bss_param.beacon_interval = bss_info.beacon_interval;
	/* Get DTIM period */
	ret = woal_set_get_dtim_period(priv, MLAN_ACT_GET,
				       MOAL_IOCTL_WAIT, &dtim_period);
	if (ret) {
		PRINTM(MERROR, "Get DTIM period failed\n");
		goto done;
	}
	sinfo->bss_param.dtim_period = dtim_period;
#endif

done:
	if (ret != MLAN_STATUS_PENDING)
		kfree(req);

	LEAVE();
	return ret;
}

/********************************************************
				Global Functions
********************************************************/
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
/**
 * @brief Set all radar channel's dfs_state
 *
 * @param wiphy           A pointer to wiphy structure
 *
 * @return                N/A
 */
void
woal_update_radar_chans_dfs_state(struct wiphy *wiphy)
{
	enum ieee80211_band band;
	struct ieee80211_supported_band *sband;
	int i;
	for (band = 0; band < IEEE80211_NUM_BANDS; band++) {
		sband = wiphy->bands[band];
		if (!sband)
			continue;
		for (i = 0; i < sband->n_channels; i++) {
			if (sband->channels[i].flags & IEEE80211_CHAN_RADAR) {
				if (dfs_offload)
					sband->channels[i].dfs_state =
						NL80211_DFS_AVAILABLE;
				else
					sband->channels[i].dfs_state =
						NL80211_DFS_USABLE;
			}
		}
	}
	PRINTM(MCMND, "Set radar dfs_state: dfs_offload=%d\n", dfs_offload);
}
#endif

/**
 * @brief Request the driver to change regulatory domain
 *
 * @param wiphy           A pointer to wiphy structure
 * @param request         A pointer to regulatory_request structure
 *
 * @return                0
 */
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
static void
#else
static int
#endif
woal_cfg80211_reg_notifier(struct wiphy *wiphy,
			   struct regulatory_request *request)
{
	moal_private *priv = NULL;
	moal_handle *handle = (moal_handle *)woal_get_wiphy_priv(wiphy);
	t_u8 region[COUNTRY_CODE_LEN];
	enum ieee80211_band band;
#if CFG80211_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	int ret = 0;
#endif

	ENTER();

	priv = woal_get_priv(handle, MLAN_BSS_ROLE_ANY);
	if (!priv) {
		PRINTM(MFATAL, "Unable to get priv in %s()\n", __func__);
		LEAVE();
#if CFG80211_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
		return -EINVAL;
#else
		return;
#endif
	}

	PRINTM(MIOCTL, "cfg80211 regulatory domain callback "
	       "%c%c initiator=%d\n", request->alpha2[0], request->alpha2[1],
	       request->initiator);
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
	if (dfs_offload)
		woal_update_radar_chans_dfs_state(wiphy);
#endif
	memset(region, 0, sizeof(region));
	memcpy(region, request->alpha2, sizeof(request->alpha2));
	region[2] = ' ';
	if ((handle->country_code[0] != request->alpha2[0]) ||
	    (handle->country_code[1] != request->alpha2[1])) {
		if (cntry_txpwr) {
			t_u8 country_code[COUNTRY_CODE_LEN];
			handle->country_code[0] = request->alpha2[0];
			handle->country_code[1] = request->alpha2[1];
			handle->country_code[2] = ' ';
			memset(country_code, 0, sizeof(country_code));
			if (MTRUE == is_cfg80211_special_region_code(region)) {
				country_code[0] = 'W';
				country_code[1] = 'W';
			} else {
				country_code[0] = request->alpha2[0];
				country_code[1] = request->alpha2[1];
			}
			if (MLAN_STATUS_SUCCESS !=
			    woal_request_country_power_table(priv,
							     country_code)) {
#if CFG80211_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
				return -EFAULT;
#else
				return;
#endif
			}
		}
	}
	if (MTRUE != is_cfg80211_special_region_code(region)) {
		if (!cntry_txpwr) {
			handle->country_code[0] = request->alpha2[0];
			handle->country_code[1] = request->alpha2[1];
			handle->country_code[2] = ' ';
		}
		if (MLAN_STATUS_SUCCESS !=
		    woal_set_region_code(priv, handle->country_code))
			PRINTM(MERROR, "Set country code failed!\n");
	}
	switch (request->initiator) {
	case NL80211_REGDOM_SET_BY_DRIVER:
		PRINTM(MCMND, "Regulatory domain BY_DRIVER\n");
		break;
	case NL80211_REGDOM_SET_BY_CORE:
		PRINTM(MCMND, "Regulatory domain BY_CORE\n");
		break;
	case NL80211_REGDOM_SET_BY_USER:
		PRINTM(MCMND, "Regulatory domain BY_USER\n");
		regulatory_hint(wiphy, request->alpha2);
		break;
		/* TODO: apply driver specific changes in channel flags based
		   on the request initiator if necessory. * */
	case NL80211_REGDOM_SET_BY_COUNTRY_IE:
		PRINTM(MCMND, "Regulatory domain BY_COUNTRY_IE\n");
		break;
	}
	if (priv->wdev && priv->wdev->wiphy &&
	    (request->initiator != NL80211_REGDOM_SET_BY_COUNTRY_IE)) {
		band = priv->phandle->band;
		priv->phandle->band = IEEE80211_BAND_2GHZ;
		woal_send_domain_info_cmd_fw(priv, MOAL_IOCTL_WAIT);
		priv->phandle->band = IEEE80211_BAND_5GHZ;
		woal_send_domain_info_cmd_fw(priv, MOAL_IOCTL_WAIT);
		priv->phandle->band = band;
	}

	LEAVE();
#if CFG80211_VERSION_CODE < KERNEL_VERSION(3, 9, 0)
	return ret;
#endif
}

#ifdef UAP_CFG80211
/**
 * @brief Swithces BSS role of interface
 *
 * @param priv          A pointer to moal_private structure
 * @param wait_option   Wait option (MOAL_IOCTL_WAIT or MOAL_NO_WAIT)
 * @param bss_role      bss role
 *
 * @return         0 --success, otherwise fail
 */
mlan_status
woal_role_switch(moal_private *priv, t_u8 wait_option, t_u8 bss_role)
{
	int ret = 0;
	mlan_ds_bss *bss = NULL;
	mlan_ioctl_req *req = NULL;
	mlan_status status = MLAN_STATUS_SUCCESS;

	ENTER();

	req = woal_alloc_mlan_ioctl_req(sizeof(mlan_ds_bss));
	if (req == NULL) {
		ret = -ENOMEM;
		goto done;
	}
	bss = (mlan_ds_bss *)req->pbuf;
	bss->sub_command = MLAN_OID_BSS_ROLE;
	req->req_id = MLAN_IOCTL_BSS;
	req->action = MLAN_ACT_SET;
	bss->param.bss_role = bss_role;

	status = woal_request_ioctl(priv, req, wait_option);
	if (status != MLAN_STATUS_SUCCESS) {
		ret = -EFAULT;
		goto done;
	}
done:
	if (status != MLAN_STATUS_PENDING)
		kfree(req);
	LEAVE();
	return ret;
}

/**
 *  @brief set/get bandcfg
 *
 *  @param priv                 A pointer to moal_private structure
 *  @param action               get or set action
 *  @param band_cfg              A pointer to mlan_ds_band_cfg structure
 *
 *  @return                     0 -- success, otherwise fail
 */
static int
woal_setget_bandcfg(moal_private *priv, t_u8 action, mlan_ds_band_cfg *band_cfg)
{
	int ret = 0;
	mlan_ioctl_req *req = NULL;
	mlan_ds_radio_cfg *radio_cfg = NULL;
	mlan_status status = MLAN_STATUS_SUCCESS;

	ENTER();

	req = woal_alloc_mlan_ioctl_req(sizeof(mlan_ds_radio_cfg));
	if (req == NULL) {
		ret = -ENOMEM;
		goto error;
	}
	radio_cfg = (mlan_ds_radio_cfg *)req->pbuf;
	radio_cfg->sub_command = MLAN_OID_BAND_CFG;
	req->req_id = MLAN_IOCTL_RADIO_CFG;
	req->action = action;

	if (req->action == MLAN_ACT_SET)
		memcpy(&radio_cfg->param.band_cfg, band_cfg,
		       sizeof(mlan_ds_band_cfg));

	status = woal_request_ioctl(priv, req, MOAL_IOCTL_WAIT);
	if (status != MLAN_STATUS_SUCCESS) {
		ret = -EFAULT;
		goto error;
	}
	memcpy(band_cfg, &radio_cfg->param.band_cfg, sizeof(mlan_ds_band_cfg));
error:
	if (status != MLAN_STATUS_PENDING)
		kfree(req);

	LEAVE();
	return ret;
}

/**
 *  @brief request scan
 *
 *  @param priv                 A pointer to moal_private structure
 *  @param scan_cfg             A pointer to wlan_user_scan_cfg structure
 *
 *  @return                     MLAN_STATUS_SUCCESS -- success, otherwise fail
 */
mlan_status
woal_uap_scan(moal_private *priv, wlan_user_scan_cfg *scan_cfg)
{
	mlan_status ret = MLAN_STATUS_SUCCESS;
	moal_handle *handle = priv->phandle;
	moal_private *tmp_priv;
	u8 role;
	mlan_ds_band_cfg org_bandcfg;
	mlan_ds_band_cfg bandcfg;
	u8 band_change = MFALSE;

	ENTER();
	if (priv->bss_index > 0)
		tmp_priv = woal_get_priv(handle, MLAN_BSS_ROLE_ANY);
	else
		tmp_priv = priv;
	if (!tmp_priv) {
		LEAVE();
		return MLAN_STATUS_FAILURE;
	}
	role = GET_BSS_ROLE(tmp_priv);
	if (role == MLAN_BSS_ROLE_UAP)
		woal_role_switch(tmp_priv, MOAL_IOCTL_WAIT, MLAN_BSS_ROLE_STA);
	if (tmp_priv != priv) {
		woal_setget_bandcfg(priv, MLAN_ACT_GET, &bandcfg);
		woal_setget_bandcfg(tmp_priv, MLAN_ACT_GET, &org_bandcfg);
		if (bandcfg.config_bands != org_bandcfg.config_bands) {
			woal_setget_bandcfg(tmp_priv, MLAN_ACT_SET, &bandcfg);
			band_change = MTRUE;
		}
	}
#ifdef REASSOCIATION
	if (MOAL_ACQ_SEMAPHORE_BLOCK(&handle->reassoc_sem)) {
		PRINTM(MERROR, "Acquire semaphore error, woal_do_combo_scan\n");
		goto done;
	}
#endif /* REASSOCIATION */

	tmp_priv->report_scan_result = MTRUE;
	ret = woal_request_userscan(tmp_priv, MOAL_IOCTL_WAIT, scan_cfg);
	woal_sched_timeout(5);
#ifdef REASSOCIATION
	MOAL_REL_SEMAPHORE(&handle->reassoc_sem);
#endif
done:
	if (role == MLAN_BSS_ROLE_UAP)
		woal_role_switch(tmp_priv, MOAL_IOCTL_WAIT, MLAN_BSS_ROLE_UAP);
	if (band_change)
		woal_setget_bandcfg(tmp_priv, MLAN_ACT_SET, &org_bandcfg);
	LEAVE();
	return ret;
}
#endif

static int
woal_find_wps_ie_in_probereq(const t_u8 *ie, int len)
{
	int left_len = len;
	const t_u8 *pos = ie;
	t_u8 ie_id, ie_len;
	IEEEtypes_VendorSpecific_t *pvendor_ie = NULL;
	const u8 wps_oui[4] = { 0x00, 0x50, 0xf2, 0x04 };

	while (left_len >= 2) {
		ie_id = *pos;
		ie_len = *(pos + 1);
		if ((ie_len + 2) > left_len)
			break;
		if (ie_id == VENDOR_SPECIFIC_221) {
			pvendor_ie = (IEEEtypes_VendorSpecific_t *)pos;
			if (!memcmp
			    (pvendor_ie->vend_hdr.oui, wps_oui,
			     sizeof(pvendor_ie->vend_hdr.oui)) &&
			    pvendor_ie->vend_hdr.oui_type == wps_oui[3])
				return MTRUE;
		}

		pos += (ie_len + 2);
		left_len -= (ie_len + 2);
	}

	return MFALSE;
}

/**
 *  @brief check if the scan result expired
 *
 *  @param priv         A pointer to moal_private
 *
 *
 *  @return             MTRUE/MFALSE;
 */
t_u8
woal_is_scan_result_expired(moal_private *priv)
{
	mlan_scan_resp scan_resp;
	struct timeval t;
	ENTER();
	if (!woal_is_any_interface_active(priv->phandle)) {
		LEAVE();
		return MTRUE;
	}

	if (MLAN_STATUS_SUCCESS !=
	    woal_get_scan_table(priv, MOAL_IOCTL_WAIT, &scan_resp)) {
		LEAVE();
		return MTRUE;
	}
	woal_get_monotonic_time(&t);
/** scan result expired value */
#define SCAN_RESULT_EXPIRTED      1
	if (t.tv_sec > (scan_resp.age_in_secs + SCAN_RESULT_EXPIRTED)) {
		LEAVE();
		return MTRUE;
	}
	LEAVE();
	return MFALSE;
}

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)
/**
 * @brief Request the driver to do a scan. Always returning
 * zero meaning that the scan request is given to driver,
 * and will be valid until passed to cfg80211_scan_done().
 * To inform scan results, call cfg80211_inform_bss().
 *
 * @param wiphy           A pointer to wiphy structure
 * @param request         A pointer to cfg80211_scan_request structure
 *
 * @return                0 -- success, otherwise fail
 */
static int
woal_cfg80211_scan(struct wiphy *wiphy, struct cfg80211_scan_request *request)
#else
/**
 * @brief Request the driver to do a scan. Always returning
 * zero meaning that the scan request is given to driver,
 * and will be valid until passed to cfg80211_scan_done().
 * To inform scan results, call cfg80211_inform_bss().
 *
 * @param wiphy           A pointer to wiphy structure
 * @param dev             A pointer to net_device structure
 * @param request         A pointer to cfg80211_scan_request structure
 *
 * @return                0 -- success, otherwise fail
 */
static int
woal_cfg80211_scan(struct wiphy *wiphy, struct net_device *dev,
		   struct cfg80211_scan_request *request)
#endif
{
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)
	struct net_device *dev = request->wdev->netdev;
#endif
	moal_private *priv = (moal_private *)woal_get_netdev_priv(dev);
	wlan_user_scan_cfg scan_req;
	mlan_bss_info bss_info;
	struct ieee80211_channel *chan;
	int ret = 0, i;
	unsigned long flags;

	ENTER();

	PRINTM(MINFO, "Received scan request on %s\n", dev->name);
	if (priv->phandle->scan_pending_on_block == MTRUE) {
		PRINTM(MCMND, "scan already in processing...\n");
		LEAVE();
		return -EAGAIN;
	}
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)
	if (priv->last_event & EVENT_BG_SCAN_REPORT) {
		PRINTM(MCMND, "block scan while pending BGSCAN result\n");
		priv->last_event = 0;
		LEAVE();
		return -EAGAIN;
	}
#endif
#if defined(STA_CFG80211) || defined(UAP_CFG80211)
#endif
	if (priv->fake_scan_complete || !woal_is_scan_result_expired(priv)) {
		if (priv->wdev->iftype == NL80211_IFTYPE_AP) {
			PRINTM(MEVENT, "Reporting fake scan results\n");
			woal_inform_bss_from_scan_result(priv, NULL,
							 MOAL_IOCTL_WAIT);
			woal_cfg80211_scan_done(request, MFALSE);
			return ret;
		}
		PRINTM(MEVENT,
		       "scan result not expired or fake scan complete flag is on\n");
		return -EAGAIN;
	}
	memset(&bss_info, 0, sizeof(bss_info));
	if (MLAN_STATUS_SUCCESS ==
	    woal_get_bss_info(priv, MOAL_IOCTL_WAIT, &bss_info)) {
		if (bss_info.scan_block) {
			PRINTM(MEVENT, "Block scan in mlan module\n");
			return -EAGAIN;
		}
	}
	if (priv->phandle->scan_request &&
	    priv->phandle->scan_request != request) {
		PRINTM(MCMND,
		       "different scan_request is coming before previous one is finished on %s...\n",
		       dev->name);
		LEAVE();
		return -EBUSY;
	}
	spin_lock_irqsave(&priv->phandle->scan_req_lock, flags);
	priv->phandle->scan_request = request;
	spin_unlock_irqrestore(&priv->phandle->scan_req_lock, flags);

	memset(&scan_req, 0x00, sizeof(scan_req));
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
	if (!is_broadcast_ether_addr(request->bssid)) {
		memcpy(scan_req.specific_bssid, request->bssid, ETH_ALEN);
		PRINTM(MIOCTL, "scan: bssid=" MACSTR "\n",
		       MAC2STR(scan_req.specific_bssid));
	}
#endif

	if (priv->phandle->scan_request->n_channels <= 38)
		scan_req.ext_scan_type = EXT_SCAN_ENHANCE;

	for (i = 0; i < priv->phandle->scan_request->n_ssids; i++) {
		memcpy(scan_req.ssid_list[i].ssid,
		       priv->phandle->scan_request->ssids[i].ssid,
		       priv->phandle->scan_request->ssids[i].ssid_len);
		if (priv->phandle->scan_request->ssids[i].ssid_len)
			scan_req.ssid_list[i].max_len = 0;
		else
			scan_req.ssid_list[i].max_len = 0xff;
		PRINTM(MIOCTL, "scan: ssid=%s\n", scan_req.ssid_list[i].ssid);
	}
	for (i = 0;
	     i < MIN(WLAN_USER_SCAN_CHAN_MAX,
		     priv->phandle->scan_request->n_channels); i++) {
		chan = priv->phandle->scan_request->channels[i];
		scan_req.chan_list[i].chan_number = chan->hw_value;
		scan_req.chan_list[i].radio_type = chan->band;
		if ((chan->flags & IEEE80211_CHAN_PASSIVE_SCAN)
		    || !priv->phandle->scan_request->n_ssids)
			scan_req.chan_list[i].scan_type =
				MLAN_SCAN_TYPE_PASSIVE;
		else if (chan->flags & IEEE80211_CHAN_RADAR)
			scan_req.chan_list[i].scan_type =
				MLAN_SCAN_TYPE_PASSIVE_TO_ACTIVE;
		else
			scan_req.chan_list[i].scan_type = MLAN_SCAN_TYPE_ACTIVE;
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
		scan_req.chan_list[i].scan_time =
			priv->phandle->scan_request->duration;
#else
		scan_req.chan_list[i].scan_time = 0;
#endif
#ifdef UAP_CFG80211
		if (GET_BSS_ROLE(priv) == MLAN_BSS_ROLE_UAP)
			scan_req.chan_list[i].scan_time =
				MIN_SPECIFIC_SCAN_CHAN_TIME;
#endif
	}
	if (priv->phandle->scan_request->ie &&
	    priv->phandle->scan_request->ie_len) {
		if (woal_find_wps_ie_in_probereq
		    ((t_u8 *)priv->phandle->scan_request->ie,
		     priv->phandle->scan_request->ie_len)) {
			PRINTM(MIOCTL,
			       "Notify firmware only keep probe response\n");
			scan_req.proberesp_only = MTRUE;
		}
		if (MLAN_STATUS_SUCCESS !=
		    woal_cfg80211_mgmt_frame_ie(priv, NULL, 0,
						NULL, 0, NULL, 0,
						(t_u8 *)priv->phandle->
						scan_request->ie,
						priv->phandle->scan_request->
						ie_len, MGMT_MASK_PROBE_REQ,
						MOAL_IOCTL_WAIT)) {
			PRINTM(MERROR, "Fail to set scan request IE\n");
			ret = -EFAULT;
			goto done;
		}
	} else {
		/** Clear SCAN IE in Firmware */
		if (priv->probereq_index != MLAN_CUSTOM_IE_AUTO_IDX_MASK)
			woal_cfg80211_mgmt_frame_ie(priv, NULL, 0, NULL, 0,
						    NULL, 0, NULL, 0,
						    MGMT_MASK_PROBE_REQ,
						    MOAL_IOCTL_WAIT);
	}
#ifdef UAP_CFG80211
	if (GET_BSS_ROLE(priv) == MLAN_BSS_ROLE_UAP) {
	/** use sync scan for uap */
		ret = woal_uap_scan(priv, &scan_req);
		if (!ret) {
			LEAVE();
			return ret;
		} else {
			PRINTM(MERROR, "Uap SCAN failure\n");
			goto done;
		}
	}
#endif
	if (MLAN_STATUS_SUCCESS != woal_do_scan(priv, &scan_req)) {
		PRINTM(MERROR, "woal_do_scan fails!\n");
		ret = -EAGAIN;
		goto done;
	}
done:
	if (ret) {
		spin_lock_irqsave(&priv->phandle->scan_req_lock, flags);
		woal_cfg80211_scan_done(request, MTRUE);
		priv->phandle->scan_request = NULL;
		priv->phandle->scan_priv = NULL;
		spin_unlock_irqrestore(&priv->phandle->scan_req_lock, flags);
	} else
		PRINTM(MMSG, "wlan: %s START SCAN\n", dev->name);
	LEAVE();
	return ret;
}

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(4, 5, 0)
static void
woal_cfg80211_abort_scan(struct wiphy *wiphy, struct wireless_dev *wdev)
{
	moal_private *priv = (moal_private *)woal_get_netdev_priv(wdev->netdev);
	ENTER();
	PRINTM(MMSG, "wlan: ABORT SCAN start\n");
	woal_cancel_scan(priv, MOAL_IOCTL_WAIT);
	LEAVE();
	return;
}
#endif
/**
 * @brief construct and send ft action request
 *
*  @param priv     A pointer to moal_private structure
 * @param ie       A pointer to ft ie
 * @param le       Value of ie len
 * @param bssid    A pointer to target ap bssid
 * @
 * @return         0 -- success, otherwise fail
 */
static int
woal_send_ft_action_requst(moal_private *priv, t_u8 *ie, t_u8 len, t_u8 *bssid,
			   t_u8 *target_ap)
{
	IEEE80211_MGMT *mgmt = NULL;
	mlan_status status = MLAN_STATUS_SUCCESS;
	pmlan_buffer pmbuf = NULL;
	t_u32 pkt_type;
	t_u32 tx_control;
	t_u16 packet_len = 0;
	t_u8 addr[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
	int ret = 0;

	ENTER();

	/* pkt_type + tx_control */
#define HEADER_SIZE				8
	/* frmctl + durationid + addr1 + addr2 + addr3 + seqctl + addr4 */
#define MGMT_HEADER_LEN		(2 + 2 + 6 + 6 + 6 + 2 +6)
	/* 14   = category + action + sta addr + target ap */
#define FT_REQUEST_LEN 14
	packet_len = (t_u16)len + MGMT_HEADER_LEN + FT_REQUEST_LEN;
	pmbuf = woal_alloc_mlan_buffer(priv->phandle,
				       MLAN_MIN_DATA_HEADER_LEN + HEADER_SIZE +
				       packet_len + sizeof(packet_len));
	if (!pmbuf) {
		PRINTM(MERROR, "Fail to allocate mlan_buffer\n");
		ret = -ENOMEM;
		goto done;
	}

	pmbuf->data_offset = MLAN_MIN_DATA_HEADER_LEN;
	pkt_type = MRVL_PKT_TYPE_MGMT_FRAME;
	tx_control = 0;
	/* Add pkt_type and tx_control */
	memcpy(pmbuf->pbuf + pmbuf->data_offset, &pkt_type, sizeof(pkt_type));
	memcpy(pmbuf->pbuf + pmbuf->data_offset + sizeof(pkt_type), &tx_control,
	       sizeof(tx_control));
	/*Add packet len */
	memcpy(pmbuf->pbuf + pmbuf->data_offset + HEADER_SIZE, &packet_len,
	       sizeof(packet_len));

	mgmt = (IEEE80211_MGMT *)(pmbuf->pbuf + pmbuf->data_offset +
				  HEADER_SIZE + sizeof(packet_len));
	memset(mgmt, 0, MGMT_HEADER_LEN);
	mgmt->frame_control = cpu_to_le16(IEEE80211_FTYPE_MGMT |
					  IEEE80211_STYPE_ACTION);
	memcpy(mgmt->da, bssid, ETH_ALEN);
	memcpy(mgmt->sa, priv->current_addr, ETH_ALEN);
	memcpy(mgmt->bssid, bssid, ETH_ALEN);
	memcpy(mgmt->addr4, addr, ETH_ALEN);

	mgmt->u.ft_req.category = 0x06;	/**ft action code 0x6*/
	mgmt->u.ft_req.action = 0x1; /**ft action request*/
	memcpy(mgmt->u.ft_req.sta_addr, priv->current_addr, ETH_ALEN);
	memcpy(mgmt->u.ft_req.target_ap_addr, target_ap, ETH_ALEN);

	if (ie && len)
		memcpy((t_u8 *)(&mgmt->u.ft_req.variable), ie, len);

	pmbuf->data_len = HEADER_SIZE + packet_len + sizeof(packet_len);
	pmbuf->buf_type = MLAN_BUF_TYPE_RAW_DATA;
	pmbuf->bss_index = priv->bss_index;
	pmbuf->priority = 7;

	status = mlan_send_packet(priv->phandle->pmlan_adapter, pmbuf);

	switch (status) {
	case MLAN_STATUS_PENDING:
		atomic_inc(&priv->phandle->tx_pending);
		queue_work(priv->phandle->workqueue, &priv->phandle->main_work);
		break;
	case MLAN_STATUS_SUCCESS:
		woal_free_mlan_buffer(priv->phandle, pmbuf);
		break;
	case MLAN_STATUS_FAILURE:
	default:
		woal_free_mlan_buffer(priv->phandle, pmbuf);
		ret = -EFAULT;
		break;
	}

done:
	LEAVE();
	return ret;
}

/**
 * @brief construct and send ft auth request
 *
*  @param priv     A pointer to moal_private structure
 * @param ie       A pointer to ft ie
 * @param le       Value of ie len
 * @param bssid    A pointer to target ap bssid
 * @
 * @return         0 -- success, otherwise fail
 */
static int
woal_send_ft_auth_requst(moal_private *priv, t_u8 *ie, t_u8 len, t_u8 *bssid)
{
	IEEE80211_MGMT *mgmt = NULL;
	mlan_status status = MLAN_STATUS_SUCCESS;
	pmlan_buffer pmbuf = NULL;
	t_u32 pkt_type;
	t_u32 tx_control;
	t_u16 packet_len = 0;
	t_u8 addr[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
	int ret = 0;

	ENTER();
	/* pkt_type + tx_control */
#define HEADER_SIZE				8
	/* frmctl + durationid + addr1 + addr2 + addr3 + seqctl + addr4 */
#define MGMT_HEADER_LEN		(2 + 2 + 6 + 6 + 6 + 2 +6)
	/* 6   = auth_alg + auth_transaction +auth_status */
#define AUTH_BODY_LEN 6
	packet_len = (t_u16)len + MGMT_HEADER_LEN + AUTH_BODY_LEN;
	pmbuf = woal_alloc_mlan_buffer(priv->phandle,
				       MLAN_MIN_DATA_HEADER_LEN + HEADER_SIZE +
				       packet_len + sizeof(packet_len));
	if (!pmbuf) {
		PRINTM(MERROR, "Fail to allocate mlan_buffer\n");
		ret = -ENOMEM;
		goto done;
	}

	pmbuf->data_offset = MLAN_MIN_DATA_HEADER_LEN;
	pkt_type = MRVL_PKT_TYPE_MGMT_FRAME;
	tx_control = 0;
	/* Add pkt_type and tx_control */
	memcpy(pmbuf->pbuf + pmbuf->data_offset, &pkt_type, sizeof(pkt_type));
	memcpy(pmbuf->pbuf + pmbuf->data_offset + sizeof(pkt_type), &tx_control,
	       sizeof(tx_control));
	/*Add packet len */
	memcpy(pmbuf->pbuf + pmbuf->data_offset + HEADER_SIZE, &packet_len,
	       sizeof(packet_len));

	mgmt = (IEEE80211_MGMT *)(pmbuf->pbuf + pmbuf->data_offset +
				  HEADER_SIZE + sizeof(packet_len));
	memset(mgmt, 0, MGMT_HEADER_LEN);
	mgmt->frame_control = cpu_to_le16(IEEE80211_FTYPE_MGMT |
					  IEEE80211_STYPE_AUTH);
	memcpy(mgmt->da, bssid, ETH_ALEN);
	memcpy(mgmt->sa, priv->current_addr, ETH_ALEN);
	memcpy(mgmt->bssid, bssid, ETH_ALEN);
	memcpy(mgmt->addr4, addr, ETH_ALEN);

	mgmt->u.auth.auth_alg = cpu_to_le16(WLAN_AUTH_FT);
	mgmt->u.auth.auth_transaction = cpu_to_le16(1);
	mgmt->u.auth.status_code = cpu_to_le16(0);
	if (ie && len)
		memcpy((t_u8 *)(&mgmt->u.auth.variable), ie, len);

	pmbuf->data_len = HEADER_SIZE + packet_len + sizeof(packet_len);
	pmbuf->buf_type = MLAN_BUF_TYPE_RAW_DATA;
	pmbuf->bss_index = priv->bss_index;
	pmbuf->priority = 7;

	status = mlan_send_packet(priv->phandle->pmlan_adapter, pmbuf);

	switch (status) {
	case MLAN_STATUS_PENDING:
		atomic_inc(&priv->phandle->tx_pending);
		queue_work(priv->phandle->workqueue, &priv->phandle->main_work);
		break;
	case MLAN_STATUS_SUCCESS:
		woal_free_mlan_buffer(priv->phandle, pmbuf);
		break;
	case MLAN_STATUS_FAILURE:
	default:
		woal_free_mlan_buffer(priv->phandle, pmbuf);
		ret = -EFAULT;
		break;
	}

done:
	LEAVE();
	return ret;
}

/**
 * @brief connect the AP through ft over air.
 *
 * @param priv            A pointer to moal_private structure
 * @param bssid           A pointer to bssid
 * @param chan            struct ieee80211_channel
 *
 * @return                0 -- success, otherwise fail
 */
static int
woal_connect_ft_over_air(moal_private *priv, t_u8 *bssid,
			 struct ieee80211_channel *chan)
{
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
	t_u8 status = 0;
#endif
	t_u8 wait_option = MOAL_IOCTL_WAIT;
	int ret = 0;
	long timeout = 0;

	ENTER();

	if (!bssid) {
		PRINTM(MERROR,
		       "Invalid bssid, unable to connect AP to through FT\n");
		LEAVE();
		return -EFAULT;
	}

	/*enable auth register frame */
	woal_mgmt_frame_register(priv, IEEE80211_STYPE_AUTH, MTRUE);

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
#define AUTH_TX_DEFAULT_WAIT_TIME  1200
	woal_cfg80211_remain_on_channel_cfg(priv, wait_option, MFALSE, &status,
					    chan, 0, AUTH_TX_DEFAULT_WAIT_TIME);
#endif
	/*construct auth request and send out */
	woal_send_ft_auth_requst(priv, priv->ft_ie, priv->ft_ie_len, bssid);
	PRINTM(MMSG, "wlan: send out FT auth,wait for auth response\n");
	/*wait until received auth response */
	priv->ft_wait_condition = MFALSE;
	timeout =
		wait_event_timeout(priv->ft_wait_q, priv->ft_wait_condition,
				   1 * HZ);
	if (!timeout) {
		/*connet fail */
		if (!priv->ft_roaming_triggered_by_driver) {
			woal_inform_bss_from_scan_result(priv, NULL,
							 wait_option);
			cfg80211_connect_result(priv->netdev, priv->cfg_bssid,
						NULL, 0, NULL, 0,
						WLAN_STATUS_SUCCESS,
						GFP_KERNEL);
		}
		priv->ft_roaming_triggered_by_driver = MFALSE;
		PRINTM(MMSG, "wlan: keep connected to bssid " MACSTR "\n",
		       MAC2STR(priv->cfg_bssid));
	} else {
		PRINTM(MMSG, "wlan: FT auth received \n");
		memcpy(priv->target_ap_bssid, bssid, ETH_ALEN);
	}
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
	woal_cfg80211_remain_on_channel_cfg(priv, wait_option, MTRUE, &status,
					    NULL, 0, 0);
#endif
	woal_mgmt_frame_register(priv, IEEE80211_STYPE_AUTH, MFALSE);

	LEAVE();
	return ret;
}

/**
 * @brief connect the AP through ft over DS.
 *
 * @param priv            A pointer to moal_private structure
 * @param bssid           A pointer to bssid
 * @param chan            struct ieee80211_channel
 *
 * @return                0 -- success, otherwise fail
 */
static int
woal_connect_ft_over_ds(moal_private *priv, t_u8 *bssid,
			struct ieee80211_channel *pchan)
{
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
	t_u8 status = 0;
#endif
	t_u8 wait_option = MOAL_IOCTL_WAIT;
	int ret = 0;
	long timeout = 0;

	ENTER();

	if (priv->media_connected) {
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
		woal_cfg80211_remain_on_channel_cfg(priv, wait_option, MFALSE,
						    &status, pchan, 0, 1200);
#endif
		/*construct ft action request and send out */
		woal_send_ft_action_requst(priv, priv->ft_ie, priv->ft_ie_len,
					   (t_u8 *)priv->cfg_bssid, bssid);
		PRINTM(MMSG,
		       "wlan: send out FT request,wait for FT response\n");
		/*wait until received auth response */
		priv->ft_wait_condition = MFALSE;
		timeout =
			wait_event_timeout(priv->ft_wait_q,
					   priv->ft_wait_condition, 1 * HZ);
		if (!timeout) {
			/*go over air, as current AP may be unreachable */
			PRINTM(MMSG, "wlan: go over air\n");
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
			woal_cfg80211_remain_on_channel_cfg(priv, wait_option,
							    MTRUE, &status,
							    NULL, 0, 0);
#endif
			woal_connect_ft_over_air(priv, bssid, pchan);
			LEAVE();
			return ret;
		} else {
			PRINTM(MMSG, "wlan: received FT response\n");
			memcpy(priv->target_ap_bssid, bssid, ETH_ALEN);
		}
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
		woal_cfg80211_remain_on_channel_cfg(priv, wait_option, MTRUE,
						    &status, NULL, 0, 0);
#endif

	}

	LEAVE();
	return ret;
}

/**
 * @brief start FT Roaming.
 *
 * @param priv               A pointer to moal_private structure
 * @param ssid_bssid         A pointer to mlan_ssid_bssid structure
 *
 *
 * @return                   0 -- success, otherwise fail
 */
static int
woal_start_ft_roaming(moal_private *priv, mlan_ssid_bssid *ssid_bssid)
{
	struct ieee80211_channel chan;
	int ret = 0;

	ENTER();
	PRINTM(MEVENT, "Try to start FT roaming......\n");
	chan.band = (ssid_bssid->channel < 36) ?
		IEEE80211_BAND_2GHZ : IEEE80211_BAND_5GHZ;
	chan.center_freq = ieee80211_channel_to_frequency(ssid_bssid->channel
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
							  , chan.band
#endif
		);

	if (!(priv->last_event & EVENT_PRE_BCN_LOST) &&
	    (ssid_bssid->ft_cap & MBIT(0))) {
		woal_connect_ft_over_ds(priv, (t_u8 *)&ssid_bssid->bssid,
					&chan);
	} else {
		/*if pre beacon lost, it need to send auth request instead ft action request when ft over ds */

		woal_connect_ft_over_air(priv, (t_u8 *)&ssid_bssid->bssid,
					 &chan);
	}

	LEAVE();
	return ret;
}

/**
 * @brief Request the driver to connect to the ESS with
 * the specified parameters from kernel
 *
 * @param wiphy           A pointer to wiphy structure
 * @param dev             A pointer to net_device structure
 * @param sme             A pointer to cfg80211_connect_params structure
 *
 * @return                0 -- success, otherwise fail
 */
static int
woal_cfg80211_connect(struct wiphy *wiphy, struct net_device *dev,
		      struct cfg80211_connect_params *sme)
{
	moal_private *priv = (moal_private *)woal_get_netdev_priv(dev);
	int ret = 0;
	mlan_bss_info bss_info;
	unsigned long flags;
	mlan_ds_misc_assoc_rsp *assoc_rsp;
	IEEEtypes_AssocRsp_t *passoc_rsp = NULL;
	mlan_ssid_bssid ssid_bssid;
	moal_handle *handle = priv->phandle;
	int i;

	ENTER();

	PRINTM(MINFO, "Received association request on %s\n", dev->name);
	priv->cfg_disconnect = MFALSE;
#ifdef UAP_CFG80211
	if (GET_BSS_ROLE(priv) == MLAN_BSS_ROLE_UAP) {
		LEAVE();
		return 0;
	}
#endif
	if (priv->wdev->iftype != NL80211_IFTYPE_STATION) {
		PRINTM(MERROR,
		       "Received infra assoc request when station not in infra mode\n");
		LEAVE();
		return -EINVAL;
	}

	memset(&ssid_bssid, 0, sizeof(ssid_bssid));
	memcpy(&ssid_bssid.ssid.ssid, sme->ssid,
	       MIN(sme->ssid_len, sizeof(ssid_bssid.ssid.ssid)));
	ssid_bssid.ssid.ssid_len = sme->ssid_len;
	if (sme->bssid)
		memcpy(&ssid_bssid.bssid, sme->bssid, ETH_ALEN);
	/* Not allowed to connect to the same AP which is already connected
	   with other interface */
	for (i = 0; i < handle->priv_num; i++) {
		if (handle->priv[i] != priv &&
		    MTRUE == woal_is_connected(handle->priv[i], &ssid_bssid)) {
			PRINTM(MMSG,
			       "wlan: already connected with other interface, bssid "
			       MACSTR "\n",
			       MAC2STR(handle->priv[i]->cfg_bssid));
			LEAVE();
			return -EINVAL;
		}
	}
	/** cancel pending scan */
	woal_cancel_scan(priv, MOAL_IOCTL_WAIT);

	/*11r roaming triggered by supplicant */
	if (priv->media_connected && priv->ft_ie_len &&
	    !(priv->ft_cap & MBIT(0))) {
	/** get current bss info */
		memset(&bss_info, 0, sizeof(bss_info));
		woal_get_bss_info(priv, MOAL_IOCTL_WAIT, &bss_info);
	/** get target bss info */
		if (MLAN_STATUS_SUCCESS !=
		    woal_find_essid(priv, &ssid_bssid, MOAL_IOCTL_WAIT)) {
			ret = woal_cfg80211_connect_scan(priv, sme,
							 MOAL_IOCTL_WAIT);
			if (!ret) {
				if (MLAN_STATUS_SUCCESS !=
				    woal_find_best_network(priv,
							   MOAL_IOCTL_WAIT,
							   &ssid_bssid)) {
					PRINTM(MERROR,
					       "can't find targe AP \n");
					// LEAVE();
					// return -EFAULT;
				}
			}
		}
		if (bss_info.mdid == ssid_bssid.ft_md &&
		    bss_info.ft_cap == ssid_bssid.ft_cap) {
			ret = woal_start_ft_roaming(priv, &ssid_bssid);
			LEAVE();
			return 0;
		}
	}
	priv->cfg_connect = MTRUE;
	if (priv->scan_type == MLAN_SCAN_TYPE_PASSIVE)
		woal_set_scan_type(priv, MLAN_SCAN_TYPE_ACTIVE);
	priv->assoc_status = 0;
	assoc_rsp = kzalloc(sizeof(mlan_ds_misc_assoc_rsp), GFP_ATOMIC);
	if (!assoc_rsp) {
		PRINTM(MERROR, "Failed to allocate memory for assoc_rsp\n");
		ret = -ENOMEM;
		LEAVE();
		return ret;
	}
	ret = woal_cfg80211_assoc(priv, (void *)sme, MOAL_IOCTL_WAIT,
				  assoc_rsp);

	if (priv->scan_type == MLAN_SCAN_TYPE_PASSIVE)
		woal_set_scan_type(priv, MLAN_SCAN_TYPE_PASSIVE);
	if (!ret) {
		passoc_rsp = (IEEEtypes_AssocRsp_t *)assoc_rsp->assoc_resp_buf;
		priv->rssi_low = DEFAULT_RSSI_LOW_THRESHOLD;
		if (priv->bss_type == MLAN_BSS_TYPE_STA)
			woal_save_conn_params(priv, sme);
		memset(&bss_info, 0, sizeof(bss_info));
		woal_get_bss_info(priv, MOAL_IOCTL_WAIT, &bss_info);
		priv->channel = bss_info.bss_chan;
		if (!ssid_bssid.ft_md) {
			priv->ft_ie_len = 0;
			priv->ft_pre_connect = MFALSE;
			priv->ft_md = 0;
			priv->ft_cap = 0;
		}
	}
	spin_lock_irqsave(&priv->connect_lock, flags);
	priv->cfg_connect = MFALSE;
	if (!ret && priv->media_connected) {
		PRINTM(MMSG,
		       "wlan: Connected to bssid " MACSTR " successfully\n",
		       MAC2STR(priv->cfg_bssid));
		spin_unlock_irqrestore(&priv->connect_lock, flags);
		cfg80211_connect_result(priv->netdev, priv->cfg_bssid, NULL, 0,
					passoc_rsp->ie_buffer,
					assoc_rsp->assoc_resp_len -
					ASSOC_RESP_FIXED_SIZE,
					WLAN_STATUS_SUCCESS, GFP_KERNEL);
	} else {
		PRINTM(MINFO, "wlan: Failed to connect to bssid " MACSTR "\n",
		       MAC2STR(priv->cfg_bssid));
		memset(priv->cfg_bssid, 0, ETH_ALEN);
		spin_unlock_irqrestore(&priv->connect_lock, flags);
		cfg80211_connect_result(priv->netdev, priv->cfg_bssid, NULL, 0,
					NULL, 0, woal_get_assoc_status(priv),
					GFP_KERNEL);

	}
	kfree(assoc_rsp);
	assoc_rsp = NULL;
	LEAVE();
	return 0;
}

/**
 *  @brief This function will print diconnect reason code according
 *  to IEEE 802.11 spec
 *
 *  @param reason_code    reason code for the deauth/disaccoc
 *                        received from firmware
 *  @return        N/A
 */
static void
woal_print_disconnect_reason(t_u16 reason_code)
{
	ENTER();

	switch (reason_code) {
	case MLAN_REASON_UNSPECIFIED:
		PRINTM(MMSG, "wlan: REASON: Unspecified reason\n");
		break;
	case MLAN_REASON_PREV_AUTH_NOT_VALID:
		PRINTM(MMSG,
		       "wlan: REASON: Previous authentication no longer valid\n");
		break;
	case MLAN_REASON_DEAUTH_LEAVING:
		PRINTM(MMSG,
		       "wlan: REASON: (Deauth) Sending STA is leaving (or has left) IBSS or ESS\n");
		break;
	case MLAN_REASON_DISASSOC_DUE_TO_INACTIVITY:
		PRINTM(MMSG,
		       "wlan: REASON: Disassociated due to inactivity \n");
		break;
	case MLAN_REASON_DISASSOC_AP_BUSY:
		PRINTM(MMSG,
		       "wlan: REASON: (Disassociated) AP unable to handle all connected STAs\n");
		break;
	case MLAN_REASON_CLASS2_FRAME_FROM_NOAUTH_STA:
		PRINTM(MMSG,
		       "wlan: REASON: Class 2 frame was received from nonauthenticated STA\n");
		break;
	case MLAN_REASON_CLASS3_FRAME_FROM_NOASSOC_STA:
		PRINTM(MMSG,
		       "wlan: REASON: Class 3 frame was received from nonassociated STA\n");
		break;
	case MLAN_REASON_DISASSOC_STA_HAS_LEFT:
		PRINTM(MMSG,
		       "wlan: REASON: (Disassocated) Sending STA is leaving (or has left) BSS\n");
		break;
	case MLAN_REASON_STA_REQ_ASSOC_WITHOUT_AUTH:
		PRINTM(MMSG,
		       "wlan: REASON: STA requesting (re)assoc is not authenticated with responding STA\n");
		break;
	default:
		break;
	}

	LEAVE();
	return;
}

/**
 * @brief Request the driver to disconnect
 *
 * @param wiphy           A pointer to wiphy structure
 * @param dev             A pointer to net_device structure
 * @param reason_code     Reason code
 *
 * @return                0 -- success, otherwise fail
 */
static int
woal_cfg80211_disconnect(struct wiphy *wiphy, struct net_device *dev,
			 t_u16 reason_code)
{
	moal_private *priv = (moal_private *)woal_get_netdev_priv(dev);

	ENTER();
	PRINTM(MMSG,
	       "wlan: Received disassociation request on %s, reason: %u\n",
	       dev->name, reason_code);
	woal_print_disconnect_reason(reason_code);
#ifdef UAP_CFG80211
	if (GET_BSS_ROLE(priv) == MLAN_BSS_ROLE_UAP) {
		LEAVE();
		return 0;
	}
#endif
	if (priv->phandle->driver_status) {
		PRINTM(MERROR,
		       "Block woal_cfg80211_disconnect in abnormal driver state\n");
		LEAVE();
		return -EFAULT;
	}

	if (priv->cfg_disconnect) {
		PRINTM(MERROR, "Disassociation already in progress\n");
		LEAVE();
		return 0;
	}

	if (priv->media_connected == MFALSE) {
		PRINTM(MMSG, " Already disconnected\n");
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
		if (priv->wdev->current_bss &&
		    (priv->wdev->iftype == NL80211_IFTYPE_STATION ||
		     priv->wdev->iftype == NL80211_IFTYPE_P2P_CLIENT)) {
			priv->cfg_disconnect = MTRUE;
			cfg80211_disconnected(priv->netdev, 0, NULL, 0,
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
					      true,
#endif
					      GFP_KERNEL);
		}
#endif
		LEAVE();
		return 0;
	}

	priv->cfg_disconnect = MTRUE;
	if (woal_disconnect
	    (priv, MOAL_IOCTL_WAIT_TIMEOUT, priv->cfg_bssid,
	     reason_code) != MLAN_STATUS_SUCCESS) {
		priv->cfg_disconnect = MFALSE;
		LEAVE();
		return -EFAULT;
	}

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
	if (priv->wdev->iftype == NL80211_IFTYPE_STATION ||
	    priv->wdev->iftype == NL80211_IFTYPE_P2P_CLIENT)
		cfg80211_disconnected(priv->netdev, 0, NULL, 0,
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(4, 2, 0)
				      true,
#endif
				      GFP_KERNEL);
#endif

	memset(priv->cfg_bssid, 0, ETH_ALEN);
	if (priv->bss_type == MLAN_BSS_TYPE_STA)
		woal_clear_conn_params(priv);
	priv->channel = 0;

	LEAVE();
	return 0;
}

/**
*  @brief This function is deauthentication handler when host MLME
*          enable.
*          In this case driver will prepare and send Deauth Req.
*
*  @param wiphy       A pointer to wiphy.
*
*  @param dev         A pointer to net_device
*
*  @param req         A pointer to cfg80211_deauth_request
*
*  @return            0 -- success, otherwise fail
*/

static int
woal_cfg80211_deauthenticate(struct wiphy *wiphy,
			     struct net_device *dev,
			     struct cfg80211_deauth_request *req)
{
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
	moal_private *priv = (moal_private *)woal_get_netdev_priv(dev);
#endif
	int status = 0;
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
	if (priv->host_mlme) {
		priv->host_mlme = MFALSE;
		priv->auth_flag = 0;
	}
#endif
	status = woal_cfg80211_disconnect(wiphy, dev, req->reason_code);

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
#if CFG80211_VERSION_CODE < KERNEL_VERSION(3, 11, 0)
	if (priv->wdev->iftype == NL80211_IFTYPE_STATION ||
	    priv->wdev->iftype == NL80211_IFTYPE_P2P_CLIENT)
		cfg80211_disconnected(priv->netdev, 0, NULL, 0, GFP_KERNEL);
#endif
#endif
	return status;
}

/**
*  @brief This function is disassociation handler when host MLME
*          enable.
*          In this case driver will prepare and send Disassoc frame.
*
*  @param wiphy       A pointer to wiphy.
*
*  @param dev         A pointer to net_device
*
*  @param req         A pointer to cfg80211_disassoc_request
*
*  @return            0 -- success, otherwise fail
*/
static int
woal_cfg80211_disassociate(struct wiphy *wiphy, struct net_device *dev,
			   struct cfg80211_disassoc_request *req)
{
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
#if CFG80211_VERSION_CODE < KERNEL_VERSION(3, 11, 0)
	moal_private *priv = (moal_private *)woal_get_netdev_priv(dev);
#endif
#endif
	int status = 0;
	status = woal_cfg80211_disconnect(wiphy, dev, req->reason_code);

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
#if CFG80211_VERSION_CODE < KERNEL_VERSION(3, 11, 0)
	if (priv->wdev->iftype == NL80211_IFTYPE_STATION ||
	    priv->wdev->iftype == NL80211_IFTYPE_P2P_CLIENT)
		cfg80211_disconnected(priv->netdev, 0, NULL, 0, GFP_KERNEL);
#endif
#endif
	return status;
}

/**
 * @brief Request the driver to get the station information
 *
 * @param wiphy           A pointer to wiphy structure
 * @param dev             A pointer to net_device structure
 * @param mac             MAC address of the station
 * @param sinfo           A pointer to station_info structure
 *
 * @return                0 -- success, otherwise fail
 */
static int
woal_cfg80211_get_station(struct wiphy *wiphy, struct net_device *dev,
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 16, 0)
			  const t_u8 *mac,
#else
			  t_u8 *mac,
#endif
			  struct station_info *sinfo)
{
	mlan_status ret = MLAN_STATUS_SUCCESS;
	moal_private *priv = (moal_private *)woal_get_netdev_priv(dev);

	ENTER();

#ifdef UAP_CFG80211
	if (GET_BSS_ROLE(priv) == MLAN_BSS_ROLE_UAP) {
		LEAVE();
		return woal_uap_cfg80211_get_station(wiphy, dev, mac, sinfo);
	}
#endif
	if (priv->media_connected == MFALSE) {
		PRINTM(MINFO, "cfg80211: Media not connected!\n");
		LEAVE();
		return -ENOENT;
	}

	if (MLAN_STATUS_SUCCESS != woal_cfg80211_dump_station_info(priv, sinfo)) {
		PRINTM(MERROR, "cfg80211: Failed to get station info\n");
		ret = -EFAULT;
	}
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3,2,0)
#endif
	LEAVE();
	return ret;
}

/**
 * @brief Request the driver to dump the station information
 *
 * @param wiphy           A pointer to wiphy structure
 * @param dev             A pointer to net_device structure
 * @param idx             Station index
 * @param mac             MAC address of the station
 * @param sinfo           A pointer to station_info structure
 *
 * @return                0 -- success, otherwise fail
 */
static int
woal_cfg80211_dump_station(struct wiphy *wiphy,
			   struct net_device *dev, int idx,
			   t_u8 *mac, struct station_info *sinfo)
{
	mlan_status ret = MLAN_STATUS_SUCCESS;
	moal_private *priv = (moal_private *)woal_get_netdev_priv(dev);

	ENTER();

#ifdef UAP_CFG80211
	if (GET_BSS_ROLE(priv) == MLAN_BSS_ROLE_UAP) {
		LEAVE();
		return woal_uap_cfg80211_dump_station(wiphy, dev, idx, mac,
						      sinfo);
	}
#endif

	if (!priv->media_connected || idx != 0) {
		PRINTM(MINFO,
		       "cfg80211: Media not connected or not for this station!\n");
		LEAVE();
		return -ENOENT;
	}

	memcpy(mac, priv->cfg_bssid, ETH_ALEN);

	if (MLAN_STATUS_SUCCESS != woal_cfg80211_dump_station_info(priv, sinfo)) {
		PRINTM(MERROR, "cfg80211: Failed to get station info\n");
		ret = -EFAULT;
	}

	LEAVE();
	return ret;
}

/**
 *  @brief Convert driver band configuration to IEEE band type
 *
 *  @param bandcfg  Driver band configuration
 *
 *  @return         IEEE band type
 */
t_u8
woal_bandcfg_to_ieee_band(Band_Config_t bandcfg)
{
	t_u8 ret_radio_type = 0;

	ENTER();

	switch (bandcfg.chanBand) {
	case BAND_5GHZ:
		ret_radio_type = IEEE80211_BAND_5GHZ;
		break;
	case BAND_2GHZ:
	default:
		ret_radio_type = IEEE80211_BAND_2GHZ;
		break;
	}
	LEAVE();
	return ret_radio_type;
}

/**
 * @brief Request the driver to dump survey info
 *
 * @param wiphy           A pointer to wiphy structure
 * @param dev             A pointer to net_device structure
 * @param idx             Station index
 * @param survey          A pointer to survey_info structure
 *
 * @return                0 -- success, otherwise fail
 */
static int
woal_cfg80211_dump_survey(struct wiphy *wiphy, struct net_device *dev,
			  int idx, struct survey_info *survey)
{
	int ret = -ENOENT;
	moal_private *priv = (moal_private *)woal_get_netdev_priv(dev);
	enum ieee80211_band band;
	ChanStatistics_t *pchan_stats = NULL;
	mlan_scan_resp scan_resp;

	ENTER();
	PRINTM(MIOCTL, "dump_survey idx=%d\n", idx);

	memset(&scan_resp, 0, sizeof(scan_resp));
	if (MLAN_STATUS_SUCCESS != woal_get_scan_table(priv,
						       MOAL_IOCTL_WAIT,
						       &scan_resp)) {
		ret = -EFAULT;
		goto done;
	}
	pchan_stats = (ChanStatistics_t *)scan_resp.pchan_stats;
	if (idx > scan_resp.num_in_chan_stats || idx < 0) {
		ret = -EFAULT;
		goto done;
	}
	if (idx == scan_resp.num_in_chan_stats ||
	    !pchan_stats[idx].cca_scan_duration)
		goto done;
	ret = 0;
	memset(survey, 0, sizeof(*survey));
	band = woal_bandcfg_to_ieee_band(pchan_stats[idx].bandcfg);
	survey->channel =
		ieee80211_get_channel(wiphy,
				      ieee80211_channel_to_frequency(pchan_stats
								     [idx].
								     chan_num
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
								     , band
#endif
				      ));
	survey->filled = SURVEY_INFO_NOISE_DBM;
	survey->noise = pchan_stats[idx].noise;
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
	survey->filled |= SURVEY_INFO_TIME | SURVEY_INFO_TIME_BUSY;
	survey->time = pchan_stats[idx].cca_scan_duration;
	survey->time_busy = pchan_stats[idx].cca_busy_duration;
#else
	survey->filled |=
		SURVEY_INFO_CHANNEL_TIME | SURVEY_INFO_CHANNEL_TIME_BUSY;
	survey->channel_time = pchan_stats[idx].cca_scan_duration;
	survey->channel_time_busy = pchan_stats[idx].cca_busy_duration;
#endif
#endif
done:
	LEAVE();
	return ret;
}

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
/**
 * @brief Function gets channel info from cfg80211
 *
 * @param wiphy           A pointer to wiphy structure
 * @param wdev            A pointer to wireless_dev structure
 * @param chandef         A pointer to cfg80211_chan_def
 *
 * @return                0 -- success, otherwise fail
 */
static int
woal_cfg80211_get_channel(struct wiphy *wiphy,
			  struct wireless_dev *wdev,
			  struct cfg80211_chan_def *chandef)
{
	moal_private *priv = (moal_private *)woal_get_netdev_priv(wdev->netdev);
	chan_band_info channel;
	moal_handle *handle = (moal_handle *)woal_get_wiphy_priv(wiphy);

	memset(&channel, 0x00, sizeof(channel));

	if (wdev->iftype == NL80211_IFTYPE_MONITOR) {
		if ((handle->mon_if) &&
		    (handle->mon_if->mon_ndev == wdev->netdev)) {
			*chandef = handle->mon_if->chandef;
			return 0;
		}
		return -EFAULT;
	}
#ifdef UAP_SUPPORT
	if (GET_BSS_ROLE(priv) == MLAN_BSS_ROLE_UAP) {
		if (priv->bss_started == MTRUE) {
			if (MLAN_STATUS_SUCCESS !=
			    woal_set_get_ap_channel(priv, MLAN_ACT_GET,
						    MOAL_IOCTL_WAIT,
						    &channel)) {
				PRINTM(MERROR, "Fail to get ap channel \n");
				return -EFAULT;
			}
		} else {
			PRINTM(MIOCTL, "get_channel when AP is not started\n");
			return -EFAULT;
		}
	} else
#endif
	if (GET_BSS_ROLE(priv) == MLAN_BSS_ROLE_STA) {
		if (priv->media_connected == MTRUE) {
			if (MLAN_STATUS_SUCCESS !=
			    woal_get_sta_channel(priv, MOAL_IOCTL_WAIT,
						 &channel)) {
				PRINTM(MERROR, "Fail to get sta channel \n");
				return -EFAULT;
			}
		} else {
			PRINTM(MIOCTL,
			       "get_channel when STA is not connected\n");
			return -EFAULT;
		}
	} else {
		PRINTM(MERROR, "BssRole not support %d.\n", GET_BSS_ROLE(priv));
		return -EFAULT;
	}

	if (MLAN_STATUS_FAILURE == woal_chandef_create(priv, chandef, &channel))
		return -EFAULT;
	else
		return 0;
}
#endif

/**
 * @brief Request the driver to change the IEEE power save
 * mdoe
 *
 * @param wiphy           A pointer to wiphy structure
 * @param dev             A pointer to net_device structure
 * @param enabled         Enable or disable
 * @param timeout         Timeout value
 *
 * @return                0 -- success, otherwise fail
 */
static int
woal_cfg80211_set_power_mgmt(struct wiphy *wiphy,
			     struct net_device *dev, bool enabled, int timeout)
{
	int ret = 0, disabled;
	moal_private *priv = (moal_private *)woal_get_netdev_priv(dev);

	ENTER();
	if (hw_test || (ps_mode == MLAN_INIT_PARA_DISABLED)) {
		PRINTM(MIOCTL, "block set power hw_test=%d ps_mode=%d\n",
		       hw_test, ps_mode);
		LEAVE();
		return -EFAULT;
	}
	if (priv->phandle->driver_status) {
		PRINTM(MERROR,
		       "Block woal_cfg80211_set_power_mgmt in abnormal driver state\n");
		LEAVE();
		return -EFAULT;
	}
	if (enabled)
		disabled = 0;
	else
		disabled = 1;

	if (MLAN_STATUS_SUCCESS !=
	    woal_set_get_power_mgmt(priv, MLAN_ACT_SET, &disabled, timeout,
				    MOAL_IOCTL_WAIT)) {
		ret = -EOPNOTSUPP;
	}

	LEAVE();
	return ret;
}

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(2, 6, 31)
/**
 * @brief Request the driver to get the transmit power info
 *
 * @param wiphy           A pointer to wiphy structure
 * @param type            TX power adjustment type
 * @param dbm             TX power in dbm
 *
 * @return                0 -- success, otherwise fail
 */
static int
woal_cfg80211_get_tx_power(struct wiphy *wiphy,
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
			   struct wireless_dev *wdev,
#endif
			   int *dbm)
{
	int ret = 0;
	moal_private *priv = NULL;
	mlan_power_cfg_t power_cfg;
	moal_handle *handle = (moal_handle *)woal_get_wiphy_priv(wiphy);

	ENTER();

	if (!handle) {
		PRINTM(MFATAL, "Unable to get handle\n");
		LEAVE();
		return -EFAULT;
	}

	priv = woal_get_priv(handle, MLAN_BSS_ROLE_ANY);

	if (!priv) {
		PRINTM(MFATAL, "Unable to get priv in %s()\n", __func__);
		LEAVE();
		return -EFAULT;
	}

	if (MLAN_STATUS_SUCCESS !=
	    woal_set_get_tx_power(priv, MLAN_ACT_GET, &power_cfg)) {
		LEAVE();
		return -EFAULT;
	}

	*dbm = power_cfg.power_level;

	LEAVE();
	return ret;
}

/**
 * @brief Request the driver to change the transmit power
 *
 * @param wiphy           A pointer to wiphy structure
 * @param type            TX power adjustment type
 * @param dbm             TX power in dbm
 *
 * @return                0 -- success, otherwise fail
 */
static int
woal_cfg80211_set_tx_power(struct wiphy *wiphy,
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
			   struct wireless_dev *wdev,
#endif
#if CFG80211_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
			   enum tx_power_setting type,
#else
			   enum nl80211_tx_power_setting type,
#endif
			   int dbm)
{
	int ret = 0;
	moal_private *priv = NULL;
	moal_handle *handle = (moal_handle *)woal_get_wiphy_priv(wiphy);
	mlan_power_cfg_t power_cfg;

	ENTER();

	priv = woal_get_priv(handle, MLAN_BSS_ROLE_ANY);
	if (!priv) {
		PRINTM(MFATAL, "Unable to get priv in %s()\n", __func__);
		LEAVE();
		return -EFAULT;
	}

	if (type) {
		power_cfg.is_power_auto = 0;
		power_cfg.power_level = dbm;
	} else
		power_cfg.is_power_auto = 1;

	if (MLAN_STATUS_SUCCESS !=
	    woal_set_get_tx_power(priv, MLAN_ACT_SET, &power_cfg))
		ret = -EFAULT;

	LEAVE();
	return ret;
}
#endif

#if CFG80211_VERSION_CODE > KERNEL_VERSION(2, 6, 35)
/**
 * CFG802.11 operation handler for connection quality monitoring.
 *
 * @param wiphy           A pointer to wiphy structure
 * @param dev             A pointer to net_device structure
 * @param rssi_thold	  rssi threshold
 * @param rssi_hyst		  rssi hysteresis
 */
static int
woal_cfg80211_set_cqm_rssi_config(struct wiphy *wiphy,
				  struct net_device *dev,
				  s32 rssi_thold, u32 rssi_hyst)
{
	moal_private *priv = (moal_private *)woal_get_netdev_priv(dev);
	ENTER();
	priv->cqm_rssi_thold = rssi_thold;
	priv->cqm_rssi_high_thold = rssi_thold;
	priv->cqm_rssi_hyst = rssi_hyst;

	PRINTM(MIOCTL, "rssi_thold=%d rssi_hyst=%d\n",
	       (int)rssi_thold, (int)rssi_hyst);
	woal_set_rssi_threshold(priv, 0, MOAL_IOCTL_WAIT);
	LEAVE();
	return 0;
}
#endif

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
/**
 * @brief remain on channel config
 *
 * @param priv              A pointer to moal_private structure
 * @param wait_option       Wait option
 * @param cancel			cancel remain on channel flag
 * @param status            A pointer to status, success, in process or reject
 * @param chan              A pointer to ieee80211_channel structure
 * @param channel_type      channel_type,
 * @param duration          Duration wait to receive frame
 *
 * @return                  0 -- success, otherwise fail
 */
int
woal_cfg80211_remain_on_channel_cfg(moal_private *priv,
				    t_u8 wait_option, t_u8 remove, t_u8 *status,
				    struct ieee80211_channel *chan,
				    enum mlan_channel_type channel_type,
				    t_u32 duration)
{
	mlan_ds_remain_chan chan_cfg;
	int ret = 0;

	ENTER();

	if (!status || (!chan && !remove)) {
		LEAVE();
		return -EFAULT;
	}
	memset(&chan_cfg, 0, sizeof(mlan_ds_remain_chan));
	if (remove) {
		chan_cfg.remove = MTRUE;
	} else {
		if (chan->band == IEEE80211_BAND_2GHZ)
			chan_cfg.bandcfg.chanBand = BAND_2GHZ;
		else if (chan->band == IEEE80211_BAND_5GHZ)
			chan_cfg.bandcfg.chanBand = BAND_5GHZ;
		switch (channel_type) {
		case CHAN_HT40MINUS:
			chan_cfg.bandcfg.chan2Offset = SEC_CHAN_BELOW;
			chan_cfg.bandcfg.chanWidth = CHAN_BW_40MHZ;
			break;
		case CHAN_HT40PLUS:
			chan_cfg.bandcfg.chan2Offset = SEC_CHAN_ABOVE;
			chan_cfg.bandcfg.chanWidth = CHAN_BW_40MHZ;
			break;
		case CHAN_VHT80:
			chan_cfg.bandcfg.chanWidth = CHAN_BW_80MHZ;
			break;
		case CHAN_NO_HT:
		case CHAN_HT20:
		default:
			break;
		}
		chan_cfg.channel =
			ieee80211_frequency_to_channel(chan->center_freq);
		chan_cfg.remain_period = duration;
		PRINTM(MCMND,
		       "Remain on Channel: chan=%d, offset=%d width=%d\n",
		       chan_cfg.channel, chan_cfg.bandcfg.chan2Offset,
		       chan_cfg.bandcfg.chanWidth);
	}
	if (MLAN_STATUS_SUCCESS ==
	    woal_set_remain_channel_ioctl(priv, wait_option, &chan_cfg))
		*status = chan_cfg.status;
	else
		ret = -EFAULT;
	LEAVE();
	return ret;
}

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)
/**
 * @brief tx mgmt frame
 *
 * @param wiphy                 A pointer to wiphy structure
 * @param wdev                  A pointer to wireless_dev structure
 * @param cookie                A pointer to frame cookie
 *
 * @return                0 -- success, otherwise fail
 */
static int
woal_cfg80211_mgmt_tx_cancel_wait(struct wiphy *wiphy,
				  struct wireless_dev *wdev, u64 cookie)
#else
/**
 * @brief tx mgmt frame
 *
 * @param wiphy                 A pointer to wiphy structure
 * @param dev                   A pointer to net_device structure
 * @param cookie                A pointer to frame cookie
 *
 * @return                0 -- success, otherwise fail
 */
static int
woal_cfg80211_mgmt_tx_cancel_wait(struct wiphy *wiphy,
				  struct net_device *dev, u64 cookie)
#endif
{
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)
	struct net_device *dev = wdev->netdev;
#endif
	moal_private *priv = (moal_private *)woal_get_netdev_priv(dev);
	int ret = 0;
	t_u8 status = 1;
	moal_private *remain_priv = NULL;

	ENTER();

	if (priv->phandle->remain_on_channel) {
		remain_priv =
			priv->phandle->priv[priv->phandle->remain_bss_index];
		if (!remain_priv) {
			PRINTM(MERROR,
			       "mgmt_tx_cancel_wait: Wrong remain_bss_index=%d\n",
			       priv->phandle->remain_bss_index);
			ret = -EFAULT;
			goto done;
		}
		if (woal_cfg80211_remain_on_channel_cfg
		    (remain_priv, MOAL_IOCTL_WAIT, MTRUE, &status, NULL, 0,
		     0)) {
			PRINTM(MERROR,
			       "mgmt_tx_cancel_wait: Fail to cancel remain on channel\n");
			ret = -EFAULT;
			goto done;
		}
		if (priv->phandle->cookie) {
			cfg80211_remain_on_channel_expired(
#if CFG80211_VERSION_CODE < KERNEL_VERSION(3, 6, 0)
								  remain_priv->
								  netdev,
#else
								  remain_priv->
								  wdev,
#endif
								  priv->
								  phandle->
								  cookie,
								  &priv->
								  phandle->chan,
#if CFG80211_VERSION_CODE < KERNEL_VERSION(3, 8, 0)
								  priv->
								  phandle->
								  channel_type,
#endif
								  GFP_ATOMIC);
			priv->phandle->cookie = 0;
		}
		priv->phandle->remain_on_channel = MFALSE;
	}

done:
	LEAVE();
	return ret;
}

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)
/**
 * @brief Make chip remain on channel
 *
 * @param wiphy                 A pointer to wiphy structure
 * @param wdev                  A pointer to wireless_dev structure
 * @param chan                  A pointer to ieee80211_channel structure
 * @param channel_type          Channel type
 * @param duration              Duration for timer
 * @param cookie                A pointer to timer cookie
 *
 * @return                  0 -- success, otherwise fail
 */
static int
woal_cfg80211_remain_on_channel(struct wiphy *wiphy,
				struct wireless_dev *wdev,
				struct ieee80211_channel *chan,
#if CFG80211_VERSION_CODE < KERNEL_VERSION(3, 8, 0)
				enum nl80211_channel_type channel_type,
#endif
				unsigned int duration, u64 * cookie)
#else
/**
 * @brief Make chip remain on channel
 *
 * @param wiphy                 A pointer to wiphy structure
 * @param dev                   A pointer to net_device structure
 * @param chan                  A pointer to ieee80211_channel structure
 * @param channel_type          Channel type
 * @param duration              Duration for timer
 * @param cookie                A pointer to timer cookie
 *
 * @return                  0 -- success, otherwise fail
 */
static int
woal_cfg80211_remain_on_channel(struct wiphy *wiphy,
				struct net_device *dev,
				struct ieee80211_channel *chan,
				enum nl80211_channel_type channel_type,
				unsigned int duration, u64 * cookie)
#endif
{
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)
	struct net_device *dev = wdev->netdev;
#endif
	moal_private *priv = (moal_private *)woal_get_netdev_priv(dev);
	int ret = 0;
	t_u8 status = 1;
	moal_private *remain_priv = NULL;

	ENTER();

	if (!chan || !cookie) {
		PRINTM(MERROR, "Invalid parameter for remain on channel\n");
		ret = -EFAULT;
		goto done;
	}
	/** cancel previous remain on channel */
	if (priv->phandle->remain_on_channel &&
	    ((priv->phandle->chan.center_freq != chan->center_freq)
	    )) {
		remain_priv =
			priv->phandle->priv[priv->phandle->remain_bss_index];
		if (!remain_priv) {
			PRINTM(MERROR,
			       "remain_on_channel: Wrong remain_bss_index=%d\n",
			       priv->phandle->remain_bss_index);
			ret = -EFAULT;
			goto done;
		}
		if (woal_cfg80211_remain_on_channel_cfg
		    (remain_priv, MOAL_IOCTL_WAIT, MTRUE, &status, NULL, 0,
		     0)) {
			PRINTM(MERROR,
			       "remain_on_channel: Fail to cancel remain on channel\n");
			ret = -EFAULT;
			goto done;
		}
		priv->phandle->cookie = 0;
		priv->phandle->remain_on_channel = MFALSE;
	}
	if (MLAN_STATUS_SUCCESS !=
	    woal_cfg80211_remain_on_channel_cfg(priv, MOAL_IOCTL_WAIT,
						MFALSE, &status, chan,
#if CFG80211_VERSION_CODE < KERNEL_VERSION(3, 8, 0)
						channel_type,
#else
						0,
#endif
						(t_u32)duration)) {
		ret = -EFAULT;
		goto done;
	}

	if (status) {
		PRINTM(MMSG,
		       "%s: Set remain on Channel: channel=%d with status=%d\n",
		       dev->name,
		       ieee80211_frequency_to_channel(chan->center_freq),
		       status);
		if (!priv->phandle->remain_on_channel) {
			priv->phandle->is_remain_timer_set = MTRUE;
			woal_mod_timer(&priv->phandle->remain_timer, duration);
		}
	}

	/* remain on channel operation success */
	/* we need update the value cookie */
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 8, 0)
	*cookie = (u64) random32() | 1;
#else
	*cookie = (u64) prandom_u32() | 1;
#endif
	priv->phandle->remain_on_channel = MTRUE;
	priv->phandle->remain_bss_index = priv->bss_index;
	priv->phandle->cookie = *cookie;
#if CFG80211_VERSION_CODE < KERNEL_VERSION(3, 8, 0)
	priv->phandle->channel_type = channel_type;
#endif
	memcpy(&priv->phandle->chan, chan, sizeof(struct ieee80211_channel));

	if (status == 0)
		PRINTM(MIOCTL,
		       "%s: Set remain on Channel: channel=%d cookie = %#llx\n",
		       dev->name,
		       ieee80211_frequency_to_channel(chan->center_freq),
		       priv->phandle->cookie);

	cfg80211_ready_on_channel(
#if CFG80211_VERSION_CODE < KERNEL_VERSION(3, 6, 0)
					 dev,
#else
					 priv->wdev,
#endif
					 *cookie, chan,
#if CFG80211_VERSION_CODE < KERNEL_VERSION(3, 8, 0)
					 channel_type,
#endif
					 duration, GFP_KERNEL);

done:
	LEAVE();
	return ret;
}

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)
/**
 * @brief Cancel remain on channel
 *
 * @param wiphy                 A pointer to wiphy structure
 * @param wdev                  A pointer to wireless_dev structure
 * @param cookie                A pointer to timer cookie
 *
 * @return                  0 -- success, otherwise fail
 */
static int
woal_cfg80211_cancel_remain_on_channel(struct wiphy *wiphy,
				       struct wireless_dev *wdev, u64 cookie)
#else
/**
 * @brief Cancel remain on channel
 *
 * @param wiphy                 A pointer to wiphy structure
 * @param dev                   A pointer to net_device structure
 * @param cookie                A pointer to timer cookie
 *
 * @return                  0 -- success, otherwise fail
 */
static int
woal_cfg80211_cancel_remain_on_channel(struct wiphy *wiphy,
				       struct net_device *dev, u64 cookie)
#endif
{
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)
	struct net_device *dev = wdev->netdev;
#endif
	moal_private *priv = (moal_private *)woal_get_netdev_priv(dev);
	moal_private *remain_priv = NULL;
	int ret = 0;
	t_u8 status = 1;

	ENTER();
	PRINTM(MIOCTL, "Cancel remain on Channel: cookie = %#llx\n", cookie);
	remain_priv = priv->phandle->priv[priv->phandle->remain_bss_index];
	if (!remain_priv) {
		PRINTM(MERROR,
		       "cancel_remain_on_channel: Wrong remain_bss_index=%d\n",
		       priv->phandle->remain_bss_index);
		ret = -EFAULT;
		goto done;
	}
	if (woal_cfg80211_remain_on_channel_cfg
	    (remain_priv, MOAL_IOCTL_WAIT, MTRUE, &status, NULL, 0, 0)) {
		PRINTM(MERROR,
		       "cancel_remain_on_channel: Fail to cancel remain on channel\n");
		ret = -EFAULT;
		goto done;
	}

	priv->phandle->remain_on_channel = MFALSE;
	if (priv->phandle->cookie)
		priv->phandle->cookie = 0;
done:
	LEAVE();
	return ret;
}
#endif /* KERNEL_VERSION */

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)
/**
 * @brief start sched scan
 *
 * @param wiphy                 A pointer to wiphy structure
 * @param dev                   A pointer to net_device structure
 * @param request               A pointer to struct cfg80211_sched_scan_request
 *
 * @return                  0 -- success, otherwise fail
 */
int
woal_cfg80211_sched_scan_start(struct wiphy *wiphy,
			       struct net_device *dev,
			       struct cfg80211_sched_scan_request *request)
{
	struct ieee80211_channel *chan = NULL;
	int i = 0;
	int ret = 0;
	moal_private *priv = (moal_private *)woal_get_netdev_priv(dev);
	struct cfg80211_ssid *ssid = NULL;
	ENTER();

#ifdef UAP_CFG80211
	if (GET_BSS_ROLE(priv) == MLAN_BSS_ROLE_UAP) {
		LEAVE();
		return -EFAULT;
	}
#endif

	memset(&priv->scan_cfg, 0, sizeof(priv->scan_cfg));
	if (!request) {
		PRINTM(MERROR, "Invalid sched_scan req parameter\n");
		LEAVE();
		return -EINVAL;
	}
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	PRINTM(MIOCTL,
	       "%s sched scan: n_ssids=%d n_match_sets=%d n_channels=%d interval=%d ie_len=%d\n",
	       priv->netdev->name, request->n_ssids, request->n_match_sets,
	       request->n_channels, request->scan_plans[0].interval,
	       (int)request->ie_len);
#else
	PRINTM(MIOCTL,
	       "%s sched scan: n_ssids=%d n_match_sets=%d n_channels=%d interval=%d ie_len=%d\n",
	       priv->netdev->name, request->n_ssids, request->n_match_sets,
	       request->n_channels, request->interval, (int)request->ie_len);
#endif
    /** We have pending scan, start bgscan later */
	if (priv->phandle->scan_pending_on_block)
		priv->scan_cfg.start_later = MTRUE;
	for (i = 0; i < request->n_match_sets; i++) {
		ssid = &request->match_sets[i].ssid;
		strncpy(priv->scan_cfg.ssid_list[i].ssid, ssid->ssid,
			ssid->ssid_len);
		priv->scan_cfg.ssid_list[i].max_len = 0;
		PRINTM(MIOCTL, "sched scan: ssid=%s\n", ssid->ssid);
	}
	/** Add broadcast scan, when n_match_sets = 0 */
	if (!request->n_match_sets)
		priv->scan_cfg.ssid_list[0].max_len = 0xff;
	for (i = 0; i < MIN(WLAN_BG_SCAN_CHAN_MAX, request->n_channels); i++) {
		chan = request->channels[i];
		priv->scan_cfg.chan_list[i].chan_number = chan->hw_value;
		priv->scan_cfg.chan_list[i].radio_type = chan->band;
		if (chan->
		    flags & (IEEE80211_CHAN_PASSIVE_SCAN |
			     IEEE80211_CHAN_RADAR))
			priv->scan_cfg.chan_list[i].scan_type =
				MLAN_SCAN_TYPE_PASSIVE;
		else
			priv->scan_cfg.chan_list[i].scan_type =
				MLAN_SCAN_TYPE_ACTIVE;
		priv->scan_cfg.chan_list[i].scan_time = 0;
	}
	priv->scan_cfg.chan_per_scan =
		MIN(WLAN_BG_SCAN_CHAN_MAX, request->n_channels);

	/** set scan request IES */
	if (request->ie && request->ie_len) {
		if (MLAN_STATUS_SUCCESS !=
		    woal_cfg80211_mgmt_frame_ie(priv, NULL, 0,
						NULL, 0, NULL, 0,
						(t_u8 *)request->ie,
						request->ie_len,
						MGMT_MASK_PROBE_REQ,
						MOAL_IOCTL_WAIT)) {
			PRINTM(MERROR, "Fail to set sched scan IE\n");
			ret = -EFAULT;
			goto done;
		}
	} else {
		/** Clear SCAN IE in Firmware */
		if (priv->probereq_index != MLAN_CUSTOM_IE_AUTO_IDX_MASK)
			woal_cfg80211_mgmt_frame_ie(priv, NULL, 0, NULL, 0,
						    NULL, 0, NULL, 0,
						    MGMT_MASK_PROBE_REQ,
						    MOAL_IOCTL_WAIT);
	}

	/* Interval between scan cycles in milliseconds,supplicant set to 10 second */
	/* We want to use 30 second for per scan cycle */
	priv->scan_cfg.scan_interval = MIN_BGSCAN_INTERVAL;
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	if (request->scan_plans[0].interval * 1000 > MIN_BGSCAN_INTERVAL)
		priv->scan_cfg.scan_interval =
			request->scan_plans[0].interval * 1000;
	if (request->n_scan_plans >= 2) {
		priv->scan_cfg.config_ees = MTRUE;
		priv->scan_cfg.ees_mode =
			MBIT(EES_MODE_HIGH) | MBIT(EES_MODE_MID);
		priv->scan_cfg.high_period =
			request->scan_plans[0].interval * 1000;
		priv->scan_cfg.high_period_count =
			request->scan_plans[0].iterations;
		priv->scan_cfg.mid_period = request->scan_plans[1].interval;
		if (request->scan_plans[1].iterations == 0)
			priv->scan_cfg.mid_period_count = DEF_REPEAT_COUNT;
		else
			priv->scan_cfg.mid_period_count =
				request->scan_plans[1].iterations;
		if (request->n_scan_plans == 3) {
			priv->scan_cfg.ees_mode |= MBIT(EES_MODE_LOW);
			priv->scan_cfg.low_period =
				request->scan_plans[2].interval;
			priv->scan_cfg.low_period_count = DEF_REPEAT_COUNT;
		}
	}
#else
	if (request->interval > MIN_BGSCAN_INTERVAL)
		priv->scan_cfg.scan_interval = request->interval;
#endif
	priv->scan_cfg.repeat_count = DEF_REPEAT_COUNT;
	priv->scan_cfg.report_condition =
		BG_SCAN_SSID_MATCH | BG_SCAN_WAIT_ALL_CHAN_DONE;
	priv->scan_cfg.bss_type = MLAN_BSS_MODE_INFRA;
	priv->scan_cfg.action = BG_SCAN_ACT_SET;
	priv->scan_cfg.enable = MTRUE;

	if (MLAN_STATUS_SUCCESS ==
	    woal_request_bgscan(priv, MOAL_IOCTL_WAIT, &priv->scan_cfg)) {
		priv->sched_scanning = MTRUE;
		priv->bg_scan_start = MTRUE;
		priv->bg_scan_reported = MFALSE;
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
		priv->bg_scan_reqid = request->reqid;
#endif
	} else
		ret = -EFAULT;
done:
	LEAVE();
	return ret;
}

/**
 * @brief stop sched scan
 *
 * @param wiphy                 A pointer to wiphy structure
 * @param dev                   A pointer to net_device structure
 *
 * @return                      0 -- success, otherwise fail
 */
int
woal_cfg80211_sched_scan_stop(struct wiphy *wiphy, struct net_device *dev
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
			      , u64 reqid
#endif
	)
{
	moal_private *priv = (moal_private *)woal_get_netdev_priv(dev);
	ENTER();
	PRINTM(MIOCTL, "sched scan stop\n");
	priv->sched_scanning = MFALSE;
	woal_stop_bg_scan(priv, MOAL_NO_WAIT);
	priv->bg_scan_start = MFALSE;
	priv->bg_scan_reported = MFALSE;
	LEAVE();
	return 0;
}
#endif

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)
/**
 * @brief cfg80211_resume handler
 *
 * @param wiphy                 A pointer to wiphy structure
 *
 * @return                      0 -- success, otherwise fail
 */
int
woal_cfg80211_resume(struct wiphy *wiphy)
{
	moal_handle *handle = (moal_handle *)woal_get_wiphy_priv(wiphy);
	moal_private *priv = woal_get_priv(handle, MLAN_BSS_ROLE_ANY);
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 11, 0) && defined(CONFIG_PM)
	struct cfg80211_wowlan_wakeup wakeup_report;
#endif
	mlan_ds_hs_wakeup_reason wakeup_reason;
	int i;

	PRINTM(MCMND, "<--- Enter woal_cfg80211_resume --->\n");

	if (!priv) {
		PRINTM(MERROR, "woal_cfg80211_resume: priv is NULL\n");
		goto done;
	}

	for (i = 0; i < MIN(handle->priv_num, MLAN_MAX_BSS_NUM); i++) {
		if (handle->priv[i] &&
		    (GET_BSS_ROLE(handle->priv[i]) == MLAN_BSS_ROLE_STA)) {
			if (handle->priv[i]->last_event & EVENT_BG_SCAN_REPORT) {
				if (handle->priv[i]->sched_scanning) {
					woal_inform_bss_from_scan_result
						(handle->priv[i], NULL,
						 MOAL_IOCTL_WAIT);
					cfg80211_sched_scan_results(handle->
								    priv[i]->
								    wdev->wiphy
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
								    , 0
#endif
						);
					cfg80211_sched_scan_stopped(priv->wdev->
								    wiphy
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
								    , 0
#endif
						);
					handle->priv[i]->sched_scanning =
						MFALSE;
					handle->priv[i]->last_event = 0;
					PRINTM(MIOCTL,
					       "Report sched scan result in cfg80211 resume\n");
				}
				if (!hw_test &&
				    handle->priv[i]->roaming_enabled) {
					handle->priv[i]->roaming_required =
						MTRUE;
#ifdef ANDROID_KERNEL
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 5, 0)
					__pm_wakeup_event(&handle->ws,
							  ROAMING_WAKE_LOCK_TIMEOUT);
#else
					wake_lock_timeout(&handle->wake_lock,
							  msecs_to_jiffies
							  (ROAMING_WAKE_LOCK_TIMEOUT));
#endif
#endif
					wake_up_interruptible(&handle->
							      reassoc_thread.
							      wait_q);
				}
			}
		}
	}

	woal_get_wakeup_reason(priv, &wakeup_reason);

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 11, 0) && defined(CONFIG_PM)
	memset(&wakeup_report, 0, sizeof(struct cfg80211_wowlan_wakeup));
	wakeup_report.pattern_idx = -1;

	switch (wakeup_reason.hs_wakeup_reason) {
	case NO_HSWAKEUP_REASON:
		break;
	case BCAST_DATA_MATCHED:
		break;
	case MCAST_DATA_MATCHED:
		break;
	case UCAST_DATA_MATCHED:
		break;
	case MASKTABLE_EVENT_MATCHED:
		break;
	case NON_MASKABLE_EVENT_MATCHED:
		break;
	case NON_MASKABLE_CONDITION_MATCHED:
		if (wiphy->wowlan_config->disconnect)
			wakeup_report.disconnect = true;
		break;
	case MAGIC_PATTERN_MATCHED:
		if (wiphy->wowlan_config->magic_pkt)
			wakeup_report.magic_pkt = true;
		if (wiphy->wowlan_config->n_patterns)
			wakeup_report.pattern_idx = 1;
		break;
	case CONTROL_FRAME_MATCHED:
		break;
	case MANAGEMENT_FRAME_MATCHED:
		break;
	case GTK_REKEY_FAILURE:
		if (wiphy->wowlan_config->gtk_rekey_failure)
			wakeup_report.gtk_rekey_failure = true;
		break;
	default:
		break;
	}

	if ((wakeup_reason.hs_wakeup_reason > 0) &&
	    (wakeup_reason.hs_wakeup_reason <= 10)) {
		cfg80211_report_wowlan_wakeup(priv->wdev, &wakeup_report,
					      GFP_KERNEL);
	}
#endif

done:
	handle->cfg80211_suspend = MFALSE;
	PRINTM(MCMND, "<--- Leave woal_cfg80211_resume --->\n");
	return 0;
}

/**
 * @brief cfg80211_suspend handler
 *
 * @param wiphy                 A pointer to wiphy structure
 * @param wow                   A pointer to cfg80211_wowlan
 *
 * @return                      0 -- success, otherwise fail
 */
int
woal_cfg80211_suspend(struct wiphy *wiphy, struct cfg80211_wowlan *wow)
{
	moal_handle *handle = (moal_handle *)woal_get_wiphy_priv(wiphy);
	int i;
	int ret = 0;

	PRINTM(MCMND, "<--- Enter woal_cfg80211_suspend --->\n");
	for (i = 0; i < MIN(handle->priv_num, MLAN_MAX_BSS_NUM); i++) {
		if (handle->priv[i] &&
		    (GET_BSS_ROLE(handle->priv[i]) == MLAN_BSS_ROLE_STA)) {
			if (handle->scan_request) {
				PRINTM(MIOCTL,
				       "Cancel pending scan in woal_cfg80211_suspend\n");
				woal_cancel_scan(handle->priv[i],
						 MOAL_IOCTL_WAIT);
			}
			handle->priv[i]->last_event = 0;
		}
	}

	handle->cfg80211_suspend = MTRUE;

	PRINTM(MCMND, "<--- Leave woal_cfg80211_suspend --->\n");
	return ret;
}
#endif

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
static void
woal_cfg80211_set_wakeup(struct wiphy *wiphy, bool enabled)
{
	moal_handle *handle = (moal_handle *)woal_get_wiphy_priv(wiphy);

	device_set_wakeup_enable(handle->hotplug_device, enabled);
}
#endif

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3,2,0)
/**
 * @brief change station info
 *
 * @param wiphy                 A pointer to wiphy structure
 * @param dev                   A pointer to net_device structure
 * @param mac                   A pointer to peer mac
 * @param params                station parameters
 *
 * @return                      0 -- success, otherwise fail
 */
static int
woal_cfg80211_change_station(struct wiphy *wiphy, struct net_device *dev,
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 16, 0)
			     const u8 *mac,
#else
			     u8 *mac,
#endif
			     struct station_parameters *params)
{
	int ret = 0;

	ENTER();

    /**do nothing*/

	LEAVE();
	return ret;
}
#endif

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3,2,0)
/**
 * @brief add station
 *
 * @param wiphy                 A pointer to wiphy structure
 * @param dev                   A pointer to net_device structure
 * @param mac                  A pointer to peer mac
 * @param params           	station parameters
 *
 * @return                  	0 -- success, otherwise fail
 */
static int
woal_cfg80211_add_station(struct wiphy *wiphy, struct net_device *dev,
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 16, 0)
			  const u8 *mac,
#else
			  u8 *mac,
#endif
			  struct station_parameters *params)
{
	moal_private *priv = (moal_private *)woal_get_netdev_priv(dev);
	int ret = 0;
	ENTER();
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
#ifdef UAP_SUPPORT
	if (host_mlme && (priv->bss_role == MLAN_BSS_ROLE_UAP)) {
		ret = woal_cfg80211_uap_add_station(wiphy, dev, (u8 *)mac,
						    params);
		LEAVE();
		return ret;
	}
#endif
#endif
	LEAVE();
	return ret;
}
#endif

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3,10,0)
/**
 * @brief Update ft ie for Fast BSS Transition
 *
 * @param wiphy           A pointer to wiphy structure
 * @param dev             A pointer to net_device structure
 * @param ftie           A pointer to cfg80211_update_ft_ies_params structure
 *
 * @return                0 success , other failure
 */
int
woal_cfg80211_update_ft_ies(struct wiphy *wiphy, struct net_device *dev,
			    struct cfg80211_update_ft_ies_params *ftie)
{
	moal_private *priv = (moal_private *)woal_get_netdev_priv(dev);
	IEEEtypes_MobilityDomain_t *md_ie = NULL;
	int ret = 0;
	mlan_ds_misc_assoc_rsp assoc_rsp;
	IEEEtypes_AssocRsp_t *passoc_rsp = NULL;
	mlan_bss_info bss_info;
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
	struct cfg80211_roam_info roam_info;
#endif

	ENTER();

	if (!ftie) {
		LEAVE();
		return ret;
	}
#ifdef MLAN_64BIT
	PRINTM(MINFO, "==>woal_cfg80211_update_ft_ies %lx \n", ftie->ie_len);
#else
	PRINTM(MINFO, "==>woal_cfg80211_update_ft_ies %x \n", ftie->ie_len);
#endif
	md_ie = (IEEEtypes_MobilityDomain_t *)woal_parse_ie_tlv(ftie->ie,
								ftie->ie_len,
								MOBILITY_DOMAIN);
	if (!md_ie) {
		PRINTM(MERROR, "No Mobility domain IE\n");
		LEAVE();
		return ret;
	}
	priv->ft_cap = md_ie->ft_cap;
	if (priv->ft_ie_len) {
		priv->pre_ft_ie_len = priv->ft_ie_len;
		memcpy(priv->pre_ft_ie, priv->ft_ie,
		       MIN(priv->ft_ie_len, MAX_IE_SIZE));
	}
	memset(priv->ft_ie, 0, MAX_IE_SIZE);
	memcpy(priv->ft_ie, ftie->ie, MIN(ftie->ie_len, MAX_IE_SIZE));
	priv->ft_ie_len = ftie->ie_len;
	priv->ft_md = ftie->md;

	if (!priv->ft_pre_connect) {
		LEAVE();
		return ret;
	}
	/* check if is different AP */
	if (!memcmp
	    (&priv->target_ap_bssid, priv->cfg_bssid, MLAN_MAC_ADDR_LENGTH)) {
		PRINTM(MMSG, "This is the same AP, no Fast bss transition\n");
		priv->ft_pre_connect = MFALSE;
		priv->ft_ie_len = 0;
		LEAVE();
		return 0;
	}

	/* start fast BSS transition to target AP */
	priv->assoc_status = 0;
	priv->sme_current.bssid = priv->conn_bssid;
	memcpy((void *)priv->sme_current.bssid, &priv->target_ap_bssid,
	       MLAN_MAC_ADDR_LENGTH);
	memset(&assoc_rsp, 0, sizeof(mlan_ds_misc_assoc_rsp));
	ret = woal_cfg80211_assoc(priv, (void *)&priv->sme_current,
				  MOAL_IOCTL_WAIT, &assoc_rsp);

	if ((priv->ft_cap & MBIT(0)) || priv->ft_roaming_triggered_by_driver) {
		if (!ret) {
			woal_inform_bss_from_scan_result(priv, NULL,
							 MOAL_IOCTL_WAIT);
			passoc_rsp =
				(IEEEtypes_AssocRsp_t *)assoc_rsp.
				assoc_resp_buf;
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
			memset(&roam_info, 0,
			       sizeof(struct cfg80211_roam_info));
			roam_info.bssid = priv->cfg_bssid;
			roam_info.req_ie = priv->sme_current.ie;
			roam_info.req_ie_len = priv->sme_current.ie_len;
			roam_info.resp_ie = passoc_rsp->ie_buffer;
			roam_info.resp_ie_len =
				assoc_rsp.assoc_resp_len -
				ASSOC_RESP_FIXED_SIZE;
			cfg80211_roamed(priv->netdev, &roam_info, GFP_KERNEL);
#else
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
			cfg80211_roamed(priv->netdev, NULL, priv->cfg_bssid,
					priv->sme_current.ie,
					priv->sme_current.ie_len,
					passoc_rsp->ie_buffer,
					assoc_rsp.assoc_resp_len -
					ASSOC_RESP_FIXED_SIZE, GFP_KERNEL);
#else
			cfg80211_roamed(priv->netdev, priv->cfg_bssid,
					priv->sme_current.ie,
					priv->sme_current.ie_len,
					passoc_rsp->ie_buffer,
					assoc_rsp.assoc_resp_len -
					ASSOC_RESP_FIXED_SIZE, GFP_KERNEL);
#endif
#endif
			PRINTM(MMSG,
			       "Fast BSS transition to bssid " MACSTR
			       " successfully\n", MAC2STR(priv->cfg_bssid));
		} else {
			PRINTM(MMSG,
			       "Fast BSS transition failed, keep connect to "
			       MACSTR " \n", MAC2STR(priv->cfg_bssid));
			memcpy((void *)priv->sme_current.bssid,
			       &priv->cfg_bssid, MLAN_MAC_ADDR_LENGTH);
			priv->ft_ie_len = priv->pre_ft_ie_len;
			memcpy(priv->ft_ie, priv->pre_ft_ie,
			       MIN(priv->pre_ft_ie_len, MAX_IE_SIZE));
		}
		priv->ft_roaming_triggered_by_driver = MFALSE;

	} else {
		PRINTM(MMSG, "Fast BSS Transition use ft-over-air\n");
		if (!ret) {
			memset(&assoc_rsp, 0, sizeof(mlan_ds_misc_assoc_rsp));
			woal_get_assoc_rsp(priv, &assoc_rsp, MOAL_IOCTL_WAIT);
			passoc_rsp =
				(IEEEtypes_AssocRsp_t *)assoc_rsp.
				assoc_resp_buf;
			cfg80211_connect_result(priv->netdev, priv->cfg_bssid,
						NULL, 0, passoc_rsp->ie_buffer,
						assoc_rsp.assoc_resp_len -
						ASSOC_RESP_FIXED_SIZE,
						WLAN_STATUS_SUCCESS,
						GFP_KERNEL);
			PRINTM(MMSG,
			       "wlan: Fast Bss transition to bssid " MACSTR
			       " successfully\n", MAC2STR(priv->cfg_bssid));

			memset(&bss_info, 0, sizeof(bss_info));
			woal_get_bss_info(priv, MOAL_IOCTL_WAIT, &bss_info);
			priv->channel = bss_info.bss_chan;
		} else {
			PRINTM(MMSG,
			       "wlan: Failed to connect to bssid " MACSTR "\n",
			       MAC2STR(priv->target_ap_bssid));
			cfg80211_connect_result(priv->netdev,
						priv->target_ap_bssid, NULL, 0,
						NULL, 0,
						woal_get_assoc_status(priv),
						GFP_KERNEL);
			memcpy((void *)priv->sme_current.bssid,
			       &priv->cfg_bssid, MLAN_MAC_ADDR_LENGTH);
			memset(priv->target_ap_bssid, 0, ETH_ALEN);
			priv->ft_ie_len = priv->pre_ft_ie_len;
			memcpy(priv->ft_ie, priv->pre_ft_ie,
			       MIN(priv->pre_ft_ie_len, MAX_IE_SIZE));
			//priv->ft_ie_len = 0;
		}
	}

	priv->ft_pre_connect = MFALSE;
	LEAVE();
	return 0;
}
#endif

/**
 * @brief Save connect parameters for roaming
 *
 * @param priv            A pointer to moal_private
 * @param sme             A pointer to cfg80211_connect_params structure
 */
void
woal_save_conn_params(moal_private *priv, struct cfg80211_connect_params *sme)
{
	ENTER();
	woal_clear_conn_params(priv);
	memcpy(&priv->sme_current, sme, sizeof(struct cfg80211_connect_params));
	if (sme->channel) {
		priv->sme_current.channel = &priv->conn_chan;
		memcpy(priv->sme_current.channel, sme->channel,
		       sizeof(struct ieee80211_channel));
	}
	if (sme->bssid) {
		priv->sme_current.bssid = priv->conn_bssid;
		memcpy((void *)priv->sme_current.bssid, sme->bssid,
		       MLAN_MAC_ADDR_LENGTH);
	}
	if (sme->ssid && sme->ssid_len) {
		priv->sme_current.ssid = priv->conn_ssid;
		memset(priv->conn_ssid, 0, MLAN_MAX_SSID_LENGTH);
		memcpy((void *)priv->sme_current.ssid, sme->ssid,
		       sme->ssid_len);
	}
	if (sme->ie && sme->ie_len) {
		priv->sme_current.ie = kzalloc(sme->ie_len, GFP_KERNEL);
		memcpy((void *)priv->sme_current.ie, sme->ie, sme->ie_len);
	}
	if (sme->key && sme->key_len && (sme->key_len <= MAX_WEP_KEY_SIZE)) {
		priv->sme_current.key = priv->conn_wep_key;
		memcpy((t_u8 *)priv->sme_current.key, sme->key, sme->key_len);
	}
}

/**
 * @brief clear connect parameters for ing
 *
 * @param priv            A pointer to moal_private
 */
void
woal_clear_conn_params(moal_private *priv)
{
	ENTER();
	if (priv->sme_current.ie_len)
		kfree(priv->sme_current.ie);
	memset(&priv->sme_current, 0, sizeof(struct cfg80211_connect_params));
	priv->roaming_required = MFALSE;
	LEAVE();
}

/**
 * @brief Build new roaming connect ie for okc
 *
 * @param priv            A pointer to moal_private
 * @param entry           A pointer to pmksa_entry
 **/
int
woal_update_okc_roaming_ie(moal_private *priv, struct pmksa_entry *entry)
{
	struct cfg80211_connect_params *sme = &priv->sme_current;
	int ret = MLAN_STATUS_SUCCESS;
	const t_u8 *sme_pos, *sme_ptr;
	t_u8 *okc_ie_pos;
	t_u8 id, ie_len;
	int left_len;

	ENTER();

	if (!sme->ie || !sme->ie_len) {
		PRINTM(MERROR, "No connect ie saved in driver\n");
		ret = MLAN_STATUS_FAILURE;
		goto done;
	}

	if (!entry) {
		PRINTM(MERROR, "No roaming ap pmkid\n");
		ret = MLAN_STATUS_FAILURE;
		goto done;
	}

	if (!priv->okc_roaming_ie) {
		int okc_ie_len = sme->ie_len + sizeof(t_u16) + PMKID_LEN;

	/** Alloc new buffer for okc roaming ie */
		priv->okc_roaming_ie = kzalloc(okc_ie_len, GFP_KERNEL);
		if (!priv->okc_roaming_ie) {
			PRINTM(MERROR, "Fail to allocate assoc req ie\n");
			ret = MLAN_STATUS_FAILURE;
			goto done;
		}
	}

	/* Build OKC RSN IE with PMKID list
	 * Format of RSN IE: length(bytes) and container
	 * | 1| 1 |   2   |          4            |           2               |
	 * |id|len|version|group data cipher suite|pairwise cipher suite count|
	 * |          4 * m           |       2       |    4 * n     |   2    |
	 * |pairwise cipher suite list|AKM suite count|AKM suite list|RSN Cap |
	 * |    2     |  16 * s  |              4              |
	 * |PMKIDCount|PMKID List|Group Management Cipher Suite|
	 */
#define PAIRWISE_CIPHER_COUNT_OFFSET 8
#define AKM_SUITE_COUNT_OFFSET(n) (10 + (n) * 4)
#define PMKID_COUNT_OFFSET(n) (14 + (n) * 4)

	sme_pos = sme->ie;
	left_len = sme->ie_len;
	okc_ie_pos = priv->okc_roaming_ie;
	priv->okc_ie_len = 0;

	while (left_len >= 2) {
		id = *sme_pos;
		ie_len = *(sme_pos + 1);
		if ((ie_len + 2) > left_len) {
			PRINTM(MERROR, "Invalid ie len %d\n", ie_len);
			ret = MLAN_STATUS_FAILURE;
			goto done;
		}

		if (id == RSN_IE) {
			t_u16 pairwise_count, akm_count;
			t_u8 *rsn_ie_len;
			int rsn_offset;

			pairwise_count =
				*(t_u16 *)(sme_pos +
					   PAIRWISE_CIPHER_COUNT_OFFSET);
			akm_count =
				*(t_u16 *)(sme_pos +
					   AKM_SUITE_COUNT_OFFSET
					   (pairwise_count));
			rsn_offset =
				PMKID_COUNT_OFFSET(pairwise_count + akm_count);
			sme_ptr = (t_u8 *)(sme_pos + rsn_offset);

			memcpy(okc_ie_pos, sme_pos, rsn_offset);
			rsn_ie_len = okc_ie_pos + 1;
			okc_ie_pos += rsn_offset;
			*(t_u16 *)okc_ie_pos = 1;
			okc_ie_pos += sizeof(t_u16);
			memcpy(okc_ie_pos, entry->pmkid, PMKID_LEN);
			okc_ie_pos += PMKID_LEN;
			priv->okc_ie_len +=
				rsn_offset + sizeof(t_u16) + PMKID_LEN;
			*rsn_ie_len =
				rsn_offset - 2 + sizeof(t_u16) + PMKID_LEN;

			if ((ie_len + 2) > rsn_offset) {
		/** Previous conn ie include pmkid list */
				u16 pmkid_count = *(t_u16 *)sme_ptr;
				rsn_offset +=
					(sizeof(t_u16) +
					 PMKID_LEN * pmkid_count);
				if ((ie_len + 2) > rsn_offset) {
					sme_ptr +=
						(sizeof(t_u16) +
						 PMKID_LEN * pmkid_count);
					memcpy(okc_ie_pos, sme_ptr,
					       (ie_len + 2 - rsn_offset));
					okc_ie_pos += (ie_len + 2 - rsn_offset);
					priv->okc_ie_len +=
						(ie_len + 2 - rsn_offset);
					*rsn_ie_len +=
						(ie_len + 2 - rsn_offset);
				}
			}
		} else {
			memcpy(okc_ie_pos, sme_pos, ie_len + 2);
			okc_ie_pos += ie_len + 2;
			priv->okc_ie_len += ie_len + 2;
		}

		sme_pos += (ie_len + 2);
		left_len -= (ie_len + 2);
	}

done:
	if (ret != MLAN_STATUS_SUCCESS) {
		if (priv->okc_roaming_ie) {
			kfree(priv->okc_roaming_ie);
			priv->okc_roaming_ie = NULL;
			priv->okc_ie_len = 0;
		}
	}

	LEAVE();
	return ret;
}

/**
 * @brief Start roaming: driver handle roaming
 *
 * @param priv      A pointer to moal_private structure
 *
 * @return          N/A
 */
void
woal_start_roaming(moal_private *priv)
{
	mlan_ds_get_signal signal;
	mlan_ssid_bssid ssid_bssid;
	char rssi_low[10];
	int ret = 0;
	mlan_ds_misc_assoc_rsp *assoc_rsp;
	IEEEtypes_AssocRsp_t *passoc_rsp = NULL;
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
	struct cfg80211_roam_info roam_info;
#endif

	ENTER();
	if (priv->ft_roaming_triggered_by_driver) {
		PRINTM(MIOCTL, "FT roaming is in processing ...... \n");
		LEAVE();
		return;
	}

	if (priv->last_event & EVENT_BG_SCAN_REPORT) {
		woal_inform_bss_from_scan_result(priv, NULL, MOAL_IOCTL_WAIT);
		PRINTM(MIOCTL, "Report bgscan result\n");
	}
	if (priv->media_connected == MFALSE || !priv->sme_current.ssid_len) {
		PRINTM(MIOCTL, "Not connected, ignore roaming\n");
		LEAVE();
		return;
	}

	/* Get signal information from the firmware */
	memset(&signal, 0, sizeof(mlan_ds_get_signal));
	if (MLAN_STATUS_SUCCESS !=
	    woal_get_signal_info(priv, MOAL_IOCTL_WAIT, &signal)) {
		PRINTM(MERROR, "Error getting signal information\n");
		ret = -EFAULT;
		goto done;
	}
	memset(&ssid_bssid, 0, sizeof(mlan_ssid_bssid));
	ssid_bssid.ssid.ssid_len = priv->sme_current.ssid_len;
	memcpy(ssid_bssid.ssid.ssid, priv->sme_current.ssid,
	       priv->sme_current.ssid_len);
	if (MLAN_STATUS_SUCCESS !=
	    woal_find_best_network(priv, MOAL_IOCTL_WAIT, &ssid_bssid)) {
		PRINTM(MIOCTL, "Can not find better network\n");
		ret = -EFAULT;
		goto done;
	}
	/* check if we found different AP */
	if (!memcmp(&ssid_bssid.bssid, priv->cfg_bssid, MLAN_MAC_ADDR_LENGTH)) {
		PRINTM(MIOCTL, "This is the same AP, no roaming\n");
		ret = -EFAULT;
		goto done;
	}
	PRINTM(MIOCTL, "Find AP: bssid=" MACSTR ", signal=%d\n",
	       MAC2STR(ssid_bssid.bssid), ssid_bssid.rssi);
	/* check signal */
	if (!(priv->last_event & EVENT_PRE_BCN_LOST)) {
		if ((abs(signal.bcn_rssi_avg) - abs(ssid_bssid.rssi)) <
		    DELTA_RSSI) {
			PRINTM(MERROR, "New AP's signal is not good too.\n");
			ret = -EFAULT;
			goto done;
		}
	}
/**check if need start FT Roaming*/
	if (priv->ft_ie_len && (priv->ft_md == ssid_bssid.ft_md) &&
	    (priv->ft_cap == ssid_bssid.ft_cap)) {
		priv->ft_roaming_triggered_by_driver = MTRUE;
		woal_start_ft_roaming(priv, &ssid_bssid);
		goto done;
	}
	/* start roaming to new AP */
	priv->sme_current.bssid = priv->conn_bssid;
	memcpy((void *)priv->sme_current.bssid, &ssid_bssid.bssid,
	       MLAN_MAC_ADDR_LENGTH);

#ifdef STA_CFG80211
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)
	if (IS_STA_CFG80211(cfg80211_wext)) {
	/** Check if current roaming support OKC offload roaming */
		if (priv->sme_current.crypto.n_akm_suites &&
		    priv->sme_current.crypto.akm_suites[0] ==
		    WLAN_AKM_SUITE_8021X) {
			struct pmksa_entry *entry = NULL;

	    /** Get OKC PMK Cache entry
             *  Firstly try to get pmksa from cfg80211
             */
			priv->wait_target_ap_pmkid = MTRUE;
			cfg80211_pmksa_candidate_notify(priv->netdev, 0,
							priv->sme_current.bssid,
							MTRUE, GFP_ATOMIC);
			if (wait_event_interruptible_timeout(priv->okc_wait_q,
							     !priv->
							     wait_target_ap_pmkid,
							     OKC_WAIT_TARGET_PMKSA_TIMEOUT))
			{
				PRINTM(MIOCTL, "OKC Roaming is ready\n");
				entry = priv->target_ap_pmksa;
			} else {
		/** Try to get pmksa from pmksa list */
				priv->wait_target_ap_pmkid = MFALSE;
				entry = woal_get_pmksa_entry(priv,
							     priv->sme_current.
							     bssid);
			}
	    /** Build okc roaming ie */
			woal_update_okc_roaming_ie(priv, entry);
			priv->target_ap_pmksa = NULL;
		}
	}
#endif
#endif
	assoc_rsp = kzalloc(sizeof(mlan_ds_misc_assoc_rsp), GFP_ATOMIC);
	if (!assoc_rsp) {
		PRINTM(MERROR, "Fail to allocate memory for assoc_rsp\n");
		ret = -ENOMEM;
		goto done;
	}

	ret = woal_cfg80211_assoc(priv, (void *)&priv->sme_current,
				  MOAL_IOCTL_WAIT, assoc_rsp);
	if (!ret) {
		const t_u8 *ie;
		int ie_len;

		woal_inform_bss_from_scan_result(priv, NULL, MOAL_IOCTL_WAIT);
		passoc_rsp = (IEEEtypes_AssocRsp_t *)assoc_rsp->assoc_resp_buf;

	/** Update connect ie in roam event */
		ie = priv->sme_current.ie;
		ie_len = priv->sme_current.ie_len;
#ifdef STA_CFG80211
		if (IS_STA_CFG80211(cfg80211_wext)) {
	/** Check if current roaming support OKC offload roaming */
			if (priv->sme_current.crypto.n_akm_suites &&
			    priv->sme_current.crypto.akm_suites[0] ==
			    WLAN_AKM_SUITE_8021X) {
				if (priv->okc_roaming_ie && priv->okc_ie_len) {
					ie = priv->okc_roaming_ie;
					ie_len = priv->okc_ie_len;
				}
			}
		}
#endif
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(4, 12, 0)
		memset(&roam_info, 0, sizeof(struct cfg80211_roam_info));
		roam_info.bssid = priv->cfg_bssid;
		roam_info.req_ie = ie;
		roam_info.req_ie_len = ie_len;
		roam_info.resp_ie = passoc_rsp->ie_buffer;
		roam_info.resp_ie_len =
			assoc_rsp->assoc_resp_len - ASSOC_RESP_FIXED_SIZE;
		cfg80211_roamed(priv->netdev, &roam_info, GFP_KERNEL);
#else
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
		cfg80211_roamed(priv->netdev, NULL, priv->cfg_bssid, ie, ie_len,
				passoc_rsp->ie_buffer,
				assoc_rsp->assoc_resp_len -
				ASSOC_RESP_FIXED_SIZE, GFP_KERNEL);
#else
		cfg80211_roamed(priv->netdev, priv->cfg_bssid, ie, ie_len,
				passoc_rsp->ie_buffer,
				assoc_rsp->assoc_resp_len -
				ASSOC_RESP_FIXED_SIZE, GFP_KERNEL);
#endif
#endif
		PRINTM(MMSG, "Roamed to bssid " MACSTR " successfully\n",
		       MAC2STR(priv->cfg_bssid));
	} else {
		PRINTM(MIOCTL, "Roaming to bssid " MACSTR " failed\n",
		       MAC2STR(ssid_bssid.bssid));
	}
	kfree(assoc_rsp);
done:
	/* config rssi low threshold again */
	priv->last_event = 0;
	priv->rssi_low = DEFAULT_RSSI_LOW_THRESHOLD;
	sprintf(rssi_low, "%d", priv->rssi_low);
	woal_set_rssi_low_threshold(priv, rssi_low, MOAL_IOCTL_WAIT);
	LEAVE();
	return;
}

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
#ifdef UAP_SUPPORT
/**
 * @brief add uap station
 *
 * @param wiphy                 A pointer to wiphy structure
 * @param dev                   A pointer to net_device structure
 * @param mac                  A pointer to peer mac
 * @param params           	station parameters
 *
 * @return                  	0 -- success, otherwise fail
 */
int
woal_cfg80211_uap_add_station(struct wiphy *wiphy, struct net_device *dev,
			      u8 *mac, struct station_parameters *params)
{
	moal_private *priv = (moal_private *)woal_get_netdev_priv(dev);
	mlan_ioctl_req *req = NULL;
	mlan_ds_bss *bss = NULL;
	t_u8 *pos;
	t_u8 qosinfo;
	MrvlIEtypes_Data_t *tlv;
	mlan_status status;
	int ret = 0;

	ENTER();
	req = woal_alloc_mlan_ioctl_req(sizeof(mlan_ds_bss));
	if (req == NULL) {
		ret = -ENOMEM;
		goto done;
	}
	bss = (mlan_ds_bss *)req->pbuf;
	bss->sub_command = MLAN_OID_UAP_ADD_STATION;
	req->req_id = MLAN_IOCTL_BSS;
	req->action = MLAN_ACT_SET;
	bss->param.sta_info.listen_interval = params->listen_interval;
	bss->param.sta_info.aid = params->aid;
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
	bss->param.sta_info.cap_info = params->capability;
#else
	bss->param.sta_info.cap_info = 0;
#endif
	bss->param.sta_info.tlv_len = 0;
	bss->param.sta_info.sta_flags = params->sta_flags_set;
	memcpy(bss->param.sta_info.peer_mac, mac, MLAN_MAC_ADDR_LENGTH);
	PRINTM(MMSG, "wlan: UAP/GO add peer station, address =" MACSTR "\n",
	       MAC2STR(mac));
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
	PRINTM(MCMND,
	       "sta_flags=0x%x listen_interval=%d aid=%d cap_info=0x%x\n",
	       params->sta_flags_set, params->listen_interval, params->aid,
	       params->capability);
#else
	PRINTM(MCMND, "sta_flags=0x%x listen_interval=%d aid=%d\n",
	       params->sta_flags_set, params->listen_interval, params->aid);
#endif
	pos = &bss->param.sta_info.tlv[0];
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
	if (params->ext_capab_len) {
		tlv = (MrvlIEtypes_Data_t *)pos;
		tlv->header.type = EXT_CAPABILITY;
		tlv->header.len = params->ext_capab_len;
		memcpy(tlv->data, params->ext_capab, tlv->header.len);
		pos += sizeof(MrvlIEtypesHeader_t) + tlv->header.len;
		bss->param.sta_info.tlv_len +=
			sizeof(MrvlIEtypesHeader_t) + tlv->header.len;
		tlv = (MrvlIEtypes_Data_t *)pos;
	}
#endif
	if (params->supported_rates_len) {
		tlv = (MrvlIEtypes_Data_t *)pos;
		tlv->header.type = SUPPORTED_RATES;
		tlv->header.len = params->supported_rates_len;
		memcpy(tlv->data, params->supported_rates, tlv->header.len);
		pos += sizeof(MrvlIEtypesHeader_t) + tlv->header.len;
		bss->param.sta_info.tlv_len +=
			sizeof(MrvlIEtypesHeader_t) + tlv->header.len;
		tlv = (MrvlIEtypes_Data_t *)pos;
	}
	if (params->uapsd_queues || params->max_sp) {
		tlv = (MrvlIEtypes_Data_t *)pos;
		tlv->header.type = QOS_INFO;
		tlv->header.len = sizeof(qosinfo);
		qosinfo = params->uapsd_queues | (params->max_sp << 5);
		memcpy(tlv->data, &qosinfo, tlv->header.len);
		pos += sizeof(MrvlIEtypesHeader_t) + tlv->header.len;
		bss->param.sta_info.tlv_len +=
			sizeof(MrvlIEtypesHeader_t) + tlv->header.len;
		tlv = (MrvlIEtypes_Data_t *)pos;
	}
	if (params->ht_capa) {
		tlv = (MrvlIEtypes_Data_t *)pos;
		tlv->header.type = HT_CAPABILITY;
		tlv->header.len = sizeof(struct ieee80211_ht_cap);
		memcpy(tlv->data, params->ht_capa, tlv->header.len);
		pos += sizeof(MrvlIEtypesHeader_t) + tlv->header.len;
		bss->param.sta_info.tlv_len +=
			sizeof(MrvlIEtypesHeader_t) + tlv->header.len;
		tlv = (MrvlIEtypes_Data_t *)pos;
	}
	if (params->vht_capa) {
		tlv = (MrvlIEtypes_Data_t *)pos;
		tlv->header.type = VHT_CAPABILITY;
		tlv->header.len = sizeof(struct ieee80211_vht_cap);
		memcpy(tlv->data, params->vht_capa, tlv->header.len);
		pos += sizeof(MrvlIEtypesHeader_t) + tlv->header.len;
		bss->param.sta_info.tlv_len +=
			sizeof(MrvlIEtypesHeader_t) + tlv->header.len;
		tlv = (MrvlIEtypes_Data_t *)pos;
	}
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
	if (params->opmode_notif_used) {
		tlv = (MrvlIEtypes_Data_t *)pos;
		tlv->header.type = OPER_MODE_NTF;
		tlv->header.len = sizeof(u8);
		memcpy(tlv->data, &params->opmode_notif, tlv->header.len);
		pos += sizeof(MrvlIEtypesHeader_t) + tlv->header.len;
		bss->param.sta_info.tlv_len +=
			sizeof(MrvlIEtypesHeader_t) + tlv->header.len;
		tlv = (MrvlIEtypes_Data_t *)pos;
	}
#endif
	DBG_HEXDUMP(MCMD_D, "sta tlv", &bss->param.sta_info.tlv[0],
		    bss->param.sta_info.tlv_len);
	/* Send IOCTL request to MLAN */
	status = woal_request_ioctl(priv, req, MOAL_IOCTL_WAIT);
	if (status != MLAN_STATUS_PENDING)
		kfree(req);
done:
	LEAVE();
	return ret;
}

/**
*  @brief This function is probe client handle.
*
*  @param wiphy       A pointer to wiphy.
*
*  @param dev         A pointer to net_device
*
*  @param peer        A pointer to peer
*
*  @param cookie      A pointer to cookie
*
*  @return            0 -- success, otherwise fail
*/
static int
woal_cfg80211_probe_client(struct wiphy *wiphy, struct net_device *dev,
			   const u8 *peer, u64 * cookie)
{
	return -1;
}
#endif

/**
 *  @brief Sends deauth packet to kernel
 *
 *  @param priv A pointer to moal_private struct
 *  @param reason_code  disconnect reason code
 *  @return     N/A
 */
void
woal_host_mlme_disconnect(moal_private *priv, t_u16 reason_code)
{
	t_u8 broadcast_addr[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	t_u8 frame_buf[26];
	struct ieee80211_mgmt *mgmt = (struct ieee80211_mgmt *)frame_buf;
	ENTER();
	mgmt->frame_control = IEEE80211_STYPE_DEAUTH;
	mgmt->duration = 0;
	mgmt->seq_ctrl = 0;
	mgmt->u.deauth.reason_code = reason_code;
	memcpy(mgmt->da, broadcast_addr, ETH_ALEN);
	memcpy(mgmt->sa, priv->sme_current.bssid, ETH_ALEN);
	memcpy(mgmt->bssid, priv->cfg_bssid, ETH_ALEN);
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
	mutex_lock(&priv->wdev->mtx);
	cfg80211_rx_mlme_mgmt(priv->netdev, frame_buf, 26);
	mutex_unlock(&priv->wdev->mtx);
#else
	cfg80211_send_deauth(priv->netdev, frame_buf, 26);
#endif
	priv->host_mlme = MFALSE;
	priv->auth_flag = 0;
	LEAVE();
	return;
}
#endif

/**
 * @brief Register the device with cfg80211
 *
 * @param dev       A pointer to net_device structure
 * @param bss_type  BSS type
 *
 * @return          MLAN_STATUS_SUCCESS or MLAN_STATUS_FAILURE
 */
mlan_status
woal_register_sta_cfg80211(struct net_device *dev, t_u8 bss_type)
{
	mlan_status ret = MLAN_STATUS_SUCCESS;
	moal_private *priv = (moal_private *)netdev_priv(dev);
	struct wireless_dev *wdev = NULL;
	int psmode = 0;

	ENTER();

	wdev = (struct wireless_dev *)&priv->w_dev;
	memset(wdev, 0, sizeof(struct wireless_dev));
	wdev->wiphy = priv->phandle->wiphy;
	if (!wdev->wiphy) {
		LEAVE();
		return MLAN_STATUS_FAILURE;
	}
	if (bss_type == MLAN_BSS_TYPE_STA) {
		wdev->iftype = NL80211_IFTYPE_STATION;
		priv->roaming_enabled = MFALSE;
		priv->roaming_required = MFALSE;
	}
	if (bss_type == MLAN_BSS_TYPE_NAN)
		wdev->iftype = NL80211_IFTYPE_STATION;
	dev_net_set(dev, wiphy_net(wdev->wiphy));
	dev->ieee80211_ptr = wdev;
	SET_NETDEV_DEV(dev, wiphy_dev(wdev->wiphy));
	priv->wdev = wdev;
	/* Get IEEE power save mode */
	if (MLAN_STATUS_SUCCESS ==
	    woal_set_get_power_mgmt(priv, MLAN_ACT_GET, &psmode, 0,
				    MOAL_IOCTL_WAIT)) {
		/* Save the IEEE power save mode to wiphy, because after
		 * warmreset wiphy power save should be updated instead
		 * of using the last saved configuration */
		if (psmode)
			priv->wdev->ps = MTRUE;
		else
			priv->wdev->ps = MFALSE;
	}
	LEAVE();
	return ret;
}

/**
 * @brief Initialize the wiphy
 *
 * @param priv            A pointer to moal_private structure
 * @param wait_option     Wait option
 *
 * @return                MLAN_STATUS_SUCCESS or MLAN_STATUS_FAILURE
 */
mlan_status
woal_cfg80211_init_wiphy(moal_private *priv, t_u8 wait_option)
{
	mlan_status ret = MLAN_STATUS_SUCCESS;
	int retry_count, rts_thr, frag_thr;
	struct wiphy *wiphy = NULL;
	mlan_ioctl_req *req = NULL;
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(2, 6, 38)
	mlan_ds_radio_cfg *radio = NULL;
#endif
	mlan_ds_11n_cfg *cfg_11n = NULL;
	t_u32 hw_dev_cap;
#ifdef UAP_SUPPORT
	mlan_uap_bss_param *sys_cfg = NULL;
#endif
#if CFG80211_VERSION_CODE > KERNEL_VERSION(3, 0, 0)
	t_u16 enable = 0;
#endif

	ENTER();

	wiphy = priv->phandle->wiphy;
	/* Get 11n tx parameters from MLAN */
	req = woal_alloc_mlan_ioctl_req(sizeof(mlan_ds_11n_cfg));
	if (req == NULL) {
		ret = MLAN_STATUS_FAILURE;
		goto done;
	}
	cfg_11n = (mlan_ds_11n_cfg *)req->pbuf;
	cfg_11n->sub_command = MLAN_OID_11N_HTCAP_CFG;
	req->req_id = MLAN_IOCTL_11N_CFG;
	req->action = MLAN_ACT_GET;
	cfg_11n->param.htcap_cfg.hw_cap_req = MTRUE;

	ret = woal_request_ioctl(priv, req, wait_option);
	if (ret != MLAN_STATUS_SUCCESS)
		goto done;
	hw_dev_cap = cfg_11n->param.htcap_cfg.htcap;

	/* Get supported MCS sets */
	memset(req->pbuf, 0, sizeof(mlan_ds_11n_cfg));
	cfg_11n->sub_command = MLAN_OID_11N_CFG_SUPPORTED_MCS_SET;
	req->req_id = MLAN_IOCTL_11N_CFG;
	req->action = MLAN_ACT_GET;

	ret = woal_request_ioctl(priv, req, wait_option);
	if (ret != MLAN_STATUS_SUCCESS)
		goto done;

	/* Initialize parameters for 2GHz and 5GHz bands */
	if (wiphy->bands[IEEE80211_BAND_2GHZ])
		woal_cfg80211_setup_ht_cap(&wiphy->bands[IEEE80211_BAND_2GHZ]->
					   ht_cap, hw_dev_cap,
					   cfg_11n->param.supported_mcs_set);
	/* For 2.4G band only card, this shouldn't be set */
	if (wiphy->bands[IEEE80211_BAND_5GHZ]) {
		woal_cfg80211_setup_ht_cap(&wiphy->bands[IEEE80211_BAND_5GHZ]->
					   ht_cap, hw_dev_cap,
					   cfg_11n->param.supported_mcs_set);
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)
		woal_cfg80211_setup_vht_cap(priv,
					    &wiphy->bands[IEEE80211_BAND_5GHZ]->
					    vht_cap);
#endif
	}
	kfree(req);

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(2, 6, 38)
	/* Get antenna modes */
	req = woal_alloc_mlan_ioctl_req(sizeof(mlan_ds_radio_cfg));
	if (req == NULL) {
		ret = MLAN_STATUS_FAILURE;
		goto done;
	}
	radio = (mlan_ds_radio_cfg *)req->pbuf;
	radio->sub_command = MLAN_OID_ANT_CFG;
	req->req_id = MLAN_IOCTL_RADIO_CFG;
	req->action = MLAN_ACT_GET;

	ret = woal_request_ioctl(priv, req, wait_option);
	if (ret != MLAN_STATUS_SUCCESS)
		goto done;

	/* Set available antennas to wiphy */
	wiphy->available_antennas_tx = radio->param.ant_cfg_1x1.antenna;
	wiphy->available_antennas_rx = radio->param.ant_cfg_1x1.antenna;
#endif /* CFG80211_VERSION_CODE */

	/* Set retry limit count to wiphy */
	if (GET_BSS_ROLE(priv) == MLAN_BSS_ROLE_STA) {
		if (MLAN_STATUS_SUCCESS !=
		    woal_set_get_retry(priv, MLAN_ACT_GET, wait_option,
				       &retry_count)) {
			ret = MLAN_STATUS_FAILURE;
			goto done;
		}
	}
#ifdef UAP_SUPPORT
	else {
		sys_cfg = kzalloc(sizeof(mlan_uap_bss_param), GFP_ATOMIC);
		if (!sys_cfg) {
			PRINTM(MERROR,
			       "Fail to alloc memory for mlan_uap_bss_param\n");
			ret = MLAN_STATUS_FAILURE;
			goto done;
		}
		if (MLAN_STATUS_SUCCESS !=
		    woal_set_get_sys_config(priv, MLAN_ACT_GET, wait_option,
					    sys_cfg)) {
			ret = MLAN_STATUS_FAILURE;
			kfree(sys_cfg);
			goto done;
		}
		retry_count = sys_cfg->retry_limit;
		kfree(sys_cfg);
	}
#endif
	wiphy->retry_long = (t_u8)retry_count;
	wiphy->retry_short = (t_u8)retry_count;
	wiphy->max_scan_ie_len = MAX_IE_SIZE;

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(2, 6, 37)
	wiphy->mgmt_stypes = ieee80211_mgmt_stypes;
#endif
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
	wiphy->max_remain_on_channel_duration = MAX_REMAIN_ON_CHANNEL_DURATION;
#endif /* KERNEL_VERSION */

	/* Set RTS threshold to wiphy */
	if (MLAN_STATUS_SUCCESS !=
	    woal_set_get_rts(priv, MLAN_ACT_GET, wait_option, &rts_thr)) {
		ret = MLAN_STATUS_FAILURE;
		goto done;
	}
	if (rts_thr < MLAN_RTS_MIN_VALUE || rts_thr > MLAN_RTS_MAX_VALUE)
		rts_thr = MLAN_FRAG_RTS_DISABLED;
	wiphy->rts_threshold = (t_u32)rts_thr;

	/* Set fragment threshold to wiphy */
	if (MLAN_STATUS_SUCCESS !=
	    woal_set_get_frag(priv, MLAN_ACT_GET, wait_option, &frag_thr)) {
		ret = MLAN_STATUS_FAILURE;
		goto done;
	}
	if (frag_thr < MLAN_RTS_MIN_VALUE || frag_thr > MLAN_RTS_MAX_VALUE)
		frag_thr = MLAN_FRAG_RTS_DISABLED;
	wiphy->frag_threshold = (t_u32)frag_thr;
#if CFG80211_VERSION_CODE > KERNEL_VERSION(3, 0, 0)
	/* Enable multi-channel by default if multi-channel is supported */
	if (cfg80211_iface_comb_ap_sta.num_different_channels > 1)
		enable = 1;
	ret = woal_mc_policy_cfg(priv, &enable, wait_option, MLAN_ACT_SET);
#endif
done:
	LEAVE();
	if (ret != MLAN_STATUS_PENDING)
		kfree(req);
	return ret;
}

/*
 * This function registers the device with CFG802.11 subsystem.
 *
 * @param priv       A pointer to moal_private
 *
 */
mlan_status
woal_register_cfg80211(moal_private *priv)
{
	mlan_status ret = MLAN_STATUS_SUCCESS;
	struct wiphy *wiphy;
	void *wdev_priv = NULL;
	mlan_fw_info fw_info;
	char *country = NULL;
	int index = 0;

	ENTER();

	woal_request_get_fw_info(priv, MOAL_IOCTL_WAIT, &fw_info);

	wiphy = wiphy_new(&woal_cfg80211_ops, sizeof(moal_handle *));
	if (!wiphy) {
		PRINTM(MERROR, "Could not allocate wiphy device\n");
		ret = MLAN_STATUS_FAILURE;
		goto err_wiphy;
	}
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
	if (host_mlme) {
		woal_cfg80211_ops.auth = woal_cfg80211_authenticate;
		woal_cfg80211_ops.assoc = woal_cfg80211_associate;
		woal_cfg80211_ops.probe_client = woal_cfg80211_probe_client;
	}
#endif
#ifdef CONFIG_PM
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
	wiphy->wowlan = &wowlan_support;
#else
	wiphy->wowlan.flags = WIPHY_WOWLAN_ANY | WIPHY_WOWLAN_MAGIC_PKT;
	wiphy->wowlan.n_patterns = MAX_NUM_FILTERS;
	wiphy->wowlan.pattern_min_len = 1;
	wiphy->wowlan.pattern_max_len = WOWLAN_MAX_PATTERN_LEN;
	wiphy->wowlan.max_pkt_offset = WOWLAN_MAX_OFFSET_LEN;
#endif
#endif
#endif
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 12, 0)
	wiphy->coalesce = &coalesce_support;
#endif
	wiphy->max_scan_ssids = MRVDRV_MAX_SSID_LIST_LENGTH;
	wiphy->max_scan_ie_len = MAX_IE_SIZE;
	wiphy->interface_modes = 0;
	wiphy->interface_modes = MBIT(NL80211_IFTYPE_STATION) |
		MBIT(NL80211_IFTYPE_AP);
	wiphy->interface_modes |= MBIT(NL80211_IFTYPE_MONITOR);

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
	woal_register_cfg80211_vendor_command(wiphy);
#endif
	/* Make this wiphy known to this driver only */
	wiphy->privid = mrvl_wiphy_privid;

	if (!fw_info.fw_bands)
		fw_info.fw_bands = BAND_B | BAND_G;
	if (fw_info.fw_bands & BAND_A) {
		wiphy->bands[IEEE80211_BAND_5GHZ] = &cfg80211_band_5ghz;
		priv->phandle->band = IEEE80211_BAND_5GHZ;
	}
	/* Supported bands */
	if (fw_info.fw_bands & (BAND_B | BAND_G | BAND_GN | BAND_GAC)) {
		wiphy->bands[IEEE80211_BAND_2GHZ] = &cfg80211_band_2ghz;
		/* If 2.4G enable, it will overwrite default to 2.4G */
		priv->phandle->band = IEEE80211_BAND_2GHZ;
	}

	if (fw_info.fw_bands & BAND_A) {
	/** reduce scan time from 110ms to 80ms */
		woal_set_scan_time(priv, INIT_ACTIVE_SCAN_CHAN_TIME,
				   INIT_PASSIVE_SCAN_CHAN_TIME,
				   INIT_SPECIFIC_SCAN_CHAN_TIME);
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 12, 0)
		cfg80211_iface_comb_ap_sta.radar_detect_widths |=
			MBIT(NL80211_CHAN_WIDTH_40);
		if (fw_info.fw_bands & BAND_AAC)
			cfg80211_iface_comb_ap_sta.radar_detect_widths |=
				MBIT(NL80211_CHAN_WIDTH_80);
#endif
	} else
		woal_set_scan_time(priv, ACTIVE_SCAN_CHAN_TIME,
				   PASSIVE_SCAN_CHAN_TIME,
				   SPECIFIC_SCAN_CHAN_TIME);

	/* Initialize cipher suits */
	wiphy->cipher_suites = cfg80211_cipher_suites;
	wiphy->n_cipher_suites = ARRAY_SIZE(cfg80211_cipher_suites);
#ifdef UAP_CFG80211
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
	if (!host_mlme)
#endif
		wiphy->max_acl_mac_addrs = MAX_MAC_FILTER_NUM;
#endif
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 15, 0)
	if (fw_info.max_ap_assoc_sta)
		wiphy->max_ap_assoc_sta = fw_info.max_ap_assoc_sta;
#endif
#endif

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
	if (cfg80211_drcs) {
		cfg80211_iface_comb_ap_sta.num_different_channels = 2;
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 12, 0)
		cfg80211_iface_comb_ap_sta.radar_detect_widths = 0;
#endif
	}
	/* Initialize interface combinations */
	wiphy->iface_combinations = &cfg80211_iface_comb_ap_sta;
	wiphy->n_iface_combinations = 1;
#endif

	memcpy(wiphy->perm_addr, priv->current_addr, ETH_ALEN);
	wiphy->signal_type = CFG80211_SIGNAL_TYPE_MBM;

	wiphy->flags = 0;
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(2, 6, 33)
	wiphy->flags |= WIPHY_FLAG_PS_ON_BY_DEFAULT;
	wiphy->flags |= WIPHY_FLAG_NETNS_OK;
#endif
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 3, 0)
	wiphy->flags |=
		WIPHY_FLAG_HAS_REMAIN_ON_CHANNEL | WIPHY_FLAG_OFFCHAN_TX;
	wiphy->flags |= WIPHY_FLAG_AP_UAPSD | WIPHY_FLAG_AP_PROBE_RESP_OFFLOAD;
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
	if (host_mlme)
		wiphy->flags |= WIPHY_FLAG_REPORTS_OBSS;
	else
#endif
		wiphy->flags |= WIPHY_FLAG_HAVE_AP_SME;
#endif
#ifdef ANDROID_KERNEL
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
	if (!host_mlme)
#endif
		wiphy->flags |= WIPHY_FLAG_HAVE_AP_SME;
#endif
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)
#if CFG80211_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
	wiphy->flags |= WIPHY_FLAG_SUPPORTS_SCHED_SCAN;
#else
	wiphy->max_sched_scan_reqs = 1;
#endif
	wiphy->max_sched_scan_ssids = MRVDRV_MAX_SSID_LIST_LENGTH;
	wiphy->max_sched_scan_ie_len = MAX_IE_SIZE;
	wiphy->max_match_sets = MRVDRV_MAX_SSID_LIST_LENGTH;
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	wiphy->max_sched_scan_plans = 3;
	wiphy->max_sched_scan_plan_iterations = 100;
#endif
#endif
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3,4,0)
	wiphy->features |= NL80211_FEATURE_INACTIVITY_TIMER;
#endif
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3,8,0)
	if (host_mlme)
		wiphy->features |= NL80211_FEATURE_SAE;
#endif

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3,8,0)
	wiphy->features |= NL80211_FEATURE_NEED_OBSS_SCAN;
#endif

	wiphy->reg_notifier = woal_cfg80211_reg_notifier;
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 12, 0)
	wiphy->flags |= WIPHY_FLAG_HAS_CHANNEL_SWITCH;
#endif
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 16, 0)
	/* Indicate to cfg80211 that the driver can support
	 * CSA and ESCA,i.e., both types of channel switch
	 * Applications like hostapd 2.6 will append CSA IE
	 * and ECSA IE and expect the driver to advertise 2
	 * in max_num_csa_counters to successfully issue a
	 * channel switch
	 */
	wiphy->max_num_csa_counters = MAX_CSA_COUNTERS_NUM;
#endif
	wiphy->flags |= WIPHY_FLAG_CONTROL_PORT_PROTOCOL;
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
	wiphy_ext_feature_set(wiphy, NL80211_EXT_FEATURE_SET_SCAN_DWELL);
#endif
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
	if (host_mlme)
		wiphy->features |= NL80211_FEATURE_SK_TX_STATUS;
#endif
	/* Set struct moal_handle pointer in wiphy_priv */
	wdev_priv = wiphy_priv(wiphy);
	*(unsigned long *)wdev_priv = (unsigned long)priv->phandle;

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(2, 6, 39)
	set_wiphy_dev(wiphy, (struct device *)priv->phandle->hotplug_device);
#endif
	/* Set phy name */
	for (index = 0; index < MAX_MLAN_ADAPTER; index++) {
		if (m_handle[index] == priv->phandle) {
			dev_set_name(&wiphy->dev, mwiphy_name, index);
			break;
		}
	}

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
	if (beacon_hints) {
		/* REGULATORY_DISABLE_BEACON_HINTS: NO-IR flag won't be removed on chn where an AP is visible! */
		wiphy->regulatory_flags |= REGULATORY_DISABLE_BEACON_HINTS;
	}
	if (country_ie_ignore) {
		PRINTM(MIOCTL, "Don't follow countryIE provided by AP.\n");
		wiphy->regulatory_flags |= REGULATORY_COUNTRY_IE_IGNORE;
	} else {
		PRINTM(MIOCTL, "Follow countryIE provided by AP.\n");
	}
#endif
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
	wiphy->regulatory_flags |=
		REGULATORY_STRICT_REG | REGULATORY_CUSTOM_REG;
#endif
	if (reg_alpha2 && !strncmp(reg_alpha2, "99", strlen("99"))) {
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
		wiphy->regulatory_flags |= REGULATORY_CUSTOM_REG |
			REGULATORY_DISABLE_BEACON_HINTS |
			REGULATORY_COUNTRY_IE_IGNORE;
#else
		wiphy->flags |= WIPHY_FLAG_CUSTOM_REGULATORY;
#endif
		wiphy_apply_custom_regulatory(wiphy, &mrvl_regdom);
	}
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 9, 0)
	if (woal_request_extcap(priv,
				(t_u8 *)&priv->extended_capabilities,
				sizeof(priv->extended_capabilities)) < 0)
		PRINTM(MERROR,
		       "Failed to get driver extended capability, use default\n");
	DBG_HEXDUMP(MCMD_D, "wiphy ext cap",
		    (t_u8 *)&priv->extended_capabilities,
		    sizeof(priv->extended_capabilities));
	wiphy->extended_capabilities = (t_u8 *)&priv->extended_capabilities;
	wiphy->extended_capabilities_mask =
		(t_u8 *)&priv->extended_capabilities;
	wiphy->extended_capabilities_len = sizeof(priv->extended_capabilities);
#endif
	if (wiphy_register(wiphy) < 0) {
		PRINTM(MERROR, "Wiphy device registration failed!\n");
		ret = MLAN_STATUS_FAILURE;
		goto err_wiphy;
	}

	if ((!reg_alpha2 || strncmp(reg_alpha2, "99", strlen("99")))
		) {
	/** we will try driver parameter first */
		if (reg_alpha2 && woal_is_valid_alpha2(reg_alpha2)) {
			PRINTM(MIOCTL, "Notify reg_alpha2 %c%c\n",
			       reg_alpha2[0], reg_alpha2[1]);
			if (!disable_regd_by_driver)
				regulatory_hint(wiphy, reg_alpha2);
		} else {
			country = region_code_2_string(fw_info.region_code);
			if (country) {
				if (fw_info.region_code != 0) {
					PRINTM(MIOCTL,
					       "Notify hw region code=%d %c%c\n",
					       fw_info.region_code, country[0],
					       country[1]);
					if (!disable_regd_by_driver)
						regulatory_hint(wiphy, country);
				}
			} else
				PRINTM(MCMND,
				       "hw region code=%d not supported\n",
				       fw_info.region_code);
		}
	}
	priv->phandle->wiphy = wiphy;
	woal_cfg80211_init_wiphy(priv, MOAL_IOCTL_WAIT);
	return ret;
err_wiphy:
	if (wiphy)
		wiphy_free(wiphy);
	LEAVE();
	return ret;
}

module_param(cfg80211_drcs, int, 0);
MODULE_PARM_DESC(cfg80211_drcs,
		 "1: Enable DRCS support; 0: Disable DRCS support");
module_param(disable_regd_by_driver, int, 0);
MODULE_PARM_DESC(disable_regd_by_driver,
		 "0: reg domain set by driver enable(default); 1: reg domain set by driver disable");
module_param(reg_alpha2, charp, 0660);
MODULE_PARM_DESC(reg_alpha2, "Regulatory alpha2");
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
module_param(country_ie_ignore, int, 0);
MODULE_PARM_DESC(country_ie_ignore,
		 "0: Follow countryIE from AP and beacon hint enable; 1: Ignore countryIE from AP and beacon hint disable");
module_param(beacon_hints, int, 0);
MODULE_PARM_DESC(beacon_hints,
		 "0: enable beacon hints(default); 1: disable beacon hints");
#endif
#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 8, 0)
module_param(host_mlme, int, 0);
MODULE_PARM_DESC(host_mlme,
		 "1: Enable Host MLME Support; 0: Disable Host MLME support");
#endif
