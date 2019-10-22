/** @file moal_cfgvendor.h
  *
  * @brief This file contains the CFG80211 vendor specific defines.
  *
  * Copyright (C) 2011-2019, Marvell International Ltd.
  *
  * This software file (the "File") is distributed by Marvell International
  * Ltd. under the terms of the GNU General Public License Version 2, June 1991
  * (the "License").  You may use, redistribute and/or modify this File in
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

#ifndef _MOAL_CFGVENDOR_H_
#define _MOAL_CFGVENDOR_H_

#include   "moal_main.h"

#if CFG80211_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)

#define ATTRIBUTE_U32_LEN                  (nla_total_size(NLA_HDRLEN  + 4))
#define VENDOR_ID_OVERHEAD                 ATTRIBUTE_U32_LEN
#define VENDOR_SUBCMD_OVERHEAD             ATTRIBUTE_U32_LEN
#define VENDOR_DATA_OVERHEAD               (nla_total_size(NLA_HDRLEN))

#define VENDOR_REPLY_OVERHEAD       (VENDOR_ID_OVERHEAD + \
									VENDOR_SUBCMD_OVERHEAD + \
									VENDOR_DATA_OVERHEAD)

/* Feature enums */
#define WIFI_FEATURE_INFRA              0x0001	// Basic infrastructure mode
#define WIFI_FEATURE_INFRA_5G           0x0002	// Support for 5 GHz Band
#define WIFI_FEATURE_HOTSPOT            0x0004	// Support for GAS/ANQP
#define WIFI_FEATURE_P2P                0x0008	// Wifi-Direct
#define WIFI_FEATURE_SOFT_AP            0x0010	// Soft AP
#define WIFI_FEATURE_GSCAN              0x0020	// Google-Scan APIs
#define WIFI_FEATURE_NAN                0x0040	// Neighbor Awareness Networking
#define WIFI_FEATURE_D2D_RTT            0x0080	// Device-to-device RTT
#define WIFI_FEATURE_D2AP_RTT           0x0100	// Device-to-AP RTT
#define WIFI_FEATURE_BATCH_SCAN         0x0200	// Batched Scan (legacy)
#define WIFI_FEATURE_PNO                0x0400	// Preferred network offload
#define WIFI_FEATURE_ADDITIONAL_STA     0x0800	// Support for two STAs
#define WIFI_FEATURE_TDLS               0x1000	// Tunnel directed link setup
#define WIFI_FEATURE_TDLS_OFFCHANNEL    0x2000	// Support for TDLS off channel
#define WIFI_FEATURE_EPR                0x4000	// Enhanced power reporting
#define WIFI_FEATURE_AP_STA             0x8000	// Support for AP STA Concurrency
#define WIFI_FEATURE_LINK_LAYER_STATS   0x10000	// Link layer stats collection
#define WIFI_FEATURE_LOGGER             0x20000	// WiFi Logger
#define WIFI_FEATURE_HAL_EPNO           0x40000	// WiFi PNO enhanced
#define WIFI_FEATURE_RSSI_MONITOR       0x80000	// RSSI Monitor
#define WIFI_FEATURE_MKEEP_ALIVE        0x100000	// WiFi mkeep_alive
#define WIFI_FEATURE_CONFIG_NDO         0x200000	// ND offload configure
#define WIFI_FEATURE_TX_TRANSMIT_POWER  0x400000	// Capture Tx transmit power levels
#define WIFI_FEATURE_CONTROL_ROAMING    0x800000	// Enable/Disable firmware roaming
#define WIFI_FEATURE_IE_WHITELIST       0x1000000	// Support Probe IE white listing
#define WIFI_FEATURE_SCAN_RAND          0x2000000	// Support MAC & Probe Sequence Number randomization
// Add more features here

#define MAX_CHANNEL_NUM 200

/** Wifi Band */
typedef enum {
	WIFI_BAND_UNSPECIFIED,
	/** 2.4 GHz */
	WIFI_BAND_BG = 1,
	/** 5 GHz without DFS */
	WIFI_BAND_A = 2,
	/** 5 GHz DFS only */
	WIFI_BAND_A_DFS = 4,
	/** 5 GHz with DFS */
	WIFI_BAND_A_WITH_DFS = 6,
	/** 2.4 GHz + 5 GHz; no DFS */
	WIFI_BAND_ABG = 3,
	/** 2.4 GHz + 5 GHz with DFS */
	WIFI_BAND_ABG_WITH_DFS = 7,

	/** Keep it last */
	WIFI_BAND_LAST,
	WIFI_BAND_MAX = WIFI_BAND_LAST - 1,
} wifi_band;

typedef enum wifi_attr {
	ATTR_FEATURE_SET_INVALID = 0,
	ATTR_FEATURE_SET = 2,
	ATTR_NODFS_VALUE = 3,
	ATTR_COUNTRY_CODE = 4,
	ATTR_CHANNELS_BAND = 5,
	ATTR_NUM_CHANNELS = 6,
	ATTR_CHANNEL_LIST = 7,
	ATTR_GET_CONCURRENCY_MATRIX_SET_SIZE_MAX = 8,
	ATTR_GET_CONCURRENCY_MATRIX_SET_SIZE = 9,
	ATTR_GET_CONCURRENCY_MATRIX_SET = 10,
	ATTR_WIFI_MAX,
} wifi_attr_t;

enum mrvl_wlan_vendor_attr_wifi_logger {
	MRVL_WLAN_VENDOR_ATTR_NAME = 10,
};

/**vendor event*/
enum vendor_event {
	event_hang = 0,
	event_rssi_monitor = 0x1501,
	event_dfs_radar_detected = 0x10004,
	event_dfs_cac_started = 0x10005,
	event_dfs_cac_finished = 0x10006,
	event_dfs_cac_aborted = 0x10007,
	event_dfs_nop_finished = 0x10008,
	event_max,
};

/** struct dfs_event */
typedef struct _dfs_event {
    /** Frequency */
	int freq;
    /** HT enable */
	int ht_enabled;
    /** Channel Offset */
	int chan_offset;
    /** Channel width */
	enum nl80211_chan_width chan_width;
    /** Center Frequency 1 */
	int cf1;
    /** Center Frequency 2 */
	int cf2;
} dfs_event;

void woal_cfg80211_dfs_vendor_event(moal_private *priv, int event,
				    struct cfg80211_chan_def *chandef);

enum ATTR_RSSI_MONITOR {
	ATTR_RSSI_MONITOR_INVALID,
	ATTR_RSSI_MONITOR_CONTROL,
	ATTR_RSSI_MONITOR_MIN_RSSI,
	ATTR_RSSI_MONITOR_MAX_RSSI,
	ATTR_RSSI_MONITOR_CUR_BSSID,
	ATTR_RSSI_MONITOR_CUR_RSSI,
	ATTR_RSSI_MONITOR_MAX,
};
void woal_cfg80211_rssi_monitor_event(moal_private *priv, t_s16 rssi);

/**vendor sub command*/
enum vendor_sub_command {
	sub_cmd_set_drvdbg = 0,
	sub_cmd_dfs_capability = 0x0005,
	sub_cmd_get_correlated_time = 0x0006,
	sub_cmd_nd_offload = 0x0100,
	sub_cmd_get_valid_channels = 0x1009,
	sub_cmd_get_wifi_supp_feature_set = 0x100a,
	sub_cmd_set_country_code = 0x100d,
	sub_cmd_get_fw_version = 0x1404,
	sub_cmd_get_drv_version = 0x1406,
	sub_cmd_rssi_monitor = 0x1500,
	sub_cmd_max,
};

void woal_register_cfg80211_vendor_command(struct wiphy *wiphy);
int woal_cfg80211_vendor_event(IN moal_private *priv,
			       IN int event, IN t_u8 *data, IN int len);

enum mrvl_wlan_vendor_attr {
	MRVL_WLAN_VENDOR_ATTR_INVALID = 0,
	/* Used by MRVL_NL80211_VENDOR_SUBCMD_DFS_CAPABILITY */
	MRVL_WLAN_VENDOR_ATTR_DFS = 1,
	MRVL_WLAN_VENDOR_ATTR_AFTER_LAST,

	MRVL_WLAN_VENDOR_ATTR_MAX = MRVL_WLAN_VENDOR_ATTR_AFTER_LAST - 1,
};

typedef enum {
	ATTR_ND_OFFLOAD_INVALID = 0,
	ATTR_ND_OFFLOAD_CONTROL,
	ATTR_ND_OFFLOAD_MAX,
} ND_OFFLOAD_ATTR;

#endif
#endif /* _MOAL_CFGVENDOR_H_ */
