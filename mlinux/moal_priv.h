
/** @file moal_priv.h
 *
 * @brief This file contains definition for extended private IOCTL call.
 *
 *
 * Copyright 2008-2020 NXP
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

/********************************************************
Change log:
    10/31/2008: initial version
********************************************************/

#ifndef _WOAL_PRIV_H_
#define _WOAL_PRIV_H_

/** 2K bytes */
#define WOAL_2K_BYTES 2000

/** PRIVATE CMD ID */
#define WOAL_IOCTL (SIOCIWFIRSTPRIV)	/* 0x8BE0 defined in wireless.h */

/** Private command ID to set one int/get word char */
#define WOAL_SETONEINT_GETWORDCHAR (WOAL_IOCTL + 1)
/** Private command ID to get version */
#define WOAL_VERSION 1
/** Private command ID to get extended version */
#define WOAL_VEREXT 2

/** Private command ID to set/get none */
#define WOAL_SETNONE_GETNONE (WOAL_IOCTL + 2)
/** Private command ID for warm reset */
#define WOAL_WARMRESET 1

/**
 * Linux Kernels later 3.9 use CONFIG_PM_RUNTIME instead of
 * CONFIG_USB_SUSPEND
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
#ifdef CONFIG_PM
#ifndef CONFIG_USB_SUSPEND
#define CONFIG_USB_SUSPEND
#endif
#endif
#else /* LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0) */
#ifdef CONFIG_PM_RUNTIME
#ifndef CONFIG_USB_SUSPEND
#define CONFIG_USB_SUSPEND
#endif
#endif
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0) */
#endif

/** Private command ID to clear 11d chan table */
#define WOAL_11D_CLR_CHAN_TABLE 4

/** Private command ID to set/get sixteen int */
#define WOAL_SET_GET_SIXTEEN_INT (WOAL_IOCTL + 3)
/** Private command ID to set/get TX power configurations */
#define WOAL_TX_POWERCFG 1
#ifdef DEBUG_LEVEL1
/** Private command ID to set/get driver debug */
#define WOAL_DRV_DBG 2
#endif
/** Private command ID to set/get beacon interval */
#define WOAL_BEACON_INTERVAL 3
/** Private command ID to get RSSI */
#define WOAL_SIGNAL 5
/** Private command ID to set/get Deep Sleep mode */
#define WOAL_DEEP_SLEEP 7
/** Private command ID for 11n ht configration */
#define WOAL_11N_TX_CFG 8
/** Private command ID for 11n usr ht configration */
#define WOAL_11N_HTCAP_CFG 9
/** Private command ID for TX Aggregation */
#define WOAL_PRIO_TBL 10
/** Private command ID for Updating ADDBA variables */
#define WOAL_ADDBA_UPDT 11
/** Private command ID to set/get Host Sleep configuration */
#define WOAL_HS_CFG 12
/** Private command ID to set Host Sleep parameters */
#define WOAL_HS_SETPARA 13
/** Private command ID to read/write registers */
#define WOAL_REG_READ_WRITE 14
/** Private command ID to set/get band/adhocband */
#define WOAL_BAND_CFG 15
/** Private command ID for TX Aggregation */
#define WOAL_11N_AMSDU_AGGR_CTRL 17
/** Private command ID to set/get Inactivity timeout */
#define WOAL_INACTIVITY_TIMEOUT_EXT 18
/** Private command ID to turn on/off sdio clock */
#define WOAL_SDIO_CLOCK 19
/** Private command ID to read/write Command 52 */
#define WOAL_CMD_52RDWR 20
/** Private command ID to set/get scan configuration parameter */
#define WOAL_SCAN_CFG 21
/** Private command ID to set/get PS configuration parameter */
#define WOAL_PS_CFG 22
/** Private command ID to read/write memory */
#define WOAL_MEM_READ_WRITE 23
/** Private command ID to control SDIO MP-A */
#define WOAL_SDIO_MPA_CTRL 25
/** Private command ID for Updating ADDBA variables */
#define WOAL_ADDBA_REJECT 27
/** Private command ID to set/get sleep parameters */
#define WOAL_SLEEP_PARAMS 28
/** Private command ID to set/get network monitor */
#define WOAL_NET_MONITOR 30
/** Private command ID to set/get TX BF capabilities */
#define WOAL_TX_BF_CAP 31
#if defined(DFS_TESTING_SUPPORT)
/** Private command ID to set/get dfs testing settings */
#define WOAL_DFS_TESTING 33
#endif
/** Private command ID to set/get CFP table codes */
#define WOAL_CFP_CODE 34
/** Private command ID to set/get tx/rx antenna */
#define WOAL_SET_GET_TX_RX_ANT 35
/** Private command ID to set/get management frame passthru mask */
#define WOAL_MGMT_FRAME_CTRL 36

/** Private command ID to configure gpio independent reset */
#define WOAL_IND_RST_CFG 37

/** Private command ID to set one int/get one int */
#define WOAL_SETONEINT_GETONEINT (WOAL_IOCTL + 5)
/** Private command ID to set/get Tx rate */
#define WOAL_SET_GET_TXRATE 1
/** Private command ID to set/get region code */
#define WOAL_SET_GET_REGIONCODE 2
/** Private command ID to turn on/off radio */
#define WOAL_SET_RADIO 3
/** Private command ID to enable WMM */
#define WOAL_WMM_ENABLE 4
/** Private command ID to enable 802.11D */
#define WOAL_11D_ENABLE 5
/** Private command ID to set/get QoS configuration */
#define WOAL_SET_GET_QOS_CFG 7
#if defined(REASSOCIATION)
/** Private command ID to set/get reassociation setting */
#define WOAL_SET_GET_REASSOC 9
#endif /* REASSOCIATION */
/** Private command ID for Updating Transmit buffer configration */
#define WOAL_TXBUF_CFG 10
/** Private command ID to set/get WWS mode */
#define WOAL_SET_GET_WWS_CFG 12
/** Private command ID to set/get sleep period */
#define WOAL_SLEEP_PD 13
/** Private command ID to set/get firmware wakeup method */
#define WOAL_FW_WAKEUP_METHOD 15
/** Private command ID to set/get auth type */
#define WOAL_AUTH_TYPE 18
/** Private command ID to set/get port control */
#define WOAL_PORT_CTRL 19
#if defined(STA_SUPPORT) && defined(UAP_SUPPORT)
/** Private command ID for set/get BSS role */
#define WOAL_SET_GET_BSS_ROLE 21
#endif
/** Private command ID for set/get 11h local power constraint */
#define WOAL_SET_GET_11H_LOCAL_PWR_CONSTRAINT 22
/** Private command ID to set/get MAC control */
#define WOAL_MAC_CONTROL 24
/** Private command ID to get thermal value */
#define WOAL_THERMAL 25

/** Private command ID to get log */
#define WOALGETLOG (WOAL_IOCTL + 7)

/** Private command ID to set a wext address variable */
#define WOAL_SETADDR_GETNONE (WOAL_IOCTL + 8)
/** Private command ID to send deauthentication */
#define WOAL_DEAUTH 1

/** Private command to get/set 256 chars */
#define WOAL_SET_GET_256_CHAR (WOAL_IOCTL + 9)
#define WOAL_ASSOCIATE 3
/** Private command ID to get WMM queue status */
#define WOAL_WMM_QUEUE_STATUS 4
/** Private command ID to get Traffic stream status */
#define WOAL_WMM_TS_STATUS 5
#define WOAL_IP_ADDRESS 7
/** Private command ID to set/get TX bemaforming */
#define WOAL_TX_BF_CFG 8

/** Get log buffer size */
#define GETLOG_BUFSIZE 1500

/** Private command ID to set none/get twelve chars*/
#define WOAL_SETNONE_GETTWELVE_CHAR (WOAL_IOCTL + 11)
/** Private command ID for WPS session */
#define WOAL_WPS_SESSION 1

/** Private command ID to set none/get four int */
#define WOAL_SETNONE_GET_FOUR_INT (WOAL_IOCTL + 13)
/** Private command ID to get data rates */
#define WOAL_DATA_RATE 1

/** Private command to get/set 64 ints */
#define WOAL_SET_GET_64_INT (WOAL_IOCTL + 15)
/** Private command ID to set/get ECL system clock */
#define WOAL_ECL_SYS_CLOCK 1

/** Private command ID for hostcmd */
#define WOAL_HOST_CMD (WOAL_IOCTL + 17)

/** Private command ID for arpfilter */
#define WOAL_ARP_FILTER (WOAL_IOCTL + 19)

/** Private command ID to set ints and get chars */
#define WOAL_SET_INTS_GET_CHARS (WOAL_IOCTL + 21)
/** Private command ID to read EEPROM data */
#define WOAL_READ_EEPROM 1

/** Private command ID to set/get 2K bytes */
#define WOAL_SET_GET_2K_BYTES (WOAL_IOCTL + 23)

/** Private command ID to read/write Command 53 */
#define WOAL_CMD_53RDWR 2

/** Private command ID for setuserscan */
#define WOAL_SET_USER_SCAN 3
/** Private command ID for getscantable */
#define WOAL_GET_SCAN_TABLE 4
/** Private command ID for setuserscanext: async without wait */
#define WOAL_SET_USER_SCAN_EXT 5

/** Private command ID to request ADDTS */
#define WOAL_WMM_ADDTS 7
/** Private command ID to request DELTS */
#define WOAL_WMM_DELTS 8
/** Private command ID to queue configuration */
#define WOAL_WMM_QUEUE_CONFIG 9
/** Private command ID to queue stats */
#define WOAL_WMM_QUEUE_STATS 10
/** Private command ID to Bypass auth packet */
#define WOAL_BYPASSED_PACKET 11

#ifdef UAP_WEXT
/** The following command IDs are for Froyo app */
/** Private command ID to start driver */
#define WOAL_FROYO_START (WOAL_IOCTL + 28)
/** Private command ID to reload FW */
#define WOAL_FROYO_WL_FW_RELOAD (WOAL_IOCTL + 29)
/** Private command ID to stop driver */
#define WOAL_FROYO_STOP (WOAL_IOCTL + 30)
#endif

/** moal_802_11_rates  */
typedef struct _moal_802_11_rates {
	/** Num of rates */
	t_u8 num_of_rates;
	/** Rates */
	t_u8 rates[MLAN_SUPPORTED_RATES];
} moal_802_11_rates, *pmoal_802_11_rates;

#if defined(STA_WEXT) || defined(UAP_WEXT)
int woal_wext_do_ioctl(struct net_device *dev, struct ifreq *req, int cmd);
#endif

#endif /* _WOAL_PRIV_H_ */
