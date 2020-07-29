/** @file mlan_sta_rx.c
 *
 *  @brief This file contains the handling of RX in MLAN
 *  module.
 *
 *
 *  Copyright 2014-2020 NXP
 *
 *  This software file (the File) is distributed by NXP
 *  under the terms of the GNU General Public License Version 2, June 1991
 *  (the License).  You may use, redistribute and/or modify the File in
 *  accordance with the terms and conditions of the License, a copy of which
 *  is available by writing to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA or on the
 *  worldwide web at http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt.
 *
 *  THE FILE IS DISTRIBUTED AS-IS, WITHOUT WARRANTY OF ANY KIND, AND THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE
 *  ARE EXPRESSLY DISCLAIMED.  The License provides additional details about
 *  this warranty disclaimer.
 *
 */

/********************************************************
Change log:
    10/27/2008: initial version
********************************************************/

#include "mlan.h"
#include "mlan_join.h"
#include "mlan_util.h"
#include "mlan_fw.h"
#include "mlan_main.h"
#include "mlan_11n_aggr.h"
#include "mlan_11n_rxreorder.h"

/********************************************************
		Local Variables
********************************************************/

/********************************************************
		Global Variables
********************************************************/

/********************************************************
		Local Functions
********************************************************/

/********************************************************
		Global functions
********************************************************/

/**
 *  @brief This function get pxpd info for radiotap info
 *
 *  @param priv A pointer to pmlan_private
 *  @param prx_pd   A pointer to RxPD
 *  @param prt_info   A pointer to radiotap_info
 *
 *  @return        N/A
 */
void
wlan_rxpdinfo_to_radiotapinfo(pmlan_private priv, RxPD *prx_pd,
			      radiotap_info * prt_info)
{
	radiotap_info rt_info_tmp;
	t_u8 rx_rate_info = 0;
	t_u8 mcs_index = 0;
	t_u8 format = 0;
	t_u8 bw = 0;
	t_u8 gi = 0;
	t_u8 ldpc = 0;
	t_u32 rxpd_cut_size = 0;
	rxpd_extra_info *pextra_info = MNULL;

	memset(priv->adapter, &rt_info_tmp, 0x00, sizeof(rt_info_tmp));
	rt_info_tmp.snr = prx_pd->snr;
	rt_info_tmp.nf = prx_pd->nf;
	rt_info_tmp.band_config = (prx_pd->rx_info & 0xf);
	rt_info_tmp.chan_num = (prx_pd->rx_info & RXPD_CHAN_MASK) >> 5;

	rt_info_tmp.antenna = prx_pd->antenna;
	rx_rate_info = prx_pd->rate_info;
	if ((rx_rate_info & 0x3) == MLAN_RATE_FORMAT_VHT) {
		/* VHT rate */
		format = MLAN_RATE_FORMAT_VHT;
		mcs_index = MIN(prx_pd->rx_rate & 0xF, 9);
		/* 20M: bw=0, 40M: bw=1, 80M: bw=2, 160M: bw=3 */
		bw = (rx_rate_info & 0xC) >> 2;
		/* LGI: gi =0, SGI: gi = 1 */
		gi = (rx_rate_info & 0x10) >> 4;
	} else if ((rx_rate_info & 0x3) == MLAN_RATE_FORMAT_HT) {
		/* HT rate */
		format = MLAN_RATE_FORMAT_HT;
		mcs_index = prx_pd->rx_rate;
		/* 20M: bw=0, 40M: bw=1 */
		bw = (rx_rate_info & 0xC) >> 2;
		/* LGI: gi =0, SGI: gi = 1 */
		gi = (rx_rate_info & 0x10) >> 4;
	} else {
		/* LG rate */
		format = MLAN_RATE_FORMAT_LG;
		mcs_index = (prx_pd->rx_rate > MLAN_RATE_INDEX_OFDM0) ?
			prx_pd->rx_rate - 1 : prx_pd->rx_rate;
	}
	ldpc = rx_rate_info & 0x40;

	rt_info_tmp.rate_info.mcs_index = mcs_index;
	rt_info_tmp.rate_info.rate_info =
		(ldpc << 5) | (format << 3) | (bw << 1) | gi;
	rt_info_tmp.rate_info.bitrate =
		wlan_index_to_data_rate(priv->adapter, prx_pd->rx_rate,
					prx_pd->rate_info);

	if (prx_pd->flags & RXPD_FLAG_EXTRA_HEADER) {
		if (!ISSUPP_RSN_REPLAY_DETECTION(priv->adapter->fw_cap_info)) {
			rxpd_cut_size = 8;
		}
		pextra_info =
			(rxpd_extra_info *) ((t_u8 *)prx_pd + sizeof(*prx_pd) -
					     rxpd_cut_size);
		endian_convert_RxPD_extra_header(pextra_info);
		memcpy(priv->adapter, &rt_info_tmp.extra_info,
		       (t_u8 *)pextra_info, sizeof(rt_info_tmp.extra_info));
	}
	memset(priv->adapter, prt_info, 0x00, sizeof(*prt_info));
	memcpy(priv->adapter, prt_info, &rt_info_tmp, sizeof(*prt_info));

	return;
}

/**
 *  @brief This function processes received packet and forwards it
 *          to kernel/upper layer
 *
 *  @param pmadapter A pointer to mlan_adapter
 *  @param pmbuf   A pointer to mlan_buffer which includes the received packet
 *
 *  @return        MLAN_STATUS_SUCCESS or MLAN_STATUS_FAILURE
 */
mlan_status
wlan_process_rx_packet(pmlan_adapter pmadapter, pmlan_buffer pmbuf)
{
	mlan_status ret = MLAN_STATUS_SUCCESS;
	pmlan_private priv = pmadapter->priv[pmbuf->bss_index];
	RxPacketHdr_t *prx_pkt;
	RxPD *prx_pd;
	int hdr_chop;
	EthII_Hdr_t *peth_hdr;
	t_u8 rfc1042_eth_hdr[MLAN_MAC_ADDR_LENGTH] = {
		0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00
	};
	t_u8 snap_oui_802_h[MLAN_MAC_ADDR_LENGTH] = {
		0xaa, 0xaa, 0x03, 0x00, 0x00, 0xf8
	};
	t_u8 appletalk_aarp_type[2] = { 0x80, 0xf3 };
	t_u8 ipx_snap_type[2] = { 0x81, 0x37 };

	ENTER();

	prx_pd = (RxPD *)(pmbuf->pbuf + pmbuf->data_offset);
	prx_pkt = (RxPacketHdr_t *)((t_u8 *)prx_pd + prx_pd->rx_pkt_offset);

/** Small debug type */
#define DBG_TYPE_SMALL  2
/** Size of debugging structure */
#define SIZE_OF_DBG_STRUCT 4
	if (prx_pd->rx_pkt_type == PKT_TYPE_DEBUG) {
		t_u8 dbg_type;
		dbg_type = *(t_u8 *)&prx_pkt->eth803_hdr;
		if (dbg_type == DBG_TYPE_SMALL) {
			PRINTM(MFW_D, "\n");
			DBG_HEXDUMP(MFW_D, "FWDBG",
				    (char *)((t_u8 *)&prx_pkt->eth803_hdr +
					     SIZE_OF_DBG_STRUCT),
				    prx_pd->rx_pkt_length);
			PRINTM(MFW_D, "FWDBG::\n");
		}
		goto done;
	}

	PRINTM(MINFO,
	       "RX Data: data_len - prx_pd->rx_pkt_offset = %d - %d = %d\n",
	       pmbuf->data_len, prx_pd->rx_pkt_offset,
	       pmbuf->data_len - prx_pd->rx_pkt_offset);

	HEXDUMP("RX Data: Dest", prx_pkt->eth803_hdr.dest_addr,
		sizeof(prx_pkt->eth803_hdr.dest_addr));
	HEXDUMP("RX Data: Src", prx_pkt->eth803_hdr.src_addr,
		sizeof(prx_pkt->eth803_hdr.src_addr));

	if ((memcmp(pmadapter, &prx_pkt->rfc1042_hdr,
		    snap_oui_802_h, sizeof(snap_oui_802_h)) == 0) ||
	    ((memcmp(pmadapter, &prx_pkt->rfc1042_hdr,
		     rfc1042_eth_hdr, sizeof(rfc1042_eth_hdr)) == 0) &&
	     memcmp(pmadapter, &prx_pkt->rfc1042_hdr.snap_type,
		    appletalk_aarp_type, sizeof(appletalk_aarp_type)) &&
	     memcmp(pmadapter, &prx_pkt->rfc1042_hdr.snap_type,
		    ipx_snap_type, sizeof(ipx_snap_type)))) {
		/*
		 * Replace the 803 header and rfc1042 header (llc/snap) with an
		 * EthernetII header, keep the src/dst and snap_type (ethertype).
		 * The firmware only passes up SNAP frames converting
		 * all RX Data from 802.11 to 802.2/LLC/SNAP frames.
		 * To create the Ethernet II, just move the src, dst address
		 * right before the snap_type.
		 */
		peth_hdr = (EthII_Hdr_t *)
			((t_u8 *)&prx_pkt->eth803_hdr
			 + sizeof(prx_pkt->eth803_hdr) +
			 sizeof(prx_pkt->rfc1042_hdr)
			 - sizeof(prx_pkt->eth803_hdr.dest_addr)
			 - sizeof(prx_pkt->eth803_hdr.src_addr)
			 - sizeof(prx_pkt->rfc1042_hdr.snap_type));

		memcpy(pmadapter, peth_hdr->src_addr,
		       prx_pkt->eth803_hdr.src_addr,
		       sizeof(peth_hdr->src_addr));
		memcpy(pmadapter, peth_hdr->dest_addr,
		       prx_pkt->eth803_hdr.dest_addr,
		       sizeof(peth_hdr->dest_addr));

		/* Chop off the RxPD + the excess memory from the 802.2/llc/snap
		 *  header that was removed.
		 */
		hdr_chop = (t_u32)((t_ptr)peth_hdr - (t_ptr)prx_pd);
	} else {
		HEXDUMP("RX Data: LLC/SNAP",
			(t_u8 *)&prx_pkt->rfc1042_hdr,
			sizeof(prx_pkt->rfc1042_hdr));
		/* Chop off the RxPD */
		hdr_chop = (t_u32)((t_ptr)&prx_pkt->eth803_hdr - (t_ptr)prx_pd);
	}

	/* Chop off the leading header bytes so the it points to the start of
	 *   either the reconstructed EthII frame or the 802.2/llc/snap frame
	 */
	pmbuf->data_len -= hdr_chop;
	pmbuf->data_offset += hdr_chop;
	pmbuf->pparent = MNULL;
	DBG_HEXDUMP(MDAT_D, "RxPD", (t_u8 *)prx_pd,
		    MIN(sizeof(RxPD), MAX_DATA_DUMP_LEN));
	DBG_HEXDUMP(MDAT_D, "Rx Payload",
		    ((t_u8 *)prx_pd + prx_pd->rx_pkt_offset),
		    MIN(prx_pd->rx_pkt_length, MAX_DATA_DUMP_LEN));

	priv->rxpd_rate = prx_pd->rx_rate;

	pmadapter->callbacks.moal_get_system_time(pmadapter->pmoal_handle,
						  &pmbuf->out_ts_sec,
						  &pmbuf->out_ts_usec);
	PRINTM_NETINTF(MDATA, priv);
	PRINTM(MDATA, "%lu.%06lu : Data => kernel seq_num=%d tid=%d\n",
	       pmbuf->out_ts_sec, pmbuf->out_ts_usec, prx_pd->seq_num,
	       prx_pd->priority);

	if (pmadapter->enable_net_mon) {
		/* set netmon flag only for a sniffed pkt */
		if (prx_pd->rx_pkt_type == PKT_TYPE_802DOT11) {
			pmbuf->flags |= MLAN_BUF_FLAG_NET_MONITOR;
			goto mon_process;
		}
	}

mon_process:
	if (pmbuf->flags & MLAN_BUF_FLAG_NET_MONITOR) {
		//Use some rxpd space to save rxpd info for radiotap header
		//We should insure radiotap_info is not bigger than RxPD
		wlan_rxpdinfo_to_radiotapinfo(priv, prx_pd,
					      (radiotap_info *) (pmbuf->pbuf +
								 pmbuf->
								 data_offset -
								 sizeof
								 (radiotap_info)));
	}
	ret = pmadapter->callbacks.moal_recv_packet(pmadapter->pmoal_handle,
						    pmbuf);
	if (ret == MLAN_STATUS_FAILURE) {
		pmbuf->status_code = MLAN_ERROR_PKT_INVALID;
		PRINTM(MERROR,
		       "STA Rx Error: moal_recv_packet returned error\n");
	}
done:
	if (ret != MLAN_STATUS_PENDING)
		wlan_free_mlan_buffer(pmadapter, pmbuf);

	LEAVE();

	return ret;
}

/**
 *   @brief This function processes the received buffer
 *
 *   @param adapter A pointer to mlan_adapter
 *   @param pmbuf     A pointer to the received buffer
 *
 *   @return        MLAN_STATUS_SUCCESS or MLAN_STATUS_FAILURE
 */
mlan_status
wlan_ops_sta_process_rx_packet(IN t_void *adapter, IN pmlan_buffer pmbuf)
{
	pmlan_adapter pmadapter = (pmlan_adapter)adapter;
	mlan_status ret = MLAN_STATUS_SUCCESS;
	RxPD *prx_pd;
	RxPacketHdr_t *prx_pkt;
	RxPD *prx_pd2;
	EthII_Hdr_t *peth_hdr2;
	wlan_802_11_header *pwlan_hdr;
	IEEEtypes_FrameCtl_t *frmctl;
	pmlan_buffer pmbuf2 = MNULL;
	mlan_802_11_mac_addr src_addr, dest_addr;
	t_u16 hdr_len;
	t_u8 snap_eth_hdr[5] = { 0xaa, 0xaa, 0x03, 0x00, 0x00 };
	pmlan_private priv = pmadapter->priv[pmbuf->bss_index];
	t_u8 ta[MLAN_MAC_ADDR_LENGTH];
	t_u16 rx_pkt_type = 0;
	wlan_mgmt_pkt *pmgmt_pkt_hdr = MNULL;

	sta_node *sta_ptr = MNULL;
	t_u8 adj_rx_rate = 0;
	t_u8 antenna = 0;
	ENTER();

	prx_pd = (RxPD *)(pmbuf->pbuf + pmbuf->data_offset);
	/* Endian conversion */
	endian_convert_RxPD(prx_pd);

	rx_pkt_type = prx_pd->rx_pkt_type;
	prx_pkt = (RxPacketHdr_t *)((t_u8 *)prx_pd + prx_pd->rx_pkt_offset);

	priv->rxpd_rate_info = prx_pd->rate_info;
	if (priv->bss_type == MLAN_BSS_TYPE_STA) {
		antenna = wlan_adjust_antenna(priv, prx_pd);
		adj_rx_rate =
			wlan_adjust_data_rate(priv, priv->rxpd_rate,
					      priv->rxpd_rate_info);
		pmadapter->callbacks.moal_hist_data_add(pmadapter->pmoal_handle,
							pmbuf->bss_index,
							adj_rx_rate,
							prx_pd->snr, prx_pd->nf,
							antenna);
	}

	if ((prx_pd->rx_pkt_offset + prx_pd->rx_pkt_length) !=
	    (t_u16)pmbuf->data_len) {
		PRINTM(MERROR,
		       "Wrong rx packet: len=%d,rx_pkt_offset=%d,"
		       " rx_pkt_length=%d\n", pmbuf->data_len,
		       prx_pd->rx_pkt_offset, prx_pd->rx_pkt_length);
		pmbuf->status_code = MLAN_ERROR_PKT_SIZE_INVALID;
		ret = MLAN_STATUS_FAILURE;
		wlan_free_mlan_buffer(pmadapter, pmbuf);
		goto done;
	}
	pmbuf->data_len = prx_pd->rx_pkt_offset + prx_pd->rx_pkt_length;

	if (pmadapter->priv[pmbuf->bss_index]->mgmt_frame_passthru_mask &&
	    prx_pd->rx_pkt_type == PKT_TYPE_MGMT_FRAME) {
		/* Check if this is mgmt packet and needs to
		 * forwarded to app as an event
		 */
		pmgmt_pkt_hdr =
			(wlan_mgmt_pkt *)((t_u8 *)prx_pd +
					  prx_pd->rx_pkt_offset);
		pmgmt_pkt_hdr->frm_len =
			wlan_le16_to_cpu(pmgmt_pkt_hdr->frm_len);

		if ((pmgmt_pkt_hdr->wlan_header.frm_ctl
		     & IEEE80211_FC_MGMT_FRAME_TYPE_MASK) == 0)
			wlan_process_802dot11_mgmt_pkt(pmadapter->
						       priv[pmbuf->bss_index],
						       (t_u8 *)&pmgmt_pkt_hdr->
						       wlan_header,
						       pmgmt_pkt_hdr->frm_len +
						       sizeof(wlan_mgmt_pkt)
						       -
						       sizeof(pmgmt_pkt_hdr->
							      frm_len), prx_pd);
		wlan_free_mlan_buffer(pmadapter, pmbuf);
		goto done;
	}

	if (pmadapter->enable_net_mon && (prx_pd->flags & RXPD_FLAG_UCAST_PKT)) {
		pwlan_hdr = (wlan_802_11_header *)
			((t_u8 *)prx_pd + prx_pd->rx_pkt_offset);
		frmctl = (IEEEtypes_FrameCtl_t *)pwlan_hdr;
		if (frmctl->type == 0x02) {
			/* This is a valid unicast destined data packet, with 802.11 and rtap
			 * headers attached. Duplicate this packet and process this copy as a
			 * sniffed packet, meant for monitor iface
			 */
			pmbuf2 = wlan_alloc_mlan_buffer(pmadapter,
							pmbuf->data_len,
							MLAN_RX_HEADER_LEN,
							MOAL_ALLOC_MLAN_BUFFER);
			if (!pmbuf2) {
				PRINTM(MERROR,
				       "Unable to allocate mlan_buffer for Rx");
				PRINTM(MERROR, "sniffed packet\n");
			} else {
				pmbuf2->bss_index = pmbuf->bss_index;
				pmbuf2->buf_type = pmbuf->buf_type;
				pmbuf2->priority = pmbuf->priority;
				pmbuf2->in_ts_sec = pmbuf->in_ts_sec;
				pmbuf2->in_ts_usec = pmbuf->in_ts_usec;
				pmbuf2->data_len = pmbuf->data_len;
				memcpy(pmadapter,
				       pmbuf2->pbuf + pmbuf2->data_offset,
				       pmbuf->pbuf + pmbuf->data_offset,
				       pmbuf->data_len);

				prx_pd2 =
					(RxPD *)(pmbuf2->pbuf +
						 pmbuf2->data_offset);
				/* set pkt type of duplicated pkt to 802.11 */
				prx_pd2->rx_pkt_type = PKT_TYPE_802DOT11;
				wlan_process_rx_packet(pmadapter, pmbuf2);
			}

			/* Now, process this pkt as a normal data packet.
			 * rx_pkt_offset points to the 802.11 hdr. Construct 802.3 header
			 * from 802.11 hdr fields and attach it just before the payload.
			 */
			memcpy(pmadapter, (t_u8 *)&dest_addr, pwlan_hdr->addr1,
			       sizeof(pwlan_hdr->addr1));
			memcpy(pmadapter, (t_u8 *)&src_addr, pwlan_hdr->addr2,
			       sizeof(pwlan_hdr->addr2));

			hdr_len = sizeof(wlan_802_11_header);

			/* subtract mac addr field size for 3 address mac80211 header */
			if (!(frmctl->from_ds && frmctl->to_ds))
				hdr_len -= sizeof(mlan_802_11_mac_addr);

			/* add 2 bytes of qos ctrl flags */
			if (frmctl->sub_type & QOS_DATA)
				hdr_len += 2;

			if (prx_pd->rx_pkt_type == PKT_TYPE_AMSDU) {
				/* no need to generate 802.3 hdr, update pkt offset */
				prx_pd->rx_pkt_offset += hdr_len;
				prx_pd->rx_pkt_length -= hdr_len;
			} else {
				/* skip 6-byte snap and 2-byte type */
				if (memcmp
				    (pmadapter, (t_u8 *)pwlan_hdr + hdr_len,
				     snap_eth_hdr, sizeof(snap_eth_hdr)) == 0)
					hdr_len += 8;

				peth_hdr2 = (EthII_Hdr_t *)
					((t_u8 *)prx_pd +
					 prx_pd->rx_pkt_offset + hdr_len -
					 sizeof(EthII_Hdr_t));
				memcpy(pmadapter, peth_hdr2->dest_addr,
				       (t_u8 *)&dest_addr,
				       sizeof(peth_hdr2->dest_addr));
				memcpy(pmadapter, peth_hdr2->src_addr,
				       (t_u8 *)&src_addr,
				       sizeof(peth_hdr2->src_addr));

				/* Update the rx_pkt_offset to point the 802.3 hdr */
				prx_pd->rx_pkt_offset +=
					(hdr_len - sizeof(EthII_Hdr_t));
				prx_pd->rx_pkt_length -=
					(hdr_len - sizeof(EthII_Hdr_t));
			}
			/* update the prx_pkt pointer */
			prx_pkt =
				(RxPacketHdr_t *)((t_u8 *)prx_pd +
						  prx_pd->rx_pkt_offset);
		} else {
			pmbuf->status_code = MLAN_ERROR_PKT_SIZE_INVALID;
			ret = MLAN_STATUS_FAILURE;
			PRINTM(MERROR,
			       "Drop invalid unicast sniffer pkt, subType=0x%x, flag=0x%x, pkt_type=%d\n",
			       frmctl->sub_type, prx_pd->flags,
			       prx_pd->rx_pkt_type);
			wlan_free_mlan_buffer(pmadapter, pmbuf);
			goto done;
		}
	}

	/*
	 * If the packet is not an unicast packet then send the packet
	 * directly to os. Don't pass thru rx reordering
	 */
	if ((!IS_11N_ENABLED(priv)
	    ) ||
	    memcmp(priv->adapter, priv->curr_addr,
		   prx_pkt->eth803_hdr.dest_addr, MLAN_MAC_ADDR_LENGTH)) {
		priv->snr = prx_pd->snr;
		priv->nf = prx_pd->nf;
		wlan_process_rx_packet(pmadapter, pmbuf);
		goto done;
	}

	if (queuing_ra_based(priv)) {
		memcpy(pmadapter, ta, prx_pkt->eth803_hdr.src_addr,
		       MLAN_MAC_ADDR_LENGTH);
		if (prx_pd->priority < MAX_NUM_TID) {
			PRINTM(MDATA, "adhoc/tdls packet %p " MACSTR "\n",
			       pmbuf, MAC2STR(ta));
			sta_ptr = wlan_get_station_entry(priv, ta);
			if (sta_ptr) {
				sta_ptr->rx_seq[prx_pd->priority] =
					prx_pd->seq_num;
				sta_ptr->snr = prx_pd->snr;
				sta_ptr->nf = prx_pd->nf;
			}
			if (!sta_ptr || !sta_ptr->is_11n_enabled) {
				wlan_process_rx_packet(pmadapter, pmbuf);
				goto done;
			}
		}
	} else {
		priv->snr = prx_pd->snr;
		priv->nf = prx_pd->nf;
		if ((rx_pkt_type != PKT_TYPE_BAR) &&
		    (prx_pd->priority < MAX_NUM_TID))
			priv->rx_seq[prx_pd->priority] = prx_pd->seq_num;
		memcpy(pmadapter, ta,
		       priv->curr_bss_params.bss_descriptor.mac_address,
		       MLAN_MAC_ADDR_LENGTH);
	}

	if ((priv->port_ctrl_mode == MTRUE && priv->port_open == MFALSE) &&
	    (rx_pkt_type != PKT_TYPE_BAR)) {
		mlan_11n_rxreorder_pkt(priv, prx_pd->seq_num, prx_pd->priority,
				       ta, (t_u8)prx_pd->rx_pkt_type,
				       (t_void *)RX_PKT_DROPPED_IN_FW);
		if (rx_pkt_type == PKT_TYPE_AMSDU) {
			pmbuf->data_len = prx_pd->rx_pkt_length;
			pmbuf->data_offset += prx_pd->rx_pkt_offset;
			wlan_11n_deaggregate_pkt(priv, pmbuf);
		} else {
			wlan_process_rx_packet(pmadapter, pmbuf);
		}
		goto done;
	}

	/* Reorder and send to OS */
	ret = mlan_11n_rxreorder_pkt(priv, prx_pd->seq_num,
				     prx_pd->priority, ta,
				     (t_u8)prx_pd->rx_pkt_type, (void *)pmbuf);
	if (ret || (rx_pkt_type == PKT_TYPE_BAR)
		) {
		wlan_free_mlan_buffer(pmadapter, pmbuf);
	}

done:

	LEAVE();
	return ret;
}
