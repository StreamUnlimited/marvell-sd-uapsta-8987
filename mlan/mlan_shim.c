/** @file mlan_shim.c
 *
 *  @brief This file contains APIs to MOAL module.
 *
 *
 *  Copyright 2008-2021 NXP
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
    10/13/2008: initial version
********************************************************/

#include "mlan.h"
#ifdef STA_SUPPORT
#include "mlan_join.h"
#endif
#include "mlan_util.h"
#include "mlan_fw.h"
#include "mlan_main.h"
#include "mlan_wmm.h"
#include "mlan_sdio.h"
#ifdef UAP_SUPPORT
#include "mlan_uap.h"
#endif
#include "mlan_11h.h"
#include "mlan_11n_rxreorder.h"

/********************************************************
			Local Variables
********************************************************/

/********************************************************
			Global Variables
********************************************************/
#ifdef STA_SUPPORT
static mlan_operations mlan_sta_ops = {
	/* init cmd handler */
	wlan_ops_sta_init_cmd,
	/* ioctl handler */
	wlan_ops_sta_ioctl,
	/* cmd handler */
	wlan_ops_sta_prepare_cmd,
	/* cmdresp handler */
	wlan_ops_sta_process_cmdresp,
	/* rx handler */
	wlan_ops_sta_process_rx_packet,
	/* Event handler */
	wlan_ops_sta_process_event,
	/* txpd handler */
	wlan_ops_sta_process_txpd,
	/* BSS role: STA */
	MLAN_BSS_ROLE_STA,
};
#endif
#ifdef UAP_SUPPORT
static mlan_operations mlan_uap_ops = {
	/* init cmd handler */
	wlan_ops_uap_init_cmd,
	/* ioctl handler */
	wlan_ops_uap_ioctl,
	/* cmd handler */
	wlan_ops_uap_prepare_cmd,
	/* cmdresp handler */
	wlan_ops_uap_process_cmdresp,
	/* rx handler */
	wlan_ops_uap_process_rx_packet,
	/* Event handler */
	wlan_ops_uap_process_event,
	/* txpd handler */
	wlan_ops_uap_process_txpd,
	/* BSS role: uAP */
	MLAN_BSS_ROLE_UAP,
};
#endif

/** mlan function table */
mlan_operations *mlan_ops[] = {
#ifdef STA_SUPPORT
	&mlan_sta_ops,
#endif
#ifdef UAP_SUPPORT
	&mlan_uap_ops,
#endif
	MNULL,
};

/** Global moal_assert callback */
t_void (*assert_callback) (t_pvoid pmoal_handle, t_u32 cond) = MNULL;
#ifdef DEBUG_LEVEL1
#ifdef DEBUG_LEVEL2
#define DEFAULT_DEBUG_MASK (0xffffffff)
#else
#define DEFAULT_DEBUG_MASK (MMSG | MFATAL | MERROR)
#endif

/** Global moal_print callback */
t_void (*print_callback) (t_pvoid pmoal_handle, t_u32 level,
			  char *pformat, IN ...) = MNULL;

/** Global moal_get_system_time callback */
mlan_status (*get_sys_time_callback) (t_pvoid pmoal_handle, t_pu32 psec,
				      t_pu32 pusec) = MNULL;

/** Global driver debug mit masks */
t_u32 mlan_drvdbg = DEFAULT_DEBUG_MASK;
#endif

/********************************************************
			Local Functions
*******************************************************/
/**
 *  @brief This function process pending ioctl
 *
 *  @param pmadapter  A pointer to mlan_adapter structure
 *
 */
static void
wlan_process_pending_ioctl(mlan_adapter *pmadapter)
{
	pmlan_ioctl_req pioctl_buf;
	mlan_status status = MLAN_STATUS_SUCCESS;
	pmlan_callbacks pcb;
#if defined(STA_SUPPORT) && defined(UAP_SUPPORT)
	pmlan_ds_bss bss = MNULL;
#endif
#ifdef STA_SUPPORT
	pmlan_ds_misc_cfg misc = MNULL;
#endif
	ENTER();

	pcb = &pmadapter->callbacks;

	while ((pioctl_buf =
		(pmlan_ioctl_req)util_dequeue_list(pmadapter->pmoal_handle,
						   &pmadapter->ioctl_pending_q,
						   pcb->moal_spin_lock,
						   pcb->moal_spin_unlock))) {
		switch (pioctl_buf->req_id) {
#if defined(STA_SUPPORT) && defined(UAP_SUPPORT)
		case MLAN_IOCTL_BSS:
			bss = (mlan_ds_bss *)pioctl_buf->pbuf;
			if (bss->sub_command == MLAN_OID_BSS_ROLE) {
				PRINTM(MCMND, "Role switch ioctl: %d\n",
				       bss->param.bss_role);
				status = wlan_bss_ioctl_bss_role(pmadapter,
								 pioctl_buf);
			}
			break;
#endif
#ifdef STA_SUPPORT
		case MLAN_IOCTL_MISC_CFG:
			misc = (mlan_ds_misc_cfg *)pioctl_buf->pbuf;
			if (misc->sub_command == MLAN_OID_MISC_WARM_RESET) {
				PRINTM(MCMND, "Warm Reset ioctl\n");
				status = wlan_misc_ioctl_warm_reset(pmadapter,
								    pioctl_buf);
			}
			break;
#endif
		default:
			break;
		}
		if (status != MLAN_STATUS_PENDING)
			pcb->moal_ioctl_complete(pmadapter->pmoal_handle,
						 pioctl_buf, status);
	}
	LEAVE();
}

/********************************************************
			Global Functions
********************************************************/

/**
 *  @brief This function registers MOAL to MLAN module.
 *
 *  @param pmdevice        A pointer to a mlan_device structure
 *                         allocated in MOAL
 *  @param ppmlan_adapter  A pointer to a t_void pointer to store
 *                         mlan_adapter structure pointer as the context
 *
 *  @return                MLAN_STATUS_SUCCESS
 *                             The registration succeeded.
 *                         MLAN_STATUS_FAILURE
 *                             The registration failed.
 *
 * mlan_status mlan_register(
 *   pmlan_device     pmdevice,
 *   t_void           **ppmlan_adapter
 * );
 *
 * Comments
 *   MOAL constructs mlan_device data structure to pass moal_handle and
 *   mlan_callback table to MLAN. MLAN returns mlan_adapter pointer to
 *   the ppmlan_adapter buffer provided by MOAL.
 * Headers:
 *   declared in mlan_decl.h
 * See Also
 *   mlan_unregister
 */
mlan_status
mlan_register(pmlan_device pmdevice, t_void **ppmlan_adapter)
{
	mlan_status ret = MLAN_STATUS_SUCCESS;
	pmlan_adapter pmadapter = MNULL;
	pmlan_callbacks pcb = MNULL;
	t_u8 i = 0;
	t_u32 j = 0;

	if (!pmdevice || !ppmlan_adapter) {
		return MLAN_STATUS_FAILURE;
	}
	MASSERT(ppmlan_adapter);
	MASSERT(pmdevice->callbacks.moal_print);
#ifdef DEBUG_LEVEL1
	print_callback = pmdevice->callbacks.moal_print;
	get_sys_time_callback = pmdevice->callbacks.moal_get_system_time;
#endif
	assert_callback = pmdevice->callbacks.moal_assert;

	ENTER();

	MASSERT(pmdevice->callbacks.moal_malloc);
	MASSERT(pmdevice->callbacks.moal_mfree);
	MASSERT(pmdevice->callbacks.moal_memset);
	MASSERT(pmdevice->callbacks.moal_memmove);
	MASSERT(pmdevice->callbacks.moal_udelay);
	MASSERT(pmdevice->callbacks.moal_usleep_range);

	if (!pmdevice->callbacks.moal_malloc ||
	    !pmdevice->callbacks.moal_mfree ||
	    !pmdevice->callbacks.moal_memset ||
	    !pmdevice->callbacks.moal_udelay ||
	    !pmdevice->callbacks.moal_usleep_range ||
	    !pmdevice->callbacks.moal_memmove) {
		LEAVE();
		return MLAN_STATUS_FAILURE;
	}
	if (pmdevice->callbacks.moal_recv_amsdu_packet)
		PRINTM(MMSG, "Enable moal_recv_amsdu_packet\n");

	/* Allocate memory for adapter structure */
	if (pmdevice->callbacks.moal_vmalloc && pmdevice->callbacks.moal_vfree)
		ret = pmdevice->callbacks.moal_vmalloc(pmdevice->pmoal_handle,
						       sizeof(mlan_adapter),
						       (t_u8 **)&pmadapter);
	else
		ret = pmdevice->callbacks.moal_malloc(pmdevice->pmoal_handle,
						      sizeof(mlan_adapter),
						      MLAN_MEM_DEF,
						      (t_u8 **)&pmadapter);
	if ((ret != MLAN_STATUS_SUCCESS) || !pmadapter) {
		ret = MLAN_STATUS_FAILURE;
		goto exit_register;
	}

	pmdevice->callbacks.moal_memset(pmdevice->pmoal_handle, pmadapter, 0,
					sizeof(mlan_adapter));

	pcb = &pmadapter->callbacks;

	/* Save callback functions */
	pmdevice->callbacks.moal_memmove(pmadapter->pmoal_handle, pcb,
					 &pmdevice->callbacks,
					 sizeof(mlan_callbacks));

	/* Assertion for all callback functions */
	MASSERT(pcb->moal_get_hw_spec_complete);
	MASSERT(pcb->moal_init_fw_complete);
	MASSERT(pcb->moal_shutdown_fw_complete);
	MASSERT(pcb->moal_send_packet_complete);
	MASSERT(pcb->moal_recv_packet);
	MASSERT(pcb->moal_recv_event);
	MASSERT(pcb->moal_ioctl_complete);

	if (!IS_USB(pmadapter->card_type)) {
		MASSERT(pcb->moal_write_reg);
		MASSERT(pcb->moal_read_reg);
		MASSERT(pcb->moal_alloc_mlan_buffer);
		MASSERT(pcb->moal_free_mlan_buffer);
	}
	MASSERT(pcb->moal_write_data_sync);
	MASSERT(pcb->moal_read_data_sync);
	MASSERT(pcb->moal_mfree);
	MASSERT(pcb->moal_memcpy);
	MASSERT(pcb->moal_memcpy_ext);
	MASSERT(pcb->moal_memcmp);
	MASSERT(pcb->moal_get_system_time);
	MASSERT(pcb->moal_init_timer);
	MASSERT(pcb->moal_free_timer);
	MASSERT(pcb->moal_get_boot_ktime);
	MASSERT(pcb->moal_start_timer);
	MASSERT(pcb->moal_stop_timer);
	MASSERT(pcb->moal_init_lock);
	MASSERT(pcb->moal_free_lock);
	MASSERT(pcb->moal_spin_lock);
	MASSERT(pcb->moal_spin_unlock);
	MASSERT(pcb->moal_hist_data_add);
	MASSERT(pcb->moal_do_div);
	/* Save pmoal_handle */
	pmadapter->pmoal_handle = pmdevice->pmoal_handle;

	pmadapter->card_type = pmdevice->card_type;
	pmadapter->card_rev = pmdevice->card_rev;
	pmadapter->init_para.uap_max_sta = pmdevice->uap_max_sta;

	if (IS_SD(pmadapter->card_type)) {
		PRINTM(MMSG,
		       "Attach mlan adapter operations.card_type is 0x%x.\n",
		       pmdevice->card_type);
		memcpy_ext(pmadapter, &pmadapter->ops, &mlan_sdio_ops,
			   sizeof(mlan_adapter_operations),
			   sizeof(mlan_adapter_operations));
		ret = wlan_get_sdio_device(pmadapter);
		if (MLAN_STATUS_SUCCESS != ret) {
			ret = MLAN_STATUS_FAILURE;
			goto error;
		}
		if ((pmdevice->int_mode == INT_MODE_GPIO) &&
		    (pmdevice->gpio_pin == 0)) {
			PRINTM(MERROR,
			       "SDIO_GPIO_INT_CONFIG: Invalid GPIO Pin\n");
			ret = MLAN_STATUS_FAILURE;
			goto error;
		}
		pmadapter->init_para.int_mode = pmdevice->int_mode;
		pmadapter->init_para.gpio_pin = pmdevice->gpio_pin;
		/* card specific probing has been deferred until now .. */
		ret = wlan_sdio_probe(pmadapter);
		if (MLAN_STATUS_SUCCESS != ret) {
			ret = MLAN_STATUS_FAILURE;
			goto error;
		}
		pmadapter->pcard_sd->max_segs = pmdevice->max_segs;
		pmadapter->pcard_sd->max_seg_size = pmdevice->max_seg_size;

		pmadapter->init_para.mpa_tx_cfg = pmdevice->mpa_tx_cfg;
		pmadapter->init_para.mpa_rx_cfg = pmdevice->mpa_rx_cfg;
		pmadapter->pcard_sd->sdio_rx_aggr_enable =
			pmdevice->sdio_rx_aggr_enable;
	}

#ifdef DEBUG_LEVEL1
	mlan_drvdbg = pmdevice->drvdbg;
#endif

#ifdef MFG_CMD_SUPPORT
	pmadapter->init_para.mfg_mode = pmdevice->mfg_mode;
#endif
	pmadapter->init_para.auto_ds = pmdevice->auto_ds;
	pmadapter->init_para.ext_scan = pmdevice->ext_scan;
	pmadapter->init_para.ps_mode = pmdevice->ps_mode;
	if (pmdevice->max_tx_buf == MLAN_TX_DATA_BUF_SIZE_2K ||
	    pmdevice->max_tx_buf == MLAN_TX_DATA_BUF_SIZE_4K ||
	    pmdevice->max_tx_buf == MLAN_TX_DATA_BUF_SIZE_12K ||
	    pmdevice->max_tx_buf == MLAN_TX_DATA_BUF_SIZE_8K)
		pmadapter->init_para.max_tx_buf = pmdevice->max_tx_buf;
#ifdef STA_SUPPORT
	pmadapter->init_para.cfg_11d = pmdevice->cfg_11d;
#else
	pmadapter->init_para.cfg_11d = 0;
#endif
	pmadapter->init_para.dfs_master_radar_det_en =
		DFS_MASTER_RADAR_DETECT_EN;
	pmadapter->init_para.dfs_slave_radar_det_en = DFS_SLAVE_RADAR_DETECT_EN;
	pmadapter->init_para.dev_cap_mask = pmdevice->dev_cap_mask;
	pmadapter->init_para.indrstcfg = pmdevice->indrstcfg;
	pmadapter->rx_work_flag = pmdevice->rx_work;
	pmadapter->init_para.passive_to_active_scan =
		pmdevice->passive_to_active_scan;
	pmadapter->fixed_beacon_buffer = pmdevice->fixed_beacon_buffer;

	pmadapter->multiple_dtim = pmdevice->multi_dtim;
	pmadapter->inact_tmo = pmdevice->inact_tmo;
	pmadapter->init_para.drcs_chantime_mode = pmdevice->drcs_chantime_mode;
	pmadapter->hs_wake_interval = pmdevice->hs_wake_interval;
	if (pmdevice->indication_gpio != 0xff) {
		pmadapter->ind_gpio = pmdevice->indication_gpio & 0x0f;
		pmadapter->level = (pmdevice->indication_gpio & 0xf0) >> 4;
		if (pmadapter->level != 0 && pmadapter->level != 1) {
			PRINTM(MERROR,
			       "Indication GPIO level is wrong and will use default value 0.\n");
			pmadapter->level = 0;
		}
	}
	pmadapter->init_para.dfs53cfg = pmdevice->dfs53cfg;
	pmadapter->priv_num = 0;
	pmadapter->priv[0] = MNULL;

	if (pcb->moal_vmalloc && pcb->moal_vfree)
		ret = pcb->moal_vmalloc(pmadapter->pmoal_handle,
					sizeof(mlan_private),
					(t_u8 **)&pmadapter->priv[0]);
	else
		ret = pcb->moal_malloc(pmadapter->pmoal_handle,
				       sizeof(mlan_private), MLAN_MEM_DEF,
				       (t_u8 **)&pmadapter->priv[0]);
	if (ret != MLAN_STATUS_SUCCESS || !pmadapter->priv[0]) {
		ret = MLAN_STATUS_FAILURE;
		goto error;
	}

	pmadapter->priv_num++;
	memset(pmadapter, pmadapter->priv[0], 0, sizeof(mlan_private));

	pmadapter->priv[0]->adapter = pmadapter;
	if (pmdevice->drv_mode & DRV_MODE_MASK) {
		/* Save bss_type, frame_type & bss_priority */
		pmadapter->priv[0]->bss_type = 0xff;
		pmadapter->priv[0]->frame_type = MLAN_DATA_FRAME_TYPE_ETH_II;
		pmadapter->priv[0]->bss_priority = 0;
		pmadapter->priv[0]->bss_role = MLAN_BSS_ROLE_STA;

		/* Save bss_index and bss_num */
		pmadapter->priv[0]->bss_index = 0;
		pmadapter->priv[0]->bss_num = 0xff;
	} else {
		pmadapter->priv[0]->bss_type =
			(t_u8)pmdevice->bss_attr[0].bss_type;
		pmadapter->priv[0]->frame_type =
			(t_u8)pmdevice->bss_attr[0].frame_type;
		pmadapter->priv[0]->bss_priority =
			(t_u8)pmdevice->bss_attr[0].bss_priority;
		if (pmdevice->bss_attr[0].bss_type == MLAN_BSS_TYPE_STA)
			pmadapter->priv[0]->bss_role = MLAN_BSS_ROLE_STA;
		else if (pmdevice->bss_attr[0].bss_type == MLAN_BSS_TYPE_UAP)
			pmadapter->priv[0]->bss_role = MLAN_BSS_ROLE_UAP;
		else if (pmdevice->bss_attr[0].bss_type ==
			 MLAN_BSS_TYPE_WIFIDIRECT) {
			pmadapter->priv[0]->bss_role = MLAN_BSS_ROLE_STA;
			if (pmdevice->bss_attr[0].bss_virtual)
				pmadapter->priv[0]->bss_virtual = MTRUE;
		}
		/* Save bss_index and bss_num */
		pmadapter->priv[0]->bss_index = 0;
		pmadapter->priv[0]->bss_num =
			(t_u8)pmdevice->bss_attr[0].bss_num;
	}

	/* init function table */
	for (j = 0; mlan_ops[j]; j++) {
		if (mlan_ops[j]->bss_role == GET_BSS_ROLE(pmadapter->priv[0])) {
			memcpy_ext(pmadapter, &pmadapter->priv[0]->ops,
				   mlan_ops[j], sizeof(mlan_operations),
				   sizeof(mlan_operations));
			break;
		}
	}
	/** back up bss_attr table */
	memcpy_ext(pmadapter, pmadapter->bss_attr, pmdevice->bss_attr,
		   sizeof(pmadapter->bss_attr), sizeof(pmadapter->bss_attr));

	/* Initialize lock variables */
	if (wlan_init_lock_list(pmadapter) != MLAN_STATUS_SUCCESS) {
		ret = MLAN_STATUS_FAILURE;
		goto error;
	}

	/** init lock varible for first priv */
	if (wlan_init_priv_lock_list(pmadapter, 0) != MLAN_STATUS_SUCCESS) {
		ret = MLAN_STATUS_FAILURE;
		goto error;
	}

	/* Allocate memory for member of adapter structure */
	if (wlan_allocate_adapter(pmadapter)) {
		ret = MLAN_STATUS_FAILURE;
		goto error;
	}

	/* Initialize timers */
	if (wlan_init_timer(pmadapter) != MLAN_STATUS_SUCCESS) {
		ret = MLAN_STATUS_FAILURE;
		goto error;
	}
	/* Return pointer of mlan_adapter to MOAL */
	*ppmlan_adapter = pmadapter;

	goto exit_register;

error:
	PRINTM(MINFO, "Leave mlan_register with error\n");
	/* Free adapter structure */
	wlan_free_adapter(pmadapter);

	for (i = 0; i < MLAN_MAX_BSS_NUM; i++) {
		if (pmadapter->priv[i]) {
			if (pcb->moal_vmalloc && pcb->moal_vfree)
				pcb->moal_vfree(pmadapter->pmoal_handle,
						(t_u8 *)pmadapter->priv[i]);
			else if (pcb->moal_mfree)
				pcb->moal_mfree(pmadapter->pmoal_handle,
						(t_u8 *)pmadapter->priv[i]);
		}
	}
	if (pcb->moal_vmalloc && pcb->moal_vfree)
		pcb->moal_vfree(pmadapter->pmoal_handle, (t_u8 *)pmadapter);
	else if (pcb->moal_mfree)
		pcb->moal_mfree(pmadapter->pmoal_handle, (t_u8 *)pmadapter);

exit_register:
	LEAVE();
	return ret;
}

/**
 *  @brief This function unregisters MOAL from MLAN module.
 *
 *  @param padapter  A pointer to a mlan_device structure
 *                         allocated in MOAL
 *
 *  @return                MLAN_STATUS_SUCCESS
 *                             The deregistration succeeded.
 */
mlan_status
mlan_unregister(t_void *padapter)
{
	mlan_status ret = MLAN_STATUS_SUCCESS;
	mlan_adapter *pmadapter = (mlan_adapter *)padapter;
	pmlan_callbacks pcb;
	t_s32 i = 0;

	MASSERT(padapter);

	ENTER();

	pcb = &pmadapter->callbacks;

	/* Free adapter structure */
	wlan_free_adapter(pmadapter);

	/* Free private structures */
	for (i = 0; i < pmadapter->priv_num; i++) {
		if (pmadapter->priv[i]) {
			if (pcb->moal_vmalloc && pcb->moal_vfree)
				pcb->moal_vfree(pmadapter->pmoal_handle,
						(t_u8 *)pmadapter->priv[i]);
			else if (pcb->moal_mfree)
				pcb->moal_mfree(pmadapter->pmoal_handle,
						(t_u8 *)pmadapter->priv[i]);
		}
	}

	/* Free mlan_adapter */
	if (pcb->moal_vmalloc && pcb->moal_vfree)
		pcb->moal_vfree(pmadapter->pmoal_handle, (t_u8 *)pmadapter);
	else if (pcb->moal_mfree)
		pcb->moal_mfree(pmadapter->pmoal_handle, (t_u8 *)pmadapter);

	LEAVE();
	return ret;
}

/**
 *  @brief This function downloads the firmware
 *
 *  @param padapter   A pointer to a t_void pointer to store
 *                         mlan_adapter structure pointer
 *  @param pmfw            A pointer to firmware image
 *
 *  @return                MLAN_STATUS_SUCCESS
 *                             The firmware download succeeded.
 *                         MLAN_STATUS_FAILURE
 *                             The firmware download failed.
 */
mlan_status
mlan_dnld_fw(t_void *padapter, pmlan_fw_image pmfw)
{
	mlan_status ret = MLAN_STATUS_FAILURE;
	mlan_adapter *pmadapter = (mlan_adapter *)padapter;

	ENTER();
	MASSERT(padapter);

	/* Download helper/firmware */
	if (pmfw) {
		ret = pmadapter->ops.dnld_fw(pmadapter, pmfw);
		if (ret != MLAN_STATUS_SUCCESS) {
			PRINTM(MERROR, "wlan_dnld_fw fail ret=0x%x\n", ret);
			LEAVE();
			return ret;
		}
	}

	LEAVE();
	return ret;
}

/**
 *  @brief This function mask host interrupt from firmware
 *
 *  @param padapter   A pointer to a t_void pointer to store
 *                         mlan_adapter structure pointer
 *
 *  @return                MLAN_STATUS_SUCCESS
 *                             The firmware download succeeded.
 *                         MLAN_STATUS_FAILURE
 *                             The firmware download failed.
 */
mlan_status
mlan_disable_host_int(t_void *padapter)
{
	mlan_status ret = MLAN_STATUS_FAILURE;
	mlan_adapter *pmadapter = (mlan_adapter *)padapter;

	ENTER();
	MASSERT(padapter);

	/* mask host interrupt from firmware */
	if (pmadapter->ops.disable_host_int) {
		ret = pmadapter->ops.disable_host_int(pmadapter);
		if (ret != MLAN_STATUS_SUCCESS) {
			PRINTM(MERROR,
			       "mlan_disable_host_int fail ret = 0x%x\n", ret);
			LEAVE();
			return ret;
		}
	}

	LEAVE();
	return ret;
}

/**
 *  @brief This function unmask host interrupt from firmware
 *
 *  @param padapter   A pointer to a t_void pointer to store
 *                         mlan_adapter structure pointer
 *
 *  @return                MLAN_STATUS_SUCCESS
 *                             The firmware download succeeded.
 *                         MLAN_STATUS_FAILURE
 *                             The firmware download failed.
 */
mlan_status
mlan_enable_host_int(t_void *padapter)
{
	mlan_status ret = MLAN_STATUS_FAILURE;
	mlan_adapter *pmadapter = (mlan_adapter *)padapter;

	ENTER();
	MASSERT(padapter);

	/* unmask host interrupt from firmware */
	if (pmadapter->ops.enable_host_int) {
		ret = pmadapter->ops.enable_host_int(pmadapter);
		if (ret != MLAN_STATUS_SUCCESS) {
			PRINTM(MERROR, "mlan_enable_host_int fail ret = 0x%x\n",
			       ret);
			LEAVE();
			return ret;
		}
	}

	LEAVE();
	return ret;
}

/**
 *  @brief This function pass init param to MLAN
 *
 *  @param padapter  A pointer to a t_void pointer to store
 *                        mlan_adapter structure pointer
 *  @param pparam         A pointer to mlan_init_param structure
 *
 *  @return               MLAN_STATUS_SUCCESS
 *
 */
mlan_status
mlan_set_init_param(t_void *padapter, pmlan_init_param pparam)
{
	mlan_status ret = MLAN_STATUS_SUCCESS;
	mlan_adapter *pmadapter = (mlan_adapter *)padapter;

	ENTER();
	MASSERT(padapter);

	/** Save DPD data in MLAN */
	if ((pparam->pdpd_data_buf) || (pparam->dpd_data_len > 0)) {
		pmadapter->pdpd_data = pparam->pdpd_data_buf;
		pmadapter->dpd_data_len = pparam->dpd_data_len;
	}
	if (pparam->ptxpwr_data_buf && (pparam->txpwr_data_len > 0)) {
		pmadapter->ptxpwr_data = pparam->ptxpwr_data_buf;
		pmadapter->txpwr_data_len = pparam->txpwr_data_len;
	}
	/** Save cal data in MLAN */
	if ((pparam->pcal_data_buf) && (pparam->cal_data_len > 0)) {
		pmadapter->pcal_data = pparam->pcal_data_buf;
		pmadapter->cal_data_len = pparam->cal_data_len;
	}

	LEAVE();
	return ret;
}

/**
 *  @brief This function initializes the firmware
 *
 *  @param padapter   A pointer to a t_void pointer to store
 *                         mlan_adapter structure pointer
 *
 *  @return                MLAN_STATUS_SUCCESS
 *                             The firmware initialization succeeded.
 *                         MLAN_STATUS_PENDING
 *                             The firmware initialization is pending.
 *                         MLAN_STATUS_FAILURE
 *                             The firmware initialization failed.
 */
mlan_status
mlan_init_fw(t_void *padapter)
{
	mlan_status ret = MLAN_STATUS_SUCCESS;
	mlan_adapter *pmadapter = (mlan_adapter *)padapter;

	ENTER();
	MASSERT(padapter);

	pmadapter->hw_status = WlanHardwareStatusGetHwSpec;

	/* Initialize firmware, may return PENDING */
	ret = wlan_init_fw(pmadapter);
	PRINTM(MINFO, "wlan_init_fw returned ret=0x%x\n", ret);

	LEAVE();
	return ret;
}

/**
 *  @brief Shutdown firmware
 *
 *  @param padapter    A pointer to mlan_adapter structure
 *
 *  @return     MLAN_STATUS_SUCCESS
 *                              The firmware shutdown call succeeded.
 *              MLAN_STATUS_PENDING
 *                              The firmware shutdown call is pending.
 *              MLAN_STATUS_FAILURE
 *                              The firmware shutdown call failed.
 */
mlan_status
mlan_shutdown_fw(t_void *padapter)
{
	mlan_status ret = MLAN_STATUS_PENDING;
	mlan_adapter *pmadapter = (mlan_adapter *)padapter;
	pmlan_buffer pmbuf;
	pmlan_ioctl_req pioctl_buf;
	pmlan_callbacks pcb;
	t_s32 i = 0;

	ENTER();

	MASSERT(padapter);
	/* MLAN already shutdown */
	if (pmadapter->hw_status == WlanHardwareStatusNotReady) {
		LEAVE();
		return MLAN_STATUS_SUCCESS;
	}

	pmadapter->hw_status = WlanHardwareStatusClosing;
	/* Wait for mlan_process to complete */
	if (pmadapter->mlan_processing) {
		PRINTM(MWARN, "MLAN main processing is still running\n");
		LEAVE();
		return ret;
	}

	/* Shut down MLAN */
	PRINTM(MINFO, "Shutdown MLAN...\n");

	/* Cancel all pending commands and complete ioctls */
	wlan_cancel_all_pending_cmd(pmadapter, MTRUE);

	/* Clean up priv structures */
	for (i = 0; i < pmadapter->priv_num; i++) {
		if (pmadapter->priv[i])
			wlan_free_priv(pmadapter->priv[i]);
	}

	pcb = &pmadapter->callbacks;
	/** cancel pending ioctl */
	while ((pioctl_buf =
		(pmlan_ioctl_req)util_dequeue_list(pmadapter->pmoal_handle,
						   &pmadapter->ioctl_pending_q,
						   pcb->moal_spin_lock,
						   pcb->moal_spin_unlock))) {
		pioctl_buf->status_code = MLAN_ERROR_CMD_CANCEL;
		pcb->moal_ioctl_complete(pmadapter->pmoal_handle, pioctl_buf,
					 MLAN_STATUS_FAILURE);
	}

	while ((pmbuf =
		(pmlan_buffer)util_dequeue_list(pmadapter->pmoal_handle,
						&pmadapter->rx_data_queue,
						pcb->moal_spin_lock,
						pcb->moal_spin_unlock))) {
		if (!IS_USB(pmadapter->card_type))
			wlan_free_mlan_buffer(pmadapter, pmbuf);
	}
	pmadapter->rx_pkts_queued = 0;

	/* Notify completion */
	ret = wlan_shutdown_fw_complete(pmadapter);

	LEAVE();
	return ret;
}

/**
 *  @brief queue main work
 *
 *  @param pmadapter	A pointer to mlan_adapter structure
 *
 *  @return			N/A
 */
static t_void
mlan_queue_main_work(mlan_adapter *pmadapter)
{
	pmlan_callbacks pcb = &pmadapter->callbacks;
	ENTER();
	pcb->moal_spin_lock(pmadapter->pmoal_handle,
			    pmadapter->pmain_proc_lock);

	/* Check if already processing */
	if (pmadapter->mlan_processing) {
		pmadapter->more_task_flag = MTRUE;
		pcb->moal_spin_unlock(pmadapter->pmoal_handle,
				      pmadapter->pmain_proc_lock);
	} else {
		pcb->moal_spin_unlock(pmadapter->pmoal_handle,
				      pmadapter->pmain_proc_lock);
		wlan_recv_event(wlan_get_priv(pmadapter, MLAN_BSS_ROLE_ANY),
				MLAN_EVENT_ID_DRV_DEFER_HANDLING, MNULL);
	}
	LEAVE();
	return;
}

/**
 *  @brief queue rx_work
 *
 *  @param pmadapter	A pointer to mlan_adapter structure
 *
 *  @return			N/A
 */
static t_void
mlan_queue_rx_work(mlan_adapter *pmadapter)
{
	pmlan_callbacks pcb = &pmadapter->callbacks;
	ENTER();

	pcb->moal_spin_lock(pmadapter->pmoal_handle, pmadapter->prx_proc_lock);

	/* Check if already processing */
	if (pmadapter->mlan_rx_processing) {
		pmadapter->more_rx_task_flag = MTRUE;
		pcb->moal_spin_unlock(pmadapter->pmoal_handle,
				      pmadapter->prx_proc_lock);
	} else {
		pcb->moal_spin_unlock(pmadapter->pmoal_handle,
				      pmadapter->prx_proc_lock);
		wlan_recv_event(wlan_get_priv(pmadapter, MLAN_BSS_ROLE_ANY),
				MLAN_EVENT_ID_DRV_DEFER_RX_WORK, MNULL);
	}
	LEAVE();
	return;
}

/**
 *  @brief block main process
 *
 *  @param pmadapter	A pointer to mlan_adapter structure
 *  @param block            MTRUE/MFALSE
 *
 *  @return			N/A
 */
void
mlan_block_main_process(mlan_adapter *pmadapter, t_u8 block)
{
	pmlan_callbacks pcb = &pmadapter->callbacks;
	pcb->moal_spin_lock(pmadapter->pmoal_handle,
			    pmadapter->pmain_proc_lock);
	if (!block) {
		pmadapter->main_lock_flag = MFALSE;
		pcb->moal_spin_unlock(pmadapter->pmoal_handle,
				      pmadapter->pmain_proc_lock);
	} else {
		pmadapter->main_lock_flag = MTRUE;
		if (pmadapter->mlan_processing) {
			pcb->moal_spin_unlock(pmadapter->pmoal_handle,
					      pmadapter->pmain_proc_lock);
			PRINTM(MEVENT, "wlan: wait main work done...\n");
			wlan_recv_event(wlan_get_priv
					(pmadapter, MLAN_BSS_ROLE_ANY),
					MLAN_EVENT_ID_DRV_FLUSH_MAIN_WORK,
					MNULL);
		} else {
			pcb->moal_spin_unlock(pmadapter->pmoal_handle,
					      pmadapter->pmain_proc_lock);
		}
	}
}

/**
 *  @brief block rx process
 *
 *  @param pmadapter	A pointer to mlan_adapter structure
 *  @param block            MTRUE/MFALSE;
 *
 *  @return			N/A
 */
void
mlan_block_rx_process(mlan_adapter *pmadapter, t_u8 block)
{
	pmlan_callbacks pcb = &pmadapter->callbacks;
	pcb->moal_spin_lock(pmadapter->pmoal_handle, pmadapter->prx_proc_lock);
	if (!block) {
		pmadapter->rx_lock_flag = MFALSE;
		pcb->moal_spin_unlock(pmadapter->pmoal_handle,
				      pmadapter->prx_proc_lock);
	} else {
		pmadapter->rx_lock_flag = MTRUE;
		if (pmadapter->mlan_rx_processing) {
			pcb->moal_spin_unlock(pmadapter->pmoal_handle,
					      pmadapter->prx_proc_lock);
			PRINTM(MEVENT, "wlan: wait rx work done...\n");
			wlan_recv_event(wlan_get_priv(pmadapter,
						      MLAN_BSS_ROLE_ANY),
					MLAN_EVENT_ID_DRV_FLUSH_RX_WORK, MNULL);
		} else {
			pcb->moal_spin_unlock(pmadapter->pmoal_handle,
					      pmadapter->prx_proc_lock);
		}
	}
}

/**
 *  @brief The receive process
 *
 *  @param padapter	A pointer to mlan_adapter structure
 *  @param rx_pkts              A pointer to save receive pkts number
 *
 *  @return			MLAN_STATUS_SUCCESS or MLAN_STATUS_FAILURE
 */
mlan_status
mlan_rx_process(t_void *padapter, t_u8 *rx_pkts)
{
	mlan_status ret = MLAN_STATUS_SUCCESS;
	mlan_adapter *pmadapter = (mlan_adapter *)padapter;
	pmlan_callbacks pcb;
	pmlan_buffer pmbuf;
	t_u8 limit = 0;
	t_u8 rx_num = 0;

	ENTER();

	MASSERT(padapter);
	pcb = &pmadapter->callbacks;
	pcb->moal_spin_lock(pmadapter->pmoal_handle, pmadapter->prx_proc_lock);
	if (pmadapter->mlan_rx_processing || pmadapter->rx_lock_flag) {
		pmadapter->more_rx_task_flag = MTRUE;
		pcb->moal_spin_unlock(pmadapter->pmoal_handle,
				      pmadapter->prx_proc_lock);
		goto exit_rx_proc;
	} else {
		pmadapter->mlan_rx_processing = MTRUE;
		pcb->moal_spin_unlock(pmadapter->pmoal_handle,
				      pmadapter->prx_proc_lock);
	}
	if (rx_pkts)
		limit = *rx_pkts;

rx_process_start:
	/* Check for Rx data */
	while (MTRUE) {
		if (pmadapter->flush_data) {
			pmadapter->flush_data = MFALSE;
			wlan_flush_rxreorder_tbl(pmadapter);
		}
		pmadapter->callbacks.moal_spin_lock(pmadapter->pmoal_handle,
						    pmadapter->rx_data_queue.
						    plock);
		pmbuf = (pmlan_buffer)util_dequeue_list(pmadapter->pmoal_handle,
							&pmadapter->
							rx_data_queue, MNULL,
							MNULL);
		if (!pmbuf) {
			pmadapter->callbacks.moal_spin_unlock(pmadapter->
							      pmoal_handle,
							      pmadapter->
							      rx_data_queue.
							      plock);
			break;
		}
		pmadapter->rx_pkts_queued--;
		rx_num++;
		pmadapter->callbacks.moal_spin_unlock(pmadapter->pmoal_handle,
						      pmadapter->rx_data_queue.
						      plock);

		if (pmadapter->delay_task_flag &&
		    (pmadapter->rx_pkts_queued < LOW_RX_PENDING)) {
			PRINTM(MEVENT, "Run\n");
			pmadapter->delay_task_flag = MFALSE;
			mlan_queue_main_work(pmadapter);
		}
		pmadapter->ops.handle_rx_packet(pmadapter, pmbuf);
		if (limit && rx_num >= limit)
			break;
	}
	if (rx_pkts)
		*rx_pkts = rx_num;
	pcb->moal_spin_lock(pmadapter->pmoal_handle, pmadapter->prx_proc_lock);
	if (pmadapter->more_rx_task_flag) {
		pmadapter->more_rx_task_flag = MFALSE;
		pcb->moal_spin_unlock(pmadapter->pmoal_handle,
				      pmadapter->prx_proc_lock);
		goto rx_process_start;
	}
	pmadapter->mlan_rx_processing = MFALSE;
	pcb->moal_spin_unlock(pmadapter->pmoal_handle,
			      pmadapter->prx_proc_lock);
exit_rx_proc:
	LEAVE();
	return ret;
}

/**
 *  @brief The main process
 *
 *  @param padapter	A pointer to mlan_adapter structure
 *
 *  @return			MLAN_STATUS_SUCCESS or MLAN_STATUS_FAILURE
 */
mlan_status
mlan_main_process(t_void *padapter)
{
	mlan_status ret = MLAN_STATUS_SUCCESS;
	mlan_adapter *pmadapter = (mlan_adapter *)padapter;
	pmlan_callbacks pcb;

	ENTER();

	MASSERT(padapter);

	pcb = &pmadapter->callbacks;

	pcb->moal_spin_lock(pmadapter->pmoal_handle,
			    pmadapter->pmain_proc_lock);

	/* Check if already processing */
	if (pmadapter->mlan_processing || pmadapter->main_lock_flag) {
		pmadapter->more_task_flag = MTRUE;
		pcb->moal_spin_unlock(pmadapter->pmoal_handle,
				      pmadapter->pmain_proc_lock);
		goto exit_main_proc;
	} else {
		pmadapter->mlan_processing = MTRUE;
		pmadapter->main_process_cnt++;
		pcb->moal_spin_unlock(pmadapter->pmoal_handle,
				      pmadapter->pmain_proc_lock);
	}
process_start:
	do {
		/* Is MLAN shutting down or not ready? */
		if ((pmadapter->hw_status == WlanHardwareStatusClosing) ||
		    (pmadapter->hw_status == WlanHardwareStatusNotReady))
			break;
		if (pmadapter->pending_ioctl) {
			wlan_process_pending_ioctl(pmadapter);
			pmadapter->pending_ioctl = MFALSE;
		}
		if (pmadapter->pending_disconnect_priv) {
			PRINTM(MEVENT, "Reset connect state\n");
			wlan_reset_connect_state(pmadapter->
						 pending_disconnect_priv,
						 MTRUE);
			pmadapter->pending_disconnect_priv = MNULL;
		}
		if (!IS_USB(pmadapter->card_type)) {
			if (pmadapter->rx_pkts_queued > HIGH_RX_PENDING) {
				PRINTM(MEVENT, "Pause\n");
				pmadapter->delay_task_flag = MTRUE;
				mlan_queue_rx_work(pmadapter);
				break;
			}
			/* Handle pending interrupts if any */
			if (pmadapter->ireg) {
				if (pmadapter->hs_activated == MTRUE)
					wlan_process_hs_config(pmadapter);
				pmadapter->ops.process_int_status(pmadapter);
				if (pmadapter->data_received)
					mlan_queue_rx_work(pmadapter);
			}
		}

		/* Need to wake up the card ? */
		if ((pmadapter->ps_state == PS_STATE_SLEEP) &&
		    (pmadapter->pm_wakeup_card_req &&
		     !pmadapter->pm_wakeup_fw_try) &&
		    (wlan_is_cmd_pending(pmadapter) ||
		     !wlan_bypass_tx_list_empty(pmadapter) ||
		     !wlan_wmm_lists_empty(pmadapter))) {
			pmadapter->ops.wakeup_card(pmadapter, MTRUE);
			pmadapter->pm_wakeup_fw_try = MTRUE;
			continue;
		}
		if (IS_CARD_RX_RCVD(pmadapter)
			) {
			pmadapter->data_received = MFALSE;
			if (pmadapter->hs_activated == MTRUE) {
				pmadapter->is_hs_configured = MFALSE;
				wlan_host_sleep_activated_event(wlan_get_priv
								(pmadapter,
								 MLAN_BSS_ROLE_ANY),
								MFALSE);
			}
			pmadapter->pm_wakeup_fw_try = MFALSE;
			if (pmadapter->ps_state == PS_STATE_SLEEP)
				pmadapter->ps_state = PS_STATE_AWAKE;
			if (pmadapter->wakeup_fw_timer_is_set) {
				pcb->moal_stop_timer(pmadapter->pmoal_handle,
						     pmadapter->
						     pwakeup_fw_timer);
				pmadapter->wakeup_fw_timer_is_set = MFALSE;
			}
		} else {
			/* We have tried to wakeup the card already */
			if (pmadapter->pm_wakeup_fw_try)
				break;
			/* Check if we need to confirm Sleep Request received
			 * previously */
			if (pmadapter->ps_state == PS_STATE_PRE_SLEEP)
				if (!pmadapter->cmd_sent &&
				    !pmadapter->curr_cmd)
					wlan_check_ps_cond(pmadapter);
			if (pmadapter->ps_state != PS_STATE_AWAKE ||
			    (pmadapter->tx_lock_flag == MTRUE))
				break;

			if (pmadapter->data_sent
			    || (wlan_bypass_tx_list_empty(pmadapter) &&
				wlan_wmm_lists_empty(pmadapter))
			    || wlan_11h_radar_detected_tx_blocked(pmadapter)
				) {
				if (pmadapter->cmd_sent ||
				    pmadapter->curr_cmd ||
				    !wlan_is_cmd_pending(pmadapter)) {
					break;
				}
			}
		}

		/* Check for Cmd Resp */
		if (pmadapter->cmd_resp_received) {
			pmadapter->cmd_resp_received = MFALSE;
			wlan_process_cmdresp(pmadapter);

			/* call moal back when init_fw is done */
			if (pmadapter->hw_status == WlanHardwareStatusInitdone) {
				pmadapter->hw_status = WlanHardwareStatusReady;
				wlan_init_fw_complete(pmadapter);
			} else if (pmadapter->hw_status ==
				   WlanHardwareStatusGetHwSpecdone) {
				pmadapter->hw_status =
					WlanHardwareStatusInitializing;
				wlan_get_hw_spec_complete(pmadapter);
			}
		}

		/* Check for event */
		if (pmadapter->event_received) {
			pmadapter->event_received = MFALSE;
			wlan_process_event(pmadapter);
		}

		/* Check if we need to confirm Sleep Request received previously
		 */
		if (pmadapter->ps_state == PS_STATE_PRE_SLEEP)
			if (!pmadapter->cmd_sent && !pmadapter->curr_cmd)
				wlan_check_ps_cond(pmadapter);

		/*
		 * The ps_state may have been changed during processing of
		 * Sleep Request event.
		 */
		if ((pmadapter->ps_state == PS_STATE_SLEEP) ||
		    (pmadapter->ps_state == PS_STATE_PRE_SLEEP)
		    || (pmadapter->ps_state == PS_STATE_SLEEP_CFM) ||
		    (pmadapter->tx_lock_flag == MTRUE)
			) {
			continue;
		}

		if (!pmadapter->cmd_sent && !pmadapter->curr_cmd) {
			if (wlan_exec_next_cmd(pmadapter) ==
			    MLAN_STATUS_FAILURE) {
				ret = MLAN_STATUS_FAILURE;
				break;
			}
		}

		if (!pmadapter->data_sent &&
		    !wlan_11h_radar_detected_tx_blocked(pmadapter) &&
		    !wlan_bypass_tx_list_empty(pmadapter)) {
			PRINTM(MINFO, "mlan_send_pkt(): deq(bybass_txq)\n");
			wlan_process_bypass_tx(pmadapter);
			if (pmadapter->hs_activated == MTRUE) {
				pmadapter->is_hs_configured = MFALSE;
				wlan_host_sleep_activated_event(wlan_get_priv
								(pmadapter,
								 MLAN_BSS_ROLE_ANY),
								MFALSE);
			}
		}

		if (!pmadapter->data_sent && !wlan_wmm_lists_empty(pmadapter)
		    && !wlan_11h_radar_detected_tx_blocked(pmadapter)
			) {
			wlan_wmm_process_tx(pmadapter);
			if (pmadapter->hs_activated == MTRUE) {
				pmadapter->is_hs_configured = MFALSE;
				wlan_host_sleep_activated_event(wlan_get_priv
								(pmadapter,
								 MLAN_BSS_ROLE_ANY),
								MFALSE);
			}
		}
#ifdef STA_SUPPORT
		if (pmadapter->delay_null_pkt && !pmadapter->cmd_sent &&
		    !pmadapter->curr_cmd && !wlan_is_cmd_pending(pmadapter) &&
		    wlan_bypass_tx_list_empty(pmadapter) &&
		    wlan_wmm_lists_empty(pmadapter)) {
			if (wlan_send_null_packet
			    (wlan_get_priv(pmadapter, MLAN_BSS_ROLE_STA),
			     MRVDRV_TxPD_POWER_MGMT_NULL_PACKET |
			     MRVDRV_TxPD_POWER_MGMT_LAST_PACKET) ==
			    MLAN_STATUS_SUCCESS) {
				pmadapter->delay_null_pkt = MFALSE;
			}
			break;
		}
#endif

	} while (MTRUE);

	pcb->moal_spin_lock(pmadapter->pmoal_handle,
			    pmadapter->pmain_proc_lock);
	if (pmadapter->more_task_flag == MTRUE) {
		pmadapter->more_task_flag = MFALSE;
		pcb->moal_spin_unlock(pmadapter->pmoal_handle,
				      pmadapter->pmain_proc_lock);
		goto process_start;
	}
	pmadapter->mlan_processing = MFALSE;
	pcb->moal_spin_unlock(pmadapter->pmoal_handle,
			      pmadapter->pmain_proc_lock);

exit_main_proc:
	if (pmadapter->hw_status == WlanHardwareStatusClosing)
		mlan_shutdown_fw(pmadapter);
	LEAVE();
	return ret;
}

/**
 *  @brief Function to send packet
 *
 *  @param padapter	A pointer to mlan_adapter structure
 *  @param pmbuf		A pointer to mlan_buffer structure
 *
 *  @return			MLAN_STATUS_PENDING
 */
mlan_status
mlan_send_packet(t_void *padapter, pmlan_buffer pmbuf)
{
	mlan_status ret = MLAN_STATUS_PENDING;
	mlan_adapter *pmadapter = (mlan_adapter *)padapter;
	mlan_private *pmpriv;
	t_u16 eth_type = 0;

	ENTER();
	MASSERT(padapter && pmbuf);

	if (!padapter || !pmbuf) {
		return MLAN_STATUS_FAILURE;
	}

	MASSERT(pmbuf->bss_index < pmadapter->priv_num);
	pmbuf->flags |= MLAN_BUF_FLAG_MOAL_TX_BUF;
	pmpriv = pmadapter->priv[pmbuf->bss_index];

	eth_type = mlan_ntohs(*(t_u16 *)&pmbuf->pbuf[pmbuf->data_offset +
						     MLAN_ETHER_PKT_TYPE_OFFSET]);
	if (((pmadapter->priv[pmbuf->bss_index]->port_ctrl_mode == MTRUE) &&
	     ((eth_type == MLAN_ETHER_PKT_TYPE_EAPOL)
	      || (eth_type == MLAN_ETHER_PKT_TYPE_ARP)
	      || (eth_type == MLAN_ETHER_PKT_TYPE_WAPI)
	     ))
	    || (pmbuf->buf_type == MLAN_BUF_TYPE_RAW_DATA)

		) {
		if (eth_type == MLAN_ETHER_PKT_TYPE_EAPOL) {
			PRINTM_NETINTF(MMSG, pmpriv);
			PRINTM(MMSG, "wlan: Send EAPOL pkt to " MACSTR "\n",
			       MAC2STR(pmbuf->pbuf + pmbuf->data_offset));
		}
		wlan_add_buf_bypass_txqueue(pmadapter, pmbuf);
	} else {
		/* Transmit the packet */
		wlan_wmm_add_buf_txqueue(pmadapter, pmbuf);
	}

	LEAVE();
	return ret;
}

/**
 *  @brief MLAN ioctl handler
 *
 *  @param adapter	A pointer to mlan_adapter structure
 *  @param pioctl_req	A pointer to ioctl request buffer
 *
 *  @return		MLAN_STATUS_SUCCESS/MLAN_STATUS_PENDING --success,
 * otherwise fail
 */
mlan_status
mlan_ioctl(t_void *adapter, pmlan_ioctl_req pioctl_req)
{
	mlan_status ret = MLAN_STATUS_SUCCESS;
	pmlan_adapter pmadapter = (pmlan_adapter)adapter;
	pmlan_private pmpriv = MNULL;

	ENTER();

	if (pioctl_req == MNULL) {
		PRINTM(MMSG, "Cancel all pending cmd!\n");
		wlan_cancel_all_pending_cmd(pmadapter, MFALSE);
		goto exit;
	}
	if (pioctl_req->action == MLAN_ACT_CANCEL) {
		wlan_cancel_pending_ioctl(pmadapter, pioctl_req);
		ret = MLAN_STATUS_SUCCESS;
		goto exit;
	}
	pmpriv = pmadapter->priv[pioctl_req->bss_index];
	ret = pmpriv->ops.ioctl(adapter, pioctl_req);
exit:
	LEAVE();
	return ret;
}

/**
 *  @brief Packet receive completion callback handler
 *
 *  @param padapter	A pointer to mlan_adapter structure
 *  @param pmbuf		A pointer to mlan_buffer structure
 *  @param status		Callback status
 *
 *  @return			MLAN_STATUS_SUCCESS
 */
mlan_status
mlan_recv_packet_complete(t_void *padapter,
			  pmlan_buffer pmbuf, mlan_status status)
{
	mlan_adapter *pmadapter = (mlan_adapter *)padapter;

	ENTER();
	wlan_recv_packet_complete(pmadapter, pmbuf, status);
	LEAVE();
	return MLAN_STATUS_SUCCESS;
}

/**
 *  @brief select wmm queue
 *
 *  @param padapter	A pointer to mlan_adapter structure
 *  @param bss_num		BSS number
 *  @param tid			TID
 *
 *  @return			wmm queue priority (0 - 3)
 */
t_u8
mlan_select_wmm_queue(t_void *padapter, t_u8 bss_num, t_u8 tid)
{
	mlan_adapter *pmadapter = (mlan_adapter *)padapter;
	pmlan_private pmpriv = pmadapter->priv[bss_num];
	t_u8 ret;
	ENTER();
	ret = wlan_wmm_select_queue(pmpriv, tid);
	LEAVE();
	return ret;
}

/**
 *  @brief this function handle the amsdu packet after deaggreate.
 *
 *  @param padapter	A pointer to mlan_adapter structure
 *  @param pmbuf    A pointer to the deaggreated buf
 *  @param drop	    A pointer to return the drop flag.
 *
 *  @return			N/A
 */
void
mlan_process_deaggr_pkt(t_void *padapter, pmlan_buffer pmbuf, t_u8 *drop)
{
	mlan_adapter *pmadapter = (mlan_adapter *)padapter;
	mlan_private *pmpriv;
	t_u16 eth_type = 0;

	*drop = MFALSE;
	pmpriv = pmadapter->priv[pmbuf->bss_index];
	eth_type = mlan_ntohs(*(t_u16 *)&pmbuf->pbuf[pmbuf->data_offset +
						     MLAN_ETHER_PKT_TYPE_OFFSET]);
	switch (eth_type) {
	default:
		break;
	}
	return;
}

/**
 *  @brief This function gets interrupt status.
 *  @param msg_id only used for PCIE
 */
/**
 *  @param msg_id  A message id
 *  @param adapter  A pointer to mlan_adapter structure
 *  @return         MLAN_STATUS_FAILURE -- if the intererupt is not for us
 */
mlan_status
mlan_interrupt(t_u16 msg_id, t_void *adapter)
{
	mlan_adapter *pmadapter = (mlan_adapter *)adapter;
	mlan_status ret;

	ENTER();
	ret = pmadapter->ops.interrupt(msg_id, pmadapter);
	LEAVE();
	return ret;
}

/**
 *  @brief This function wakeup firmware.
 *
 *  @param adapter  A pointer to mlan_adapter structure
 *  @param keep_wakeup   keep wake up flag
 *  @return         N/A
 */
t_void
mlan_pm_wakeup_card(t_void *adapter, t_u8 keep_wakeup)
{
	mlan_adapter *pmadapter = (mlan_adapter *)adapter;

	ENTER();
	if (keep_wakeup)
		pmadapter->ops.wakeup_card(pmadapter, MFALSE);
	pmadapter->keep_wakeup = keep_wakeup;

	LEAVE();
}

/**
 *  @brief This function check main_process status.
 *
 *  @param adapter  A pointer to mlan_adapter structure
 *  @return         MTRUE/MFALSE
 */
t_u8
mlan_is_main_process_running(t_void *adapter)
{
	mlan_adapter *pmadapter = (mlan_adapter *)adapter;
	pmlan_callbacks pcb = &pmadapter->callbacks;
	t_u8 ret = MFALSE;
	ENTER();
	pcb->moal_spin_lock(pmadapter->pmoal_handle,
			    pmadapter->pmain_proc_lock);

	/* Check if already processing */
	if (pmadapter->mlan_processing) {
		pmadapter->more_task_flag = MTRUE;
		ret = MTRUE;
	}
	pcb->moal_spin_unlock(pmadapter->pmoal_handle,
			      pmadapter->pmain_proc_lock);
	LEAVE();
	return ret;
}
