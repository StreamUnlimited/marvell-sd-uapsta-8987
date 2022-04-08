/** @file moal_sdio_mmc.c
 *
 *  @brief This file contains SDIO MMC IF (interface) module
 *  related functions.
 *
 *
 * Copyright 2008-2021 NXP
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
/****************************************************
Change log:
	02/25/09: Initial creation -
		  This file supports SDIO MMC only
****************************************************/

#include <linux/firmware.h>

#include "moal_sdio.h"

/** define nxp vendor id */
#define MRVL_VENDOR_ID 0x02df
/* The macros below are hardware platform dependent.
   The definition should match the actual platform */
/** Initialize GPIO port */
#define GPIO_PORT_INIT()
/** Set GPIO port to high */
#define GPIO_PORT_TO_HIGH()
/** Set GPIO port to low */
#define GPIO_PORT_TO_LOW()

/********************************************************
		Local Variables
********************************************************/
/* moal interface ops */
static moal_if_ops sdiommc_ops;
/********************************************************
		Global Variables
********************************************************/

/** Device ID for SD8987 */
#define SD_DEVICE_ID_8987 (0x9149)

/** WLAN IDs */
static const struct sdio_device_id wlan_ids[] = {
	{SDIO_DEVICE(MRVL_VENDOR_ID, SD_DEVICE_ID_8987)},
	{},
};

MODULE_DEVICE_TABLE(sdio, wlan_ids);

int woal_sdio_probe(struct sdio_func *func, const struct sdio_device_id *id);
void woal_sdio_remove(struct sdio_func *func);
static void woal_sdiommc_reg_dbg(pmoal_handle handle);

#ifdef SDIO_SUSPEND_RESUME
#ifdef MMC_PM_KEEP_POWER
int woal_sdio_suspend(struct device *dev);
int woal_sdio_resume(struct device *dev);

static struct dev_pm_ops wlan_sdio_pm_ops = {
	.suspend = woal_sdio_suspend,
	.resume = woal_sdio_resume,
};

void woal_sdio_shutdown(struct device *dev);
#endif
#endif

// clang-format off
static struct sdio_driver REFDATA wlan_sdio = {
	.name = "wlan_sdio",
	.id_table = wlan_ids,
	.probe = woal_sdio_probe,
	.remove = woal_sdio_remove,
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 29)
	.drv = {
		.owner = THIS_MODULE,
#ifdef SDIO_SUSPEND_RESUME
#ifdef MMC_PM_KEEP_POWER
		.pm = &wlan_sdio_pm_ops,
		.shutdown = woal_sdio_shutdown,
#endif
#endif

		}
#else
#ifdef SDIO_SUSPEND_RESUME
#ifdef MMC_PM_KEEP_POWER
	.drv = {
		.pm = &wlan_sdio_pm_ops,
		.shutdown = woal_sdio_shutdown,
		}
#endif
#endif
#endif
};

// clang-format on

/********************************************************
		Local Functions
********************************************************/
static void woal_sdiommc_dump_fw_info(moal_handle *phandle);
#if 0
/**  @brief This function dump the sdio register
 *
 *  @param handle   A Pointer to the moal_handle structure
 *  @return         N/A
 */
static void
woal_dump_sdio_reg(moal_handle *handle)
{
	int ret = 0;
	t_u8 data, i;
	int fun0_reg[] = { 0x05, 0x04 };
	t_u8 array_size = 0;
	int fun1_reg_other[] = { 0x03, 0x04, 0x05, 0x60, 0x61 };
	int *fun1_reg = NULL;

	for (i = 0; i < ARRAY_SIZE(fun0_reg); i++) {
		data = sdio_f0_readb(((struct sdio_mmc_card *)handle->card)->
				     func, fun0_reg[i], &ret);
		PRINTM(MMSG, "fun0: reg 0x%02x=0x%02x ret=%d\n", fun0_reg[i],
		       data, ret);
	}

	fun1_reg = fun1_reg_other;
	array_size = sizeof(fun1_reg_other) / sizeof(int);
	for (i = 0; i < array_size; i++) {
		data = sdio_readb(((struct sdio_mmc_card *)handle->card)->func,
				  fun1_reg[i], &ret);
		PRINTM(MMSG, "fun1: reg 0x%02x=0x%02x ret=%d\n", fun1_reg[i],
		       data, ret);
	}
	return;
}
#endif
/********************************************************
		Global Functions
********************************************************/
/**
 *  @brief This function handles the interrupt.
 *
 *  @param func     A pointer to the sdio_func structure
 *  @return         N/A
 */
static void
woal_sdio_interrupt(struct sdio_func *func)
{
	moal_handle *handle;
	struct sdio_mmc_card *card;

	ENTER();

	card = sdio_get_drvdata(func);
	if (!card || !card->handle) {
		PRINTM(MINFO,
		       "sdio_mmc_interrupt(func = %p) card or handle is NULL, card=%p\n",
		       func, card);
		LEAVE();
		return;
	}
	handle = card->handle;
	if (handle->surprise_removed == MTRUE) {
		LEAVE();
		return;
	}
	handle->main_state = MOAL_RECV_INT;
	PRINTM(MINFO, "*** IN SDIO IRQ ***\n");
	PRINTM(MINTR, "*\n");

	/* call mlan_interrupt to read int status */
	mlan_interrupt(0, handle->pmlan_adapter);
#ifdef SDIO_SUSPEND_RESUME
	if (handle->is_suspended) {
		PRINTM(MINTR, "Receive interrupt in hs_suspended\n");
		LEAVE();
		return;
	}
#endif
	handle->main_state = MOAL_START_MAIN_PROCESS;
	/* Call MLAN main process */
	mlan_main_process(handle->pmlan_adapter);
	handle->main_state = MOAL_END_MAIN_PROCESS;
	LEAVE();
}

/**  @brief This function updates the card types
 *
 *  @param handle   A Pointer to the moal_handle structure
 *  @param card     A Pointer to card
 *
 *  @return         N/A
 */
static t_u16
woal_update_card_type(t_void *card)
{
	struct sdio_mmc_card *cardp_sd = (struct sdio_mmc_card *)card;
	t_u16 card_type = 0;

	/* Update card type */

	if (cardp_sd->func->device == SD_DEVICE_ID_8987) {
		card_type = CARD_TYPE_SD8987;
		moal_memcpy_ext(NULL, driver_version, CARD_SD8987,
				strlen(CARD_SD8987), strlen(driver_version));
		moal_memcpy_ext(NULL,
				driver_version + strlen(INTF_CARDTYPE) +
				strlen(KERN_VERSION),
				V16, strlen(V16),
				strlen(driver_version) -
				(strlen(INTF_CARDTYPE) + strlen(KERN_VERSION)));
	}
	return card_type;
}

/**  @brief This function handles client driver probe.
 *
 *  @param func     A pointer to sdio_func structure.
 *  @param id       A pointer to sdio_device_id structure.
 *  @return         MLAN_STATUS_SUCCESS or MLAN_STATUS_FAILURE/error code
 */
int
woal_sdio_probe(struct sdio_func *func, const struct sdio_device_id *id)
{
	int ret = MLAN_STATUS_SUCCESS;
	struct sdio_mmc_card *card = NULL;
	t_u16 card_type = 0;

	ENTER();

	PRINTM(MMSG, "vendor=0x%4.04X device=0x%4.04X class=%d function=%d\n",
	       func->vendor, func->device, func->class, func->num);

	card = kzalloc(sizeof(struct sdio_mmc_card), GFP_KERNEL);
	if (!card) {
		PRINTM(MFATAL,
		       "Failed to allocate memory in probe function!\n");
		LEAVE();
		return -ENOMEM;
	}

	card->func = func;

#ifdef MMC_QUIRK_BLKSZ_FOR_BYTE_MODE
	/* The byte mode patch is available in kernel MMC driver
	 * which fixes one issue in MP-A transfer.
	 * bit1: use func->cur_blksize for byte mode
	 */
	func->card->quirks |= MMC_QUIRK_BLKSZ_FOR_BYTE_MODE;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
	func->card->quirks |= MMC_QUIRK_LENIENT_FN0;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
	/* wait for chip fully wake up */
	if (!func->enable_timeout)
		func->enable_timeout = 200;
#endif
	sdio_claim_host(func);
	ret = sdio_enable_func(func);
	if (ret) {
		sdio_release_host(func);
		PRINTM(MFATAL, "sdio_enable_func() failed: ret=%d\n", ret);
		ret = -EIO;
		goto err;
	}
	sdio_release_host(func);

	card_type = woal_update_card_type(card);
	if (!card_type) {
		PRINTM(MERROR, "sdmmc probe: woal_update_card_type() failed\n");
		ret = MLAN_STATUS_FAILURE;
		goto err;
	}

	if (NULL ==
	    woal_add_card(card, &card->func->dev, &sdiommc_ops, card_type)) {
		PRINTM(MERROR, "woal_add_card failed\n");
		ret = MLAN_STATUS_FAILURE;
		goto err;
	}
#ifdef IMX_SUPPORT
	woal_regist_oob_wakeup_irq(card->handle);
#endif /* IMX_SUPPORT */

	LEAVE();
	return ret;
err:
	kfree(card);
	sdio_claim_host(func);
	sdio_disable_func(func);
	sdio_release_host(func);

	LEAVE();
	return ret;
}

/**  @brief This function handles client driver remove.
 *
 *  @param func     A pointer to sdio_func structure.
 *  @return         N/A
 */
void
woal_sdio_remove(struct sdio_func *func)
{
	struct sdio_mmc_card *card;

	ENTER();

	if (func) {
		PRINTM(MINFO, "SDIO func=%d\n", func->num);
		card = sdio_get_drvdata(func);
		if (card) {
#ifdef IMX_SUPPORT
			woal_unregist_oob_wakeup_irq(card->handle);
#endif /* IMX_SUPPORT */
			woal_remove_card(card);
			kfree(card);
		}
	}

	LEAVE();
}

#ifdef SDIO_SUSPEND_RESUME
#ifdef MMC_PM_KEEP_POWER
#ifdef MMC_PM_FUNC_SUSPENDED
/**  @brief This function tells lower driver that WLAN is suspended
 *
 *  @param handle   A Pointer to the moal_handle structure
 *  @return         N/A
 */
void
woal_wlan_is_suspended(moal_handle *handle)
{
	ENTER();
	if (handle->suspend_notify_req == MTRUE) {
		handle->is_suspended = MTRUE;
		sdio_func_suspended(((struct sdio_mmc_card *)handle->card)->
				    func);
	}
	LEAVE();
}
#endif

/**  @brief This function handles client driver shutdown
 *
 *  @param dev      A pointer to device structure
 *  @return         N/A
 */
void
woal_sdio_shutdown(struct device *dev)
{
	struct sdio_func *func = dev_to_sdio_func(dev);
	moal_handle *handle = NULL;
	struct sdio_mmc_card *cardp;
	mlan_ds_ps_info pm_info;
	int i, retry_num = 8;

	ENTER();
	PRINTM(MCMND, "<--- Enter woal_sdio_shutdown --->\n");
	cardp = sdio_get_drvdata(func);
	if (!cardp || !cardp->handle) {
		PRINTM(MERROR, "Card or moal_handle structure is not valid\n");
		LEAVE();
		return;
	}
	handle = cardp->handle;
	for (i = 0; i < handle->priv_num; i++)
		netif_device_detach(handle->priv[i]->netdev);

	if (moal_extflg_isset(handle, EXT_SHUTDOWN_HS)) {
		handle->shutdown_hs_in_process = MTRUE;
		memset(&pm_info, 0, sizeof(pm_info));
		for (i = 0; i < retry_num; i++) {
			if (MLAN_STATUS_SUCCESS ==
			    woal_get_pm_info(woal_get_priv(handle,
							   MLAN_BSS_ROLE_ANY),
					     &pm_info)) {
				if (pm_info.is_suspend_allowed == MTRUE)
					break;
				else
					PRINTM(MMSG,
					       "Shutdown not allowed and retry again\n");
			}
			woal_sched_timeout(100);
		}
		if (pm_info.is_suspend_allowed == MFALSE) {
			PRINTM(MMSG, "Shutdown not allowed\n");
			goto done;
		}
		woal_enable_hs(woal_get_priv(handle, MLAN_BSS_ROLE_ANY));

		wait_event_interruptible_timeout(handle->hs_activate_wait_q,
						 handle->
						 hs_activate_wait_q_woken,
						 HS_ACTIVE_TIMEOUT);
		if (handle->hs_activated == MTRUE)
			PRINTM(MMSG, "HS actived in shutdown\n");
		else
			PRINTM(MMSG, "Fail to enable HS in shutdown\n");
	} else {
		for (i = 0; i < MIN(handle->priv_num, MLAN_MAX_BSS_NUM); i++) {
			if (handle->priv[i]) {
				if (handle->priv[i]->media_connected == MTRUE
#ifdef UAP_SUPPORT
				    || (GET_BSS_ROLE(handle->priv[i]) ==
					MLAN_BSS_ROLE_UAP)
#endif
					) {
					PRINTM(MIOCTL,
					       "disconnect on suspend\n");
					woal_disconnect(handle->priv[i],
							MOAL_NO_WAIT, NULL,
							DEF_DEAUTH_REASON_CODE);
				}
			}
		}
	}

done:
	PRINTM(MCMND, "<--- Leave woal_sdio_shutdown --->\n");
	LEAVE();
	return;
}

/**  @brief This function handles client driver suspend
 *
 *  @param dev      A pointer to device structure
 *  @return         MLAN_STATUS_SUCCESS or error code
 */
int
woal_sdio_suspend(struct device *dev)
{
	struct sdio_func *func = dev_to_sdio_func(dev);
	mmc_pm_flag_t pm_flags = 0;
	moal_handle *handle = NULL;
	struct sdio_mmc_card *cardp;
	int i, retry_num = 8;
	int ret = MLAN_STATUS_SUCCESS;
	int hs_actived = 0;
	mlan_ds_ps_info pm_info;

	ENTER();
	PRINTM(MCMND, "<--- Enter woal_sdio_suspend --->\n");
	pm_flags = sdio_get_host_pm_caps(func);
	PRINTM(MCMND, "%s: suspend: PM flags = 0x%x\n", sdio_func_id(func),
	       pm_flags);
	cardp = sdio_get_drvdata(func);
	if (!cardp || !cardp->handle) {
		PRINTM(MERROR, "Card or moal_handle structure is not valid\n");
		LEAVE();
		return MLAN_STATUS_SUCCESS;
	}

	handle = cardp->handle;

	if (moal_extflg_isset(handle, EXT_PM_KEEP_POWER) &&
	    !(pm_flags & MMC_PM_KEEP_POWER)) {
		PRINTM(MERROR,
		       "%s: cannot remain alive while host is suspended\n",
		       sdio_func_id(func));
		LEAVE();
		return -ENOSYS;
	}
	if (handle->is_suspended == MTRUE) {
		PRINTM(MWARN, "Device already suspended\n");
		LEAVE();
		return MLAN_STATUS_SUCCESS;
	}
	if (handle->fw_dump) {
		PRINTM(MMSG, "suspend not allowed while FW dump!");
		ret = -EBUSY;
		goto done;
	}
#ifdef STA_SUPPORT
	for (i = 0; i < MIN(handle->priv_num, MLAN_MAX_BSS_NUM); i++) {
		if (handle->priv[i] &&
		    (GET_BSS_ROLE(handle->priv[i]) == MLAN_BSS_ROLE_STA))
			woal_cancel_scan(handle->priv[i], MOAL_IOCTL_WAIT);
	}
#endif
	handle->suspend_fail = MFALSE;
	memset(&pm_info, 0, sizeof(pm_info));
	for (i = 0; i < retry_num; i++) {
		if (MLAN_STATUS_SUCCESS ==
		    woal_get_pm_info(woal_get_priv(handle, MLAN_BSS_ROLE_ANY),
				     &pm_info)) {
			if (pm_info.is_suspend_allowed == MTRUE)
				break;
			else
				PRINTM(MMSG,
				       "Suspend not allowed and retry again\n");
		}
		woal_sched_timeout(100);
	}
	if (pm_info.is_suspend_allowed == MFALSE) {
		PRINTM(MMSG, "Suspend not allowed\n");
		ret = -EBUSY;
		goto done;
	}

	for (i = 0; i < handle->priv_num; i++)
		netif_device_detach(handle->priv[i]->netdev);

	if (moal_extflg_isset(handle, EXT_PM_KEEP_POWER)) {
		/* Enable the Host Sleep */
#ifdef MMC_PM_FUNC_SUSPENDED
		handle->suspend_notify_req = MTRUE;
#endif
		hs_actived =
			woal_enable_hs(woal_get_priv
				       (handle, MLAN_BSS_ROLE_ANY));
#ifdef MMC_PM_FUNC_SUSPENDED
		handle->suspend_notify_req = MFALSE;
#endif
		if (hs_actived) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 3, 4)
			if (pm_flags & MMC_PM_WAKE_SDIO_IRQ) {
				ret = sdio_set_host_pm_flags(func,
							     MMC_PM_WAKE_SDIO_IRQ);
				PRINTM(MCMND,
				       "suspend with MMC_PM_WAKE_SDIO_IRQ ret=%d\n",
				       ret);
			}
#endif
#ifdef MMC_PM_SKIP_RESUME_PROBE
			PRINTM(MCMND,
			       "suspend with MMC_PM_KEEP_POWER and MMC_PM_SKIP_RESUME_PROBE\n");
			ret = sdio_set_host_pm_flags(func,
						     MMC_PM_KEEP_POWER |
						     MMC_PM_SKIP_RESUME_PROBE);
#else
			PRINTM(MCMND, "suspend with MMC_PM_KEEP_POWER\n");
			ret = sdio_set_host_pm_flags(func, MMC_PM_KEEP_POWER);
#endif
		} else {
			PRINTM(MMSG, "HS not actived, suspend fail!");
			handle->suspend_fail = MTRUE;
			for (i = 0; i < handle->priv_num; i++)
				netif_device_attach(handle->priv[i]->netdev);
			ret = -EBUSY;
			goto done;
		}
	}

	/* Indicate device suspended */
	handle->is_suspended = MTRUE;
#ifdef IMX_SUPPORT
	woal_enable_oob_wakeup_irq(handle);
#endif /* IMX_SUPPORT */
done:
	PRINTM(MCMND, "<--- Leave woal_sdio_suspend --->\n");
	LEAVE();
	return ret;
}

/**  @brief This function handles client driver resume
 *
 *  @param dev      A pointer to device structure
 *  @return         MLAN_STATUS_SUCCESS
 */
int
woal_sdio_resume(struct device *dev)
{
	struct sdio_func *func = dev_to_sdio_func(dev);
	mmc_pm_flag_t pm_flags = 0;
	moal_handle *handle = NULL;
	struct sdio_mmc_card *cardp;
	int i;

	ENTER();
	PRINTM(MCMND, "<--- Enter woal_sdio_resume --->\n");
	pm_flags = sdio_get_host_pm_caps(func);
	PRINTM(MCMND, "%s: resume: PM flags = 0x%x\n", sdio_func_id(func),
	       pm_flags);
	cardp = sdio_get_drvdata(func);
	if (!cardp || !cardp->handle) {
		PRINTM(MERROR, "Card or moal_handle structure is not valid\n");
		LEAVE();
		return MLAN_STATUS_SUCCESS;
	}
	handle = cardp->handle;

	if (handle->is_suspended == MFALSE) {
		PRINTM(MWARN, "Device already resumed\n");
		LEAVE();
		return MLAN_STATUS_SUCCESS;
	}
	handle->is_suspended = MFALSE;
	if (woal_check_driver_status(handle)) {
		PRINTM(MERROR, "Resuem, device is in hang state\n");
		LEAVE();
		return MLAN_STATUS_SUCCESS;
	}
	for (i = 0; i < handle->priv_num; i++)
		netif_device_attach(handle->priv[i]->netdev);

	/* Disable Host Sleep */
	woal_cancel_hs(woal_get_priv(handle, MLAN_BSS_ROLE_ANY), MOAL_NO_WAIT);
#ifdef IMX_SUPPORT
	woal_disable_oob_wakeup_irq(handle);
#endif /* IMX_SUPPORT */
	PRINTM(MCMND, "<--- Leave woal_sdio_resume --->\n");
	LEAVE();
	return MLAN_STATUS_SUCCESS;
}
#endif
#endif /* SDIO_SUSPEND_RESUME */

/**
 *  @brief This function writes data into card register
 *
 *  @param handle   A Pointer to the moal_handle structure
 *  @param reg      Register offset
 *  @param data     Value
 *
 *  @return         MLAN_STATUS_SUCCESS or MLAN_STATUS_FAILURE
 */
static mlan_status
woal_sdiommc_write_reg(moal_handle *handle, t_u32 reg, t_u32 data)
{
	mlan_status ret = MLAN_STATUS_FAILURE;
	sdio_claim_host(((struct sdio_mmc_card *)handle->card)->func);
	sdio_writeb(((struct sdio_mmc_card *)handle->card)->func, (t_u8)data,
		    reg, (int *)&ret);
	sdio_release_host(((struct sdio_mmc_card *)handle->card)->func);
	return ret;
}

/**
 *  @brief This function reads data from card register
 *
 *  @param handle   A Pointer to the moal_handle structure
 *  @param reg      Register offset
 *  @param data     Value
 *
 *  @return         MLAN_STATUS_SUCCESS or MLAN_STATUS_FAILURE
 */
static mlan_status
woal_sdiommc_read_reg(moal_handle *handle, t_u32 reg, t_u32 *data)
{
	mlan_status ret = MLAN_STATUS_FAILURE;
	t_u8 val;
	sdio_claim_host(((struct sdio_mmc_card *)handle->card)->func);
	val = sdio_readb(((struct sdio_mmc_card *)handle->card)->func, reg,
			 (int *)&ret);
	sdio_release_host(((struct sdio_mmc_card *)handle->card)->func);
	*data = val;

	return ret;
}

/**
 *  @brief This function writes data into card register
 *
 *  @param handle   A Pointer to the moal_handle structure
 *  @param reg      Register offset
 *  @param data     Value
 *
 *  @return         MLAN_STATUS_SUCCESS or MLAN_STATUS_FAILURE
 */
static mlan_status
woal_sdio_writeb(moal_handle *handle, t_u32 reg, t_u8 data)
{
	mlan_status ret = MLAN_STATUS_FAILURE;
	sdio_claim_host(((struct sdio_mmc_card *)handle->card)->func);
	sdio_writeb(((struct sdio_mmc_card *)handle->card)->func, (t_u8)data,
		    reg, (int *)&ret);
	sdio_release_host(((struct sdio_mmc_card *)handle->card)->func);
	return ret;
}

/**
 *  @brief This function reads data from card register
 *
 *  @param handle   A Pointer to the moal_handle structure
 *  @param reg      Register offset
 *  @param data     Value
 *
 *  @return         MLAN_STATUS_SUCCESS or MLAN_STATUS_FAILURE
 */
static mlan_status
woal_sdio_readb(moal_handle *handle, t_u32 reg, t_u8 *data)
{
	mlan_status ret = MLAN_STATUS_FAILURE;
	t_u8 val;
	sdio_claim_host(((struct sdio_mmc_card *)handle->card)->func);
	val = sdio_readb(((struct sdio_mmc_card *)handle->card)->func, reg,
			 (int *)&ret);
	sdio_release_host(((struct sdio_mmc_card *)handle->card)->func);
	*data = val;

	return ret;
}

/**
 *  @brief This function reads data from card register FN0
 *
 *  @param handle   A Pointer to the moal_handle structure
 *  @param reg      Register offset
 *  @param data     Value
 *
 *  @return         MLAN_STATUS_SUCCESS or MLAN_STATUS_FAILURE
 */
static mlan_status
woal_sdio_f0_readb(moal_handle *handle, t_u32 reg, t_u8 *data)
{
	mlan_status ret = MLAN_STATUS_FAILURE;
	t_u8 val;
	sdio_claim_host(((struct sdio_mmc_card *)handle->card)->func);
	val = sdio_f0_readb(((struct sdio_mmc_card *)handle->card)->func, reg,
			    (int *)&ret);
	sdio_release_host(((struct sdio_mmc_card *)handle->card)->func);
	*data = val;

	return ret;
}

/**
 *  @brief This function use SG mode to read/write data into card memory
 *
 *  @param handle   A Pointer to the moal_handle structure
 *  @param pmbuf_list   Pointer to a linked list of mlan_buffer structure
 *  @param port     Port
 *  @param write    write flag
 *
 *  @return         MLAN_STATUS_SUCCESS or MLAN_STATUS_FAILURE
 */
static mlan_status
woal_sdio_rw_mb(moal_handle *handle, pmlan_buffer pmbuf_list,
		t_u32 port, t_u8 write)
{
	struct scatterlist sg_list[SDIO_MP_AGGR_DEF_PKT_LIMIT_MAX];
	int num_sg = pmbuf_list->use_count;
	int i = 0;
	mlan_buffer *pmbuf = NULL;
	struct mmc_request mmc_req;
	struct mmc_command mmc_cmd;
	struct mmc_data mmc_dat;
	struct sdio_func *func = ((struct sdio_mmc_card *)handle->card)->func;
	t_u32 ioport = (port & MLAN_SDIO_IO_PORT_MASK);
	t_u32 blkcnt = pmbuf_list->data_len / MLAN_SDIO_BLOCK_SIZE;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
	int status;
#endif

	if (num_sg > SDIO_MP_AGGR_DEF_PKT_LIMIT_MAX) {
		PRINTM(MERROR, "ERROR: num_sg=%d", num_sg);
		return MLAN_STATUS_FAILURE;
	}
	sg_init_table(sg_list, num_sg);
	pmbuf = pmbuf_list->pnext;
	for (i = 0; i < num_sg; i++) {
		if (pmbuf == pmbuf_list)
			break;
		sg_set_buf(&sg_list[i], pmbuf->pbuf + pmbuf->data_offset,
			   pmbuf->data_len);
		pmbuf = pmbuf->pnext;
	}
	memset(&mmc_req, 0, sizeof(struct mmc_request));
	memset(&mmc_cmd, 0, sizeof(struct mmc_command));
	memset(&mmc_dat, 0, sizeof(struct mmc_data));

	mmc_dat.sg = sg_list;
	mmc_dat.sg_len = num_sg;
	mmc_dat.blksz = MLAN_SDIO_BLOCK_SIZE;
	mmc_dat.blocks = blkcnt;
	mmc_dat.flags = write ? MMC_DATA_WRITE : MMC_DATA_READ;

	mmc_cmd.opcode = SD_IO_RW_EXTENDED;
	mmc_cmd.arg = write ? 1 << 31 : 0;
	mmc_cmd.arg |= (func->num & 0x7) << 28;
	mmc_cmd.arg |= 1 << 27;	/* block basic */
	mmc_cmd.arg |= 0;	/* fix address */
	mmc_cmd.arg |= (ioport & 0x1FFFF) << 9;
	mmc_cmd.arg |= blkcnt & 0x1FF;
	mmc_cmd.flags = MMC_RSP_SPI_R5 | MMC_RSP_R5 | MMC_CMD_ADTC;

	mmc_req.cmd = &mmc_cmd;
	mmc_req.data = &mmc_dat;

	sdio_claim_host(((struct sdio_mmc_card *)handle->card)->func);
	mmc_set_data_timeout(&mmc_dat,
			     ((struct sdio_mmc_card *)handle->card)->func->
			     card);
	mmc_wait_for_req(((struct sdio_mmc_card *)handle->card)->func->card->
			 host, &mmc_req);

	if (mmc_cmd.error || mmc_dat.error) {
		PRINTM(MERROR, "CMD53 %s cmd_error = %d data_error=%d\n",
		       write ? "write" : "read", mmc_cmd.error, mmc_dat.error);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
		/* issue abort cmd52 command through F0 */
		sdio_f0_writeb(((struct sdio_mmc_card *)handle->card)->func,
			       0x01, SDIO_CCCR_ABORT, &status);
#endif
		sdio_release_host(((struct sdio_mmc_card *)handle->card)->func);
		return MLAN_STATUS_FAILURE;
	}
	sdio_release_host(((struct sdio_mmc_card *)handle->card)->func);
	return MLAN_STATUS_SUCCESS;
}

/**
 *  @brief This function writes multiple bytes into card memory
 *
 *  @param handle   A Pointer to the moal_handle structure
 *  @param pmbuf    Pointer to mlan_buffer structure
 *  @param port     Port
 *  @param timeout  Time out value
 *
 *  @return         MLAN_STATUS_SUCCESS or MLAN_STATUS_FAILURE
 */
static mlan_status
woal_sdiommc_write_data_sync(moal_handle *handle,
			     mlan_buffer *pmbuf, t_u32 port, t_u32 timeout)
{
	mlan_status ret = MLAN_STATUS_FAILURE;
	t_u8 *buffer = (t_u8 *)(pmbuf->pbuf + pmbuf->data_offset);
	t_u8 blkmode =
		(port & MLAN_SDIO_BYTE_MODE_MASK) ? BYTE_MODE : BLOCK_MODE;
	t_u32 blksz = (blkmode == BLOCK_MODE) ? MLAN_SDIO_BLOCK_SIZE : 1;
	t_u32 blkcnt = (blkmode == BLOCK_MODE) ?
		(pmbuf->data_len / MLAN_SDIO_BLOCK_SIZE) : pmbuf->data_len;
	t_u32 ioport = (port & MLAN_SDIO_IO_PORT_MASK);
	int status = 0;
	if (pmbuf->use_count > 1)
		return woal_sdio_rw_mb(handle, pmbuf, port, MTRUE);
#ifdef SDIO_MMC_DEBUG
	handle->cmd53w = 1;
#endif
	sdio_claim_host(((struct sdio_mmc_card *)handle->card)->func);
	status = sdio_writesb(((struct sdio_mmc_card *)handle->card)->func,
			      ioport, buffer, blkcnt * blksz);
	if (!status)
		ret = MLAN_STATUS_SUCCESS;
	else {
		PRINTM(MERROR, "cmd53 write error=%d\n", status);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
		/* issue abort cmd52 command through F0 */
		sdio_f0_writeb(((struct sdio_mmc_card *)handle->card)->func,
			       0x01, SDIO_CCCR_ABORT, &status);
#endif
	}
	sdio_release_host(((struct sdio_mmc_card *)handle->card)->func);
#ifdef SDIO_MMC_DEBUG
	handle->cmd53w = 2;
#endif
	return ret;
}

/**
 *  @brief This function reads multiple bytes from card memory
 *
 *  @param handle   A Pointer to the moal_handle structure
 *  @param pmbuf    Pointer to mlan_buffer structure
 *  @param port     Port
 *  @param timeout  Time out value
 *
 *  @return         MLAN_STATUS_SUCCESS or MLAN_STATUS_FAILURE
 */
static mlan_status
woal_sdiommc_read_data_sync(moal_handle *handle,
			    mlan_buffer *pmbuf, t_u32 port, t_u32 timeout)
{
	mlan_status ret = MLAN_STATUS_FAILURE;
	t_u8 *buffer = (t_u8 *)(pmbuf->pbuf + pmbuf->data_offset);
	t_u8 blkmode =
		(port & MLAN_SDIO_BYTE_MODE_MASK) ? BYTE_MODE : BLOCK_MODE;
	t_u32 blksz = (blkmode == BLOCK_MODE) ? MLAN_SDIO_BLOCK_SIZE : 1;
	t_u32 blkcnt = (blkmode == BLOCK_MODE) ?
		(pmbuf->data_len / MLAN_SDIO_BLOCK_SIZE) : pmbuf->data_len;
	t_u32 ioport = (port & MLAN_SDIO_IO_PORT_MASK);
	int status = 0;
	if (pmbuf->use_count > 1)
		return woal_sdio_rw_mb(handle, pmbuf, port, MFALSE);
#ifdef SDIO_MMC_DEBUG
	handle->cmd53r = 1;
#endif
	sdio_claim_host(((struct sdio_mmc_card *)handle->card)->func);
	status = sdio_readsb(((struct sdio_mmc_card *)handle->card)->func,
			     buffer, ioport, blkcnt * blksz);
	if (!status) {
		ret = MLAN_STATUS_SUCCESS;
	} else {
		PRINTM(MERROR, "cmd53 read error=%d\n", status);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
		/* issue abort cmd52 command through F0 */
		sdio_f0_writeb(((struct sdio_mmc_card *)handle->card)->func,
			       0x01, SDIO_CCCR_ABORT, &status);
#endif
	}
	sdio_release_host(((struct sdio_mmc_card *)handle->card)->func);
#ifdef SDIO_MMC_DEBUG
	handle->cmd53r = 2;
#endif
	return ret;
}

/**
 *  @brief This function registers the IF module in bus driver
 *
 *  @return    MLAN_STATUS_SUCCESS or MLAN_STATUS_FAILURE
 */
mlan_status
woal_sdiommc_bus_register(void)
{
	mlan_status ret = MLAN_STATUS_SUCCESS;

	ENTER();

	/* SDIO Driver Registration */
	if (sdio_register_driver(&wlan_sdio)) {
		PRINTM(MFATAL, "SDIO Driver Registration Failed \n");
		LEAVE();
		return MLAN_STATUS_FAILURE;
	}

	/* init GPIO PORT for wakeup purpose */
	GPIO_PORT_INIT();
	/* set default value */
	GPIO_PORT_TO_HIGH();

	LEAVE();
	return ret;
}

/**
 *  @brief This function de-registers the IF module in bus driver
 *
 *  @return         N/A
 */
void
woal_sdiommc_bus_unregister(void)
{
	ENTER();

	/* SDIO Driver Unregistration */
	sdio_unregister_driver(&wlan_sdio);

	LEAVE();
}

/**
 *  @brief This function de-registers the device
 *
 *  @param handle A pointer to moal_handle structure
 *  @return         N/A
 */
static void
woal_sdiommc_unregister_dev(moal_handle *handle)
{
	ENTER();
	if (handle->card) {
		struct sdio_mmc_card *card = handle->card;
		struct sdio_func *func = card->func;

		/* Release the SDIO IRQ */
		sdio_claim_host(card->func);
		sdio_release_irq(card->func);
		sdio_disable_func(card->func);
		if (handle->driver_status)
			mmc_hw_reset(func->card->host);
		sdio_release_host(card->func);

		sdio_set_drvdata(card->func, NULL);

		GPIO_PORT_TO_LOW();
		PRINTM(MWARN, "Making the sdio dev card as NULL\n");
		card->handle = NULL;
	}

	LEAVE();
}

/**
 *  @brief This function registers the device
 *
 *  @param handle  A pointer to moal_handle structure
 *  @return         MLAN_STATUS_SUCCESS or MLAN_STATUS_FAILURE
 */
static mlan_status
woal_sdiommc_register_dev(moal_handle *handle)
{
	int ret = MLAN_STATUS_SUCCESS;
	struct sdio_mmc_card *card = handle->card;
	struct sdio_func *func;

	ENTER();

	GPIO_PORT_INIT();
	GPIO_PORT_TO_HIGH();

	/* save adapter pointer in card */
	card->handle = handle;
	func = card->func;
	sdio_claim_host(func);
	/* Request the SDIO IRQ */
	ret = sdio_claim_irq(func, woal_sdio_interrupt);
	if (ret) {
		PRINTM(MFATAL, "sdio_claim_irq failed: ret=%d\n", ret);
		goto release_host;
	}

	/* Set block size */
	ret = sdio_set_block_size(card->func, MLAN_SDIO_BLOCK_SIZE);
	if (ret) {
		PRINTM(MERROR,
		       "sdio_set_block_seize(): cannot set SDIO block size\n");
		ret = MLAN_STATUS_FAILURE;
		goto release_irq;
	}

	sdio_release_host(func);
	sdio_set_drvdata(func, card);

	LEAVE();
	return MLAN_STATUS_SUCCESS;

release_irq:
	sdio_release_irq(func);
release_host:
	sdio_release_host(func);
	handle->card = NULL;

	LEAVE();
	return MLAN_STATUS_FAILURE;
}

/**
 *  @brief This function set bus clock on/off
 *
 *  @param handle   A pointer to moal_handle structure
 *  @param option   TRUE--on , FALSE--off
 *  @return         MLAN_STATUS_SUCCESS
 */
int
woal_sdio_set_bus_clock(moal_handle *handle, t_u8 option)
{
	struct sdio_mmc_card *cardp = (struct sdio_mmc_card *)handle->card;
	struct mmc_host *host = cardp->func->card->host;

	ENTER();
	if (option == MTRUE) {
		/* restore value if non-zero */
		if (cardp->host_clock)
			host->ios.clock = cardp->host_clock;
	} else {
		/* backup value if non-zero, then clear */
		if (host->ios.clock)
			cardp->host_clock = host->ios.clock;
		host->ios.clock = 0;
	}

	host->ops->set_ios(host, &host->ios);
	LEAVE();
	return MLAN_STATUS_SUCCESS;
}

/**
 *  @brief This function updates card reg based on the Cmd52 value in dev
 * structure
 *
 *  @param handle   A pointer to moal_handle structure
 *  @param func     A pointer to store func variable
 *  @param reg      A pointer to store reg variable
 *  @param val      A pointer to store val variable
 *  @return         MLAN_STATUS_SUCCESS or MLAN_STATUS_FAILURE
 */
int
woal_sdio_read_write_cmd52(moal_handle *handle, int func, int reg, int val)
{
	int ret = MLAN_STATUS_SUCCESS;
	struct sdio_mmc_card *card = (struct sdio_mmc_card *)handle->card;

	ENTER();
	/* Save current func and reg for read */
	handle->cmd52_func = func;
	handle->cmd52_reg = reg;
	sdio_claim_host(card->func);
	if (val >= 0) {
		/* Perform actual write only if val is provided */
		if (func)
			sdio_writeb(card->func, val, reg, &ret);
		else
			sdio_f0_writeb(card->func, val, reg, &ret);
		if (ret) {
			PRINTM(MERROR,
			       "Cannot write value (0x%x) to func %d reg 0x%x\n",
			       val, func, reg);
		} else {
			PRINTM(MMSG, "write value (0x%x) to func %d reg 0x%x\n",
			       (u8)val, func, reg);
			handle->cmd52_val = val;
		}
	} else {
		if (func)
			val = sdio_readb(card->func, reg, &ret);
		else
			val = sdio_f0_readb(card->func, reg, &ret);
		if (ret) {
			PRINTM(MERROR,
			       "Cannot read value from func %d reg 0x%x\n",
			       func, reg);
		} else {
			PRINTM(MMSG,
			       "read value (0x%x) from func %d reg 0x%x\n",
			       (u8)val, func, reg);
			handle->cmd52_val = val;
		}
	}
	sdio_release_host(card->func);
	LEAVE();
	return ret;
}

static mlan_status
woal_sdiommc_get_fw_name(moal_handle *handle)
{
	mlan_status ret = MLAN_STATUS_SUCCESS;

	t_u32 magic_reg = handle->card_info->magic_reg;
	t_u32 magic = 0;
	t_u32 host_strap_reg = handle->card_info->host_strap_reg;
	t_u32 strap = 0;

	ENTER();

	if (handle->params.fw_name)
		goto done;

	/** Revision ID register */
	woal_sdiommc_read_reg(handle, magic_reg, &magic);
	/** Revision ID register */
	woal_sdiommc_read_reg(handle, host_strap_reg, &strap);
	strap &= 0x1;
	magic &= 0xFF;
	/* 1 = SDSD, 0 --SD UART */
	PRINTM(MCMND, "magic=0x%x strap=0x%x\n", magic, strap);

	if (IS_SD8987(handle->card_type)) {
		if (magic == CHIP_MAGIC_VALUE) {
			if (strap == CARD_TYPE_SD_UART)
				strcpy(handle->card_info->fw_name,
				       SDUART8987_DEFAULT_COMBO_FW_NAME);
			else
				strcpy(handle->card_info->fw_name,
				       SDSD8987_DEFAULT_COMBO_FW_NAME);
		}
	}

done:
	PRINTM(MCMND, "combo fw:%s wlan fw:%s \n", handle->card_info->fw_name,
	       handle->card_info->fw_name_wlan);
	LEAVE();
	return ret;
}

#define DEBUG_FW_DONE 0xFF
#define DEBUG_MEMDUMP_FINISH 0xFE
#define MAX_POLL_TRIES 100

typedef enum {
	DUMP_TYPE_ITCM = 0,
	DUMP_TYPE_DTCM = 1,
	DUMP_TYPE_SQRAM = 2,
	DUMP_TYPE_APU_REGS = 3,
	DUMP_TYPE_CIU_REGS = 4,
	DUMP_TYPE_ICU_REGS = 5,
	DUMP_TYPE_MAC_REGS = 6,
	DUMP_TYPE_EXTEND_7 = 7,
	DUMP_TYPE_EXTEND_8 = 8,
	DUMP_TYPE_EXTEND_9 = 9,
	DUMP_TYPE_EXTEND_10 = 10,
	DUMP_TYPE_EXTEND_11 = 11,
	DUMP_TYPE_EXTEND_12 = 12,
	DUMP_TYPE_EXTEND_13 = 13,
	DUMP_TYPE_EXTEND_LAST = 14
} dumped_mem_type;

#define MAX_NAME_LEN 8

typedef struct {
	t_u8 mem_name[MAX_NAME_LEN];
	t_u8 *mem_Ptr;
	struct file *pfile_mem;
	t_u8 done_flag;
	t_u8 type;
} memory_type_mapping;

static memory_type_mapping mem_type_mapping_tbl[] = {
	{"ITCM", NULL, NULL, 0xF0, FW_DUMP_TYPE_MEM_ITCM},
	{"DTCM", NULL, NULL, 0xF1, FW_DUMP_TYPE_MEM_DTCM},
	{"SQRAM", NULL, NULL, 0xF2, FW_DUMP_TYPE_MEM_SQRAM},
	{"APU", NULL, NULL, 0xF3, FW_DUMP_TYPE_REG_APU},
	{"CIU", NULL, NULL, 0xF4, FW_DUMP_TYPE_REG_CIU},
	{"ICU", NULL, NULL, 0xF5, FW_DUMP_TYPE_REG_ICU},
	{"MAC", NULL, NULL, 0xF6, FW_DUMP_TYPE_REG_MAC},
	{"EXT7", NULL, NULL, 0xF7, 0},
	{"EXT8", NULL, NULL, 0xF8, 0},
	{"EXT9", NULL, NULL, 0xF9, 0},
	{"EXT10", NULL, NULL, 0xFA, 0},
	{"EXT11", NULL, NULL, 0xFB, 0},
	{"EXT12", NULL, NULL, 0xFC, 0},
	{"EXT13", NULL, NULL, 0xFD, 0},
	{"EXTLAST", NULL, NULL, 0xFE, 0},
};

static memory_type_mapping mem_type_mapping_tbl_8977_8997 = { "DUMP", NULL,
	NULL, 0xDD, 0
};

/**
 *  @brief This function read/write firmware via cmd52
 *
 *  @param phandle   A pointer to moal_handle
 *  @param doneflag  A flag
 *
 *  @return         MLAN_STATUS_SUCCESS
 */
static rdwr_status
woal_cmd52_rdwr_firmware(moal_handle *phandle, t_u8 doneflag)
{
	int ret = 0;
	int tries = 0;
	t_u8 ctrl_data = 0;
	t_u8 dbg_dump_ctrl_reg = phandle->card_info->dump_fw_ctrl_reg;
	t_u8 debug_host_ready = phandle->card_info->dump_fw_host_ready;

	ret = woal_sdio_writeb(phandle, dbg_dump_ctrl_reg, debug_host_ready);
	if (ret) {
		PRINTM(MERROR, "SDIO Write ERR\n");
		return RDWR_STATUS_FAILURE;
	}
	for (tries = 0; tries < MAX_POLL_TRIES; tries++) {
		ret = woal_sdio_readb(phandle, dbg_dump_ctrl_reg, &ctrl_data);
		if (ret) {
			PRINTM(MERROR, "SDIO READ ERR\n");
			return RDWR_STATUS_FAILURE;
		}
		if (ctrl_data == DEBUG_FW_DONE)
			break;
		if (doneflag && ctrl_data == doneflag)
			return RDWR_STATUS_DONE;
		if (ctrl_data != debug_host_ready) {
			PRINTM(MMSG,
			       "The ctrl reg was changed, re-try again!\n");
			ret = woal_sdio_writeb(phandle, dbg_dump_ctrl_reg,
					       debug_host_ready);
			if (ret) {
				PRINTM(MERROR, "SDIO Write ERR\n");
				return RDWR_STATUS_FAILURE;
			}
		}
		udelay(100);
	}
	if (ctrl_data == debug_host_ready || tries == MAX_POLL_TRIES) {
		PRINTM(MERROR, "Fail to pull ctrl_data\n");
		return RDWR_STATUS_FAILURE;
	}
	return RDWR_STATUS_SUCCESS;
}

/**
 *  @brief This function dump firmware memory to file
 *
 *  @param phandle   A pointer to moal_handle
 *
 *  @return         N/A
 */
void
woal_dump_firmware_info_v2(moal_handle *phandle)
{
	int ret = 0;
	unsigned int reg, reg_start, reg_end;
	t_u8 *dbg_ptr = NULL;
	t_u32 sec, usec;
	t_u8 dump_num = 0;
	t_u8 idx = 0;
	t_u8 doneflag = 0;
	rdwr_status stat;
	t_u8 i = 0;
	t_u8 read_reg = 0;
	t_u32 memory_size = 0;
	t_u8 path_name[64], file_name[32], firmware_dump_file[128];
	t_u8 *end_ptr = NULL;
	t_u8 dbg_dump_start_reg = 0;
	t_u8 dbg_dump_end_reg = 0;
	t_u8 dbg_dump_ctrl_reg = 0;

	if (!phandle) {
		PRINTM(MERROR, "Could not dump firmwware info\n");
		return;
	}

	dbg_dump_start_reg = phandle->card_info->dump_fw_start_reg;
	dbg_dump_end_reg = phandle->card_info->dump_fw_end_reg;
	dbg_dump_ctrl_reg = phandle->card_info->dump_fw_ctrl_reg;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 1, 0)
	/** Create dump directort*/
	woal_create_dump_dir(phandle, path_name, sizeof(path_name));
#else
	memset(path_name, 0, sizeof(path_name));
	strcpy(path_name, "/data");
#endif
	PRINTM(MMSG, "Directory name is %s\n", path_name);

	woal_dump_drv_info(phandle, path_name);

	/* start dump fw memory */
	moal_get_system_time(phandle, &sec, &usec);
	PRINTM(MMSG, "==== DEBUG MODE OUTPUT START: %u.%06u ====\n", sec, usec);
	/* read the number of the memories which will dump */
	if (RDWR_STATUS_FAILURE == woal_cmd52_rdwr_firmware(phandle, doneflag))
		goto done;
	reg = dbg_dump_start_reg;
	ret = woal_sdio_readb(phandle, reg, &dump_num);
	if (ret) {
		PRINTM(MMSG, "SDIO READ MEM NUM ERR\n");
		goto done;
	}

	/* read the length of every memory which will dump */
	for (idx = 0; idx < dump_num; idx++) {
		if (RDWR_STATUS_FAILURE ==
		    woal_cmd52_rdwr_firmware(phandle, doneflag))
			goto done;
		memory_size = 0;
		reg = dbg_dump_start_reg;
		for (i = 0; i < 4; i++) {
			ret = woal_sdio_readb(phandle, reg, &read_reg);
			if (ret) {
				PRINTM(MMSG, "SDIO READ ERR\n");
				goto done;
			}
			memory_size |= (read_reg << i * 8);
			reg++;
		}
		if (memory_size == 0) {
			PRINTM(MMSG, "Firmware Dump Finished!\n");
			ret = woal_sdiommc_write_reg(phandle, dbg_dump_ctrl_reg,
						     DEBUG_MEMDUMP_FINISH);
			if (ret) {
				PRINTM(MERROR,
				       "SDIO Write MEMDUMP_FINISH ERR\n");
				goto done;
			}
			break;
		} else {
			PRINTM(MMSG, "%s_SIZE=0x%x\n",
			       mem_type_mapping_tbl[idx].mem_name, memory_size);
			ret = moal_vmalloc(phandle, memory_size + 1,
					   (t_u8 **)&mem_type_mapping_tbl[idx].
					   mem_Ptr);
			if ((ret != MLAN_STATUS_SUCCESS) ||
			    !mem_type_mapping_tbl[idx].mem_Ptr) {
				PRINTM(MERROR,
				       "Error: vmalloc %s buffer failed!!!\n",
				       mem_type_mapping_tbl[idx].mem_name);
				goto done;
			}
			dbg_ptr = mem_type_mapping_tbl[idx].mem_Ptr;
			end_ptr = dbg_ptr + memory_size;
		}
		doneflag = mem_type_mapping_tbl[idx].done_flag;
		moal_get_system_time(phandle, &sec, &usec);
		PRINTM(MMSG, "Start %s output %u.%06u, please wait...\n",
		       mem_type_mapping_tbl[idx].mem_name, sec, usec);
		do {
			stat = woal_cmd52_rdwr_firmware(phandle, doneflag);
			if (RDWR_STATUS_FAILURE == stat)
				goto done;
			reg_start = dbg_dump_start_reg;
			reg_end = dbg_dump_end_reg;
			for (reg = reg_start; reg <= reg_end; reg++) {
				ret = woal_sdio_readb(phandle, reg, dbg_ptr);
				if (ret) {
					PRINTM(MMSG, "SDIO READ ERR\n");
					goto done;
				}
				if (dbg_ptr < end_ptr)
					dbg_ptr++;
				else
					PRINTM(MMSG,
					       "pre-allocced buf is not enough\n");
			}
			if (RDWR_STATUS_DONE == stat) {
#ifdef MLAN_64BIT
				PRINTM(MMSG,
				       "%s done:"
				       "size = 0x%lx\n",
				       mem_type_mapping_tbl[idx].mem_name,
				       dbg_ptr - mem_type_mapping_tbl[idx]
				       .mem_Ptr);
#else
				PRINTM(MMSG,
				       "%s done:"
				       "size = 0x%x\n",
				       mem_type_mapping_tbl[idx].mem_name,
				       dbg_ptr - mem_type_mapping_tbl[idx]
				       .mem_Ptr);
#endif
				memset(file_name, 0, sizeof(file_name));
				sprintf(file_name, "%s%s", "file_sdio_",
					mem_type_mapping_tbl[idx].mem_name);
				if (MLAN_STATUS_SUCCESS !=
				    woal_save_dump_info_to_file(path_name,
								file_name,
								mem_type_mapping_tbl
								[idx].mem_Ptr,
								memory_size))
					PRINTM(MERROR,
					       "Can't save dump file %s in %s\n",
					       file_name, path_name);
				moal_vfree(phandle,
					   mem_type_mapping_tbl[idx].mem_Ptr);
				mem_type_mapping_tbl[idx].mem_Ptr = NULL;
				break;
			}
		} while (1);
	}
	moal_get_system_time(phandle, &sec, &usec);
	PRINTM(MMSG, "==== DEBUG MODE OUTPUT END: %u.%06u ====\n", sec, usec);
	/* end dump fw memory */
	memset(firmware_dump_file, 0, sizeof(firmware_dump_file));
	sprintf(firmware_dump_file, "%s/%s", path_name, file_name);
	moal_memcpy_ext(phandle, phandle->firmware_dump_file,
			firmware_dump_file, sizeof(firmware_dump_file),
			sizeof(phandle->firmware_dump_file));
done:
	for (idx = 0; idx < dump_num; idx++) {
		if (mem_type_mapping_tbl[idx].mem_Ptr) {
			moal_vfree(phandle, mem_type_mapping_tbl[idx].mem_Ptr);
			mem_type_mapping_tbl[idx].mem_Ptr = NULL;
		}
	}
	PRINTM(MMSG, "==== DEBUG MODE END ====\n");
	return;
}

/**
 *  @brief This function dump firmware memory to file
 *
 *  @param phandle   A pointer to moal_handle
 *
 *  @return         N/A
 */
void
woal_dump_firmware_info_v3(moal_handle *phandle)
{
	int ret = 0;
	int tries = 0;
	unsigned int reg, reg_start, reg_end;
	t_u8 *dbg_ptr = NULL;
	t_u8 *temp_Ptr = NULL;
	t_u32 sec, usec;
	t_u8 start_flag = 0;
	t_u8 doneflag = 0;
	rdwr_status stat;
	t_u32 memory_size = 0;
	t_u8 path_name[64], file_name[32], firmware_dump_file[128];
	t_u8 *end_ptr = NULL;
	t_u8 dbg_dump_start_reg = 0;
	t_u8 dbg_dump_end_reg = 0;
	memory_type_mapping *pmem_type_mapping_tbl =
		&mem_type_mapping_tbl_8977_8997;

	if (!phandle) {
		PRINTM(MERROR, "Could not dump firmwware info\n");
		return;
	}

	dbg_dump_start_reg = phandle->card_info->dump_fw_start_reg;
	dbg_dump_end_reg = phandle->card_info->dump_fw_end_reg;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 1, 0)
	/** Create dump directort*/
	woal_create_dump_dir(phandle, path_name, sizeof(path_name));
#else
	memset(path_name, 0, sizeof(path_name));
	strcpy(path_name, "/data");
#endif
	PRINTM(MMSG, "Directory name is %s\n", path_name);
	woal_dump_drv_info(phandle, path_name);

	/* start dump fw memory */
	moal_get_system_time(phandle, &sec, &usec);
	PRINTM(MMSG, "==== DEBUG MODE OUTPUT START: %u.%06u ====\n", sec, usec);
	/* read the number of the memories which will dump */
	if (RDWR_STATUS_FAILURE == woal_cmd52_rdwr_firmware(phandle, doneflag))
		goto done;

	/** check the reg which indicate dump starting */
	for (reg = dbg_dump_start_reg; reg <= dbg_dump_end_reg; reg++) {
		for (tries = 0; tries < MAX_POLL_TRIES; tries++) {
			ret = woal_sdio_readb(phandle, reg, &start_flag);
			if (ret) {
				PRINTM(MMSG, "SDIO READ ERR\n");
				goto done;
			}
			/** 0 means dump starting*/
			if (start_flag == 0)
				break;
			udelay(100);
		}
		if (tries == MAX_POLL_TRIES) {
			PRINTM(MMSG, "FW not ready to dump\n");
			goto done;
		}
	}
	memory_size = 0xF0000;
	PRINTM(MMSG, "%s_SIZE=0x%x\n", pmem_type_mapping_tbl->mem_name,
	       memory_size);
	ret = moal_vmalloc(phandle, memory_size + 1,
			   (t_u8 **)&pmem_type_mapping_tbl->mem_Ptr);
	if ((ret != MLAN_STATUS_SUCCESS) || !pmem_type_mapping_tbl->mem_Ptr) {
		PRINTM(MERROR, "Error: vmalloc %s buffer failed!!!\n",
		       pmem_type_mapping_tbl->mem_name);
		goto done;
	}
	dbg_ptr = pmem_type_mapping_tbl->mem_Ptr;
	end_ptr = dbg_ptr + memory_size;
	doneflag = pmem_type_mapping_tbl->done_flag;
	moal_get_system_time(phandle, &sec, &usec);
	PRINTM(MMSG, "Start %s output %u.%06u, please wait...\n",
	       pmem_type_mapping_tbl->mem_name, sec, usec);
	do {
		stat = woal_cmd52_rdwr_firmware(phandle, doneflag);
		if (RDWR_STATUS_FAILURE == stat)
			goto done;
		reg_start = dbg_dump_start_reg;
		reg_end = dbg_dump_end_reg;
		for (reg = reg_start; reg <= reg_end; reg++) {
			ret = woal_sdio_readb(phandle, reg, dbg_ptr);
			if (ret) {
				PRINTM(MMSG, "SDIO READ ERR\n");
				goto done;
			}
			dbg_ptr++;
			if (dbg_ptr >= end_ptr) {
				PRINTM(MMSG,
				       "pre-allocced buf is not enough\n");
				ret = moal_vmalloc(phandle,
						   memory_size + 0x4000 + 1,
						   (t_u8 **)&temp_Ptr);
				if ((ret != MLAN_STATUS_SUCCESS) || !temp_Ptr) {
					PRINTM(MERROR,
					       "Error: vmalloc  buffer failed!!!\n");
					goto done;
				}
				moal_memcpy_ext(phandle, temp_Ptr,
						pmem_type_mapping_tbl->mem_Ptr,
						memory_size,
						memory_size + 0x4000);
				moal_vfree(phandle,
					   pmem_type_mapping_tbl->mem_Ptr);
				pmem_type_mapping_tbl->mem_Ptr = temp_Ptr;
				temp_Ptr = NULL;
				dbg_ptr = pmem_type_mapping_tbl->mem_Ptr +
					memory_size;
				memory_size += 0x4000;
				end_ptr = pmem_type_mapping_tbl->mem_Ptr +
					memory_size;
			}
		}
		if (RDWR_STATUS_DONE == stat) {
#ifdef MLAN_64BIT
			PRINTM(MMSG,
			       "%s done:"
			       "size = 0x%lx\n",
			       pmem_type_mapping_tbl->mem_name,
			       dbg_ptr - pmem_type_mapping_tbl->mem_Ptr);
#else
			PRINTM(MMSG,
			       "%s done:"
			       "size = 0x%x\n",
			       pmem_type_mapping_tbl->mem_name,
			       dbg_ptr - pmem_type_mapping_tbl->mem_Ptr);

#endif
			memset(file_name, 0, sizeof(file_name));
			sprintf(file_name, "%s%s", "file_sdio_",
				pmem_type_mapping_tbl->mem_name);
			if (MLAN_STATUS_SUCCESS !=
			    woal_save_dump_info_to_file(path_name, file_name,
							pmem_type_mapping_tbl->
							mem_Ptr,
							dbg_ptr -
							pmem_type_mapping_tbl->
							mem_Ptr))
				PRINTM(MERROR,
				       "Can't save dump file %s in %s\n",
				       file_name, path_name);
			moal_vfree(phandle, pmem_type_mapping_tbl->mem_Ptr);
			pmem_type_mapping_tbl->mem_Ptr = NULL;
			break;
		}
	} while (1);
	moal_get_system_time(phandle, &sec, &usec);
	PRINTM(MMSG, "==== DEBUG MODE OUTPUT END: %u.%06u ====\n", sec, usec);
	/* end dump fw memory */
	memset(firmware_dump_file, 0, sizeof(firmware_dump_file));
	sprintf(firmware_dump_file, "%s/%s", path_name, file_name);
	moal_memcpy_ext(phandle, phandle->firmware_dump_file,
			firmware_dump_file, sizeof(firmware_dump_file),
			sizeof(phandle->firmware_dump_file));
done:
	if (pmem_type_mapping_tbl->mem_Ptr) {
		moal_vfree(phandle, pmem_type_mapping_tbl->mem_Ptr);
		pmem_type_mapping_tbl->mem_Ptr = NULL;
	}
	PRINTM(MMSG, "==== DEBUG MODE END ====\n");
	return;
}

/**
 *  @brief This function reads and displays SDIO registers for debugging
 *
 *  @param phandle  A pointer to moal_handle
 *
 *  @return         N/A
 */
static void
woal_sdiommc_reg_dbg(moal_handle *phandle)
{
	int ret = 0;
	t_u8 loop, index = 0, func, data;
	unsigned int reg, reg_start, reg_end;
	unsigned int scratch_reg = phandle->card_info->scratch_reg;
	t_u8 *reg_table = phandle->card_info->dump_reg.reg_table;
	t_u8 reg_table_size = phandle->card_info->dump_reg.reg_table_size;
	char buf[256], *ptr;

	mlan_pm_wakeup_card(phandle->pmlan_adapter, MTRUE);
	for (loop = 0; loop < 5; loop++) {
		memset(buf, 0, sizeof(buf));
		ptr = buf;
		if (loop == 0) {
			/* Read the registers of SDIO function0 */
			func = loop;
			reg_start = 0;
			reg_end = 9;
		} else if (loop == 1) {
			/* Read the registers of SDIO function1 */
			func = loop;
			reg_start = phandle->card_info->func1_reg_start;
			reg_end = phandle->card_info->func1_reg_end;
		} else if (loop == 2) {
			/* Read specific registers of SDIO function1 */
			index = 0;
			func = 1;
			reg_start = reg_table[index++];
			reg_end = reg_table[reg_table_size - 1];
		} else {
			/* Read the scratch registers of SDIO function1 */
			if (loop == 4)
				mdelay(100);
			func = 1;
			reg_start = scratch_reg;
			reg_end = scratch_reg + 10;
		}
		if (loop != 2)
			ptr += sprintf(ptr, "SDIO Func%d (%#x-%#x): ", func,
				       reg_start, reg_end);
		else
			ptr += sprintf(ptr, "SDIO Func%d: ", func);
		for (reg = reg_start; reg <= reg_end;) {
			if (func == 0)
				ret = woal_sdio_f0_readb(phandle, reg, &data);
			else
				ret = woal_sdio_readb(phandle, reg, &data);
			if (loop == 2)
				ptr += sprintf(ptr, "(%#x) ", reg);
			if (!ret)
				ptr += sprintf(ptr, "%02x ", data);
			else {
				ptr += sprintf(ptr, "ERR");
				break;
			}
			if (loop == 2 && reg < reg_end)
				reg = reg_table[index++];
			else
				reg++;
		}
		PRINTM(MMSG, "%s\n", buf);
	}
	mlan_pm_wakeup_card(phandle->pmlan_adapter, MFALSE);
}

/**
 *  @brief This function dump firmware memory to file
 *
 *  @param phandle   A pointer to moal_handle
 *
 *  @return         N/A
 */
static void
woal_sdiommc_dump_fw_info(moal_handle *phandle)
{
	if (!phandle) {
		PRINTM(MERROR, "Could not dump firmwware info\n");
		return;
	}
	mlan_pm_wakeup_card(phandle->pmlan_adapter, MTRUE);
	phandle->fw_dump = MTRUE;
	if (phandle->card_info->dump_fw_info == DUMP_FW_SDIO_V2) {
		woal_dump_firmware_info_v2(phandle);
	} else if (phandle->card_info->dump_fw_info == DUMP_FW_SDIO_V3) {
		woal_dump_firmware_info_v3(phandle);
		if (phandle->event_fw_dump) {
			phandle->event_fw_dump = MFALSE;
			queue_work(phandle->workqueue, &phandle->main_work);
			phandle->is_fw_dump_timer_set = MTRUE;
			woal_mod_timer(&phandle->fw_dump_timer, MOAL_TIMER_5S);
			return;
		}
	}
	woal_send_fw_dump_complete_event(woal_get_priv
					 (phandle, MLAN_BSS_ROLE_ANY));
	phandle->fw_dump = MFALSE;
	mlan_pm_wakeup_card(phandle->pmlan_adapter, MFALSE);
	queue_work(phandle->workqueue, &phandle->main_work);
	woal_process_hang(phandle);
	return;
}

/**
 *  @brief This function save sdio reg info
 *
 *  @param phandle   A pointer to moal_handle
 *  @param buf       A pointer buffer saving log
 *
 *  @return          The length of this log
 */
static int
woal_sdiommc_dump_reg_info(moal_handle *phandle, t_u8 *drv_buf)
{
	char *drv_ptr = (char *)drv_buf;
	int ret = 0;
	t_u8 loop, index = 0, func, data;
	unsigned int reg, reg_start, reg_end;
	unsigned int scratch_reg = 0;
	t_u8 *reg_table = NULL;
	t_u8 reg_table_size = 0;
	char buf[256], *ptr;

	ENTER();

	if (!phandle || !drv_buf) {
		PRINTM(MMSG, "%s: can't retreive info\n", __func__);
		LEAVE();
		return 0;
	}

	scratch_reg = phandle->card_info->scratch_reg;
	reg_table = phandle->card_info->dump_reg.reg_table;
	reg_table_size = phandle->card_info->dump_reg.reg_table_size;

	mlan_pm_wakeup_card(phandle->pmlan_adapter, MTRUE);

	drv_ptr += sprintf(drv_ptr, "--------sdio_reg_debug_info---------\n");
	for (loop = 0; loop < 5; loop++) {
		memset(buf, 0, sizeof(buf));
		ptr = buf;
		if (loop == 0) {
			/* Read the registers of SDIO function0 */
			func = loop;
			reg_start = 0;
			reg_end = 9;

		} else if (loop == 1) {
			/* Read the registers of SDIO function1 */
			func = loop;
			reg_start = phandle->card_info->func1_reg_start;
			reg_end = phandle->card_info->func1_reg_end;
		} else if (loop == 2) {
			/* Read specific registers of SDIO function1 */
			index = 0;
			func = 1;
			reg_start = reg_table[index++];
			reg_end = reg_table[reg_table_size - 1];
		} else {
			/* Read the scratch registers of SDIO function1 */
			if (loop == 4)
				mdelay(100);
			func = 1;
			reg_start = scratch_reg;
			reg_end = scratch_reg + 10;
		}
		if (loop != 2)
			ptr += sprintf(ptr, "SDIO Func%d (%#x-%#x): ", func,
				       reg_start, reg_end);
		else
			ptr += sprintf(ptr, "SDIO Func%d: ", func);
		for (reg = reg_start; reg <= reg_end;) {
			if (func == 0)
				ret = woal_sdio_f0_readb(phandle, reg, &data);
			else
				ret = woal_sdio_readb(phandle, reg, &data);

			if (loop == 2)
				ptr += sprintf(ptr, "(%#x) ", reg);
			if (!ret)
				ptr += sprintf(ptr, "%02x ", data);
			else {
				ptr += sprintf(ptr, "ERR");
				break;
			}
			if (loop == 2 && reg < reg_end)
				reg = reg_table[index++];
			else
				reg++;
		}
		drv_ptr += sprintf(drv_ptr, "%s\n", buf);
	}

	drv_ptr +=
		sprintf(drv_ptr, "--------sdio_reg_debug_info End---------\n");
	mlan_pm_wakeup_card(phandle->pmlan_adapter, MFALSE);

	LEAVE();
	return drv_ptr - (char *)drv_buf;
}

/**
 *  @brief This function reset sdio through sdio bus driver
 *
 *  @param phandle   A pointer to moal_handle
 *
 *  @return          N/A
 */
void
woal_sdio_reset_hw(moal_handle *handle)
{
	struct sdio_mmc_card *card = handle->card;
	struct sdio_func *func = card->func;
	ENTER();
	sdio_claim_host(func);
	sdio_release_irq(card->func);
	sdio_disable_func(card->func);
	mmc_hw_reset(func->card->host);
#ifdef MMC_QUIRK_BLKSZ_FOR_BYTE_MODE
	/* The byte mode patch is available in kernel MMC driver
	 * which fixes one issue in MP-A transfer.
	 * bit1: use func->cur_blksize for byte mode
	 */
	func->card->quirks |= MMC_QUIRK_BLKSZ_FOR_BYTE_MODE;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
	func->card->quirks |= MMC_QUIRK_LENIENT_FN0;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
	/* wait for chip fully wake up */
	if (!func->enable_timeout)
		func->enable_timeout = 200;
#endif
	sdio_enable_func(func);
	sdio_claim_irq(func, woal_sdio_interrupt);
	sdio_set_block_size(card->func, MLAN_SDIO_BLOCK_SIZE);
	sdio_release_host(func);
	LEAVE();
	return;
}

static moal_if_ops sdiommc_ops = {
	.register_dev = woal_sdiommc_register_dev,
	.unregister_dev = woal_sdiommc_unregister_dev,
	.read_reg = woal_sdiommc_read_reg,
	.write_reg = woal_sdiommc_write_reg,
	.read_data_sync = woal_sdiommc_read_data_sync,
	.write_data_sync = woal_sdiommc_write_data_sync,
	.get_fw_name = woal_sdiommc_get_fw_name,
	.dump_fw_info = woal_sdiommc_dump_fw_info,
	.dump_reg_info = woal_sdiommc_dump_reg_info,
	.reg_dbg = woal_sdiommc_reg_dbg,
};
