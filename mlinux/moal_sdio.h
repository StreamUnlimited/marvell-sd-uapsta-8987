/** @file moal_sdio.h
 *
 * @brief This file contains definitions for SDIO interface.
 * driver.
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
****************************************************/

#ifndef _MOAL_SDIO_H
#define _MOAL_SDIO_H

#include <linux/mmc/sdio.h>
#include <linux/mmc/sdio_ids.h>
#include <linux/mmc/sdio_func.h>
#include <linux/mmc/card.h>
#include <linux/mmc/host.h>

#include "moal_main.h"

#ifndef BLOCK_MODE
/** Block mode */
#define BLOCK_MODE 1
#endif

#ifndef BYTE_MODE
/** Byte Mode */
#define BYTE_MODE 0
#endif

#ifndef FIXED_ADDRESS
/** Fixed address mode */
#define FIXED_ADDRESS 0
#endif

/** Default firmware name */

#define SD8987_DEFAULT_COMBO_FW_NAME "nxp/sduart8987_combo.bin"
#define SDUART8987_DEFAULT_COMBO_FW_NAME "nxp/sduart8987_combo.bin"
#define SDSD8987_DEFAULT_COMBO_FW_NAME "nxp/sdsd8987_combo.bin"
#define SD8987_DEFAULT_WLAN_FW_NAME "nxp/sd8987_wlan.bin"

/********************************************************
		Global Functions
********************************************************/

/** Register to bus driver function */
mlan_status woal_sdiommc_bus_register(void);
/** Unregister from bus driver function */
void woal_sdiommc_bus_unregister(void);

int woal_sdio_set_bus_clock(moal_handle *handle, t_u8 option);

#ifdef SDIO_SUSPEND_RESUME
#ifdef MMC_PM_FUNC_SUSPENDED
/** Notify SDIO bus driver that WLAN is suspended */
void woal_wlan_is_suspended(moal_handle *handle);
#endif
/** SDIO Suspend */
int woal_sdio_suspend(struct device *dev);
/** SDIO Resume */
int woal_sdio_resume(struct device *dev);
#endif /* SDIO_SUSPEND_RESUME */

/** Structure: SDIO MMC card */
struct sdio_mmc_card {
	/** sdio_func structure pointer */
	struct sdio_func *func;
	/** moal_handle structure pointer */
	moal_handle *handle;
	/** saved host clock value */
	unsigned int host_clock;
};
void woal_sdio_reset_hw(moal_handle *handle);

/** cmd52 read write */
int woal_sdio_read_write_cmd52(moal_handle *handle, int func, int reg, int val);
#endif /* _MOAL_SDIO_H */
