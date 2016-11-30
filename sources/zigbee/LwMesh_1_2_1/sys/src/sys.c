/**
 * \file sys.c
 *
 * \brief Main system routines implementation
 *
 * Copyright (C) 2012-2014, Atmel Corporation. All rights reserved.
 *
 * \asf_license_start
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. The name of Atmel may not be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * 4. This software may only be redistributed and used in connection with an
 *    Atmel microcontroller product.
 *
 * THIS SOFTWARE IS PROVIDED BY ATMEL "AS IS" AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT ARE
 * EXPRESSLY AND SPECIFICALLY DISCLAIMED. IN NO EVENT SHALL ATMEL BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * \asf_license_stop
 *
 * Modification and other use of this code is subject to Atmel's Limited
 * License Agreement (license.txt).
 *
 * $Id: sys.c,v 1.1 2015/02/02 09:20:35 bhagavan Exp $
 *
 */

/*- Includes ---------------------------------------------------------------*/
#include "sysConfig.h"
#include "phy.h"
#include "nwk.h"
#include "hal.h"
#include "sys.h"
#include "sysTimer.h"

/*- Implementations --------------------------------------------------------*/

/*************************************************************************//**
*****************************************************************************/
void SYS_Init(void)
{
	printf("-->%d. %s, %s\n", __LINE__, __FUNCTION__, __FILE__);

  HAL_Init();
	printf("-->%d. %s, %s\n", __LINE__, __FUNCTION__, __FILE__);
  SYS_TimerInit();
	printf("-->%d. %s, %s\n", __LINE__, __FUNCTION__, __FILE__);
  PHY_Init();
	printf("-->%d. %s, %s\n", __LINE__, __FUNCTION__, __FILE__);
  NWK_Init();
	printf("-->%d. %s, %s\n", __LINE__, __FUNCTION__, __FILE__);
}

/*************************************************************************//**
*****************************************************************************/
void SYS_TaskHandler(void)
{
  PHY_TaskHandler();
  NWK_TaskHandler();
  SYS_TimerTaskHandler();
}
