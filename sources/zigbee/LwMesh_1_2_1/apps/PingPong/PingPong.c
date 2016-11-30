/*
 * Copyright (c) 2014, Alex Taradov <taradov@gmail.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*- Includes ---------------------------------------------------------------*/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "config.h"
#include "hal.h"
#include "halTimer.h"
#include "phy.h"
#include "sys.h"
#include "nwk.h"
#include "nwkRoute.h"
#include "nwkSecurity.h"
#include "sysTimer.h"

/*- Definitions ------------------------------------------------------------*/
#define APP_MAX_PAYLOAD_SIZE    32

/*- Types ------------------------------------------------------------------*/
typedef enum AppState_t
{
  APP_STATE_INITIAL,
  APP_STATE_IDLE,
  APP_STATE_WAIT_CONF,
} AppState_t;

typedef struct PACK
{
  uint32_t     counter;
  uint8_t      data[APP_MAX_PAYLOAD_SIZE];
} AppData_t;

/*- Prototypes -------------------------------------------------------------*/
static void appSendData(void);

/*- Variables --------------------------------------------------------------*/
static AppState_t appState = APP_STATE_INITIAL;
static NWK_DataReq_t nwkDataReq;
static AppData_t appData;

/*- Implementations --------------------------------------------------------*/

/*************************************************************************//**
*****************************************************************************/
static bool appDataInd(NWK_DataInd_t *ind)
{
  AppData_t *data = (AppData_t *)ind->data;

  if (data->counter > appData.counter)
  {
    appData.counter = data->counter + 1;
    appSendData();
  }

  return true;
}

/*************************************************************************//**
*****************************************************************************/
static void appDataConf(NWK_DataReq_t *req)
{
  if (NWK_SUCCESS_STATUS == req->status)
  {
    appState = APP_STATE_IDLE;
  }
  else
  {
    NWK_DataReq(&nwkDataReq);
    appState = APP_STATE_WAIT_CONF;
  }
}

/*************************************************************************//**
*****************************************************************************/
static void appSendData(void)
{
  do
  {
    nwkDataReq.dstAddr = SYS_CTRL_RAND % APP_NWK_SIZE;
  } while (nwkDataReq.dstAddr == SYS_CTRL_ID);

  nwkDataReq.dstEndpoint = APP_ENDPOINT;
  nwkDataReq.srcEndpoint = APP_ENDPOINT;
  nwkDataReq.options = NWK_OPT_ACK_REQUEST | NWK_OPT_ENABLE_SECURITY;
  nwkDataReq.data = (uint8_t *)&appData;
  nwkDataReq.size = sizeof(appData);
  nwkDataReq.confirm = appDataConf;
  NWK_DataReq(&nwkDataReq);

  appState = APP_STATE_WAIT_CONF;
}

/*************************************************************************//**
*****************************************************************************/
static void appInit(void)
{
  appData.counter = 0;
  for (uint8_t i = 0; i < sizeof(appData.data); i++)
    appData.data[i] = 0x55;

  NWK_SetAddr(SYS_CTRL_ID);
  NWK_SetPanId(APP_PANID);
  PHY_SetChannel(APP_CHANNEL);
  PHY_SetRxState(true);

#ifdef NWK_ENABLE_SECURITY
  NWK_SetSecurityKey((uint8_t *)APP_SECURITY_KEY);
#endif

  NWK_OpenEndpoint(APP_ENDPOINT, appDataInd);

  srand(SYS_CTRL_RAND);

  appState = APP_STATE_IDLE;

  if (0 == SYS_CTRL_ID)
  {
    appData.counter = 1;
    appSendData();
  }
}

/*************************************************************************//**
*****************************************************************************/
static void APP_TaskHandler(void)
{
}

/*************************************************************************//**
*****************************************************************************/
int main(void)
{
	printf("-->%d. %s, %s\n", __LINE__, __FUNCTION__, __FILE__);

  SYS_Init();
	printf("-->%d. %s, %s\n", __LINE__, __FUNCTION__, __FILE__);
  appInit();
	printf("-->%d. %s, %s\n", __LINE__, __FUNCTION__, __FILE__);

  while (1)
  {
    SYS_TaskHandler();
    HAL_TimerTaskHandler();
    APP_TaskHandler();
  }
}

