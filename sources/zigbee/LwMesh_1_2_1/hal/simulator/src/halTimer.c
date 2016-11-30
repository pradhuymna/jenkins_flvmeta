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
#include "hal.h"
#include "halTimer.h"

/*- Definitions ------------------------------------------------------------*/
#define ms    1000

/*- Variables --------------------------------------------------------------*/
volatile uint8_t halTimerIrqCount;

/*- Implementations --------------------------------------------------------*/

/*************************************************************************//**
*****************************************************************************/
void HAL_TimerInit(void)
{
	printf("-->%d. %s, %s\n", __LINE__, __FUNCTION__, __FILE__);

  SYS_TICK_COUNTER  = 0;
  SYS_TICK_PERIOD   = HAL_TIMER_INTERVAL * ms;
	printf("-->%d. %s, %s\n", __LINE__, __FUNCTION__, __FILE__);

}

/*************************************************************************//**
*****************************************************************************/
void HAL_TimerDelay(uint16_t us)
{
  for (uint16_t i = 0; i < us; i++)
    asm("nop");
}

/*************************************************************************//**
*****************************************************************************/
void HAL_TimerTaskHandler(void)
{
  uint32_t cnt = SYS_TICK_COUNTER;

  if (cnt)
  {
    SYS_TICK_COUNTER = 0; // TODO: this has potential to lose ticks
    halTimerIrqCount += cnt;
  }
}

