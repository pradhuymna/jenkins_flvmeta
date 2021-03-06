/**
 * \file halStartup.c
 *
 * \brief ATSAMD20 startup code
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
 * $Id: halStartup.c,v 1.1 2015/02/02 09:20:21 bhagavan Exp $
 *
 */

/*- Includes ---------------------------------------------------------------*/
#include <unistd.h>

/*- Definitions ------------------------------------------------------------*/
#define DUMMY         __attribute__ ((weak, alias ("HAL_IrqHandlerDummy")))

/*- Variables --------------------------------------------------------------*/
extern void _stack_top(void);
extern unsigned int _etext;
extern unsigned int _data;
extern unsigned int _edata;
extern unsigned int _bss;
extern unsigned int _ebss;

/*- Prototypes -------------------------------------------------------------*/
void HAL_IrqHandlerReset(void);
DUMMY void HAL_IrqHandlerNmi(void);
DUMMY void HAL_IrqHandlerHardFault(void);
DUMMY void HAL_IrqHandlerSvCall(void);
DUMMY void HAL_IrqHandlerPendSv(void);
DUMMY void HAL_IrqHandlerSysTick(void);

DUMMY void HAL_IrqHandlerPm(void);
DUMMY void HAL_IrqHandlerSysctrl(void);
DUMMY void HAL_IrqHandlerWdt(void);
DUMMY void HAL_IrqHandlerRtc(void);
DUMMY void HAL_IrqHandlerEic(void);
DUMMY void HAL_IrqHandlerNvmctrl(void);
DUMMY void HAL_IrqHandlerEvsys(void);
DUMMY void HAL_IrqHandlerSercom0(void);
DUMMY void HAL_IrqHandlerSercom1(void);
DUMMY void HAL_IrqHandlerSercom2(void);
DUMMY void HAL_IrqHandlerSercom3(void);
DUMMY void HAL_IrqHandlerSercom4(void);
DUMMY void HAL_IrqHandlerSercom5(void);
DUMMY void HAL_IrqHandlerTc0(void);
DUMMY void HAL_IrqHandlerTc1(void);
DUMMY void HAL_IrqHandlerTc2(void);
DUMMY void HAL_IrqHandlerTc3(void);
DUMMY void HAL_IrqHandlerTc4(void);
DUMMY void HAL_IrqHandlerTc5(void);
DUMMY void HAL_IrqHandlerTc6(void);
DUMMY void HAL_IrqHandlerTc7(void);
DUMMY void HAL_IrqHandlerAdc(void);
DUMMY void HAL_IrqHandlerAc(void);
DUMMY void HAL_IrqHandlerDac(void);
DUMMY void HAL_IrqHandlerPtc(void);

void HAL_IrqHandlerDummy(void);

extern int main(void);

__attribute__ ((section(".vectors")))
void (* const vectors[])(void) =
{
  &_stack_top,                   // 0 - Initial Stack Pointer Value

  // Cortex-M0+ handlers
  HAL_IrqHandlerReset,           // 1 - Reset
  HAL_IrqHandlerNmi,             // 2 - NMI
  HAL_IrqHandlerHardFault,       // 3 - Hard Fault
  0,                             // 4 - Reserved
  0,                             // 5 - Reserved
  0,                             // 6 - Reserved
  0,                             // 7 - Reserved
  0,                             // 8 - Reserved
  0,                             // 9 - Reserved
  0,                             // 10 - Reserved
  HAL_IrqHandlerSvCall,          // 11 - SVCall
  0,                             // 12 - Reserved
  0,                             // 13 - Reserved
  HAL_IrqHandlerPendSv,          // 14 - PendSV
  HAL_IrqHandlerSysTick,         // 15 - SysTick

  // Peripheral handlers
  HAL_IrqHandlerPm,              // 0 - Power Manager
  HAL_IrqHandlerSysctrl,         // 1 - System Controller
  HAL_IrqHandlerWdt,             // 2 - Watchdog Timer
  HAL_IrqHandlerRtc,             // 3 - Real Time Counter
  HAL_IrqHandlerEic,             // 4 - External Interrupt Controller
  HAL_IrqHandlerNvmctrl,         // 5 - Non-Volatile Memory Controller
  HAL_IrqHandlerEvsys,           // 6 - Event System
  HAL_IrqHandlerSercom0,         // 7 - Serial Communication Interface 0
  HAL_IrqHandlerSercom1,         // 8 - Serial Communication Interface 1
  HAL_IrqHandlerSercom2,         // 9 - Serial Communication Interface 2
  HAL_IrqHandlerSercom3,         // 10 - Serial Communication Interface 3
  HAL_IrqHandlerSercom4,         // 11 - Serial Communication Interface 4
  HAL_IrqHandlerSercom5,         // 12 - Serial Communication Interface 5
  HAL_IrqHandlerTc0,             // 13 - Timer/Counter 0
  HAL_IrqHandlerTc1,             // 14 - Timer/Counter 1
  HAL_IrqHandlerTc2,             // 15 - Timer/Counter 2
  HAL_IrqHandlerTc3,             // 16 - Timer/Counter 3
  HAL_IrqHandlerTc4,             // 17 - Timer/Counter 4
  HAL_IrqHandlerTc5,             // 18 - Timer/Counter 5
  HAL_IrqHandlerTc6,             // 19 - Timer/Counter 6
  HAL_IrqHandlerTc7,             // 20 - Timer/Counter 7
  HAL_IrqHandlerAdc,             // 21 - Analog-to-Digital Converter
  HAL_IrqHandlerAc,              // 22 - Analog Comparator
  HAL_IrqHandlerDac,             // 23 - Digital-to-Analog Converter
  HAL_IrqHandlerPtc,             // 24 - Peripheral Touch Controller
};

/*- Implementations --------------------------------------------------------*/

/*************************************************************************//**
*****************************************************************************/
void HAL_IrqHandlerReset(void)
{
  unsigned int *src, *dst;

  src = &_etext;
  dst = &_data;
  while (dst < &_edata)
    *dst++ = *src++;

  dst = &_bss;
  while (dst < &_ebss)
    *dst++ = 0;

  main();
  while (1);
}

/*************************************************************************//**
*****************************************************************************/
void HAL_IrqHandlerDummy(void)
{
  while (1);
}

/*************************************************************************//**
*****************************************************************************/
void _exit(int status)
{
  (void)status;
  while (1);
}
