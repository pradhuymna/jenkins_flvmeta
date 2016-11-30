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

#ifndef _HAL_GPIO_H_
#define _HAL_GPIO_H_

/*- Includes ---------------------------------------------------------------*/
#include "sysTypes.h"

/*- Definitions ------------------------------------------------------------*/
#define HAL_GPIO_PIN(name, port, bit) \
  INLINE void    HAL_GPIO_##name##_set(void)      { } \
  INLINE void    HAL_GPIO_##name##_clr(void)      { } \
  INLINE void    HAL_GPIO_##name##_toggle(void)   { } \
  INLINE void    HAL_GPIO_##name##_in(void)       { } \
  INLINE void    HAL_GPIO_##name##_out(void)      { } \
  INLINE void    HAL_GPIO_##name##_pullup(void)   { } \
  INLINE uint8_t HAL_GPIO_##name##_read(void)     { return 0; } \
  INLINE uint8_t HAL_GPIO_##name##_state(void)    { return 0; }

#endif // _HAL_GPIO_H_

