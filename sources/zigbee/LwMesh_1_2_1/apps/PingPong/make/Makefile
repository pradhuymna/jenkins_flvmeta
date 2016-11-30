##############################################################################
CONFIG = Debug
#CONFIG = Release

##############################################################################
.PHONY: all directory clean size

STACK_PATH = ../../..
APP_PATH = ..

CC = gcc
OBJCOPY = objcopy
SIZE = size

CFLAGS += -W -Wall --std=gnu99 -Os
CFLAGS += -fdata-sections -ffunction-sections
CFLAGS += -funsigned-char -funsigned-bitfields
#CFLAGS += -mtune=cortex-m0plus -mthumb
CFLAGS += -MD -MP -MT $(CONFIG)/$(*F).o -MF $(CONFIG)/$(@F).d

ifeq ($(CONFIG), Debug)
  CFLAGS += -g
endif

LDFLAGS += -mcpu=cortex-m0plus -mthumb
LDFLAGS += -Wl,--gc-sections
LDFLAGS += -Wl,--script=../linker/simulator.ld

INCLUDES += \
  -I$(STACK_PATH)/hal/simulator/inc \
  -I$(STACK_PATH)/phy/simulator/inc \
  -I$(STACK_PATH)/nwk/inc \
  -I$(STACK_PATH)/sys/inc \
  -I$(APP_PATH) 

SRCS += \
  $(STACK_PATH)/hal/simulator/src/hal.c \
  $(STACK_PATH)/hal/simulator/src/halTimer.c \
  $(STACK_PATH)/hal/simulator/src/startup.c \
  $(STACK_PATH)/phy/simulator/src/phy.c \
  $(STACK_PATH)/nwk/src/nwk.c \
  $(STACK_PATH)/nwk/src/nwkDataReq.c \
  $(STACK_PATH)/nwk/src/nwkSecurity.c \
  $(STACK_PATH)/nwk/src/nwkFrame.c \
  $(STACK_PATH)/nwk/src/nwkGroup.c \
  $(STACK_PATH)/nwk/src/nwkRoute.c \
  $(STACK_PATH)/nwk/src/nwkRouteDiscovery.c \
  $(STACK_PATH)/nwk/src/nwkRx.c \
  $(STACK_PATH)/nwk/src/nwkTx.c \
  $(STACK_PATH)/sys/src/sys.c \
  $(STACK_PATH)/sys/src/sysTimer.c \
  $(STACK_PATH)/sys/src/sysEncrypt.c \
  $(APP_PATH)/PingPong.c 

DEFINES += \
  -DPHY_SIMULATOR \
  -DHAL_SIMULATOR \
  -DPLATFORM_SIMULATOR \
  -DF_CPU=1000000

CFLAGS += $(INCLUDES) $(DEFINES)

OBJS = $(addprefix $(CONFIG)/, $(notdir %/$(subst .c,.o, $(SRCS))))

all: directory $(CONFIG)/PingPong.elf $(CONFIG)/PingPong.hex $(CONFIG)/PingPong.bin size

$(CONFIG)/PingPong.elf: $(OBJS)
	@echo LD $@
	$(CC) $(LDFLAGS) $(OBJS) $(LIBS) -o $@

$(CONFIG)/PingPong.hex: $(CONFIG)/PingPong.elf
	@echo OBJCOPY $@
	$(OBJCOPY) -O ihex -R .eeprom $^ $@

$(CONFIG)/PingPong.bin: $(CONFIG)/PingPong.elf
	@echo OBJCOPY $@
	$(OBJCOPY) -O binary -R .eeprom $^ $@

%.o:
	@echo CC $@
	$(CC) $(CFLAGS) $(filter %$(subst .o,.c,$(notdir $@)), $(SRCS)) -c -o $@

directory:
	@mkdir -p $(CONFIG)

size: $(CONFIG)/PingPong.elf
	@echo size:
	$(SIZE) -t $^

clean:
	@echo clean
	-rm -rf $(CONFIG)

-include $(wildcard $(CONFIG)/*.d)

