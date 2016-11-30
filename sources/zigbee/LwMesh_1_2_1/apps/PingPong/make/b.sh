set -v
gcc Debug/hal.o Debug/halTimer.o Debug/startup.o Debug/phy.o Debug/nwk.o Debug/nwkDataReq.o Debug/nwkSecurity.o Debug/nwkFrame.o Debug/nwkGroup.o Debug/nwkRoute.o Debug/nwkRouteDiscovery.o Debug/nwkRx.o Debug/nwkTx.o Debug/sys.o Debug/sysTimer.o Debug/sysEncrypt.o Debug/PingPong.o  -o Debug/PingPong
