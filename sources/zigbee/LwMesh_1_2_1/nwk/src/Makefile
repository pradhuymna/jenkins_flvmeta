zigbee : nwkDataReq.o nwkGroup.o nwkRouteDiscovery.o nwkSecurity.o nwk.o nwkFrame.o nwkRoute.o nwkRx.o 
	gcc -nwkDataReq.o nwkGroup.o nwkRouteDiscovery.o nwkSecurity.o nwk.o
	nwkFrame.o nwkRoute.o nwkRx.o -o zigbee
nwkDataReq.o : nwkDataReq.c
	gcc  nwkDataReq.c -g -c
nwkGroup.o : nwkGroup.c
	gcc  nwkGroup.c  -g -c
nwkRouteDiscovery.o : nwkRouteDiscovery.c
	gcc nwkRouteDiscovery.c -g -c
nwkSecurity.o : nwkSecurity.c
	gcc nwkSecurity.c -g -c
nwk.o : nwk.c
	gcc nwk.c -g -c
nwkFrame.o : nwkFrame.c
	gcc nwkFrame.c -g -c
nwkRoute.o : nwkRoute.c
	gcc nwkRoute.c -g -c
nwkRx.o : nwkRx.c
	gcc nwkRx.c -g -c




remove :
	rm -rf zigbee
	rm -rf *.o


