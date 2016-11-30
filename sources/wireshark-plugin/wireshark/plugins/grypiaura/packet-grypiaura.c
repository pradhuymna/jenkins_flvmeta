/* packet-echo.c
 * Routines for ECHO packet disassembly (RFC862)
 *
 * Only useful to mark the packets as ECHO in the summary and in the
 * protocol hierarchy statistics (since not so many fields to decode ;-)
 *
 * Laurent Deniel <laurent.deniel@free.fr>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"
#include <ctype.h>
#include <epan/packet.h>

#define ECHO_PORT  15678
#include "t.h"
char * fun(char *,int , char *);
char* ParseMTI(int ,char* );
char* DumpMTIFeild(int , int );

struct Temp 
{
	int value;
	char *pInfo;
};
/*
   struct DATA
   {
   char *s;
   int len;
   };
 */

/*
   struct Data
   {
   int 	value;
   char 	*pDataType;
   int 	DataSize;
   char 	*pInfo;
   };
 */
typedef struct Temp MTIMsgVersion;
typedef struct Temp MTIMsgClass;
typedef struct Temp MTIMsgSubClass;
typedef struct Temp MTIMsgOrigin;
//typedef struct Data MTIMsgData;

typedef struct _ISO8583Info
{
	MTIMsgVersion  	Ver[10];
	MTIMsgClass 	Class[10];
	MTIMsgSubClass	SClass[10];
	MTIMsgOrigin	Orign[6];
	//	MTIMsgData	Feilds[128];
}ISO8583Info;

ISO8583Info Info={
	/*MTI Description*/
	/*Version*/
	{
		{0,	"ISO 8583-1:1987 version"},
		{1,	"ISO 8583-2:1993 version"},
		{2,	"ISO 8583-3:2003 version"},
		{3,	"Reserved for ISO use"},
		{4,	"Reserved for ISO use"},
		{5,	"Reserved for ISO use"},
		{6,	"Reserved for ISO use"},
		{7,	"Reserved for ISO use"},
		{8,	"Reserved for National use"},
		{9,	"Reserved for Private use"}
	},
	/*Msg Class*/
	{
		{0,	"Not In Use"},
		{1,	"Authorization Message"},
		{2,	"Financial Messages"},
		{3,	"File Actions Message"},
		{4,	"Reversal and Chargeback Messages"},
		{5,	"Reconciliation Message"},
		{6,	"Administrative Message"},
		{7,	"Fee Collection Messages"},
		{8,	"Network Management Message"},
		{9,	"Reserved by ISO"}
	},
	/*SubClass- Function*/
	{
		{0,	"Request"},
		{1,	"Request Response"},
		{2,	"Advice"},
		{3,	"Advice Response"},
		{4,	"Notification"},
		{5,	"Notification Acknowledgement"},
		{6,	"Instruction (ISO 8583:2003 only)"},
		{7,	"Instruction Acknowledgement (ISO 8583:2003 only)"},
		{8,	"Reserved for ISO use.(Response acknowledgment) "},
		{9,	"Reserved for ISO use.(Negative acknowledgment)"}
	},
	/*Msg Origin*/
	{
		{1,	"Acquirer"},
		{2,	"Acquirer Repeat"},
		{3,	"Issuer"},
		{4,	"Issuer Repeat"},
		{5,	"Other"},
		{6,	"Other Repeat"}
	}
	/*Data Feilds Information*/
};



struct DATA1 
{
	char *s;
	int len;
};

struct DATA1 data[128]={
	{"1.Secondary bitmap",16},
	{"2.Primary account number(PAN)",0},
	{"3.Processing code",6},
	{"4.Amount transaction",12},
	{"5.Amount settlement",12},
	{"6.Amount cardholder billing",12},
	{"7.Transmission date & time",10},
	{"8.Amount cardholder billing fee",8},
	{"9.Conversion rate, settlement",8},
	{"10.Conversion rate, cardholder billing",8},
	{"11.System trace audit number",6},
	{"12.Time, local transaction (hhmmss)",6},
	{"13.Date, local transaction (MMDD)",4},
	{"14.Date, expiration",4},
	{"15.Date, settlement",4},
	{"16.Date, conversion",4},
	{"17.Date, capture",4},
	{"18.Merchant type",4},
	{"19.Acquiring institution country code",3},
	{"20.PAN extended, country code",3},
	{"21.Forwarding institution. country code",3},
	{"22.Point of service entry mode",3},
	{"23.Application PAN sequence number",3},
	{"24.Function code ",3},
	{"25.Point of service condition code",2},
	{"26.Point of service capture code",2},
	{"27.Authorizing identification response length",1},
	{"28.Amount, transaction fee",8},
	{"29.Amount, settlement fee",8},
	{"30.Amount, transaction processing fee",8},
	{"31.Amount, settlement processing fee",8},
	{"32.Acquiring institution identification code",0},
	{"33.Forwarding institution identification code",0},
	{"34.Primary account number, extended",0},
	{"35.Track 2 data",0},
	{"36.Track 3 data",0},
	{"37.Retrieval reference number",12},
	{"38.Authorization identification response",6},
	{"39.Response code",2},
	{"40.Service restriction code",3},
	{"41.Card acceptor terminal identification",10},
	{"42.Card acceptor identification code",15},
	{"43.Card acceptor name/location",22},
	{"44.Additional response data",0},
	{"45.Track 1 data",0},
	{"46.Additional data - ISO",0},
	{"47.Additional data - national",0},
	{"48.Additional data - private",0},
	{"49.Currency code, transaction",3},
	{"50.Currency code, settlement",3},
	{"51.Currency code, cardholder billing",3},
	{"52.Personal identification number data",16},
	{"53.Security related control information",18},
	{"54.Additional amounts",0},
	{"55.Reserved ISO",0},
	{"56.Reserved ISO",0},
	{"57.Reserved national",0},
	{"58.Reserved national",0},
	{"59.Reserved national",0},
	{"60.Reserved national",0},
	{"61.Reserved private",0},
	{"62.Reserved private",0},
	{"63.Reserved private",0},
	{"64.Message authentication code (MAC)",16},
	{"65.Bitmap, extended",0},
	{"66.Settlement code",1},
	{"67.Extended payment code",2},
	{"68.Receiving institution country code",3},
	{"69.Settlement institution country code",3},
	{"70.Network management information code",3},
	{"71.Message number",4},
	{"72.Message number, last",0},
	{"73.Date, action (YYMMDD)",6},
	{"74.Credits, number",10},
	{"75.Credits, reversal number",10},
	{"76.Debits, number",10},
	{"77.Debits, reversal number",10},
	{"78.Transfer number",10},
	{"79.Transfer, reversal number",10},
	{"80.Inquiries number",10},
	{"81.Authorizations, number",10},
	{"82.Credits, processing fee amount",12},
	{"83.Credits, transaction fee amount",12},
	{"84.Debits, processing fee amount",12},
	{"85.Debits, transaction fee amount",12},
	{"86.Credits, amount",15},
	{"87.Credits, reversal amount",15},
	{"88.Debits, amount",15},
	{"89.Debits, reversal amount",15},
	{"90.Original data elements",42},
	{"91.File update code",1},
	{"92.File security code",2},
	{"93.Response indicator",5},
	{"94.Service indicator",7},
	{"95.Replacement amounts",42},
	{"96.Message security code",8},
	{"97.Amount, net settlement",16},
	{"98.Payee",25},	
	{"99.Settlement institution identification code",0},
	{"100.Receiving institution identification code",0},
	{"101.File name",0},
	{"102.Account identification 1",0},
	{"103.Account identification 2",0},
	{"104.Transaction description",0},
	{"105.Reserved for ISO use",0},
	{"106.Reserved for ISO use",0},
	{"107.Reserved for ISO use",0},
	{"108.Reserved for ISO use",0},
	{"109.Reserved for ISO use",0},
	{"110.Reserved for ISO use",0},
	{"111.Reserved for ISO use",0},
	{"112.Reserved for national use",0},
	{"113.Reserved for national use",0},
	{"114.Reserved for national use",0},
	{"115.Reserved for national use",0},
	{"116.Reserved for national use",0},
	{"117.Reserved for national use",0},
	{"118.Reserved for national use",0},
	{"119.Reserved for national use",0},
	{"120.Reserved for private use",0},
	{"121.Reserved for private use",0},
	{"122.Reserved for private use",0},
	{"123.Reserved for private use",0},
	{"124.Reserved for private use",0},
	{"125.Reserved for private use",0},
	{"126.Reserved for private use",0},
	{"127.Reserved for private use",0},
	{"128.Message authentication code",16}
};


int conv(char c)
{
	int num=0;
	if(isdigit(c)) 
		num = c -'0';
	else if(c>='a' && c<='f')
		num = 10 + c - 'a';
	else if(c>='A' && c<='F')
		num = 10 + c - 'A';
	return num;
}

char * fun(char *start, int len, char *dest)
{
	strncpy(dest, start, len);

	return (start+len);
}

char* ParseMTI(int a,char* pMTI)
{
	char* ptr =	DumpMTIFeild(a,pMTI[a]-'0');
	return ptr;
	//	DumpMTIFeild(1,pMTI[1]-'0');
	//	DumpMTIFeild(2,pMTI[2]-'0');
	//	DumpMTIFeild(3,pMTI[3]-'0');
}

char* DumpMTIFeild(int pos, int value)
{	
	switch(pos)
	{
		case 0:
			return( Info.Ver[value].pInfo);
			break;
		case 1:
			return(Info.Class[value].pInfo);
			break;
		case 2:
			return(Info.SClass[value].pInfo);
			break;
		case 3:	
			return(Info.Orign[value].pInfo);
			break;
		default:
			break;
	}
	return 0;
}

int proto_register_echo(void);
void proto_reg_handoff_echo(void);

static int proto_echo = -1;

static int hf_echo_data = -1;
static int hf_echo_request = -1;
static int hf_echo_response = -1;
static int hf_echo_header = -1;
static gint ett_echo = -1;

static void dissect_echo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	char a[100],d[1024],sbitmap[20];
	int count = 0,len=0,l=0;
	char *temp,*str;
	int n=0,k=0,bi=0;
	int i =0,j=0;
	int         offset    = 0;
	gboolean    request   = FALSE;
	int retval            = 0;
	char local_data[4096] = {0};
	g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);
	if (pinfo->destport == ECHO_PORT) 
	{
		g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);
		request = TRUE;
		g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);
	}

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "AuraNetworks");
	g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);
	col_set_str(pinfo->cinfo, COL_INFO, (request) ? "Request" : "Response");
	g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);

	g_warning("-->%d. length :%d", __LINE__, tvb->length);
	g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);
	g_warning("-->%d. rlenth :%d", __LINE__, tvb->reported_length);
	g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);

	retval = tvb_get_nstringz0(tvb, 0, tvb->length, local_data);
	g_warning("-->%d. retval :%d", __LINE__, retval);
	local_data[retval] = '\0';
	if (tree) 
	{
		proto_tree *echo_tree=NULL;
		proto_tree *MTI_tree=NULL;
		proto_tree *BMAP_tree=NULL;
		proto_tree *PRIMARY_tree=NULL;
		proto_tree *SECONDARY_tree=NULL;

		proto_item *ti = NULL;
		proto_item *pi = NULL;
		proto_item *qi = NULL;
		proto_item *ri = NULL;
		//*pi,*ri,*qi,*hidden_item;
		char *si;

		ti = proto_tree_add_item(tree, proto_echo, tvb, offset, -1, ENC_NA);
		echo_tree = proto_item_add_subtree(ti, ett_echo);
		g_warning("--> going to add request of data");

		proto_tree_add_text(echo_tree,tvb,offset,-1,"len = %d",tvb->length);
		g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);
		proto_tree_add_item(echo_tree, hf_echo_data,     tvb, offset,  -1, ENC_NA);

		temp = fun(local_data, 12, a);
		strncpy(a, local_data, 12);
		
		a[ISO8583_HEADER] = '\0';
		g_warning("------>%s\n",a);


		// strncpy(a, local_data, ISO8583_HEADER);
		//g_warning("---->%s\n", a);
		proto_tree_add_text(echo_tree, tvb, offset, -1, "ISO Header : %s", a);

		strncpy(a,temp,4);
		temp = fun(temp,4,a);
		a[ISO8583_MTI_SIZE] = '\0';
		g_warning("------>%s\n",a);
		ri = proto_tree_add_text(echo_tree,tvb,offset,-1,"MTI");
		MTI_tree = proto_item_add_subtree(ri, ett_echo);
		proto_tree_add_text(MTI_tree,tvb,offset,-1,"%s",a);
		for(i=0;i<4;i++)
		{
			//proto_tree_add_text(echo_tree,tvb,offset,-1,"%c:",a[i]);
			si= ParseMTI(i,a);
			g_warning("---->%s\n",si);
			proto_tree_add_text(MTI_tree,tvb,offset,-1,"%c :%s",a[i],si);
		}
		strncpy(a,temp,16);
		temp = fun(temp,16,a);
		a[ISO8583_PBITMAP_SIZE]='\0';
		g_warning("------>%s\n",a);
		pi = proto_tree_add_text(echo_tree,tvb,offset,-1,"BIT MAP");

		BMAP_tree = proto_item_add_subtree(pi, ett_echo);

		echo_tree = proto_tree_add_text(BMAP_tree,tvb,offset,-1,"PRIMARY BITMAP :%s",a);
		PRIMARY_tree = proto_item_add_subtree(echo_tree, ett_echo);
		//	DATA_ELEMENTS(a,temp);
		for(i=0; i<16 ;i++)
		{

			g_warning("hex digit number  :%c\n",a[i]);
			n=conv(a[i]);
			g_warning("decimal number is :>%d\n",n);
			for(j=3;j>=0;j--)
			{
				//static int count = 0;
				int m=0;
				m=n & (1<<j);
				count++;
				if(m!=0)
				{
					k = count;
					g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);
					g_warning("PRESENT POSITION : %d\n",k);

					str  = data[k-1].s; 
					g_warning("RESPECTIVE FIELD  : >%s\n",str);

					len = data[k-1].len;
					g_warning("FIELD LENGTH  : >%d\n",len);

					if( k == 2 || (k >= 32 && k <= 35) || k ==44 || k ==45 || (k >= 99 && k <= 103) )
					{	
						strncpy(d,temp,2);
						d[2]='\0';
						g_warning("RESPECTIVE FIELD  : >%s\n",d);
						l =atoi(d);
						len +=l;
						g_warning("FIELD LENGTH  : >%d\n",len);
						temp=temp+2;
					}
					else if(k == 36||(k >= 46 && k <= 48)||(k >= 54 && k<= 63) || k==104 || k ==72)
					{	
						strncpy(d,temp,3);
						d[3]='\0';
						g_warning("RESPECTIVE FIELD  : >%s\n",d);
						l =atoi(d);
						len += l;
						g_warning("FIELD LENGTH  : >%d\n",len);
						temp=temp+3;
					}
					strncpy(d,temp,len);
					d[len]='\0';
					if(k == 1)
					{
						bi = 1;
						strncpy(sbitmap,d,len);
						sbitmap[len] = '\0';
					}
					g_warning("REQUEST MSG IS : ------>%s\n",d);
					qi= proto_tree_add_text(PRIMARY_tree,tvb,offset,-1,"%s :%s",str,d);
					ri=proto_item_add_subtree(qi, ett_echo);
					temp = fun(temp,len,d);
				}
			}
		}
		if(bi == 1)
		{
			echo_tree = proto_tree_add_text(BMAP_tree,tvb,offset,-1,"SECONDARY BITMAP :%s",sbitmap);
			SECONDARY_tree = proto_item_add_subtree(echo_tree, ett_echo);
			g_warning("sbitmap IS : ------>%s\n",sbitmap);
			for(i=0; i<16 ;i++)
			{

				g_warning("hex digit number  :%c\n",sbitmap[i]);
				n=conv(sbitmap[i]);
				g_warning("decimal number is :>%d\n",n);
				for(j=3;j>=0;j--)
				{
					//		static int count = 0;
					int m=0;
					m=n & (1<<j);
					count++;
					if(m!=0)
					{
						k = count;
						g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);
						g_warning("PRESENT POSITION : %d\n",k);

						str  = data[k-1].s; 
						g_warning("RESPECTIVE FIELD  : >%s\n",str);

						len = data[k-1].len;
						g_warning("FIELD LENGTH  : >%d\n",len);

						if( k == 2 || (k >= 32 && k <= 35) || k ==44 || k ==45 || (k >= 99 && k <= 103) )
						{	
							strncpy(d,temp,2);
							d[2]='\0';
							g_warning("RESPECTIVE FIELD  : >%s\n",d);
							l =atoi(d);
							len +=l;
							g_warning("FIELD LENGTH  : >%d\n",len);
							temp=temp+2;
						}
						else if(k == 36||(k >= 46 && k <= 48)||(k >= 54 && k<= 63) || k==104 || k ==72)
						{	
							strncpy(d,temp,3);
							d[3]='\0';
							g_warning("RESPECTIVE FIELD  : >%s\n",d);
							l =atoi(d);
							len += l;
							g_warning("FIELD LENGTH  : >%d\n",len);
							temp=temp+3;
						}
						strncpy(d,temp,len);
						d[len]='\0';
						g_warning("REQUEST MSG IS : ------>%s\n",d);
						qi= proto_tree_add_text(SECONDARY_tree,tvb,offset,-1,"%s :%s",str,d);
						ri=proto_item_add_subtree(qi, ett_echo);
						temp = fun(temp,len,d);


					}
				}
			}

		}



	}	
}

int proto_register_echo(void)
{
	g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);

	static hf_register_info hf[] = {
		{ &hf_echo_data,
			{ "Echo data",    "echo.data",     FT_BYTES,   BASE_NONE, NULL, 0x0, NULL,        HFILL }},
		{ &hf_echo_request,
			{ "Echo request", "echo.request",  FT_BOOLEAN, BASE_NONE, NULL, 0x0, "Echo Request", HFILL }},
		{ &hf_echo_response,
			{ "Echo response","echo.response", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "Echo Data", HFILL }},
		{ &hf_echo_header,
			{ "Echo header","echo.header", FT_BYTES, BASE_NONE, NULL, 0x0, "Echo Operator", HFILL }},
	};

	static gint *ett[] = { &ett_echo};

//	proto_echo = proto_register_protocol("Echo", "ECHO", "echo");
	proto_echo = proto_register_protocol("AuraNet", "AURA", "aura");
	proto_register_field_array(proto_echo, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	return 0;
}

void proto_reg_handoff_echo(void)
{
	g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);

	dissector_handle_t echo_handle;
	g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);

	echo_handle = create_dissector_handle(dissect_echo, proto_echo);

//	dissector_add_uint("udp.port", ECHO_PORT, echo_handle);
	dissector_add_uint("tcp.port", ECHO_PORT, echo_handle);

}
