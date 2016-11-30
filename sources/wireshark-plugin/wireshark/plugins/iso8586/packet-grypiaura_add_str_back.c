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

#include <epan/packet.h>

#define ECHO_PORT  15678

void proto_register_echo(void);
void proto_reg_handoff_echo(void);

static int proto_echo = -1;

static int hf_echo_data = -1;
static int hf_echo_request = -1;
static int hf_echo_response = -1;
static int hf_echo_operation = -1;
static int hf_echo_values = -1;
static gint ett_echo = -1;

/*typedef struct data_t
{
	int rtype;
	int ans;
	char cmd[50];
}rdata;
*/
static void dissect_echo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	char a[20];
	int i=0;
//	int         offset    = 0;
	gboolean    request   = FALSE;
	int retval            = 0;
	char local_data[100]  = "";
//	rdata ldata;
	char tBuff[10];
	memset(tBuff,0,sizeof(tBuff));
	g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);
	if (pinfo->destport == ECHO_PORT) 
	{
		request = TRUE;
	}

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "AuraNetworks");
	col_set_str(pinfo->cinfo, COL_INFO, (request) ? "Request" : "Response");

	g_warning("-->%d. length :%d", __LINE__, tvb->length);
	g_warning("-->%d. rlenth :%d", __LINE__, tvb->reported_length);

	retval = tvb_get_nstringz0(tvb, 0, tvb->length, local_data);
	g_warning("-->%d. retval :%d", __LINE__, retval);
	local_data[retval] = '\0';
 	proto_tree_add_text(echo_tree,tvb,offset,-1,"%s :",local_data);
	for(i=0;i<2;i++)
	{
	 a[i] = tvb_get_guint8 (local_data,offset+i);
	}
	a[i]='\0';
	g_warning("---->%s\n ",a);
 	proto_tree_add_text(echo_tree,tvb,offset,-1,"Echo operation : %s\n",a);


	//pdata =  (rdata *)tvb;
	//tvb_memcpy(tvb, &ldata, 0,  tvb->length);

//	g_warning("-->rtype :%d", ldata.rtype);
//	g_warning("-->ans   :%d", ldata.ans);
//	g_warning("-->cmd   :%s", ldata.cmd);
	//strncpy(tBuff,ldata.cmd,3);
/*	strncpy(tBuff,ldata.cmd,3);
	if (tree) 
	{
		proto_tree *echo_tree;
		proto_item *ti, *hidden_item;

		ti = proto_tree_add_item(tree, proto_echo, tvb, offset, -1, ENC_NA);
		echo_tree = proto_item_add_subtree(ti, ett_echo);
		g_warning("--> going to add request of data");

		proto_tree_add_text(echo_tree,tvb,offset,-1,"len = %d type = '%s'",tvb->length,(ldata.rtype==1)?"Request":"Response");
        if(ldata.ans)
		proto_tree_add_text(echo_tree,tvb,offset,-1,"ans =%d",ldata.ans);
		if(request) 
		{
			g_warning("--> i am in request printing data");
			hidden_item = proto_tree_add_boolean(echo_tree, hf_echo_request, tvb,  0, 0, 1);
	 		g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);
		} 
		else 
		{
			g_warning("--> i am in response printing data");
			hidden_item = proto_tree_add_boolean(echo_tree, hf_echo_response, tvb, 0, 0, 1);
	 		g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);
		}
		PROTO_ITEM_SET_HIDDEN(hidden_item);

	 	g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);
	//	proto_tree_add_item(echo_tree, hf_echo_data,     tvb, offset,  -1, ENC_NA);
	 	g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);
	//	proto_tree_add_item(echo_tree, hf_echo_operation,tvb, offset+8, 3, FALSE);
	 	g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);
	//	proto_tree_add_item(echo_tree, hf_echo_values,   tvb, offset+12,2, TRUE);
	 	g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);
	//	proto_tree_add_item(echo_tree, hf_echo_values,   tvb, offset+15,2, TRUE);
	 	g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);
	

		for(i = 0; i < 3; i++)
		{
			a[i] = tvb_get_guint8 (tvb,offset+8+i);
		}

		a[i] = '\0';

		g_warning("---->%s\n ",a);
		proto_tree_add_text(echo_tree,tvb,offset,-1,"Echo operation : %s",a);
		for(i=0;i<2;i++)
		{
			a[i] = tvb_get_guint8 (tvb,offset+12+i);
		}
		a[i]='\0';
		g_warning("---->%s\n ",a);
		proto_tree_add_text(echo_tree,tvb,offset,-1,"Echo values : %s",a);
		for(i=0;i<2;i++)
		{
			a[i] = tvb_get_guint8 (tvb,offset+15+i);
		}
		a[i]='\0';
		g_warning("---->%s\n ",a);
		proto_tree_add_text(echo_tree,tvb,offset,-1,"Echo values : %s",a);
#if 0
		proto_tree_add_text(echo_tree,tvb,offset+8, 3, "Operator:");
#endif
	}
*/
} /* dissect_echo */

void proto_register_echo(void)
{
	 static hf_register_info hf[] = {
		{ &hf_echo_data,
			{ "Echo data",    "echo.data",     FT_BYTES,   BASE_NONE, NULL, 0x0, NULL,        HFILL }},
		{ &hf_echo_request,
			{ "Echo request", "echo.request",  FT_BOOLEAN, BASE_NONE, NULL, 0x0, "Echo Request", HFILL }},
		{ &hf_echo_response,
			{ "Echo response","echo.response", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "Echo Data", HFILL }},
		{ &hf_echo_operation,
			{ "Echo Operation","echo.operaiton", FT_BYTES, BASE_NONE, NULL, 0x0, "Echo Operator", HFILL }},
		{ &hf_echo_values,
			{ "Echo values",    "echo.values",  FT_BYTES, BASE_NONE, NULL, 0x0, "Echo Values", HFILL }},
	};

	static gint *ett[] = {
		&ett_echo
	};

	g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);

  //proto_echo = proto_register_protocol("Echo", "ECHO", "echo");
	proto_echo = proto_register_protocol("AuraNet", "AURA", "aura");
	proto_register_field_array(proto_echo, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_echo(void)
{
	dissector_handle_t echo_handle;

	g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);
	echo_handle = create_dissector_handle(dissect_echo, proto_echo);

	dissector_add_uint("udp.port", ECHO_PORT, echo_handle);
	dissector_add_uint("tcp.port", ECHO_PORT, echo_handle);

}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
