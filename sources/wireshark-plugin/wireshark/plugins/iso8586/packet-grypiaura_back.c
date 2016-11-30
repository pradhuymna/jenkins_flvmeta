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
#include <string.h>
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

static void dissect_echo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int i=0;
	//char a[20];
	int retval = 0;
	int offset = 0;
	gboolean request = FALSE;
	char local_data[200];
	char buff1[100];
	int j,p,a=0,r,g=0,l=0,k=0,s,f;

	if (pinfo->destport == ECHO_PORT) 
	{
		request = TRUE;
	}

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "AuraNetworks");
	col_set_str(pinfo->cinfo, COL_INFO, (request)?"Request" : "Response");
	//g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);

	g_warning("-->%d. length :%d", __LINE__, tvb->length);
	g_warning("-->%d. rlenth :%d", __LINE__, tvb->reported_length);

	retval = tvb_get_nstringz0(tvb, 0, tvb->length, local_data);
	g_warning("-->%d. retval :%d", __LINE__, retval);
	local_data[retval] = '\0';
	g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);
	g_warning("___________>%s\n ", local_data);
	 	g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);

	if (tree) 
	{
	 	g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);
		proto_tree *echo_tree;
	 	g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);
		proto_item *ti, *hidden_item;
	 	g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);

		ti = proto_tree_add_item(tree, proto_echo, tvb, offset, -1, ENC_NA);
	 	g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);
		echo_tree = proto_item_add_subtree(ti, ett_echo);
	 	g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);
		proto_tree_add_text(echo_tree,tvb,offset,-1,"Echo BUFF: %s",local_data);
	 	g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);
		g_warning("--> going to add request of data");
		proto_tree_add_text(echo_tree,tvb,offset,-1,"len = %d",strlen(local_data));
	 	g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);
	
	/*
		//proto_tree_add_text(echo_tree,tvb,offset,-1,"len = %d type = '%s'",tvb->length,(ldata.rtype == 1)?"Request":"Response");
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
		//proto_tree_add_item(echo_tree, hf_echo_data,     tvb, offset,  -1, ENC_NA);
	 	g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);
		//proto_tree_add_item(echo_tree, hf_echo_operation,tvb, offset+8, 3, FALSE);
	 	g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);
		//proto_tree_add_item(echo_tree, hf_echo_values,   tvb, offset+12,2, TRUE);
	 	g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);
		//proto_tree_add_item(echo_tree, hf_echo_values,   tvb, offset+15,2, TRUE);
	 	g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);
	*/
		g_warning("----------------> %s\n ",local_data);
		//for(i=0;local_data[i] == ' ' && buff[i] != '\0';i++);
		for(i=0;local_data[i] != ' ' ;i++)
			buff1[i]=local_data[i];
		buff1[i]='\0';
		g_warning("---->%s\n ",buff1);
		g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);


		for(j=i;local_data[j] == ' ' ;j++);
		g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);

		for(p=j;local_data[p] != ' ' ;p++)
			buff1[a++]=local_data[p];
		buff1[a]='\0';
		g_warning("---->%s\n ",buff1);
		g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);

		for(j=p;local_data[j] == ' ' ;j++);

		for(r=j ;local_data[r] != ' ' ;r++)
			buff1[g++] = local_data[r];
		buff1[g]='\0';
		g_warning("---->%s\n ",buff1);
		proto_tree_add_text(echo_tree,tvb,offset,-1,"Echo operation : %s",buff1);
		g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);

		for(j=r;local_data[j] == ' ' ;j++);
		//g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);

		for(s=j ;local_data[s] != ' ' ;s++)
			buff1[l++]=local_data[s];
		buff1[l]='\0';
		g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);
		g_warning("---->%s\n ",buff1);
		proto_tree_add_text(echo_tree,tvb,offset,-1,"Echo values : %s",buff1);
		g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);

		for(j=s;local_data[j] == ' ' ;j++);
		//g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);

		for(f=j ;local_data[f] != ' ' ;f++)
			buff1[k++]=local_data[f];
		buff1[k]='\0';
		g_warning("---->%s\n ",buff1);
		g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);
		proto_tree_add_text(echo_tree,tvb,offset,-1,"Echo values : %s",buff1);
		g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);
/*
		for(i = 0; i < 4; i++)
		{
			a[i] = tvb_get_guint8 (tvb,offset+6+i);
		}
		a[i] = '\0';
		g_warning("---->%s\n ",a);
		g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);
		proto_tree_add_text(echo_tree,tvb,offset,-1,"Echo operation : %s",a);
		g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);

		for(i=0;i<3;i++)
		{
			a[i] = tvb_get_guint8 (tvb,offset+11+i);
		}
		a[i]='\0';
		g_warning("---->%s\n ",a);
		proto_tree_add_text(echo_tree,tvb,offset,-1,"Echo values : %s",a);
		g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);

		for(i=0; i<3 ;i++)
		{
			a[i] = tvb_get_guint8 (tvb,offset+11+i);
		}
		a[i]='\0';
		g_warning("---->%s\n ",a);
		proto_tree_add_text(echo_tree,tvb,offset,-1,"Echo values : %s",a);
		g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);
	*/
	}

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

	g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);
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
	g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);
	dissector_handle_t echo_handle;

	g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);
	echo_handle = create_dissector_handle(dissect_echo, proto_echo);
	 	g_warning("-->%d. %s %s", __LINE__, __FUNCTION__, __FILE__);

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
