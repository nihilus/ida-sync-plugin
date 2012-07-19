///////////////////////////////////////////////////////////////////////////////
//
//  File     : IDA_SYNC_PLUGIN.cpp
//  Author   : obaby
//  Date     : 19/06/2012
//  Homepage : http://www.h4ck.org.cn
//  
//  License  : Copyright ?2012 火星信息安全研究院
//
//  This software is provided 'as-is', without any express or
//  implied warranty. In no event will the authors be held liable
//  for any damages arising from the use of this software.
//
///////////////////////////////////////////////////////////////////////////////

//-----------------------------------------------------------------------------

#include "IDA_SYNC_PLUGIN.h"

#include "IDAconnector.hpp"



// Global Variables:
int gSdkVersion;
char gszVersion[]      = "3.0.2.1";
// Plugin name listed in (Edit | Plugins)
char gszWantedName[]   = "IDA_SYNC_PLUGIN";
// plug-in hotkey
char gszWantedHotKey[] = "Alt-Shift-C";

char *gszPluginHelp;
char *gszPluginComment;



bool GetKernelVersion(char *szBuf, int bufSize)
{
	int major, minor, len;
	get_kernel_version(szBuf, bufSize);
	if ( qsscanf(szBuf, "%d.%n%d", &major, &len, &minor) != 2 )
		return false;
	if ( isdigit(szBuf[len + 1]) )
		gSdkVersion = 100*major + minor;
	else
		gSdkVersion = 10 * (10*major + minor);
	return true;
}

//-----------------------------------------------------------------------------
// Function:  idp_event_callback
// Hook the HT_IDB 
// automatic push the new changed names to the server ,and no more need the extra hotkeys
//
int idaapi idp_event_callback (void *user_data,int notif_code,va_list va)
{
	char buf     [MAXSTR+128];
	char newname [MAXSTR];
	char title   [128];
	flags_t		 name_flags;
	func_t       *fct;


	memset(buf,     0, sizeof(buf));
	memset(newname, 0, sizeof(newname));
	memset(title,   0, sizeof(title));

	ea_t addr = va_arg(va,ea_t);

	switch (notif_code)
	{
	case processor_t::rename:
		break;
	case processor_t::renamed:
		//If can't get the function name  it means that current ea is not a function start addr
		if (get_func_name(addr,newname,sizeof(newname) -1 ) ==NULL) 
		{
			get_name(BADADDR,addr,newname,sizeof(newname) -1 );
			if (!is_my_func_name(newname))	//Check if the name is a dummy name
			{
				name_flags = get_flags_novalue(addr);
				//msg("Name changed at addr %x. and name is %s\n",addr,comment);
				qsnprintf(buf, sizeof(buf) - 1, "%d:::%08x:::%08x*%s", IDA_SYNC_COMMAND_NORMAL_NAME, addr, name_flags, newname);

				if (connector_push(buf))
					msg("[*] IDA Sync> Successfully pushed normal name at address 0x%08x to server.\n", addr);
			}
			return 0;
		}
		//get flags at addr
		if (!is_my_func_name(newname)) //Check if the function name is a dummy name
		{
			fct = get_func(addr);
			//name_flags = get_flags_novalue(addr);
			//name_flags = get_func_
			//msg("Name changed at addr %x. and name is %s\n",addr,comment);
			qsnprintf(buf, sizeof(buf) - 1, "%d:::%08x:::%08x*%s", IDA_SYNC_COMMAND_FUNC_NAME, addr, fct->flags, newname);

			if (connector_push(buf))
				msg("[*] IDA Sync> Successfully pushed func name at address 0x%08x to server.\n", addr);
		}

		break;
	default:
		break;
	}
	return 0;
}

//-----------------------------------------------------------------------------
// Function:  idb_event_callback
// Hook the HT_IDB .
// automatic push the comment to the server ,and no more need the extra hotkeys
//
int idaapi idb_event_callback (void *user_data, int notif_code, va_list va)
{
	char buf     [MAXSTR+128];
	char comment [MAXSTR];
	char title   [128];


	memset(buf,     0, sizeof(buf));
	memset(comment, 0, sizeof(comment));
	memset(title,   0, sizeof(title));

	ea_t addr = va_arg(va,ea_t);

	switch (notif_code)
	{
	case idb_event::changing_cmt:							//called
		//get_cmt(addr,true,comment,sizeof(comment)-1);
		//msg("Calling changing_cmt at addr %X  and comment is %s \n",addr,comment);
		break;
	case idb_event::cmt_changed:							//called
		if (get_cmt(addr,true,comment,sizeof(comment)-1) > 0)
		{
			//msg("[*] IDA Sync>  Set repeatable comment at addr %08X and comment is %s.\n",addr,comment); 
			// push the entered comment to the server.
			
			qsnprintf(buf, sizeof(buf) - 1, "%d:::%08x:::%s", IDA_SYNC_COMMAND_REP_COMMENT, addr, comment);
			if (connector_push(buf))
			{
				msg("[*] IDA Sync> Successfully pushed repeatable comment at address 0x%08x to server.\n", addr);
			} else {
				msg("[*] IDA Sync> Failed pushed repeatable comment at address 0x%08x to server.\n", addr);
			}
		}
		if (get_cmt(addr,false,comment,sizeof(comment)-1) > 0)
		{
			//msg("[*] IDA Sync>  Set nonrepeatable at addr %08X and comment is %s.\n",addr,comment);  
			// push the entered comment to the server.
			qsnprintf(buf, sizeof(buf) - 1, "%d:::%08x:::%s", IDA_SYNC_COMMAND_REG_COMMENT, addr, comment);
			if (connector_push(buf))
			{
				msg("[*] IDA Sync> Successfully pushed nonrepeatable comment at address 0x%08x to server.\n", addr);
			} else {
				msg("[*] IDA Sync> Failed pushed nonrepeatable comment at address 0x%08x to server.\n", addr);
			}
		}
		break;
	case idb_event::struc_cmt_changed:
		msg("[*] IDA Sync> callback struc_cmt_changed.\n");
		break;
	case idb_event::area_cmt_changed:
		msg("[*] IDA Sync> callback area_cmt_changed.\n");
		break;
	case idb_event::changing_area_cmt:
		msg("[*] IDA Sync> callback changing_area_cmt.\n");
		break;
	default:
		break;
	}
	return 0;
}


//-----------------------------------------------------------------------------
// Function:  is_my_func_name
// check if the function name is a dummy name
//
bool is_my_func_name(char * func_name)
{
	bool bRet = false;
	if ((strnicmp(func_name, "sub_", 4) == 0) ||(strnicmp(func_name, "_", 1) == 0)||(strnicmp(func_name, "?", 1) == 0)||(strnicmp(func_name, "unknown", 7) == 0)||(strnicmp(func_name, "SEH_", 4) == 0)) 
		bRet = true;
	return bRet;
}
//-----------------------------------------------------------------------------
// Function: init
//
// init is a plugin_t function. It is executed when the plugin is
// initially loaded by IDA.
// Three return codes are possible:
//    PLUGIN_SKIP - Plugin is unloaded and not made available
//    PLUGIN_KEEP - Plugin is kept in memory
//    PLUGIN_OK   - Plugin will be loaded upon 1st use
//
// Check are added here to ensure the plug-in is compatible with
// the current disassembly.
//-----------------------------------------------------------------------------
int initPlugin(void)
{
	char szBuffer[MAXSTR];
	char sdkVersion[32];
	int nRetCode = PLUGIN_OK;

	HINSTANCE hInstance = ::GetModuleHandle(NULL);

	// Initialize global strings
	LoadString(hInstance, IDS_PLUGIN_HELP, szBuffer, sizeof(szBuffer));
	gszPluginHelp = qstrdup(szBuffer);
	LoadString(hInstance, IDS_PLUGIN_COMMENT, szBuffer, sizeof(szBuffer));
	gszPluginComment = qstrdup(szBuffer);
	if ( !GetKernelVersion(sdkVersion, sizeof(sdkVersion)) )
	{
		msg("%s: could not determine IDA version\n", gszWantedName);
		nRetCode = PLUGIN_SKIP;
	}
	else if ( gSdkVersion < 610 )
	{
		warning("Sorry, the %s plugin required IDA v%s or higher\n", gszWantedName, sdkVersion);
		nRetCode = PLUGIN_SKIP;
	}
	else if ( ph.id != PLFM_386 || ( !inf.is_32bit() && !inf.is_64bit() ) || inf.like_binary() )
	{
		msg("%s: could not load plugin\n", gszWantedName);
		nRetCode = PLUGIN_SKIP;
	}
	else
	{
		msg("\n--------------------------------------------------------------------------------------\n");
		msg( "%s (v%s) plugin has been loaded\n"
			"  The hotkeys to invoke the plugin is %s.\n"
			"  Please check the Edit/Plugins menu for more informaton.\n",
			gszWantedName, gszVersion, gszWantedHotKey);
	}
	//hook the idb change notification in ord to automatic push the comment to the server 
	hook_to_notification_point(HT_IDB,idb_event_callback,NULL);
	hook_to_notification_point(HT_IDP,idp_event_callback,NULL);

	msg("\n[*] IDA_SYNC initialized. Compiled on " __DATE__ "\n");
	msg("[*] Pedram Amini <pedram.amini@gmail.com>\n\n");
	msg("[*] Rebuild and Fix By obaby <root@h4ck.ws>\n"
			"--------------------------------------------------------------------------------------\n");

	
	return nRetCode;
}

//-----------------------------------------------------------------------------
// Function: term
//
// term is a plugin_t function. It is executed when the plugin is
// unloading. Typically cleanup code is executed here.
//-----------------------------------------------------------------------------
void termPlugin(void)
{
	//unload the hook function
	unhook_from_notification_point(HT_IDB,idb_event_callback,NULL);
	unhook_from_notification_point(HT_IDP,idp_event_callback,NULL);

	connector->cleanup();
}

//-----------------------------------------------------------------------------
// Function: run
//
// run is a plugin_t function. It is executed when the plugin is run.
//
// The argument 'arg' can be passed by adding an entry in
// plugins.cfg or passed manually via IDC:
//
//   success RunPlugin(string name, long arg);
//-----------------------------------------------------------------------------
void runPlugin(int arg)
{
	// parse the argument.
	switch (arg)
	{
		// default plug-in run.
		// connect to the server.
	case 0:
		connector->server_connect();

		if (!connector->is_connected())
			return;

		msg("[*] IDA Sync> Connection to server established.\n");
		break;

		// regular indented comment hook.
	case 1:
		if (connector->is_connected())
			insert_comment(get_screen_ea(), false);
		break;

		// repeatable comment hook.
	case 2:
		if (connector->is_connected())
			insert_comment(get_screen_ea(), true);
		break;

		// name hook.
	case 3:
		if (connector->is_connected())
			insert_name(get_screen_ea());
		break;

		// publish all function names hook
	case 4:
		if (connector->is_connected())
			publish_all_func_names();
		break;

		//publish all breakpoints hook
	case 5:
		if (connector->is_connected())
			publish_all_breakpoints();

	default:
		break;
	}

	// force a refresh.
	refresh_idaview_anyway();
//  Uncomment the following code to allow plugin unloading.
//  This allows the editing/building of the plugin without
//  restarting IDA.
//
//  1. to unload the plugin execute the following IDC statement:
//        RunPlugin("IDA_SYNC_PLUGIN", 415);
//  2. Make changes to source code and rebuild within Visual Studio
//  3. Copy plugin to IDA plugin dir
//     (may be automatic if option was selected within wizard)
//  4. Run plugin via the menu, hotkey, or IDC statement
//
// 	if (arg == 415)
// 	{
// 		PLUGIN.flags |= PLUGIN_UNL;
// 		msg("Unloading IDA_SYNC_PLUGIN plugin...\n");
// 	}
}

///////////////////////////////////////////////////////////////////////////////
//
//                         PLUGIN DESCRIPTION BLOCK
//
///////////////////////////////////////////////////////////////////////////////
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  0,              // plugin flags
  initPlugin,           // initialize
  termPlugin,           // terminate. this pointer may be NULL.
  runPlugin,            // invoke plugin
  gszPluginComment,     // comment about the plugin
  gszPluginHelp,        // multiline help about the plugin
  gszWantedName,        // the preferred short name of the plugin
  gszWantedHotKey       // the preferred hotkey to run the plugin
};

bool connector_pull (void)
{
	int   len;
	char  buf  [1024];
	char  data [1024];
	char  name [1024];
	int   command;
	int   name_flags;

	ea_t   address;
	ea_t   offset;
	SOCKET connection;

	struc_t *stk_frame;

	memset(buf,     0, sizeof(buf));
	memset(data,    0, sizeof(data));

	// grab the socket we wil be reading from.
	connection = connector->get_connection();

	len = recv(connection, buf, sizeof(buf) - 1, 0);

	// connection closed.
	if (len == 0 || len == SOCKET_ERROR)
	{
		connector->cleanup();
		msg("[!] IDA Sync> Socket read failed. Connection closed.\n");
		return false;
	}

	// null terminate the string.
	buf[len] = 0;

	// parse the inbound request. if we can't extract the correct fields, return.
	if (sscanf(buf, "%d:::%08x:::%1023[^\0]", &command, &address, data) != 3)
		return true;
	//msg("[!] IDA Sync> Received data %s.\n",buf);
	//
	// handle the received command appropriately.
	//

	switch(command)
	{
	case IDA_SYNC_COMMAND_JUMPTO:
		jumpto(address);
		break;

	case IDA_SYNC_COMMAND_NAME:
		if (sscanf(data,"%08x*%1023[^0]", &name_flags, name) != 2)
		{
			msg("[!] IDA Sync> Received invalid name command.\n");
			break;
		}

		msg("[*] IDA Sync> Received new name @%08x: %s\n", address, name);
		set_name(address, name, name_flags);
		break;

	case IDA_SYNC_COMMAND_REG_COMMENT:
		msg("[*] IDA Sync> Received regular comment @%08x: %s\n", address, data);
		set_cmt(address, data, false);
		break;

	case IDA_SYNC_COMMAND_REP_COMMENT:
		msg("[*] IDA Sync> Received repeatable comment @%08x: %s\n", address, data);
		set_cmt(address, data, true);
		break;

	case IDA_SYNC_COMMAND_STACK_VAR_NAME:
		if (sscanf(data,"%08x*%1023[^0]", &offset, name) != 2)
		{
			msg("[!] IDA Sync> Received invalid stack name command.\n");
			break;
		}

		msg("[*] IDA Sync> Received new stack variable name @%08x: %s\n", address, name);
		stk_frame = get_frame(address);
		set_member_name(stk_frame, offset, name);
		break;

	case IDA_SYNC_COMMAND_BPT_SOFT_ENB:
		msg("[*] IDA Sync> Received breakpoint at address @%08x: and comment is %s\n", address, data);
		set_cmt(address, data, true);
		if (add_bpt(address,0,BPT_SOFT))
		{
			enable_bpt(address,true);
		}else{
			if (exist_bpt(address))
			{
				enable_bpt(address,true);
				msg("[*] IDA Sync> Set Breakpoint at address @%08x: Enabled.\n", address);
			} else {
				msg("[*] IDA Sync> Add breakpoint at address @%08x: failed.\n", address);
			}	
		}
		break;

	case IDA_SYNC_COMMAND_BPT_SOFT_DIS:
		msg("[*] IDA Sync> Received breakpoint at address @%08x: and comment is %s\n", address, data);
		set_cmt(address, data, true);
		if (add_bpt(address,0,BPT_SOFT))
		{
			enable_bpt(address,false);
		}else{
			if (exist_bpt(address))
			{
				enable_bpt(address,false);
				msg("[*] IDA Sync> Set Breakpoint at address @%08x: Disabled.\n", address);
			} else {
				msg("[*] IDA Sync> Add breakpoint at address @%08x: failed.\n", address);
			}			
		}
		break;
	
	case IDA_SYNC_COMMAND_BPT_HARD_ENB:
		msg("[*] IDA Sync> Received breakpoint at address @%08x: and comment is %s\n", address, data);
		set_cmt(address, data, true);
		if (add_bpt(address,0,BPT_RDWR))
		{
			enable_bpt(address,true);
		}else{
			if (exist_bpt(address))
			{
				enable_bpt(address,true);
				msg("[*] IDA Sync> Set Breakpoint at address @%08x: Enabled.\n", address);
			} else {
				msg("[*] IDA Sync> Add breakpoint at address @%08x: failed.\n", address);
			}	
		}
		break;

	case IDA_SYNC_COMMAND_BPT_HARD_DIS:
		msg("[*] IDA Sync> Received breakpoint at address @%08x: and comment is %s\n", address, data);
		set_cmt(address, data, true);
		if (add_bpt(address,0,BPT_RDWR))
		{
			enable_bpt(address,false);
		}else{
			if (exist_bpt(address))
			{
				enable_bpt(address,false);
				msg("[*] IDA Sync> Set Breakpoint at address @%08x: Disabled.\n", address);
			} else {
				msg("[*] IDA Sync> Add breakpoint at address @%08x: failed.\n", address);
			}	
		}
		break;
	case IDA_SYNC_COMMAND_NORMAL_NAME:
		if (sscanf(data,"%08x*%1023[^0]", &name_flags, name) != 2)
		{
			msg("[!] IDA Sync> Received invalid normal name command.\n");
			break;
		}

		msg("[*] IDA Sync> Received new normal name @%08x: %s\n", address, name);
		set_name(address, name, name_flags);
		break;

	case IDA_SYNC_COMMAND_FUNC_NAME:
		if (sscanf(data,"%08x*%1023[^0]", &name_flags, name) != 2)
		{
			msg("[!] IDA Sync> Received invalid function name command.\n");
			break;
		}

		/*msg("[*] IDA Sync> Received new stack variable name @%08x: %s\n", address, name);
		stk_frame = get_frame(address);
		set_member_name(stk_frame, offset, name);*/
		msg("[*] IDA Sync> Received new function name @%08x: %s\n", address, name);
		set_name(address, name, name_flags);
		
		break;

	default:
		msg("[*] IDA Sync> Received unknown command code: %d, ignoring.\n", command);
	}

	// force a refresh.
	refresh_idaview_anyway();

	// ping pong.
	send(connection, "1", 1, 0);

	return true;
}


/////////////////////////////////////////////////////////////////////////////////////////
// connector_push()
//
// this routine is utilized to transmit data to the server.
//
// arguments: buf - buffer containing data to send to server.
// returns:   boolean value representing success.
//

bool connector_push (char *buf)
{
	int    len;
	SOCKET connection;

	// grab the socket we wil be writing to.
	connection = connector->get_connection();

	len = strlen(buf);

	if (send(connection, buf, len, 0) != len)
	{
		connector->cleanup();
		msg("[!] IDA Sync> Socket write failed. Connection closed.\n");
		return false;
	}

	return true;
}


/////////////////////////////////////////////////////////////////////////////////////////
// insert_comment()
//
// prompt the user for a comment and insert it at the specified address. push the
// comment/address pair to the server.
//
// arguments: ea         - effective address to add comment.
//            repeatable - boolean flag for whether or not this comment is repeatable.
// returns:   none.
//

void insert_comment (ea_t ea, bool repeatable)
{
	char buf     [MAXSTR+128];
	char comment [MAXSTR];
	char title   [128];

	memset(buf,     0, sizeof(buf));
	memset(comment, 0, sizeof(comment));
	memset(title,   0, sizeof(title));

	if (repeatable)
		qstrncpy(title, "IDA Sync> Enter repeatable comment.", sizeof(title));
	else
		qstrncpy(title, "IDA Sync> Enter comment.", sizeof(title));

	// present the user with a multi-line form to enter a comment.
	get_cmt(ea, repeatable, comment, sizeof(comment) - 1);

	if (asktext(MAXSTR - 1, comment, comment, title) == NULL)
		return;

	// update the comment in the local IDA database.
	set_cmt(ea, comment, repeatable);

	// push the entered comment to the server.
	if (repeatable)
		qsnprintf(buf, sizeof(buf) - 1, "%d:::%08x:::%s", IDA_SYNC_COMMAND_REP_COMMENT, ea, comment);
	else
		qsnprintf(buf, sizeof(buf) - 1, "%d:::%08x:::%s", IDA_SYNC_COMMAND_REG_COMMENT, ea, comment);

	if (connector_push(buf))
		msg("[*] IDA Sync> Successfully pushed comment at address 0x%08x to server.\n", ea);
}


/////////////////////////////////////////////////////////////////////////////////////////
// insert_name()
//
// prompt the user for a name and insert it at the specified address. push the
// name/address pair to the server.
//
// arguments: ea - effective address to add name.
// returns:   none.
//

void insert_name (ea_t ea)
{
	char buf      [MAXSTR+128];
	char old_name [MAXSTR];
	char new_name [MAXSTR];
	char sel_name [MAXSTR];

	ea_t  name_address = BADADDR;
	ea_t  fcref_from   = get_first_fcref_from(ea);
	ea_t  dref_from    = get_first_dref_from (ea);
	ea_t  fcref_to     = get_first_fcref_to  (ea);
	ea_t  dref_to      = get_first_dref_to   (ea);
	short check_boxes  = 0;
	int   name_flags   = 0;
	int   x, y;

	struc_t  *stk_frame;
	ea_t      stk_offset;
	func_t   *pfn;
	member_t *stk_item;
	char     *line;
	char     *selection;

	const short IB_LOCAL    = 0x1;
	const short IB_INCLUDE  = 0x2;
	const short IB_PUBLIC   = 0x4;
	const short IB_AUTO     = 0x8;

	//msg("Insert name here\n");

	const char dialog_format [] =
		"STARTITEM 0\n"
		"IDA Sync Rename Address\n"
		"Address: %$\n"
		"<~N~ame:A:255:32::>\n"
		"         <Local name:C>\n"
		"         <Include in names list:C>\n"
		"         <Public name:C>\n"
		"         <Autogenerated name:C>>\n\n";

	const char dialog_stk_var [] =
		"STARTITEM 0\n"
		"IDA Sync Rename Stack Variable\n"
		"<Enter stack variable name:A:255:64::>\n";

	memset(buf,      0, sizeof(buf));
	memset(old_name, 0, sizeof(old_name));
	memset(new_name, 0, sizeof(new_name));
	memset(sel_name, 0, sizeof(sel_name));

	// default flags:
	//
	//      offset names are default "include in names list" and "autogenerated name".
	//      sub names are default "include in names list"
	//      location names are default "local name"

	//
	// stack variable names.
	//

	// get x/y coordinates of cursor.
	get_cursor(&x, &y);

	// retrieve the current line.
	line = get_curline();
	tag_remove(line, buf, sizeof(buf));
	extract_name(buf, x, sel_name, sizeof(sel_name));

	// the stack variable name is the last item.
	selection = sel_name;

	while (strstr(selection, "+") != NULL)
		selection = strstr(selection, "+") + 1;

	while (strstr(selection, "-") != NULL)
		selection = strstr(selection, "-") + 1;

	// retrieve the stack frame pointer.
	stk_frame = get_frame(ea);

	// retrieve a pointer pointer to the current function.
	pfn = get_func(ea);

	stk_offset = find_offset_from_name( stk_frame, pfn, selection );

	// rename the stack variable.
	if (stk_offset != -1)
	{
		// calculate the stack offset based on the current function, the address, and the operand
		// XXX - need to figure out how to know which operand we have selected.

		// retrieve the stack frame member.
		stk_item = get_member(stk_frame, stk_offset);

		// retrieve the item name and copy it as the default value.
		get_member_name(stk_item->id, new_name, sizeof(new_name) - 1);

		// present the user with a dialog asking for the new name.
		// if cancel was selected then simply return.
		if (!AskUsingForm_c(dialog_stk_var, new_name))
			return;

		// set the stack_frame member name based on the stack frame pointer and the offset.
		set_member_name(stk_frame, stk_offset, new_name);

		// push the entered name to the server.
		qsnprintf(buf, sizeof(buf) - 1, "%d:::%08x:::%08x*%s", IDA_SYNC_COMMAND_STACK_VAR_NAME, ea, stk_offset, new_name);

		if (connector_push(buf))
			msg("[*] IDA Sync> Successfully pushed stack variable name at offset 0x%08x:0x%08x to server.\n", ea, stk_offset);

		return;
	}

	//
	// offset names.
	//

	if (dref_to != BADADDR)                 // current ea is an offset name.
	{
		check_boxes = IB_INCLUDE | IB_AUTO;
		get_name(BADADDR, ea, old_name, MAXSTR - 1);
		name_address = get_name_ea(ea, old_name);
	}

	else if (dref_from != BADADDR)          // current ea references an offset name.
	{
		check_boxes = IB_INCLUDE | IB_AUTO;
		get_name(ea, dref_from, old_name, MAXSTR - 1);
		name_address = get_name_ea(dref_from, old_name);
	}

	//
	// sub-routine names.
	//

	else if (is_sub_routine(ea))            // current ea is the start of a sub-routine.
	{
		check_boxes = IB_INCLUDE;
		get_name(BADADDR, ea, old_name, MAXSTR - 1);
		name_address = get_name_ea(ea, old_name);
	}

	else if (is_sub_routine(fcref_from))    // current ea calls a sub-routine.
	{
		check_boxes = IB_INCLUDE;
		get_name(ea, fcref_from, old_name, MAXSTR - 1);
		name_address = get_name_ea(fcref_from, old_name);
	}

	//
	// location names.
	//

	else if (fcref_to != BADADDR)           // current ea is the start of a location.
	{
		check_boxes = IB_LOCAL;
		get_name(BADADDR, ea, old_name, MAXSTR - 1);
		name_address = get_name_ea(ea, old_name);
	}

	else if (fcref_from != BADADDR)         // current ea references a location.
	{
		check_boxes = IB_LOCAL;
		get_name(ea, fcref_from, old_name, MAXSTR - 1);
		name_address = get_name_ea(fcref_from, old_name);
	}
	else                                    // there is no name at this location.
	{
		return;
	}

	// ensure we have a name.
	if (name_address == BADADDR)
		return;

	qstrncpy(new_name, old_name, sizeof(new_name));

	// present the user with a dialog asking for the new name.
	// if cancel was selected then simply return.
	if (!AskUsingForm_c(dialog_format, &name_address, new_name, &check_boxes))
		return;

	// parse the radio button value and set the appropriate name flags.
	if (check_boxes & IB_LOCAL)      name_flags |= SN_LOCAL;
	if (check_boxes & IB_PUBLIC)     name_flags |= SN_PUBLIC;
	if (check_boxes & IB_AUTO)       name_flags |= SN_AUTO;
	if (!(check_boxes & IB_INCLUDE)) name_flags |= SN_NOLIST;

	// update the name in the local IDA database.
	set_name(name_address, new_name, name_flags);

	// push the entered name to the server.
	qsnprintf(buf, sizeof(buf) - 1, "%d:::%08x:::%08x*%s", IDA_SYNC_COMMAND_NAME, name_address, name_flags, new_name);

	if (connector_push(buf))
		msg("[*] IDA Sync> Successfully pushed name at address 0x%08x to server.\n", name_address);
}


/////////////////////////////////////////////////////////////////////////////////////////
// is_sub_routine()
//
// determine if the supplied address is the start of a sub-routine.
//
// arguments: ea - effective address to examine.
// returns:   boolean value.
//

bool is_sub_routine (ea_t ea)
{
	func_t *fptr;
	size_t i;

	// step through all functions.
	for (i = 0; i < get_func_qty(); i++)
	{
		// get a pointer to the current function.
		if ((fptr = getn_func(i)) == NULL)
			continue;

		// see if we have a match.
		if (fptr->startEA == ea)
			return true;
	}

	return false;
}



/////////////////////////////////////////////////////////////////////////////////////////
// publish_all_func_names()
//
// push all function names to the server.
//
// arguments: none.
// returns:   none.
//

void publish_all_func_names ()
{
	func_t *fptr;
	size_t i;
	char func_name[MAXSTR];
	char buf      [MAXSTR + 128];
	flags_t func_flag;

	memset(func_name, 0, sizeof(func_name));
	memset(buf,       0, sizeof(buf));

	// step through all functions.
	for (i = 0; i < get_func_qty(); i++)
	{
		// get a pointer to the current function.
		if ((fptr = getn_func(i)) == NULL)
			continue;

		if (get_name(BADADDR, fptr->startEA, func_name, MAXSTR - 1) == NULL)
			continue;

		// we don't want to push the generic IDA generated names to the sync server.
		//if (strnicmp(func_name, "sub_", 4) == 0)
		if (is_my_func_name(func_name))
			continue;

		// check if the function name is a dummy name
		//func_flag = get_flags_novalue(fptr->startEA);
		
		//if (!has_user_name(fptr->flags))
		//	continue;

		// push the entered comment to the server.
		qsnprintf(buf, sizeof(buf) - 1, "%d:::%08x:::%08x*%s", IDA_SYNC_COMMAND_NAME, fptr->startEA, fptr->flags, func_name);

		if (connector_push(buf))
			msg("[*] IDA Sync> Successfully pushed function '%s' @0x%08x to server.\n", func_name, fptr->startEA);
	}
}


/////////////////////////////////////////////////////////////////////////////////////////
// publish_all_comments()
//
// push all comments to the server.
//
// arguments: none.
// returns:   none.
//
void publish_all_comments()
{
	char buf     [MAXSTR+128];
	char comment [MAXSTR];
	char title   [128];
	size_t		  i;

	memset(buf,     0, sizeof(buf));
	memset(comment, 0, sizeof(comment));
	memset(title,   0, sizeof(title));


}
/////////////////////////////////////////////////////////////////////////////////////////
// publish_all_breakpoints()
//
// push all breakpoints to the server.
//
// arguments: none.
// returns:   none.
//
void publish_all_breakpoints()
{
	int bpt_count;
	char buf     [MAXSTR+128];
	char comment [MAXSTR];
	char title   [128];

	memset(buf,     0, sizeof(buf));
	memset(comment, 0, sizeof(comment));
	memset(title,   0, sizeof(title));
	bpt_count = get_bpt_qty();

	msg("[*] IDA Sync> There are %d breakpoints in the database.\n", bpt_count);

	for (int i = 0 ;i < bpt_count ;i ++)
	{
		bpt_t brkpnt;
		// getn_bpt fills bpt_t struct with breakpoint information based
		// on the breakpoint number supplied.
		getn_bpt(i,&brkpnt);

		get_cmt(brkpnt.ea,false,comment, sizeof(comment) - 1);

		if (brkpnt.type == BPT_SOFT)
		{
			if (brkpnt.enabled())
			{
				qsnprintf(buf, sizeof(buf) - 1, "%d:::%08x:::%s", IDA_SYNC_COMMAND_BPT_SOFT_ENB, brkpnt.ea, comment);
			} else {
				qsnprintf(buf, sizeof(buf) - 1, "%d:::%08x:::%s", IDA_SYNC_COMMAND_BPT_SOFT_DIS, brkpnt.ea, comment);
			}
		} else {
			if (brkpnt.enabled())
			{
				qsnprintf(buf, sizeof(buf) - 1, "%d:::%08x:::%s", IDA_SYNC_COMMAND_BPT_HARD_ENB, brkpnt.ea, comment);
			} else {
				qsnprintf(buf, sizeof(buf) - 1, "%d:::%08x:::%s", IDA_SYNC_COMMAND_BPT_HARD_DIS, brkpnt.ea, comment);
			}
		}
			
		if (connector_push(buf))
			msg("[*] IDA Sync> Successfully pushed breakpoint at address 0x%08x to server.\n", brkpnt.ea);
		Sleep(300);
	}

}

//////////////////////////////////////////////////////////////////////////////////////
// find_offset_from_name()
//
// walk the stack structure and find the offset for a given name.
//
// arguments: stk_frame - stack struct_t
//            pfn       - function pfn
//            name      - name to find
// returns:   unsigned

long find_offset_from_name (struc_t *stk_frame, func_t *pfn, char *name)
{
	unsigned i;
	char item_name [MAXSTR];
	member_t *stk_item;

	for (i = 0; i <= get_frame_size(pfn); i++)
	{
		stk_item = get_member(stk_frame, i);

		if (stk_item != NULL)
		{
			get_member_name(stk_item->id, item_name, sizeof(item_name) - 1);

			if (strcmp(item_name, name) == 0)
				return i;
		}
	}

	return -1;
}

// include the data structures that describe the plugin to IDA.
//#include "plugin_info.h"

