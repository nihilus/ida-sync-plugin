///////////////////////////////////////////////////////////////////////////////
//
//  File     : IDA_SYNC_PLUGIN.h
//  Author   : obaby
//  Date     : 19/06/2012
//  Homepage : http://www.h4ck.org.cn
//  
//  License  : Copyright © 2012 火星信息安全研究院
//
//  This software is provided 'as-is', without any express or
//  implied warranty. In no event will the authors be held liable
//  for any damages arising from the use of this software.
//
///////////////////////////////////////////////////////////////////////////////

#pragma once

//#include <windows.h>
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <dbg.hpp>
#include "resource.h"

#define _WINSOCKAPI_
//#include <winsock2.h>

#include <bytes.hpp>
#include <expr.hpp>
#include <frame.hpp>
#include <name.hpp>
#include <struct.hpp>

#pragma warning (disable:4273)



#ifndef __IDA_SYNC_H__
#define __IDA_SYNC_H__

#define IDA_SYNC_COMMAND_JUMPTO          0x01
#define IDA_SYNC_COMMAND_NAME            0x02
#define IDA_SYNC_COMMAND_REG_COMMENT     0x04
#define IDA_SYNC_COMMAND_REP_COMMENT     0x08
#define IDA_SYNC_COMMAND_STACK_VAR_NAME  0x10
#define IDA_SYNC_COMMAND_BPT_SOFT_ENB	 0x12
#define IDA_SYNC_COMMAND_BPT_SOFT_DIS	 0x14
#define IDA_SYNC_COMMAND_BPT_HARD_ENB	 0x16
#define IDA_SYNC_COMMAND_BPT_HARD_DIS	 0x18

bool connector_pull         (void);
bool connector_push         (char *);
void insert_comment         (ea_t, bool);
void insert_name            (ea_t);
bool is_sub_routine         (ea_t);
long find_offset_from_name  (struc_t *, func_t *, char *);
void publish_all_func_names (void);
void publish_all_comments	(void);
bool is_my_func_name		(char *);
void publish_all_breakpoints(void);

#endif