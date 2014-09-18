//
// Source Server Query Library
// Copyright (C) 2005 Pascal Herget
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
//

#define SSQ_GS_TIMEOUT 1<<0
#define SSQ_LOG_TIMEOUT 1<<1
#define SSQ_MS_TIMEOUT 1<<2
#define SSQ_RCON_TIMEOUT 1<<3

#define WINAPI __stdcall

enum
{
	SSQ_USA_EAST = 0,
	SSQ_USA_WEST,
	SSQ_SOUTH_AMERICA,
	SSQ_EUROPE,
	SSQ_ASIA,
	SSQ_AUSTRALIA,
	SSQ_MIDDLE_EAST,
	SSQ_AFRICA,
	SSQ_WORLD = 255
};

enum
{
	SSQ_BATCH_REPLY_CALLBACK = 0,
	SSQ_LOG_REPLY_CALLBACK,
	SSQ_RCON_REPLY_CALLBACK,
	SSQ_RULES_REPLY_CALLBACK,
	SSQ_LOG_THREAD_NOTIFY
};

typedef struct
{
	long num_servers;
	long data_size;
	char* data;
}SSQ_BATCH_REPLY,*PSSQ_BATCH_REPLY;

typedef struct
{
	char version;
	char hostname[256];
	char map[32];
	char game_directory[32];
	char game_description[256];
	short app_id;
	char num_players ;
	char max_players;
	char num_of_bots;
	char dedicated;
	char os;
	char password;
	char secure;
	char game_version[32];
}SSQ_INFO_REPLY,*PSSQ_INFO_REPLY;

typedef struct
{
	char index;
	char player_name[32];
	long kills;
	float time_connected;
}SSQ_PLAYER_ITEM,*PSSQ_PLAYER_ITEM;

typedef struct
{
	char num_players;
	SSQ_PLAYER_ITEM player[64];
}SSQ_PLAYER_REPLY,*PSSQ_PLAYER_REPLY;

typedef struct
{
	short num_rules;
	long data_size;
	char* data;
}SSQ_RULES_REPLY,*PSSQ_RULES_REPLY;

typedef union
{
	PSSQ_BATCH_REPLY batch_reply;
	char* log_reply;
	PSSQ_RULES_REPLY rules_reply;
	char* rcon_reply;
	BOOL log_notify;
}SSQ_REPLY_UNION,*PSSQ_REPLY_UNION;

typedef bool(WINAPI* SSQ_CALLBACK)(DWORD, PSSQ_REPLY_UNION);

char* WINAPI SSQ_FormatBatchReply(PSSQ_BATCH_REPLY batch_reply,int index);
BOOL WINAPI SSQ_GetBatchReply(BYTE region,char* filter);
BOOL WINAPI SSQ_GetInfoReply(PSSQ_INFO_REPLY info_reply);
BOOL WINAPI SSQ_GetPlayerReply(PSSQ_PLAYER_REPLY player_reply);
BOOL WINAPI SSQ_GetRconReply(char* password,char* command);
char* WINAPI SSQ_GetRuleName(PSSQ_RULES_REPLY rules_reply,short index);
char* WINAPI SSQ_GetRuleValue(PSSQ_RULES_REPLY rules_reply,short index);
BOOL WINAPI SSQ_GetRulesReply();
BOOL WINAPI SSQ_Initialize(BOOL exit);
DWORD WINAPI SSQ_Ping();
BOOL WINAPI SSQ_SetCallbackAddress(SSQ_CALLBACK callback);
BOOL WINAPI SSQ_SetGameServer(char* address);
BOOL WINAPI SSQ_SetLogStatus(BOOL status,unsigned short port);
BOOL WINAPI SSQ_SetMasterServer(char* address);
BOOL WINAPI SSQ_SetTimeout(DWORD type,int timeout);