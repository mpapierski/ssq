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

// Thanks to TLOTB Astharoth for some bugfixes

// Modified by Beerdude26 (beerdude26@gmail.com) to get it running (roughly) in Source engine

#include "ssq.h"
#include <sys/socket.h>
#include <string.h>

//#pragma comment(linker,"/entry:DllMain /subsystem:windows /nodefaultlib")
//#pragma comment(linker,"/filealign:512 /merge:.rdata=.text /merge:.data=.text")
//#pragma comment(linker,"/section:.text,rwe /ignore:4078")

typedef unsigned short USHORT;
typedef char *PCHAR;
typedef short *PSHORT;
typedef int *PINT;
typedef long *PLONG;
typedef void *PVOID;

typedef unsigned char *PUCHAR;
typedef unsigned short *PUSHORT;
typedef unsigned int *PUINT;
typedef unsigned long *PULONG;
typedef unsigned long long ULONG64;
typedef unsigned long long LARGE_INTEGER;
typedef unsigned int UINT32;

#define SOCKET_ERROR -1

#define A2M_GET_SERVERS_BATCH2 0x31
#define S2C_CHALLENGE 0x41
#define S2A_PLAYER 0x44
#define S2A_RULES 0x45
#define S2A_INFO 0x49
#define S2A_LOG 0x52
#define A2S_INFO "\xFF\xFF\xFF\xFF\x54Source Engine Query"
#define A2S_INFO_LENGTH 25
#define A2S_PLAYER "\xFF\xFF\xFF\xFF\x55\x00\x00\x00\x00"
//#define A2S_PLAYER_CHALLENGE "\xFF\xFF\xFF\xFF\x55\xFF\xFF\xFF\xFF"
#define A2S_PLAYER_LENGTH 9
#define A2S_RULES "\xFF\xFF\xFF\xFF\x56\x00\x00\x00\x00"
//#define A2S_RULES_CHALLENGE "\xFF\xFF\xFF\xFF\x56\xFF\xFF\xFF\xFF"
#define A2S_RULES_LENGTH 9
#define A2S_SERVERQUERY_GETCHALLENGE "\xFF\xFF\xFF\xFF\x57"
#define A2S_SERVERQUERY_GETCHALLENGE_LENGTH 5
#define M2A_SERVER_BATCH 0x66
#define A2A_PING "\xFF\xFF\xFF\xFF\x69"
#define A2A_PING_LENGTH 5
#define A2A_ACK 0x6A

#define SERVERDATA_EXECCOMMAND 2
#define SERVERDATA_AUTH 3
#define SERVERDATA_RESPONSE_VALUE 0
#define SERVERDATA_AUTH_RESPONSE 2

#define SSQ_SOCKET_COUNT 4

enum
{
	EXTERNAL_SSQ_FORMAT_BATCH_REPLY = 0,
	EXTERNAL_SSQ_GET_BATCH_REPLY,
	EXTERNAL_SSQ_GET_INFO_REPLY,
	EXTERNAL_SSQ_GET_PLAYER_REPLY,
	EXTERNAL_SSQ_GET_RCON_REPLY,
	EXTERNAL_SSQ_GET_RULE_NAME,
	EXTERNAL_SSQ_GET_RULE_VALUE,
	EXTERNAL_SSQ_GET_RULES_REPLY,
	EXTERNAL_SSQ_INITIALIZE,
	EXTERNAL_SSQ_PING,
	EXTERNAL_SSQ_SET_CALLBACK_ADDRESS,
	EXTERNAL_SSQ_SET_GAME_SERVER,
	EXTERNAL_SSQ_SET_LOG_STATUS,
	EXTERNAL_SSQ_SET_MASTER_SERVER,
	EXTERNAL_SSQ_SET_TIMEOUT
};

enum
{
	INTERNAL_SSQ_ADDRESS_TO_FUNCTION_NAME = 0,
	INTERNAL_SSQ_CLEANUP,
	INTERNAL_SSQ_GET_IP_PORT,
	INTERNAL_SSQ_LOG_THREAD,
	INTERNAL_SSQ_OUTPUT_DEBUG_STRING,
	INTERNAL_SSQ_STARTUP
};

enum
{
	SSQ_UDP_GS = 0,
	SSQ_UDP_LOG,
	SSQ_UDP_MS,
	SSQ_TCP_RCON
};

bool ssq_is_initialized = false;
bool log_status = false;
bool exit_log_thread = false;

#ifdef __cplusplus
extern "C" {
#endif
int __fltused=0; 
#ifdef __cplusplus
}
#endif
char debug_string[1024];

char* rs_buffer;
char* ssq_functions_external[15];
char* ssq_functions_internal[6] =
{
	"SSQ_AddressToFunctionName",
	"SSQ_Cleanup",
	"SSQ_GetIpPort",
	"SSQ_LogThread",
	"SSQ_OutputDebugString",
	"SSQ_Startup"
};

unsigned int exit_code_log_thread;
unsigned int identifier_log_thread;

int int_log_thread;
int int_module;

#if !defined(_WIN32)
typedef int SOCKET;
#endif

SOCKET ssq_socket[SSQ_SOCKET_COUNT];

SSQ_CALLBACK Callback;

SSQ_REPLY_UNION reply_union;

int max_rs_size = 65535;

void SSQ_OutputDebugString(unsigned char index,unsigned char winsock,unsigned char doExport,unsigned int address);
bool SSQ_Startup();

bool SSQ_AddressToFunctionName(unsigned int address,char** module,char** function)
{
#if 0
	static int int_snapshot;
	static MODULEENTRY32 module_entry;
	static bool module_next;
	static PIMAGE_DOS_HEADER dos_header;
	static PIMAGE_NT_HEADERS nt_headers;
	static PIMAGE_EXPORT_DIRECTORY export_directory;
	static unsigned int counter;
	static unsigned int counter2;

	if(HIWORD(address)==0||HIWORD(module)==0||HIWORD(function)==0)
	{
		return false;
	}

	int_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,GetCurrentProcessId());

	if(int_snapshot==INVALID_int_VALUE)
	{
		return false;
	}

	module_entry.dwSize = sizeof(module_entry);

	if(Module32First(int_snapshot,&module_entry)==false)
	{
		Closeint(int_snapshot);

		return false;
	}

	do
	{
		if(address>=(unsigned int)module_entry.modBaseAddr&&address<((unsigned int)module_entry.modBaseAddr+module_entry.modBaseSize))
		{
			*module = module_entry.szModule;

			break;
		}
	}
	while((module_next = Module32Next(int_snapshot,&module_entry))==true);

	Closeint(int_snapshot);

	if(module_next==false)
	{
		return false;
	}

	dos_header = (PIMAGE_DOS_HEADER)module_entry.modBaseAddr;
	nt_headers = (PIMAGE_NT_HEADERS)((unsigned int)dos_header+dos_header->e_lfanew);
	export_directory = (PIMAGE_EXPORT_DIRECTORY)((unsigned int)dos_header+nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	for(counter = 0;counter<export_directory->NumberOfFunctions;counter++)
	{
		if(((unsigned int)dos_header+((PULONG)((unsigned int)dos_header+(unsigned int)export_directory->AddressOfFunctions))[counter])==address)
		{
			for(counter2 = 0;counter2<export_directory->NumberOfNames;counter2++)
			{
				if(((PUSHORT)((unsigned int)dos_header+(unsigned int)export_directory->AddressOfNameOrdinals))[counter2]==counter)
				{
					*function = (char*)((unsigned int)dos_header+((PULONG)((unsigned int)dos_header+(unsigned int)export_directory->AddressOfNames))[counter2]);

					//wsprintf(test,"c: %i c2 %i address: 0x%08X ordinal: %i %08X aof %08X",counter,counter2,address,ordinal,(unsigned int)dos_header+(unsigned int)export_directory->AddressOfNameOrdinals,(unsigned int)dos_header+(unsigned int)export_directory->AddressOfFunctions);
					//MessageBox(0,*function,test,0);

					return true;				
				}
			}
		}
	}
#endif
	return false;
}

bool SSQ_Cleanup()
{
#if 0
	static bool result;
	static unsigned char socket_count;

	result = true;

	for(socket_count = 0;socket_count<SSQ_SOCKET_COUNT;socket_count++)
	{
		if(closesocket(ssq_socket[socket_count])==SOCKET_ERROR)
		{
			SSQ_OutputDebugString(INTERNAL_SSQ_CLEANUP,1,0,(unsigned int)closesocket);

			result = false;
		}
	}

	if(GetExitCodeThread(int_log_thread,&exit_code_log_thread)==false)
	{
		SSQ_OutputDebugString(INTERNAL_SSQ_CLEANUP,0,0,(unsigned int)GetExitCodeThread);

		result = false;
	}

	if(exit_code_log_thread==STILL_ACTIVE&&log_status==true)
	{
		exit_log_thread = true;

		if(WaitForSingleObject(int_log_thread,INFINITE)==WAIT_FAILED)
		{
			SSQ_OutputDebugString(INTERNAL_SSQ_CLEANUP,0,0,(unsigned int)WaitForSingleObject);

			result = false;
		}
	}

	if(Closeint(int_log_thread)==false)
	{
		SSQ_OutputDebugString(INTERNAL_SSQ_CLEANUP,0,0,(unsigned int)Closeint);

		result = false;
	}

	if(VirtualFree(rs_buffer,0,MEM_RELEASE)==0)
	{
		SSQ_OutputDebugString(INTERNAL_SSQ_CLEANUP,0,0,(unsigned int)VirtualFree);

		result = false;
	}

	if(WSACleanup()==SOCKET_ERROR)
	{
		SSQ_OutputDebugString(INTERNAL_SSQ_CLEANUP,1,0,(unsigned int)WSACleanup);

		result = false;
	}

	return result;
#endif
}

char* SSQ_FormatBatchReply(PSSQ_BATCH_REPLY batch_reply,int index)
{
	static char* address_pointer;
	static char address[22];

	if(HIWORD(batch_reply)==0||batch_reply->data_size==0||batch_reply->data==0||index>(batch_reply->num_servers-1)||ssq_is_initialized==false)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_FORMAT_BATCH_REPLY,0,1,0);

		return 0;
	}

	address_pointer = inet_ntoa(*(PIN_ADDR)&batch_reply->data[index*6]);

	if(address_pointer==0)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_FORMAT_BATCH_REPLY,1,1,(unsigned int)inet_ntoa);

		return 0;
	}

	wsprintf(address,"%s:%hu",address_pointer,ntohs(*(PUSHORT)&batch_reply->data[index*6+4]));

	return address;
}

bool SSQ_GetBatchReply(unsigned char region,char* filter)
{
	static char address[22];
	static char start_address[10] = "0.0.0.0:0";
	static int string_length_address;
	static int string_length_filter;
	static int Bytes_received;
	static SSQ_BATCH_REPLY batch_reply;
	static char* address_pointer;

	if((region>7&&region<255)||HIWORD(filter)==0||HIWORD(Callback)==0||ssq_is_initialized==false)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_GET_BATCH_REPLY,0,1,0);

		return false;
	}
	else if(lstrcpyn(address,start_address,sizeof(start_address))==0)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_GET_BATCH_REPLY,0,1,(unsigned int)lstrcpyn);

		return false;
	}

	do
	{
		rs_buffer[0] = A2M_GET_SERVERS_BATCH2;
		rs_buffer[1] = region;

		string_length_address = lstrlen(address)+1;

		if(lstrcpyn(&rs_buffer[2],address,string_length_address)==0)
		{
			SSQ_OutputDebugString(EXTERNAL_SSQ_GET_BATCH_REPLY,0,1,(unsigned int)lstrcpyn);

			return false;
		}

		string_length_filter = lstrlen(filter)+1;

		if(lstrcpyn(&rs_buffer[2+string_length_address],filter,string_length_filter)==0)
		{
			SSQ_OutputDebugString(EXTERNAL_SSQ_GET_BATCH_REPLY,0,1,(unsigned int)lstrcpyn);

			return false;
		}
		else if(send(ssq_socket[SSQ_UDP_MS],rs_buffer,2+string_length_address+string_length_filter,0)==SOCKET_ERROR)
		{
			SSQ_OutputDebugString(EXTERNAL_SSQ_GET_BATCH_REPLY,1,1,(unsigned int)send);

			return false;
		}

		Bytes_received = recv(ssq_socket[SSQ_UDP_MS],rs_buffer,max_rs_size,0);

		if(Bytes_received==SOCKET_ERROR||Bytes_received==0)
		{
			SSQ_OutputDebugString(EXTERNAL_SSQ_GET_BATCH_REPLY,1,1,(unsigned int)recv);

			return false;
		}
		else if(rs_buffer[4]!=M2A_SERVER_BATCH)
		{
			SSQ_OutputDebugString(EXTERNAL_SSQ_GET_BATCH_REPLY,0,1,0);

			return false;
		}

		batch_reply.num_servers = (Bytes_received-6)/6;
		batch_reply.data_size = Bytes_received-6;
		batch_reply.data = &rs_buffer[6];

		reply_union.batch_reply = &batch_reply;

		if(Callback(SSQ_BATCH_REPLY_CALLBACK,&reply_union)==false)
		{
			break;
		}

		address_pointer = inet_ntoa(*(PIN_ADDR)&rs_buffer[Bytes_received-6]);

		if(address_pointer==0)
		{
			SSQ_OutputDebugString(EXTERNAL_SSQ_GET_BATCH_REPLY,1,1,(unsigned int)inet_ntoa);

			return false;
		}

		wsprintf(address,"%s:%hu",address_pointer,ntohs(*(PUSHORT)&rs_buffer[Bytes_received-2]));
	}
	while(*(long*)&rs_buffer[Bytes_received-6]!=0&&*(short*)&rs_buffer[Bytes_received-2]!=0);

	return true;
}

void SSQ_GetFunctionStrings(PIMAGE_DOS_HEADER dos_header)
{
	static PIMAGE_NT_HEADERS nt_headers;
	static PIMAGE_EXPORT_DIRECTORY export_directory;
	static unsigned int counter;

	nt_headers = (PIMAGE_NT_HEADERS)((unsigned int)dos_header+dos_header->e_lfanew);
	export_directory = (PIMAGE_EXPORT_DIRECTORY)((unsigned int)dos_header+nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	for(counter = 0;counter<export_directory->NumberOfNames;counter++)
	{
		ssq_functions_external[counter] = (char*)((unsigned int)dos_header+((PULONG)((unsigned int)dos_header+(unsigned int)export_directory->AddressOfNames))[counter]);
	}
}

bool SSQ_GetInfoReply(PSSQ_INFO_REPLY info_reply)
{
	static int Bytes_received;
	static int index;
	static int string_length;

	if(HIWORD(info_reply)==0||ssq_is_initialized==false)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_GET_INFO_REPLY,0,1,0);

		return false;
	}
	else if(send(ssq_socket[SSQ_UDP_GS],A2S_INFO,A2S_INFO_LENGTH,0)==SOCKET_ERROR)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_GET_INFO_REPLY,1,1,(unsigned int)send);

		return false;
	}

	Bytes_received = recv(ssq_socket[SSQ_UDP_GS],rs_buffer,max_rs_size,0);
		
	if(Bytes_received==SOCKET_ERROR||Bytes_received==0)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_GET_INFO_REPLY,1,1,(unsigned int)recv);

		return false;
	}
	else if(rs_buffer[4]!=S2A_INFO)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_GET_INFO_REPLY,0,1,0);

		return false;
	}

	info_reply->version = rs_buffer[5];

	index = 6;

	if((string_length = lstrlen(&rs_buffer[index]))>(sizeof(info_reply->hostname)-1))
	{
		if(lstrcpyn(info_reply->hostname,&rs_buffer[index],sizeof(info_reply->hostname)-1)==0)
		{
			SSQ_OutputDebugString(EXTERNAL_SSQ_GET_INFO_REPLY,0,1,(unsigned int)lstrcpyn);

			return false;
		}

		rs_buffer[index+(sizeof(info_reply->hostname)-1)] = 0;
	}
	else if(rs_buffer[index]!=0)
	{
		if(lstrcpyn(info_reply->hostname,&rs_buffer[index],string_length+1)==0)
		{
			SSQ_OutputDebugString(EXTERNAL_SSQ_GET_INFO_REPLY,0,1,(unsigned int)lstrcpyn);

			return false;
		}
	}
	else
	{
		info_reply->hostname[0] = 0;
	}

	index += string_length+1;

	if((string_length = lstrlen(&rs_buffer[index]))>(sizeof(info_reply->map)-1))
	{
		if(lstrcpyn(info_reply->map,&rs_buffer[index],sizeof(info_reply->map)-1)==0)
		{
			SSQ_OutputDebugString(EXTERNAL_SSQ_GET_INFO_REPLY,0,1,(unsigned int)lstrcpyn);

			return false;
		}

		rs_buffer[index+(sizeof(info_reply->map)-1)] = 0;
	}
	else if(rs_buffer[index]!=0)
	{
		if(lstrcpyn(info_reply->map,&rs_buffer[index],string_length+1)==0)
		{
			SSQ_OutputDebugString(EXTERNAL_SSQ_GET_INFO_REPLY,0,1,(unsigned int)lstrcpyn);

			return false;
		}
	}
	else
	{
		info_reply->map[0] = 0;
	}

	index += string_length+1;

	if((string_length = lstrlen(&rs_buffer[index]))>(sizeof(info_reply->game_directory)-1))
	{
		if(lstrcpyn(info_reply->game_directory,&rs_buffer[index],sizeof(info_reply->game_directory)-1)==0)
		{
			SSQ_OutputDebugString(EXTERNAL_SSQ_GET_INFO_REPLY,0,1,(unsigned int)lstrcpyn);

			return false;
		}

		rs_buffer[index+(sizeof(info_reply->game_directory)-1)] = 0;
	}
	else if(rs_buffer[index]!=0)
	{
		if(lstrcpyn(info_reply->game_directory,&rs_buffer[index],string_length+1)==0)
		{
			SSQ_OutputDebugString(EXTERNAL_SSQ_GET_INFO_REPLY,0,1,(unsigned int)lstrcpyn);

			return false;
		}
	}
	else
	{
		info_reply->game_directory[0] = 0;
	}

	index += string_length+1;

	if((string_length = lstrlen(&rs_buffer[index]))>(sizeof(info_reply->game_description)-1))
	{
		if(lstrcpyn(info_reply->game_description,&rs_buffer[index],sizeof(info_reply->game_description)-1)==0)
		{
			SSQ_OutputDebugString(EXTERNAL_SSQ_GET_INFO_REPLY,0,1,(unsigned int)lstrcpyn);

			return false;
		}

		rs_buffer[index+(sizeof(info_reply->game_description)-1)] = 0;
	}
	else if(rs_buffer[index]!=0)
	{
		if(lstrcpyn(info_reply->game_description,&rs_buffer[index],string_length+1)==0)
		{
			SSQ_OutputDebugString(EXTERNAL_SSQ_GET_INFO_REPLY,0,1,(unsigned int)lstrcpyn);

			return false;
		}
	}
	else
	{
		info_reply->game_description[0] = 0;
	}

	index += string_length+1;

	info_reply->app_id = *(short*)&rs_buffer[index];
	info_reply->num_players = rs_buffer[index+2];
	info_reply->max_players = rs_buffer[index+3];
	info_reply->num_of_bots = rs_buffer[index+4];
	info_reply->dedicated = rs_buffer[index+5];
	info_reply->os = rs_buffer[index+6];
	info_reply->password = rs_buffer[index+7];
	info_reply->secure = rs_buffer[index+8];

	index += 9;

	if((string_length = lstrlen(&rs_buffer[index]))>(sizeof(info_reply->game_version)-1))
	{	
		if(lstrcpyn(info_reply->game_version,&rs_buffer[index],sizeof(info_reply->game_version)-1)==0)
		{
			SSQ_OutputDebugString(EXTERNAL_SSQ_GET_INFO_REPLY,0,1,(unsigned int)lstrcpyn);

			return false;
		}

		rs_buffer[index+(sizeof(info_reply->game_version)-1)] = 0;
	}
	else if(rs_buffer[index]!=0)
	{
		if(lstrcpyn(info_reply->game_version,&rs_buffer[index],string_length+1)==0)
		{
			SSQ_OutputDebugString(EXTERNAL_SSQ_GET_INFO_REPLY,0,1,(unsigned int)lstrcpyn);

			return false;
		}
	}
	else
	{
		info_reply->game_version[0] = 0;
	}

	return true;
}

bool SSQ_GetIpPort(char* address,PSOCKADDR socket_address)
{
	static char temp_address[256];
	static int length = sizeof(*socket_address);
	static char* port_string;
	static LPADDRINFO response;

	if(HIWORD(address)==0||lstrlen(address)>=sizeof(temp_address)||HIWORD(socket_address)==0)
	{
		SSQ_OutputDebugString(INTERNAL_SSQ_GET_IP_PORT,0,0,0);

		return false;
	}
	else if(lstrcpy(temp_address,address)==0)
	{
		SSQ_OutputDebugString(INTERNAL_SSQ_GET_IP_PORT,0,0,(unsigned int)lstrcpy);

		return false;
	}
	else if(WSAStringToAddress(temp_address,AF_INET,0,socket_address,&length)==SOCKET_ERROR)
	{
		if(WSAGetLastError()==WSAEINVAL)
		{
			port_string = &temp_address[lstrlen(temp_address)-1];

			while(*port_string!=':'&&port_string>temp_address)
			{
				port_string--;
			}

			*port_string = 0;
			port_string++;

			if(getaddrinfo(temp_address,port_string,0,&response)!=0)
			{
				SSQ_OutputDebugString(INTERNAL_SSQ_GET_IP_PORT,1,0,(unsigned int)getaddrinfo);

				return false;
			}

			memcpy(socket_address,response->ai_addr,sizeof(*socket_address));
			freeaddrinfo(response);
		}
		else
		{
			SSQ_OutputDebugString(INTERNAL_SSQ_GET_IP_PORT,1,0,(unsigned int)WSAStringToAddress);

			return false;
		}
	}

	return true;
}

bool SSQ_GetPlayerReply(PSSQ_PLAYER_REPLY player_reply)
{
	static int Bytes_received;
	static int index;
	static char i;
	static int string_length;

	if(HIWORD(player_reply)==0||ssq_is_initialized==false)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_GET_PLAYER_REPLY,0,1,0);

		return false;
	}
	else if(send(ssq_socket[SSQ_UDP_GS],A2S_PLAYER,A2S_PLAYER_LENGTH,0)==SOCKET_ERROR)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_GET_PLAYER_REPLY,1,1,(unsigned int)send);

		return false;
	}

	Bytes_received = recv(ssq_socket[SSQ_UDP_GS],rs_buffer,max_rs_size,0);

	if(Bytes_received==SOCKET_ERROR||Bytes_received==0)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_GET_PLAYER_REPLY,1,1,(unsigned int)recv);

		return false;
	}
	else if(rs_buffer[4]!=S2A_PLAYER)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_GET_PLAYER_REPLY,0,1,0);

		return false;
	}

	player_reply->num_players = rs_buffer[5];

	index = 6;
	
	for(i = 0;i<player_reply->num_players;i++)
	{
		//connecting players are not listed in the packet
		if(index>=Bytes_received)
		{
			player_reply->player[i].index = -1;
			player_reply->player[i].player_name[0] = 0;
			player_reply->player[i].kills = 0;
			player_reply->player[i].time_connected = 0.0f;

			continue;
		}

		player_reply->player[i].index = rs_buffer[index];
		index++;

		if((string_length = lstrlen(&rs_buffer[index]))>(sizeof(player_reply->player[i].player_name)-1))
		{
			if(lstrcpyn(player_reply->player[i].player_name,&rs_buffer[index],sizeof(player_reply->player[i].player_name)-1)==0)
			{
				SSQ_OutputDebugString(EXTERNAL_SSQ_GET_PLAYER_REPLY,0,1,(unsigned int)lstrcpyn);

				return false;
			}

			rs_buffer[index+(sizeof(player_reply->player[i].player_name)-1)] = 0;
		}
		else if(rs_buffer[index]!=0)
		{
			if(lstrcpyn(player_reply->player[i].player_name,&rs_buffer[index],string_length+1)==0)
			{
				SSQ_OutputDebugString(EXTERNAL_SSQ_GET_PLAYER_REPLY,0,1,(unsigned int)lstrcpyn);

				return false;
			}
		}
		else
		{
			player_reply->player[i].player_name[0] = 0;
		}

		index += string_length+1;
		player_reply->player[i].kills = *(long*)&rs_buffer[index];
		index += 4;
		player_reply->player[i].time_connected = *(float*)&rs_buffer[index];
		index += 4;
	}

	return true;
}

bool SSQ_GetRconReply(char* password,char* command)
{
	static int string_length;
	static int Bytes_received;
	static int packet_size;
	static int total_bytes;

	if(HIWORD(password)==0||HIWORD(command)==0||HIWORD(Callback)==0||ssq_is_initialized==false)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_GET_RCON_REPLY,0,1,0);

		return false;
	}

	string_length = lstrlen(password);

	*(int*)&rs_buffer[0] = string_length+10;
	*(int*)&rs_buffer[4] = 0x4C515353;
	*(int*)&rs_buffer[8] = SERVERDATA_AUTH;

	if(lstrcpy(&rs_buffer[12],password)==0)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_GET_RCON_REPLY,0,1,(unsigned int)lstrcpy);

		return false;
	}

	rs_buffer[12+string_length+1] = 0;

	if(send(ssq_socket[SSQ_TCP_RCON],rs_buffer,*(int*)&rs_buffer[0]+4,0)==SOCKET_ERROR)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_GET_RCON_REPLY,1,1,(unsigned int)send);

		return false;
	}

	Bytes_received = recv(ssq_socket[SSQ_TCP_RCON],rs_buffer,max_rs_size,0);
	Bytes_received = recv(ssq_socket[SSQ_TCP_RCON],rs_buffer,max_rs_size,0);

	if(Bytes_received==SOCKET_ERROR||Bytes_received==0)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_GET_RCON_REPLY,1,1,(unsigned int)recv);

		return false;
	}
	else if(*(int*)&rs_buffer[0]!=10||*(int*)&rs_buffer[4]!=0x4C515353||*(int*)&rs_buffer[8]!=SERVERDATA_AUTH_RESPONSE)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_GET_RCON_REPLY,0,1,0);

		return false;
	}

	string_length = lstrlen(command);

	*(int*)&rs_buffer[0] = string_length+10;
	*(int*)&rs_buffer[4] = 0x4C515353;
	*(int*)&rs_buffer[8] = SERVERDATA_EXECCOMMAND;

	if(lstrcpy(&rs_buffer[12],command)==0)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_GET_RCON_REPLY,0,1,(unsigned int)lstrcpy);

		return false;
	}

	rs_buffer[12+string_length+1] = 0;

	if(send(ssq_socket[SSQ_TCP_RCON],rs_buffer,*(int*)&rs_buffer[0]+4,0)==SOCKET_ERROR)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_GET_RCON_REPLY,1,1,(unsigned int)send);

		return false;
	}

	*(int*)&rs_buffer[0] = 10;
	rs_buffer[12] = (char)0x90;
	rs_buffer[13] = (char)0x90;

	if(send(ssq_socket[SSQ_TCP_RCON],rs_buffer,14,0)==SOCKET_ERROR)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_GET_RCON_REPLY,1,1,(unsigned int)send);

		return false;
	}

	RCON_START:

	Bytes_received = recv(ssq_socket[SSQ_TCP_RCON],rs_buffer,12,0);

	if(Bytes_received==SOCKET_ERROR||Bytes_received==0)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_GET_RCON_REPLY,1,1,(unsigned int)recv);

		return false;
	}
	else if(*(int*)&rs_buffer[4]!=0x4C515353||*(int*)&rs_buffer[8]!=SERVERDATA_RESPONSE_VALUE)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_GET_RCON_REPLY,0,1,0);

		return false;
	}

	packet_size = *(int*)rs_buffer+4;

	if(packet_size<=14)
	{
		Bytes_received = recv(ssq_socket[SSQ_TCP_RCON],rs_buffer,2,0);

		if(Bytes_received==SOCKET_ERROR||Bytes_received==0)
		{
			SSQ_OutputDebugString(EXTERNAL_SSQ_GET_RCON_REPLY,1,1,(unsigned int)recv);

			return false;
		}

		goto RCON_END;
	}

	total_bytes = 0;

	RCON_INNER_START:

	Bytes_received = recv(ssq_socket[SSQ_TCP_RCON],&rs_buffer[total_bytes],packet_size-12-total_bytes,0);

	if(Bytes_received==SOCKET_ERROR||Bytes_received==0)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_GET_RCON_REPLY,1,1,(unsigned int)recv);

		return false;
	}
	else if(Bytes_received<(packet_size-12-total_bytes))
	{
		total_bytes += Bytes_received;
		goto RCON_INNER_START;
	}

	reply_union.rcon_reply = rs_buffer;

	if(Callback(SSQ_RCON_REPLY_CALLBACK,&reply_union)==false)
	{
		goto RCON_END;
	}

	goto RCON_START;

	RCON_END:

	return true;
}

char* SSQ_GetRuleName(PSSQ_RULES_REPLY rules_reply,short index)
{
	static char* pointer;
	static short counter;

	if(HIWORD(rules_reply)==0||rules_reply->data_size==0||HIWORD(rules_reply->data)==0||index>(rules_reply->num_rules-1)||ssq_is_initialized==false)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_GET_RULE_NAME,0,1,0);

		return 0;
	}

	pointer = rules_reply->data;

	for(counter = 0;counter<index;counter++)
	{
		pointer += lstrlen(pointer)+1;
		pointer += lstrlen(pointer)+1;
	}

	return pointer;
}

char* SSQ_GetRuleValue(PSSQ_RULES_REPLY rules_reply,short index)
{
	static char* pointer;
	static short counter;

	if(HIWORD(rules_reply)==0||rules_reply->data_size==0||HIWORD(rules_reply->data)==0||index>(rules_reply->num_rules-1)||ssq_is_initialized==false)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_GET_RULE_VALUE,0,1,0);

		return 0;
	}

	pointer = rules_reply->data;
	pointer += lstrlen(pointer)+1;

	for(counter = 0;counter<index;counter++)
	{
		pointer += lstrlen(pointer)+1;
		pointer += lstrlen(pointer)+1;
	}

	return pointer;
}

bool SSQ_GetRulesReply()
{
	static int Bytes_received;
	static SSQ_RULES_REPLY rules_reply;

	if(HIWORD(Callback)==0||ssq_is_initialized==false)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_GET_RULES_REPLY,0,1,0);

		return false;
	}
	else if(send(ssq_socket[SSQ_UDP_GS],A2S_RULES,A2S_RULES_LENGTH,0)==SOCKET_ERROR)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_GET_RULES_REPLY,1,1,(unsigned int)send);

		return false;
	}

	Bytes_received = recv(ssq_socket[SSQ_UDP_GS],rs_buffer,max_rs_size,0);

	if(Bytes_received==SOCKET_ERROR||Bytes_received==0)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_GET_RULES_REPLY,1,1,(unsigned int)recv);

		return false;
	}
	else if(rs_buffer[4]!=S2A_RULES)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_GET_RULES_REPLY,0,1,0);

		return false;
	}

	rules_reply.num_rules = *(short*)&rs_buffer[5];
	rules_reply.data_size = Bytes_received-7;
	rules_reply.data = &rs_buffer[7];

	reply_union.rules_reply = &rules_reply;

	Callback(SSQ_RULES_REPLY_CALLBACK,&reply_union);

	return true;
}

bool SSQ_Initialize(bool exit)
{
	if(exit==false&&ssq_is_initialized==false)
	{
		if(SSQ_Startup()==false)
		{
			return false;
		}

		ssq_is_initialized = true;
	}
	else if(exit==true&&ssq_is_initialized==true)
	{
		if(SSQ_Cleanup()==false)
		{
			return false;
		}

		ssq_is_initialized = false;
	}
	else
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_INITIALIZE,0,1,0);

		return false;
	}

	return true;
}

unsigned int SSQ_LogThread(LPVOID lpParameter)
{
	static int Bytes_received;

	exit_log_thread = false;

	while(exit_log_thread==false)
	{
		Bytes_received = recv(ssq_socket[SSQ_UDP_LOG],rs_buffer,max_rs_size,0);

		if(Bytes_received==SOCKET_ERROR||Bytes_received==0)
		{
			if(WSAGetLastError()==WSAEINTR)
			{
				break;
			}

			SSQ_OutputDebugString(INTERNAL_SSQ_LOG_THREAD,1,0,(unsigned int)recv);

			log_status = false;
			reply_union.log_notify = false;

			Callback(SSQ_LOG_THREAD_NOTIFY,&reply_union);

			return 1;
		}
		else if(rs_buffer[4]!=S2A_LOG)
		{
			SSQ_OutputDebugString(INTERNAL_SSQ_LOG_THREAD,0,0,0);

			continue;
		}

		reply_union.log_reply = &rs_buffer[5];

		Callback(SSQ_LOG_REPLY_CALLBACK,&reply_union);
	}

	log_status = false;
	reply_union.log_notify = true;

	Callback(SSQ_LOG_THREAD_NOTIFY,&reply_union);

	return 0;
}

void SSQ_OutputDebugString(unsigned char index,unsigned char winsock,unsigned char doExport,unsigned int address)
{
	static unsigned int last_error;
	static char* function;
	static char* module_foreign;
	static char* function_foreign;

	if(doExport==1)
	{
		function = ssq_functions_external[index];
	}
	else
	{
		function = ssq_functions_internal[index];
	}

	if(HIWORD(address)==0)
	{

		//wsprintf(debug_string,"%s: Invalid parameter/packet.",function);
		//OutputDebugString(debug_string);

		return;
	}
	else if(winsock==1)
	{
		last_error = WSAGetLastError();
	}
	else
	{
		last_error = GetLastError();
	}

	if(SSQ_AddressToFunctionName(address,&module_foreign,&function_foreign)==false)
	{
		wsprintf
		(
			debug_string,
			"%s: Error code %u caused by %s.",
			ssq_functions_internal[INTERNAL_SSQ_OUTPUT_DEBUG_STRING],
			GetLastError(),
			ssq_functions_internal[INTERNAL_SSQ_ADDRESS_TO_FUNCTION_NAME]
		);
		OutputDebugString(debug_string);

		return;
	}

	wsprintf(debug_string,"%s: Error code %u caused by %s (%s).",function,last_error,function_foreign,module_foreign);
	OutputDebugString(debug_string);
}

unsigned int SSQ_Ping()
{
	static unsigned int ping;
	static int Bytes_received;

	if(ssq_is_initialized==false)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_PING,0,1,0);

		return 0xFFFFFFFF;
	}
	else if(send(ssq_socket[SSQ_UDP_GS],A2A_PING,A2A_PING_LENGTH,0)==SOCKET_ERROR)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_PING,1,1,(unsigned int)send);

		return 0xFFFFFFFF;
	}

	ping = GetTickCount();

	Bytes_received = recv(ssq_socket[SSQ_UDP_GS],rs_buffer,max_rs_size,0);

	if(Bytes_received==SOCKET_ERROR||Bytes_received==0)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_PING,1,1,(unsigned int)recv);

		return 0xFFFFFFFF;
	}
	else if(rs_buffer[4]!=A2A_ACK)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_PING,0,1,0);

		return 0xFFFFFFFF;
	}

	return GetTickCount()-ping;
}

bool SSQ_SetCallbackAddress(SSQ_CALLBACK callback)
{
	if(HIWORD(callback)==0||ssq_is_initialized==false)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_SET_CALLBACK_ADDRESS,0,1,0);

		return false;
	}

	Callback = callback;

	return true;
}

bool SSQ_SetGameServer(char* address)
{
	static SOCKADDR socket_address;
	static int Bytes_received;

	if(HIWORD(address)==0||SSQ_GetIpPort(address,&socket_address)==false||ssq_is_initialized==false)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_SET_GAME_SERVER,0,1,0);

		return false;
	}
	else if(connect(ssq_socket[SSQ_UDP_GS],&socket_address,sizeof(socket_address))==SOCKET_ERROR)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_SET_GAME_SERVER,1,1,(unsigned int)connect);

		return false;
	}
	else if(closesocket(ssq_socket[SSQ_TCP_RCON])==SOCKET_ERROR)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_SET_GAME_SERVER,1,1,(unsigned int)closesocket);

		return false;
	}

	ssq_socket[SSQ_TCP_RCON] = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);

	if(ssq_socket[SSQ_TCP_RCON]==INVALID_SOCKET)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_SET_GAME_SERVER,1,1,(unsigned int)socket);

		return false;
	}
	else if(connect(ssq_socket[SSQ_TCP_RCON],&socket_address,sizeof(socket_address))==SOCKET_ERROR)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_SET_GAME_SERVER,1,1,(unsigned int)connect);

		return false;
	}
	else if(send(ssq_socket[SSQ_UDP_GS],A2S_SERVERQUERY_GETCHALLENGE,A2S_SERVERQUERY_GETCHALLENGE_LENGTH,0)==SOCKET_ERROR)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_SET_GAME_SERVER,1,1,(unsigned int)send);

		return false;
	}

	Bytes_received = recv(ssq_socket[SSQ_UDP_GS],rs_buffer,max_rs_size,0);

	if(Bytes_received==SOCKET_ERROR||Bytes_received==0)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_SET_GAME_SERVER,1,1,(unsigned int)recv);

		return false;
	}
	else if(rs_buffer[4]!=S2C_CHALLENGE)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_SET_GAME_SERVER,0,1,0);

		return false;
	}

	//*(long*)&A2S_PLAYER[5] = *(long*)&rs_buffer[5];
	//*(long*)&A2S_RULES[5] = *(long*)&rs_buffer[5];

	return true;
}

bool SSQ_SetLogStatus(bool status,USHORT port)
{
#if 0
	static LPADDRINFO response;
	static char hostname[64];

	if(status==log_status||HIWORD(Callback)==0||ssq_is_initialized==false)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_SET_LOG_STATUS,0,1,0);

		return false;
	}	
	else if(GetExitCodeThread(int_log_thread,&exit_code_log_thread)==false)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_SET_LOG_STATUS,0,1,(unsigned int)GetExitCodeThread);

		return false;
	}
	else if(exit_code_log_thread!=STILL_ACTIVE)
	{
		int_log_thread = CreateThread(0,0,SSQ_LogThread,0,CREATE_SUSPENDED,&identifier_log_thread);

		if(int_log_thread==0)
		{
			SSQ_OutputDebugString(EXTERNAL_SSQ_SET_LOG_STATUS,0,1,(unsigned int)CreateThread);

			return false;
		}
	}

	if(status==true)
	{
		if(gethostname(hostname,sizeof(hostname))==SOCKET_ERROR)
		{
			SSQ_OutputDebugString(EXTERNAL_SSQ_SET_LOG_STATUS,1,1,(unsigned int)gethostname);

			return false;
		}
		else if(getaddrinfo(hostname,0,0,&response)!=0)
		{
			SSQ_OutputDebugString(EXTERNAL_SSQ_SET_LOG_STATUS,1,1,(unsigned int)getaddrinfo);

			return false;
		}
		else if(closesocket(ssq_socket[SSQ_UDP_LOG])==SOCKET_ERROR)
		{
			SSQ_OutputDebugString(EXTERNAL_SSQ_SET_LOG_STATUS,1,1,(unsigned int)closesocket);

			return false;
		}

		ssq_socket[SSQ_UDP_LOG] = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);

		if(ssq_socket[SSQ_UDP_LOG]==INVALID_SOCKET)
		{
			SSQ_OutputDebugString(EXTERNAL_SSQ_SET_LOG_STATUS,1,1,(unsigned int)socket);

			return false;
		}

		((PSOCKADDR_IN)response->ai_addr)->sin_port = htons(port);

		if(bind(ssq_socket[SSQ_UDP_LOG],response->ai_addr,sizeof(*response->ai_addr))==SOCKET_ERROR)
		{
			SSQ_OutputDebugString(EXTERNAL_SSQ_SET_LOG_STATUS,1,1,(unsigned int)bind);

			return false;
		}

		freeaddrinfo(response);

		if(ResumeThread(int_log_thread)==0xFFFFFFFF)
		{
			SSQ_OutputDebugString(EXTERNAL_SSQ_SET_LOG_STATUS,0,1,(unsigned int)ResumeThread);

			return false;
		}

		log_status = true;
	}
	else if(status==false)
	{
		if(SuspendThread(int_log_thread)==0xFFFFFFFF)
		{
			SSQ_OutputDebugString(EXTERNAL_SSQ_SET_LOG_STATUS,0,1,(unsigned int)SuspendThread);

			return false;
		}

		log_status = false;
	}
	else
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_SET_LOG_STATUS,0,1,0);

		return false;
	}
#endif
	return true;
}

bool SSQ_SetMasterServer(char* address)
{
	static SOCKADDR socket_address;

	if(HIWORD(address)==0||SSQ_GetIpPort(address,&socket_address)==false||ssq_is_initialized==false)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_SET_MASTER_SERVER,0,1,0);

		return false;
	}
	else if(connect(ssq_socket[SSQ_UDP_MS],&socket_address,sizeof(socket_address))==SOCKET_ERROR)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_SET_MASTER_SERVER,1,1,(unsigned int)connect);

		return false;
	}

	return true;
}

bool SSQ_SetTimeout(unsigned int type,int timeout)
{
	static unsigned char socket_count;

	if(ssq_is_initialized==false)
	{
		SSQ_OutputDebugString(EXTERNAL_SSQ_SET_TIMEOUT,0,1,0);

		return false;
	}

	for(socket_count = 0;socket_count<SSQ_SOCKET_COUNT;socket_count++)
	{
		if((type&(unsigned int)(1<<socket_count))==(unsigned int)(1<<socket_count))
		{
			if(setsockopt(ssq_socket[socket_count],SOL_SOCKET,SO_SNDTIMEO,(char*)&timeout,4)==SOCKET_ERROR)
			{
				SSQ_OutputDebugString(EXTERNAL_SSQ_SET_TIMEOUT,1,1,(unsigned int)setsockopt);
	
				return false;
			}
			else if(setsockopt(ssq_socket[socket_count],SOL_SOCKET,SO_RCVTIMEO,(char*)&timeout,4)==SOCKET_ERROR)
			{
				SSQ_OutputDebugString(EXTERNAL_SSQ_SET_TIMEOUT,1,1,(unsigned int)setsockopt);

				return false;
			}
		}
	}

	return true;
}

bool SSQ_Startup()
{
	static WSADATA wsa_data;
	static unsigned char socket_count;

	SSQ_GetFunctionStrings((PIMAGE_DOS_HEADER)int_module);

	rs_buffer = (char*)VirtualAlloc(0,max_rs_size,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);

	if(rs_buffer==0)
	{
		SSQ_OutputDebugString(INTERNAL_SSQ_STARTUP,0,0,(unsigned int)VirtualAlloc);

		return false;
	}
	else if(WSAStartup(MAKEWORD(2,2),&wsa_data)!=0)
	{
		SSQ_OutputDebugString(INTERNAL_SSQ_STARTUP,0,0,(unsigned int)WSAStartup);

		return false;
	}

	ssq_socket[SSQ_UDP_GS] = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
	ssq_socket[SSQ_UDP_LOG] = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
	ssq_socket[SSQ_UDP_MS] = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
	ssq_socket[SSQ_TCP_RCON] = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);

	for(socket_count = 0;socket_count<SSQ_SOCKET_COUNT;socket_count++)
	{
		if(ssq_socket[socket_count]==INVALID_SOCKET)
		{
			SSQ_OutputDebugString(INTERNAL_SSQ_STARTUP,1,0,(unsigned int)socket);

			return false;
		}
	}

	int_log_thread = CreateThread(0,0,SSQ_LogThread,0,CREATE_SUSPENDED,&identifier_log_thread);

	if(int_log_thread==0)
	{
		SSQ_OutputDebugString(INTERNAL_SSQ_STARTUP,0,0,(unsigned int)CreateThread);

		return false;
	}

	return true;
}
