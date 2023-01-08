#include <iostream>
#include <cinttypes>
#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include "include/capstone/capstone.h"

#pragma comment(lib, "capstone.lib")

using namespace std;

int main(void)
{
    HMODULE NTDLLBase = GetModuleHandle(_T("ntdll.dll"));
    if (NTDLLBase == NULL) {
        _tprintf(_T("[x] Failed to get ntdll.dll module\n"));
        return 0;
    }

    // 获取ntdll的.text段地址，以及.text段大小
    PUCHAR NTDLLCode = (PUCHAR)((UINT_PTR)NTDLLBase + 0x1000);
    PIMAGE_NT_HEADERS NTDLLPEHeader = (PIMAGE_NT_HEADERS)((UINT_PTR)NTDLLBase + ((IMAGE_DOS_HEADER*)NTDLLBase)->e_lfanew);
    DWORD NTDLLCodeSize = NTDLLPEHeader->OptionalHeader.SizeOfCode;

    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle)) {
        printf("ERROR: Failed to initialize engine!\n");
        return -1;
    }

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    const int MAX_OPCODE_SIZE = 16; // OP指令的最大长度
    const int MAX_OPCODE_COUNT = 5; // 一次性反汇编的数量
    for (unsigned int i = 0; i < NTDLLCodeSize - MAX_OPCODE_SIZE * MAX_OPCODE_COUNT; i++) {

        // 一次性反汇编 MAX_OPCODE_COUNT 条指令
        cs_insn* insn;
        size_t count = cs_disasm(handle, NTDLLCode + i, MAX_OPCODE_SIZE * MAX_OPCODE_COUNT, 0, MAX_OPCODE_COUNT, &insn);
        if (count == 0)
            continue;

        // 寻找mov指令
        if (strcmp(insn->mnemonic, "mov") != 0) {
            cs_free(insn, count);
            continue;
        }

        cs_x86_op* opl = &(insn->detail->x86.operands[0]);
        cs_x86_op* opr = &(insn->detail->x86.operands[1]);

        // 要求左操作数为内存，右操作数为寄存器
        if (opl->type != X86_OP_MEM || opr->type != X86_OP_REG) {
            cs_free(insn, count);
            continue;
        }

        // 检查右操作是否为非易蒸发寄存器
        if (opr->reg != X86_REG_RBX &&
            opr->reg != X86_REG_RSI &&
            opr->reg != X86_REG_RDI &&
            opr->reg != X86_REG_R12 &&
            opr->reg != X86_REG_R13 &&
            opr->reg != X86_REG_R14 &&
            opr->reg != X86_REG_R15) {
            cs_free(insn, count);
            continue;
        }

        // 检查左操作数是否为非易蒸发寄存器
        if (opl->mem.base != X86_REG_RBX &&
            opl->mem.base != X86_REG_RSI &&
            opl->mem.base != X86_REG_RDI &&
            opl->mem.base != X86_REG_R12 &&
            opl->mem.base != X86_REG_R13 &&
            opl->mem.base != X86_REG_R14 &&
            opl->mem.base != X86_REG_R15) {
            cs_free(insn, count);
            continue;
        }

        // 检查左操作数是否存在位移数
        //if (opl->mem.disp != 0) {
        //    cs_free(insn, count);
        //    continue;
        //}

        // 左操作数是否等于右操作数
        if (opl->mem.base == opr->reg) {
            cs_free(insn, count);
            continue;
        }

        // 寻找符合条件的ret指令
        for (size_t j = 1; j < count; j++) {

            // 寻找 ret 指令
            if (strcmp(insn[j].mnemonic, "ret") == 0) {

                for (size_t k = 0; k <= j; k++) {
                    printf("0x%Ix:\t%s\t\t%s\n", 0x180001000 + i, insn[k].mnemonic, insn[k].op_str);
                }
                printf("\n");
                break;
            }

            // 允许 mov reg, ?? 指令
            else if (strcmp(insn[j].mnemonic, "mov") == 0) {

                cs_x86_op* opl = &(insn[j].detail->x86.operands[0]);

                // 要求左操作数为寄存器
                if (opl->type != X86_OP_REG) {
                    break;
                }
            }

            // 允许 add rsp, ?? 指令
            else if (strcmp(insn[j].mnemonic, "add") == 0) {

                cs_x86_op* opl = &(insn[j].detail->x86.operands[0]);
                cs_x86_op* opr = &(insn[j].detail->x86.operands[1]);

                // 要求左操作数为寄存器，右操作数为立即数
                if (opl->type != X86_OP_REG || opr->type != X86_OP_IMM) {
                    break;
                }

                //printf("0x%Ix:\t%s\t\t%s\n", 0x180001000 + i, insn[j].mnemonic, insn[j].op_str);
                //printf("insn->detail->x86.op_count = %d, opl->type = %d, opr->type = %d\n", insn->detail->x86.op_count, opl->type, opr->type);

                // 如果左操作数是rsp，则保存立即数
                if (opl->reg == X86_REG_RSP) {
                    // opr->imm
                }
            }

            // 允许 xor reg, ?? 指令
            else if (strcmp(insn[j].mnemonic, "xor") == 0) {

                cs_x86_op* opl = &(insn[j].detail->x86.operands[0]);

                // 要求左操作数为寄存器
                if (opl->type != X86_OP_REG) {
                    break;
                }
            }

            // 允许 pop reg 指令
            else if (strcmp(insn[j].mnemonic, "pop") == 0) {

                // 增加pop计数
            }

            // 不接受其他指令
            else {
                break;
            }
        }

        cs_free(insn, count);
        
    }

    cs_close(&handle);

    return 0;
}
