#include "binaryninjacore.h"
#include <cstddef>
#define _CRT_SECURE_NO_WARNINGS
#define NOMINMAX

#include <stdio.h>
#include <string.h>

#include "binaryninjaapi.h"
#include "lowlevelilinstruction.h"
#include "arcompact.h"
#include "arcompact_il.h"

using namespace BinaryNinja;
using namespace ArCompact;

class ArcArchitecture : public Architecture {
	protected:
	BNEndianness m_endian;
	ArcVersion m_version;

	public:
	ArcArchitecture(const std::string& name, ArcVersion version, BNEndianness endian): Architecture(name), m_version(version), m_endian(endian) {
	}

	virtual BNEndianness GetEndianness() const override {
		return m_endian;
	}

	virtual size_t GetInstructionAlignment() const override {
		return 2;
	}

	virtual size_t GetMaxInstructionLength() const override {
		return 16; // 2 instructions with long imms, for delay slot
	}
	
	virtual size_t GetAddressSize() const override {
		return 4;
	}

	virtual size_t GetDefaultIntegerSize() const override {
		return 4;
	}
	
	virtual size_t GetOpcodeDisplayLength() const override {
		return 4;
	}

	virtual uint32_t GetStackPointerRegister() override {
		return REG_SP;
	}

	virtual uint32_t GetLinkRegister() override {
		return REG_BLINK;
	}

	virtual bool CanAssemble() override {
		return false;
	}

	virtual std::string GetRegisterName(uint32_t reg) override {
		const char* reg_str = nullptr;

		if (reg < END_REG) {
			reg_str = get_register((Reg)reg);
		}
		if (reg_str == nullptr) {
			return "";
		}
		return reg_str;
	}

	virtual BNRegisterInfo GetRegisterInfo(uint32_t reg) override {
		BNRegisterInfo result = {reg, 0, 4, NoExtend};
		return result;
	}

	virtual std::vector<uint32_t> GetAllFlags() override {
		return std::vector<uint32_t>{
			FLAG_STATUS_L,
			FLAG_STATUS_Z,
			FLAG_STATUS_N,
			FLAG_STATUS_C,
			FLAG_STATUS_V,
			FLAG_STATUS_U,
			FLAG_STATUS_DE,
			FLAG_STATUS_AE,
			FLAG_STATUS_A1,
			FLAG_STATUS_A2,
			FLAG_STATUS_E1,
			FLAG_STATUS_E2,
			FLAG_STATUS_H,

			// AUX_MACMODE
			FLAG_STATUS_S1,
			FLAG_STATUS_S2,
		};
	}

	virtual std::string GetFlagName(uint32_t flag) override {
		const char* flag_str = nullptr;

		if (flag < END_REG) {
			flag_str = get_flag((Flag)flag);
		}
		if (flag_str == nullptr) {
			return "";
		}
		return flag_str;
	}

	virtual std::string GetFlagWriteTypeName(uint32_t flags) override {
		switch (flags) {
			case IL_FLAGWRITE_NONE: return "";
			case IL_FLAGWRITE_ZN: return "ZN";
			case IL_FLAGWRITE_ZNC: return "ZNC";
			case IL_FLAGWRITE_ZNV: return "ZNV";
			case IL_FLAGWRITE_ZNCV: return "ZNCV";
			default:
				return "";
		}
	}

	virtual BNFlagRole GetFlagRole(uint32_t flag, uint32_t) override {
		/*
			SpecialFlagRole = 0,
			ZeroFlagRole = 1,
			PositiveSignFlagRole = 2,
			NegativeSignFlagRole = 3,
			CarryFlagRole = 4,
			OverflowFlagRole = 5,
			HalfCarryFlagRole = 6,
			EvenParityFlagRole = 7,
			OddParityFlagRole = 8,
			OrderedFlagRole = 9,
			UnorderedFlagRole = 10
		*/
		switch (flag) {
			case FLAG_STATUS_Z:
				return ZeroFlagRole;
			case FLAG_STATUS_N:
				return NegativeSignFlagRole;
			case FLAG_STATUS_C:
				return CarryFlagRole;
			case FLAG_STATUS_V:
				return OverflowFlagRole;
			default:
				return SpecialFlagRole;
		}
	}

	virtual std::vector<uint32_t> GetFlagsWrittenByFlagWriteType(uint32_t flags) override {
		switch (flags) {
		case IL_FLAGWRITE_NONE:
			case IL_FLAGWRITE_ZN:
				return std::vector<uint32_t>{ FLAG_STATUS_Z, FLAG_STATUS_N };
			case IL_FLAGWRITE_ZNC:
				return std::vector<uint32_t>{ FLAG_STATUS_Z, FLAG_STATUS_N, FLAG_STATUS_C };
			case IL_FLAGWRITE_ZNV:
				return std::vector<uint32_t>{ FLAG_STATUS_Z, FLAG_STATUS_N, FLAG_STATUS_V };
			case IL_FLAGWRITE_ZNCV:
				return std::vector<uint32_t>{ FLAG_STATUS_Z, FLAG_STATUS_N, FLAG_STATUS_C, FLAG_STATUS_V };
			default:
				return std::vector<uint32_t>{};
		}
	}

	virtual std::vector<uint32_t> GetFlagsRequiredForFlagCondition(BNLowLevelILFlagCondition cond, uint32_t) override {
		switch (cond) {
			case LLFC_E:
			case LLFC_NE:
				return std::vector<uint32_t>{ FLAG_STATUS_Z };
			case LLFC_SLT:
			case LLFC_SGE:
				return std::vector<uint32_t>{ FLAG_STATUS_N, FLAG_STATUS_V };
			case LLFC_ULT:
			case LLFC_UGE:
				return std::vector<uint32_t>{ FLAG_STATUS_C };
			case LLFC_SLE:
			case LLFC_SGT:
				return std::vector<uint32_t>{ FLAG_STATUS_Z, FLAG_STATUS_N, FLAG_STATUS_V };
			case LLFC_ULE:
			case LLFC_UGT:
				return std::vector<uint32_t>{ FLAG_STATUS_C, FLAG_STATUS_Z };
			case LLFC_NEG:
			case LLFC_POS:
				return std::vector<uint32_t>{ FLAG_STATUS_N };
			case LLFC_O:
			case LLFC_NO:
				return std::vector<uint32_t>{ FLAG_STATUS_V };
			default:
				return std::vector<uint32_t>();
		}
	}

	virtual std::vector<uint32_t> GetAllFlagWriteTypes() override {
		return std::vector<uint32_t>{
			IL_FLAGWRITE_NONE,
			IL_FLAGWRITE_ZN,
			IL_FLAGWRITE_ZNC,
			IL_FLAGWRITE_ZNV,
			IL_FLAGWRITE_ZNCV,
		};
	}

	bool Disassemble(const uint8_t* data, uint32_t addr, size_t maxLen, Instruction& result) {
		memset(&result, 0, sizeof(result));
		if (arcompact_decompose(
			(const uint16_t*) data,
			maxLen,
			&result,
			m_version,
			addr,
			(this->m_endian == BigEndian) ? 1 : 0
		)) {
			return false;
		}

		return true;
	}

	virtual std::vector<uint32_t> GetFullWidthRegisters() override {
		return GetAllRegisters();
	}

	virtual std::vector<uint32_t> GetAllRegisters() override {
		return std::vector<uint32_t>{
			REG_R0, REG_R1, REG_R2, REG_R3,
			REG_R4, REG_R5, REG_R6, REG_R7,
			REG_R8, REG_R9, REG_R10, REG_R11,
			REG_R12, REG_R13, REG_R14, REG_R15,
			REG_R16, REG_R17, REG_R18, REG_R19,
			REG_R20, REG_R21, REG_R22, REG_R23,
			REG_R24, REG_R25, REG_GP, REG_FP,
			REG_SP, REG_ILINK1, REG_ILINK2, REG_BLINK,

			// Extension Core Registers
			REG_R32, REG_R33, REG_R34, REG_R35,
			REG_R36, REG_R37, REG_R38, REG_R39,
			REG_R40, REG_R41, REG_R42, REG_R43,
			REG_R44, REG_R45, REG_R46, REG_R47,
			REG_R48, REG_R49, REG_R50, REG_R51,
			REG_R52, REG_R53, REG_R54, REG_R55,
			REG_R56, REG_R57, REG_R58, REG_R59,
			REG_LP_COUNT,
			REG_R61, // Reserved
			REG_R62, // Long immediate data indicator
			REG_PCL,
		};
	}

	virtual bool GetInstructionLowLevelIL(const uint8_t* data, uint64_t addr, size_t& len, LowLevelILFunction& il) override {
		Instruction instruction;
		if (!Disassemble(data, addr, len, instruction)) {
			il.AddInstruction(il.Undefined());
			return false;
		}

		size_t remainingLen = len - instruction.size; 
		len = instruction.size;
		
		Instruction delaySlot;
		if (instruction.delayed) {
			if (!Disassemble(data + instruction.size, addr + instruction.size, remainingLen, delaySlot)) {
				il.AddInstruction(il.Undefined());
				return false;
			}
			len += delaySlot.size;
		}

		return GetLowLevelILForInstruction(this, addr, il, instruction, &delaySlot);
	}

	virtual bool GetInstructionInfo(const uint8_t* data, uint64_t addr, size_t maxLen, InstructionInfo& result) override {
		Instruction instruction;
		if (!Disassemble(data, addr, maxLen, instruction)) {
			return false;
		}

		uint32_t next_addr = addr + instruction.size;

		Instruction delaySlot;
		if (instruction.delayed) {
			if (!Disassemble(data + instruction.size, addr + instruction.size, maxLen - instruction.size, delaySlot)) {
				return false;
			}

			next_addr += delaySlot.size;
		}

		result = InstructionInfo();
		result.length = instruction.size;

		switch (instruction.operation) {
			case ARC_BBIT0:
			case ARC_BBIT1:
				result.AddBranch(
					TrueBranch,
					instruction.operands[2].address,
					nullptr,
					instruction.delayed
				);
				result.AddBranch(
					FalseBranch,
					next_addr,
					nullptr,
					instruction.delayed
				);
				break;
			case ARC_B:
				if (instruction.condition == AL || instruction.condition == NONE) {
					result.AddBranch(
						UnconditionalBranch,
						instruction.operands[0].address,
						nullptr,
						instruction.delayed
					);

					break;
				}

				result.AddBranch(
					TrueBranch,
					instruction.operands[0].address,
					nullptr,
					instruction.delayed
				);
				result.AddBranch(
					FalseBranch,
					next_addr,
					nullptr,
					instruction.delayed
				);
				break;
			case ARC_BL:
				result.AddBranch(
					CallDestination,
					instruction.operands[0].address,
					nullptr,
					instruction.delayed
				);
				break;
			case ARC_BR:
				result.AddBranch(
					TrueBranch,
					instruction.operands[2].address,
					nullptr,
					instruction.delayed
				);
				result.AddBranch(
					FalseBranch,
					next_addr,
					nullptr,
					instruction.delayed
				);
				break;
			case ARC_J:
				if (instruction.operands[0].operand_class == LABEL) {
					if (instruction.condition == AL || instruction.condition == NONE) {
						if (instruction.operands[0].operand_class == LABEL) {
							result.AddBranch(
								UnconditionalBranch,
								instruction.operands[0].address,
								nullptr,
								instruction.delayed
							);
						}
						break;
					}

					result.AddBranch(
						TrueBranch,
						instruction.operands[0].address,
						nullptr,
						instruction.delayed
					);
					result.AddBranch(
						FalseBranch,
						next_addr,
						nullptr,
						instruction.delayed
					);
				} else if (instruction.operands[0].operand_class == REG && (
					instruction.operands[0].reg == REG_BLINK ||
					instruction.operands[0].reg == REG_ILINK1 ||
					instruction.operands[0].reg == REG_ILINK2)
				) {
					result.AddBranch(FunctionReturn, 0, nullptr, instruction.delayed);
				} else {
					result.AddBranch(IndirectBranch, 0, nullptr, instruction.delayed);
				}
				break;
			case ARC_JL:
				if (instruction.operands[0].operand_class == LABEL) {
					result.AddBranch(
						CallDestination,
						instruction.operands[0].address,
						nullptr,
						instruction.delayed
					);
				} else {
					result.AddBranch(IndirectBranch, 0, nullptr, instruction.delayed);
				}
				break;
			case ARC_LP:
				if (instruction.condition == AL || instruction.condition == NONE) {
					break;
				}

				result.AddBranch(FalseBranch, instruction.operands[2].address);
				result.AddBranch(TrueBranch, next_addr);
				break;
			case ARC_RTIE:
				result.AddBranch(FunctionReturn);
				break;
			case ARC_SWI:
			case ARC_TRAP:
				result.AddBranch(ExceptionBranch);
				break;
			default:
				break;
		}

		return true;
	}

	virtual bool GetInstructionText(const uint8_t* data, uint64_t addr, size_t& len, std::vector<InstructionTextToken>& result) override {
		Instruction instruction;
		if (!Disassemble(data, addr, len, instruction)) {
			return false;
		}

		len = instruction.size;

		char operation[0x10] = { 0 };
		size_t bytes_left = sizeof(operation) - 1;

		const char* operation_name = get_operation(instruction.operation);
		if (operation_name == NULL)
			return false;

		strncpy(operation, operation_name, sizeof(operation));
		bytes_left -= strlen(operation_name);

		switch (instruction.operation) {
			case ARC_LD:
			case ARC_ST:
			case ARC_SEX:
			case ARC_EXT:
			case ARC_ABSS:
			case ARC_NEGS:
			case ARC_NORM:
				if (instruction.data_size) {
					strncat(operation, (instruction.data_size == BYTE) ? "b" : "w", 1);
					bytes_left -= 1;
				}
			default:
				break;
		}

		if (instruction.condition != NONE) {
			switch (instruction.operation) {
				case ARC_B:
				case ARC_BL:
				case ARC_BR:
				case ARC_J:
				case ARC_JL:
				case ARC_LP:
					break;
				default:
					strncat(operation, ".", 1);
					bytes_left -= 1;
					break;
			}

			const char* condition = get_condition((ConditionCode)instruction.condition);
			if (condition == NULL)
				return false;

			strncat(operation, condition, bytes_left);
			bytes_left -= strlen(condition);
		}

		if (instruction.sign_extend) {
			strncat(operation, ".x", 2);
			bytes_left -= 2;
		}

		switch (instruction.address_writeback) {
			case NO_WRITEBACK:
				break;
			case AW:
				strncat(operation, ".aw", 3);
				bytes_left -= 3;
				break;
			case AB:
				strncat(operation, ".ab", 3);
				bytes_left -= 3;
				break;
			case AS:
				strncat(operation, ".as", 3);
				bytes_left -= 3;
				break;
			default:
				return false;
		}

		if (instruction.bypass_direct_data_cache) {
			strncat(operation, ".di", 3);
			bytes_left -= 3;
		}

		if (instruction.delayed) {
			strncat(operation, ".d", 2);
			bytes_left -= 2;
		}

		if (instruction.set_flag) {
			switch (instruction.operation) {
				case ARC_CMP:
				case ARC_RCMP:
				case ARC_BTST:
				case ARC_TST:
				default:
					strncat(operation, ".f", 2);
					bytes_left -= 2;
			}
		}

		result.emplace_back(InstructionToken, operation);
		result.emplace_back(TextToken, " ");

		char operand[64];
		for (size_t i = 0; i < MAX_OPERANDS; i++) {
			InstructionOperand& current_operand = instruction.operands[i];
			if (current_operand.operand_class == EMPTY) {
				return true;
			}

			if (i != 0)
				result.emplace_back(OperandSeparatorToken, ", ");

			switch (current_operand.operand_class) {
				case IMM: {
					int32_t imm = current_operand.immediate;
					if (imm < -9) {
						snprintf(operand, sizeof(operand), "-%#x", -imm);
					} else if (imm < 0) {
						snprintf(operand, sizeof(operand), "-%d", -imm);
					} else if (imm < 10) {
						snprintf(operand, sizeof(operand), "%d", imm);
					} else {
						snprintf(operand, sizeof(operand), "%#x", imm);
					}

					result.emplace_back(IntegerToken, operand, imm);
				}
				break;
				case LABEL: {
					uint64_t address = current_operand.address;
					snprintf(operand, sizeof(operand), "%#lx", address);
					result.emplace_back(PossibleAddressToken, operand, address);
				}
				break;
				case REG: {
					const char* reg = get_register((Reg)current_operand.reg);
					if (reg == NULL) {
						return false;
					}
					result.emplace_back(RegisterToken, reg);
				}
				break;
				case REG_IMM_REL: {

					result.emplace_back(BeginMemoryOperandToken, "");
					result.emplace_back(BraceToken, "[");

					const char* reg = get_register((Reg)current_operand.reg);
					if (reg == NULL)
						return false;
					result.emplace_back(RegisterToken, reg);

					int32_t offset = current_operand.offset;
					if (offset != 0) {
						result.emplace_back(OperandSeparatorToken, ", ");

						if (offset < -9) {
							snprintf(operand, sizeof(operand), "-%#x", -offset);
						} else if (offset < 0) {
							snprintf(operand, sizeof(operand), "-%d", -offset);
						} else if (offset < 10) {
							snprintf(operand, sizeof(operand), "%d", offset);
						} else {
							snprintf(operand, sizeof(operand), "%#x", offset);
						}

						result.emplace_back(IntegerToken, operand, offset);
					}

					result.emplace_back(BraceToken, "]");
					result.emplace_back(EndMemoryOperandToken, "");
				}
				break;
				case REG_REG_REL: {

					result.emplace_back(BeginMemoryOperandToken, "");
					result.emplace_back(BraceToken, "[");

					const char* reg = get_register((Reg)current_operand.reg);
					if (reg == NULL)
						return false;
					result.emplace_back(RegisterToken, reg);

					result.emplace_back(OperandSeparatorToken, ", ");

					const char* displacement_reg = get_register((Reg)current_operand.displacement_reg);
					if (reg == NULL)
						return false;
					result.emplace_back(RegisterToken, displacement_reg);

					result.emplace_back(BraceToken, "]");
					result.emplace_back(EndMemoryOperandToken, "");
				}
				break;
				case IMM_REG_REL: {

					result.emplace_back(BeginMemoryOperandToken, "");
					result.emplace_back(BraceToken, "[");

					int32_t imm = current_operand.offset;
					if (imm != 0) {
						if (imm < -9) {
							snprintf(operand, sizeof(operand), "-%#x", -imm);
						} else if (imm < 0) {
							snprintf(operand, sizeof(operand), "-%d", -imm);
						} else if (imm < 10) {
							snprintf(operand, sizeof(operand), "%d", imm);
						} else {
							snprintf(operand, sizeof(operand), "%#x", imm);
						}

						result.emplace_back(IntegerToken, operand, imm);
						result.emplace_back(OperandSeparatorToken, ", ");
					}

					const char* displacement_reg = get_register((Reg)current_operand.reg);
					if (displacement_reg == NULL)
						return false;
					result.emplace_back(RegisterToken, displacement_reg);

					result.emplace_back(BraceToken, "]");
					result.emplace_back(EndMemoryOperandToken, "");
				}
				break;
				default:
					LogError("operand_class %x\n", current_operand.operand_class);
					return false;
			}
		}

		return true;
	}
};

class ArcCallingConvention: public CallingConvention {
	public:
	ArcCallingConvention(Architecture* arch): CallingConvention(arch, "arc600") {
	}

	virtual uint32_t GetIntegerReturnValueRegister() override {
		return REG_R0;
	}

	virtual std::vector<uint32_t> GetIntegerArgumentRegisters() override {
		return std::vector<uint32_t>{
			REG_R0, REG_R1, REG_R2, REG_R3,
			REG_R4, REG_R5, REG_R6, REG_R7,
		};
	}

	virtual bool IsStackReservedForArgumentRegisters() override {
		return false;
	}

	virtual std::vector<uint32_t> GetCallerSavedRegisters() override {
		return std::vector<uint32_t>{
			REG_R0, REG_R1, REG_R2, REG_R3,
			REG_R4, REG_R5, REG_R6, REG_R7,
			REG_R8, REG_R9, REG_R10, REG_R11,
			REG_R12,
			REG_R25,
			REG_R30,
			REG_LP_COUNT,
		};
	}

	virtual std::vector<uint32_t> GetCalleeSavedRegisters() override {
		return std::vector<uint32_t>{
			REG_R13, REG_R14, REG_R15,
			REG_R16, REG_R17, REG_R18, REG_R19,
			REG_R20, REG_R21, REG_R22, REG_R23,
			REG_R24, REG_R25,
		};
	}

	virtual uint32_t GetGlobalPointerRegister() override {
		return REG_GP;
	}
};

extern "C" {
	BN_DECLARE_CORE_ABI_VERSION

	BINARYNINJAPLUGIN bool CorePluginInit() {
		Architecture* a5el = new ArcArchitecture("arctangent-a5", ARC_TANGENT_A5, LittleEndian);
		Architecture* a5eb = new ArcArchitecture("arctangent-a5eb", ARC_TANGENT_A5, BigEndian);
		Architecture* arc600el = new ArcArchitecture("arc600", ARC_600, LittleEndian);
		Architecture* arc600eb = new ArcArchitecture("arc600eb", ARC_600, BigEndian);
		Architecture* arc700el = new ArcArchitecture("arc700", ARC_700, LittleEndian);
		Architecture* arc700eb = new ArcArchitecture("arc700eb", ARC_700, BigEndian);

		Architecture::Register(a5el);
		Architecture::Register(a5eb);
		Architecture::Register(arc600el);
		Architecture::Register(arc600eb);
		Architecture::Register(arc700el);
		Architecture::Register(arc700eb);

		ArcCallingConvention* o32LE = new ArcCallingConvention(arc600eb);


		// TODO bvtype register
		return true;
	}
}