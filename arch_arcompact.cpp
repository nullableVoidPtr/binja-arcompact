#include "binaryninjacore.h"
#define _CRT_SECURE_NO_WARNINGS
#define NOMINMAX

#include <stdio.h>
#include <string.h>

#include "binaryninjaapi.h"
#include "lowlevelilinstruction.h"
#include "arcompact.h"

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
		return 8;
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

	virtual bool CanAssemble() override {
		return false;
	}

	bool Disassemble(const uint8_t* data, uint64_t addr, size_t maxLen, Instruction& result) {
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

	virtual bool GetInstructionInfo(const uint8_t* data, uint64_t addr, size_t maxLen, InstructionInfo& result) override {
		Instruction instruction;
		if (!Disassemble(data, addr, maxLen, instruction)) {
			return false;
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
				result.AddBranch(FalseBranch, addr + instruction.size);
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
					addr + instruction.size,
					nullptr
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
				result.AddBranch(FalseBranch, addr + instruction.size);
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
					result.AddBranch(FalseBranch, addr + instruction.size);
				} else if (instruction.operands[0].operand_class == REG && (
					instruction.operands[0].reg == REG_BLINK ||
					instruction.operands[0].reg == REG_ILINK1 ||
					instruction.operands[0].reg == REG_ILINK2)
				) {
					result.AddBranch(FunctionReturn);
				} else {
					result.AddBranch(IndirectBranch);
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
					result.AddBranch(IndirectBranch);
				}
				break;
			case ARC_LP:
				if (instruction.condition == AL || instruction.condition == NONE) {
					break;
				}

				result.AddBranch(FalseBranch, instruction.operands[2].address);
				result.AddBranch(TrueBranch, addr + instruction.size);
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

		if (instruction.operation == ARC_LD || instruction.operation == ARC_ST) {
			if (instruction.data_size) {
				strncat(operation, (instruction.data_size == 0b01) ? "b" : "w", 1);
				bytes_left -= 1;
			}
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
			strncat(operation, ".f", 2);
			bytes_left -= 2;
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
					result.emplace_back(RegisterToken, reg);

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

					const char* displacement_reg = get_register((Reg)current_operand.displacement_reg);
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

	virtual uint32_t GetIntegerReturnValueRegister() override
	{
		return REG_R0;
	}

	virtual std::vector<uint32_t> GetIntegerArgumentRegisters() override
	{
		return std::vector<uint32_t>{
			REG_R0, REG_R1, REG_R2, REG_R3,
			REG_R4, REG_R5, REG_R6, REG_R7,
		};
	}

	virtual bool IsStackReservedForArgumentRegisters() override
	{
		return false;
	}

	virtual std::vector<uint32_t> GetCallerSavedRegisters() override
	{
	}

	virtual std::vector<uint32_t> GetCalleeSavedRegisters() override
	{
		return std::vector<uint32_t>{
			REG_R16, REG_R17, REG_R18, REG_R19,
			REG_R20, REG_R21, REG_R22, REG_R23,
			REG_R24, REG_R25,
		};
	}

	virtual uint32_t GetGlobalPointerRegister() override
	{
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