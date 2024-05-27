#include <byteswap.h>
#include <cstdint>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include "arcompact.h"

namespace ArCompact {
	#define ALIGN32(ADDR) ((ADDR >> 2) << 2)
	#define SIMM(VALUE, SIZE) (((VALUE) & ((1U << SIZE) - 1)) ^ (1U << (SIZE - 1))) - (1U << (SIZE - 1))

	#define _R(REG_IDX) Reg(REG_R0 + REG_IDX)

	#define ARG_REG(OPERAND, REGISTER) do { \
		(OPERAND)->operand_class = REG; \
		(OPERAND)->reg = REGISTER; \
	} while (0)
	#define ARG_IMM(OPERAND, VALUE) do { \
		(OPERAND)->operand_class = IMM; \
		(OPERAND)->immediate = VALUE; \
	} while (0)
	#define ARG_LABEL(OPERAND, ADDRESS, OFFSET) do { \
		(OPERAND)->operand_class = LABEL; \
		(OPERAND)->address = ADDRESS + OFFSET; \
	} while (0)
	#define ARG_REG_REG_REL(OPERAND, BASE, DISPLACEMENT) do { \
		(OPERAND)->operand_class = REG_REG_REL; \
		(OPERAND)->reg = BASE; \
		(OPERAND)->displacement_reg = DISPLACEMENT; \
	} while (0)
	#define ARG_REG_IMM_REL(OPERAND, BASE, OFFSET) do { \
		(OPERAND)->operand_class = REG_IMM_REL; \
		(OPERAND)->reg = BASE; \
		(OPERAND)->offset = OFFSET; \
	} while (0)

	static const char* OperationStrings[] = {
		"INVALID",

		"add",
		"adc",
		"sub",
		"sbc",
		"and",
		"or",
		"bic",
		"xor",
		"max",
		"min",
		"mov",
		"tst",
		"cmp",
		"rcmp",
		"rsub",
		"bset",
		"bclr",
		"btst",
		"bxor",
		"bmsk",
		"add1",
		"add2",
		"add3",
		"sub1",
		"sub2",
		"sub3",
		"asl",
		"asr",
		"lsr",
		"ror",
		"sex",
		"ext",
		"not",
		"neg",
		"abs",
		"flag",
		"rlc",
		"rrc",
		"nop",
		"sleep",
		"swi",
		"brk",
		"trap",
		"unimp",
		"rtie",
		"sync",
		"usext",
		"b",
		"bl",
		"br",
		"bbit0",
		"bbit1",
		"j",
		"jl",
		"lp",
		"lr",
		"sr",
		"ld",
		"st",
		"push",
		"pop",
		"ex",
		"mul64",
		"mulu64",
		"mpy",
		"mpyh",
		"mpyhu",
		"mpyu",
		"norm",
		"swap",
		"adds",
		"subs",
		"divaw",
		"asls",
		"asrs",
		"addsdw",
		"subsdw",
		"sat16",
		"rnd16",
		"abss",
		"negs",
	};

	static const char* RegisterStrings[] = {
		"r0",
		"r1",
		"r2",
		"r3",
		"r4",
		"r5",
		"r6",
		"r7",
		"r8",
		"r9",
		"r10",
		"r11",
		"r12",
		"r13",
		"r14",
		"r15",
		"r16",
		"r17",
		"r18",
		"r19",
		"r20",
		"r21",
		"r22",
		"r23",
		"r24",
		"r25",
		"gp",
		"fp",
		"sp",
		"ilink1",
		"ilink2",
		"blink",

		// Extension Core Registers
		"r32",
		"r33",
		"r34",
		"r35",
		"r36",
		"r37",
		"r38",
		"r39",
		"r40",
		"r41",
		"r42",
		"r43",
		"r44",
		"r45",
		"r46",
		"r47",
		"r48",
		"r49",
		"r50",
		"r51",
		"r52",
		"r53",
		"r54",
		"r55",
		"r56",
		"r57",
		"r58",
		"r59",
		"LP_COUNT",
		"r61",
		"r62",
		"pcl",
	};

	static const char* AuxiliaryRegisterStrings[] = {
		[REG_STATUS]="STATUS",
		[REG_SEMAPHORE]="SEMAPHORE",
		[REG_LP_START]="LP_START",
		[REG_LP_END]="LP_END",
		[REG_IDENTITY]="IDENTITY",
		[REG_DEBUG]="DEBUG",
		[REG_PC]="PC",
		[REG_STATUS32]="STATUS32",
		[REG_STATUS32_L1]="STATUS32_L1",
		[REG_STATUS32_L2]="STATUS32_L2",
		[REG_MULHI]="MULHI",

		[REG_COUNT0]="COUNT0",
		[REG_CONTROL0]="CONTROL0",
		[REG_LIMIT0]="LIMIT0",

		[REG_INT_VECTOR_BASE]="INT_VECTOR_BASE",
		[REG_AUX_MACMODE]="AUX_MACMODE",
		[REG_AUX_IRQ_LV12]="AUX_IRQ_LV12",

		// Build Configuration Registers
		[REG_BCR_VER]="BCR_VER",
		[REG_BTA_LINK_BUILD]="BTA_LINK_BUILD",
		[REG_EA_BUILD]="EA_BUILD",
		[REG_VECBASE_AC_BUILD]="VECBASE_AC_BUILD",
		[REG_RF_BUILD]="RF_BUILD",
		[REG_TIMER_BUILD]="TIMER_BUILD",
		[REG_MULTIPLY_BUILD]="MULTIPLY_BUILD", 
		[REG_SWAP_BUILD]="SWAP_BUILD",
		[REG_NORM_BUILD]="NORM_BUILD",
		[REG_MINMAX_BUILD]="MINMAX_BUILD",
		[REG_BARREL_BUILD]="BARREL_BUILD",

		[REG_COUNT1]="COUNT1",
		[REG_CONTROL1]="CONTROL1",
		[REG_LIMIT1]="LIMIT1",

		[AUX_IRQ_LEV]="AUX_IRQ_LEV",
		[AUX_IRQ_HINT]="AUX_IRQ_HINT",

		[ERET]="ERET",
		[ERBTA]="ERBTA",
		[ERSTATUS]="ERSTATUS",
		[ECR]="ECR",
		[EFA]="EFA",
		[ICAUSE1]="ICAUSE1",
		[ICAUSE2]="ICAUSE2",
		[AUX_IENABLE]="AUX_IENABLE",
		[AUX_ITRIGGER]="AUX_ITRIGGER",
		[XPU]="XPU",
		[BTA]="BTA",
		[BTA_L1]="BTA_L1",
		[BTA_L2]="BTA_L2",
		[AUX_IRQ_PULSE_CANCEL]="AUX_IRQ_PULSE_CANCEL",
		[AUX_IRQ_PENDING]="AUX_IRQ_PENDING",
	};

	static const char* ConditionStrings[] = {
		"al",
		"eq",
		"ne",
		"pl",
		"mi",
		"cs",
		"cc",
		"vs",
		"vc",
		"gt",
		"ge",
		"lt",
		"le",
		"hi",
		"ls",
		"pnz",
		"ss",
		"sc",
	};

	static const char* FlagStrings[] = {
		"L",
		"Z",
		"N",
		"C",
		"V",
		"U",
		"DE",
		"AE",
		"A1",
		"A2",
		"E1",
		"E2",
		"H",
		"S1",
		"S2",
	};

	uint8_t cvt_16bit_reg(uint8_t reg) {
		if (reg > 7) {
			return END_REG;
		}

		if (reg < 4) {
			return REG_R0 + reg;
		}

		return REG_R12 + reg - 4;
	}

	#define ARG_REG_REDUCED(OPERAND, _REG_IDX) ARG_REG(OPERAND, cvt_16bit_reg(_REG_IDX));

	const char* get_operation(Operation operation)
	{
		if (operation >= 0 && operation < ARC_OPERATION_END) {
			return OperationStrings[operation];
		}

		return NULL;
	}

	const char* get_register(Reg reg)
	{
		if (reg >= END_REG) {
			return NULL;
		}

		if (reg >= AUXREG_START) {
			return AuxiliaryRegisterStrings[reg];
		}

		if (reg >= 0)
			return RegisterStrings[reg];
		return NULL;
	}

	const char* get_flag(Flag flag)
	{
		if (flag >= 0 && flag < END_FLAG) {
			return FlagStrings[flag];
		}

		return NULL;
	}

	const char* get_condition(ConditionCode condition)
	{
		if (condition == NEVER) {
			return "na";
		}

		if (condition >= 0 && condition < END_CONDITION)
			return ConditionStrings[condition];
		return NULL;
	}

	static uint32_t decompose_zero_operand(
			encoded_instruction ins,
			Instruction* __restrict instruction,
			uint32_t version,
			uint64_t address) {
		general decoded_ins = ins.general;

		uint8_t sub_opcode = (decoded_ins.b_upper << 3) | decoded_ins.b_lower;
		switch (sub_opcode) {
			case 0x01: {
				instruction->operation = ARC_SLEEP;

				InstructionOperand* src = &instruction->operands[0];
				if (version >= ARC_700) {
					if (decoded_ins.operand_format == 0b01) {
						if (decoded_ins.c != 0) {
							ARG_IMM(src, decoded_ins.c);
						}
					} else {
						ARG_REG(src, _R(decoded_ins.c));
					}
				}
			}
			break;
			case 0x02:
				instruction->operation = ARC_SWI;
				break;
			case 0x03:
				instruction->operation = ARC_SYNC;
				break;
			case 0x04:
				instruction->operation = ARC_RTIE;
				break;
			case 0x05:
				instruction->operation = ARC_BRK;
				break;
			default:
				return 1;
		}

		return 0;
	}

	static void decompose_src_operand(
		general decoded_ins,
		Instruction* __restrict instruction
	) {
		InstructionOperand* dst = &instruction->operands[0];
		InstructionOperand* src = &instruction->operands[1];

		ARG_REG(dst, _R((decoded_ins.b_upper << 3) | decoded_ins.b_lower));

		if (decoded_ins.operand_format == 0b01) {
			ARG_IMM(src, decoded_ins.c);
		} else {
			ARG_REG(src, _R(decoded_ins.c));
		}
	}

	static uint32_t decompose_single_operand(
			encoded_instruction ins,
			Instruction* __restrict instruction,
			uint32_t version,
			uint64_t address) {
		general decoded_ins = ins.general;

		if (decoded_ins.operand_format >= 0b10) {
			return 1;
		}

		uint8_t sub_opcode = decoded_ins.a;
		switch (sub_opcode) {
			case 0x00:
			case 0x01:
			case 0x02:
			case 0x03: {
				switch (sub_opcode) {
					case 0x00:
						instruction->operation = ARC_ASL;
						break;
					case 0x01:
						instruction->operation = ARC_ASR;
						break;
					case 0x02:
						instruction->operation = ARC_LSR;
						break;
					case 0x03:
						instruction->operation = ARC_ROR;
						break;
				}

				ARG_IMM(&instruction->operands[2], 1);

				return 0;
			}
			break;
			case 0x04:
				instruction->operation = ARC_RRC;
				break;
			case 0x05:
				instruction->operation = ARC_SEX;
				instruction->data_size = BYTE;
				break;
			case 0x06:
				instruction->operation = ARC_SEX;
				instruction->data_size = WORD;
				break;
			case 0x07:
				instruction->operation = ARC_EXT;
				instruction->data_size = BYTE;
				break;
			case 0x08:
				instruction->operation = ARC_EXT;
				instruction->data_size = WORD;
				break;
			case 0x09:
				instruction->operation = ARC_ABS;
				break;
			case 0x0A:
				instruction->operation = ARC_NOT;
				break;
			case 0x0B:
				instruction->operation = ARC_RLC;
				break;
			case 0x0C:
				instruction->operation = ARC_EX;
				break;
			case 0x3F:
				return decompose_zero_operand(
					ins,
					instruction,
					version,
					address
				);
			default:
				return 1;
		}

		instruction->set_flag = decoded_ins.set_flag;

		decompose_src_operand(decoded_ins, instruction);

		return 0;
	}

	static void decompose_right_operand(
		general decoded_ins,
		Instruction* __restrict instruction,
		InstructionOperand* right
	) {
		switch (decoded_ins.operand_format) {
			case 0b00:
				ARG_REG(right, _R(decoded_ins.c));
				if (right->reg == REG_R62) {
					instruction->has_long_imm = true;
				}
				break;
			case 0b01:
				ARG_IMM(right, decoded_ins.c);
				break;
			case 0b10:
				// SIMM(c | a) to right
				ARG_IMM(right, SIMM((decoded_ins.a << 6) | decoded_ins.c, 12));
				break;
			case 0b11:
				instruction->condition = decoded_ins.a & 0x1F;

				if ((decoded_ins.a >> 5) == 0) {
					ARG_REG(right, _R(decoded_ins.c));
					if (right->reg == REG_R62) {
						instruction->has_long_imm = true;
					}
				} else {
					ARG_IMM(right, decoded_ins.c);
				}
				break;
		}
	}

	static void decompose_left_right_operands(
		general decoded_ins,
		Instruction* __restrict instruction,
		bool decode_dst
	) {
		InstructionOperand* dst = &instruction->operands[0];
		InstructionOperand* left = &instruction->operands[0];
		InstructionOperand* right = &instruction->operands[1];

		if (decode_dst) {
			left = &instruction->operands[1];
			right = &instruction->operands[2];
		}

		// Reg(b) to left
		ARG_REG(left, _R((decoded_ins.b_upper << 3) | decoded_ins.b_lower));
		if (left->reg == REG_R62) {
			if (instruction->operation == ARC_MOV) {
				ARG_IMM(left, 0);
			} else {
				instruction->has_long_imm = true;
			}
		}

		if (decode_dst) {
			switch (decoded_ins.operand_format) {
				case 0b00:
				case 0b01:
					// Reg(a) to dst
					ARG_REG(dst, _R(decoded_ins.a));
					break;
				case 0b10:
				case 0b11:
					// Reg(b) to dst
					ARG_REG(dst, _R((decoded_ins.b_upper << 3) | decoded_ins.b_lower));
					break;
			}

			if (dst->reg == REG_R62) {
				ARG_IMM(dst, 0);
			}
		}

		decompose_right_operand(decoded_ins, instruction, right);
	}

	static uint32_t decompose_general_instruction(
			encoded_instruction ins,
			Instruction* __restrict instruction,
			uint32_t version,
			uint64_t address) {
		general decoded_ins = ins.general;

		bool decode_dst = true;
		switch (decoded_ins.sub_opcode) {
			case 0x00:
				instruction->operation = ARC_ADD;
				break;
			case 0x01:
				instruction->operation = ARC_ADC;
				break;
			case 0x02:
				instruction->operation = ARC_SUB;
				break;
			case 0x03:
				instruction->operation = ARC_SBC;
				break;
			case 0x04:
				instruction->operation = ARC_AND;
				break;
			case 0x05:
				instruction->operation = ARC_OR;
				break;
			case 0x06:
				instruction->operation = ARC_BIC;
				break;
			case 0x07:
				instruction->operation = ARC_XOR;
				break;
			case 0x08:
				instruction->operation = ARC_MAX;
				break;
			case 0x09:
				instruction->operation = ARC_MIN;
				break;
			case 0x0A:
				instruction->operation = ARC_MOV;

				decode_dst = false;
				break;
			case 0x0B:
				instruction->operation = ARC_TST;

				decode_dst = false;
				break;
			case 0x0C:
				instruction->operation = ARC_CMP;

				decode_dst = false;
				break;
			case 0x0D:
				instruction->operation = ARC_RCMP;

				decode_dst = false;
				break;
			case 0x0E:
				instruction->operation = ARC_RSUB;
				break;
			case 0x0F:
				instruction->operation = ARC_BSET;
				break;
			case 0x10:
				instruction->operation = ARC_BCLR;
				break;
			case 0x11:
				instruction->operation = ARC_BTST;

				decode_dst = false;
				break;
			case 0x12:
				instruction->operation = ARC_BXOR;
				break;
			case 0x13:
				instruction->operation = ARC_BMSK;
				break;
			case 0x14:
				instruction->operation = ARC_ADD1;
				break;
			case 0x15:
				instruction->operation = ARC_ADD2;
				break;
			case 0x16:
				instruction->operation = ARC_ADD3;
				break;
			case 0x17:
				instruction->operation = ARC_SUB1;
				break;
			case 0x18:
				instruction->operation = ARC_SUB2;
				break;
			case 0x19:
				instruction->operation = ARC_SUB3;
				break;
			case 0x1A:
				if (version != ARC_700) {
					return 1;
				}
				instruction->operation = ARC_MPY;
				break;
			case 0x1B:
				if (version != ARC_700) {
					return 1;
				}
				instruction->operation = ARC_MPYH;
				break;
			case 0x1C:
				if (version != ARC_700) {
					return 1;
				}
				instruction->operation = ARC_MPYHU;
				break;
			case 0x1D:
				if (version != ARC_700) {
					return 1;
				}
				instruction->operation = ARC_MPYU;
				break;
			case 0x20:
			case 0x21:
			case 0x22:
			case 0x23: {
				switch (decoded_ins.sub_opcode) {
					case 0x20:
						instruction->operation = ARC_J;
						break;
					case 0x21:
						instruction->operation = ARC_J;
						instruction->delayed = true;
						break;
					case 0x22:
						instruction->operation = ARC_JL;
						break;
					case 0x23:
						instruction->operation = ARC_JL;
						instruction->delayed = true;
						break;
				}

				InstructionOperand* target = &instruction->operands[0];

				switch (decoded_ins.operand_format) {
					case 0b00:
					case 0b01:
						instruction->condition = NONE;
						break;
					case 0b10:
						ARG_LABEL(target, 0, SIMM((decoded_ins.c << 6) | decoded_ins.a, 12));
						return 0;
					case 0b11:
						instruction->condition = decoded_ins.a & 0x1F;

						if ((decoded_ins.a >> 5) == 1) {
							ARG_IMM(target, decoded_ins.c);
							return 0;
						}
				}

				ARG_REG(target, _R(decoded_ins.c));
				if (target->reg == REG_ILINK1 || target->reg == REG_ILINK2) {
					if (!decoded_ins.set_flag) {
						return 1;
					}
				} else if (target->reg == REG_R62) {
					instruction->has_long_imm = true;
				}

				return 0;
			}
			case 0x28:
			case 0x29: {
				if (decoded_ins.sub_opcode == 0x28) {
					instruction->operation = ARC_LP;
				} else {
					instruction->operation = ARC_FLAG;
				}

				InstructionOperand* right = &instruction->operands[0];
				decompose_right_operand(decoded_ins, instruction, right);

				if (instruction->operation == ARC_LP) {
					if (right->operand_class == IMM) {
						ARG_LABEL(right, ALIGN32(address), right->immediate);
					}
				}

				return 0;
			}
			case 0x2A:
				instruction->operation = ARC_LR;

				decode_dst = false;
				break;
			case 0x2B:
				instruction->operation = ARC_SR;

				decode_dst = false;
				break;
			case 0x2F:
				return decompose_single_operand(
					ins,
					instruction,
					version,
					address
				);
			case 0x30:
			case 0x31:
			case 0x32:
			case 0x33:
			case 0x34:
			case 0x35:
			case 0x36:
			case 0x37: {
				ld_reg_reg decoded_ld = ins.ld_reg_reg;

				instruction->operation = ARC_LD;

				if (decoded_ld.dst == 0x3E) {
					if (version <= ARC_600) {
						return 1;
					}
					if (decoded_ld.address_writeback == 0x1 || decoded_ld.address_writeback == 0x2) {
						return 1;
					}
				}
				if (decoded_ld.dst >= 0x20 && decoded_ins.a <= 0x3B) {
					return 1;
				}
				if (decoded_ld.dst == 0x3D || decoded_ins.a == 0x3F) {
					return 1;
				}
				if (decoded_ld.data_size == 0x3) {
					return 1;
				}
				instruction->address_writeback = decoded_ld.address_writeback;
				instruction->data_size = decoded_ld.data_size;
				instruction->bypass_direct_data_cache = decoded_ld.bypass_direct_data_cache;

				if (decoded_ld.sign_extend == 1) {
					if (decoded_ld.data_size == 0x0) {
						return 1;
					}

					instruction->sign_extend = true;
				}

				InstructionOperand* dst = &instruction->operands[0];
				InstructionOperand* src = &instruction->operands[1];
				
				ARG_REG(dst, _R(decoded_ld.dst));
				if (dst->reg == REG_R62) {
					ARG_IMM(dst, 0);
				}


				ARG_REG_REG_REL(
					src,
					_R((decoded_ld.base_upper << 3) | decoded_ld.base_lower),
					_R(decoded_ld.offset)
				);

				if (src->reg == REG_R62 || src->displacement_reg == REG_R62) {
					instruction->has_long_imm = true;
				}

				return 0;
			}
			default:
				return 1;
		}

		instruction->set_flag = decoded_ins.set_flag;

		decompose_left_right_operands(decoded_ins, instruction, decode_dst);

		return 0;
	}

	static uint32_t decompose_extension_zero_operand(
			encoded_instruction ins,
			Instruction* __restrict instruction,
			uint32_t version,
			uint64_t address) {
		return 1;
	}

	static uint32_t decompose_extension_single_operand(
			encoded_instruction ins,
			Instruction* __restrict instruction,
			uint32_t version,
			uint64_t address) {
		general decoded_ins = ins.general;

		if (decoded_ins.operand_format >= 0b10) {
			return 1;
		}

		uint8_t sub_opcode = decoded_ins.a;
		switch (sub_opcode) {
			case 0x00:
				instruction->operation = ARC_SWAP;
				break;
			case 0x01:
				instruction->operation = ARC_NORM;
				break;
			case 0x02:
				instruction->operation = ARC_SAT16;
				break;
			case 0x03: 
				instruction->operation = ARC_RND16;
				break;
			case 0x04:
				instruction->operation = ARC_ABSS;
				instruction->data_size = WORD;
				break;
			case 0x05:
				instruction->operation = ARC_ABSS;
				break;
			case 0x06:
				instruction->operation = ARC_NEGS;
				instruction->data_size = WORD;
			case 0x07:
				instruction->operation = ARC_NEGS;
			case 0x08:
				instruction->operation = ARC_NORM;
				instruction->data_size = WORD;
			case 0x3F:
				return decompose_extension_zero_operand(
					ins,
					instruction,
					version,
					address
				);
			default:
				return 1;
		}

		instruction->set_flag = decoded_ins.set_flag;

		decompose_src_operand(decoded_ins, instruction);

		return 0;
	}

	static uint32_t decompose_extension_instruction(
			encoded_instruction ins,
			Instruction* __restrict instruction,
			uint32_t version,
			uint64_t address) {
		general decoded_ins = ins.general;

		switch (decoded_ins.sub_opcode) {
			case 0x00:
				instruction->operation = ARC_ASL;
				break;
			case 0x01:
				instruction->operation = ARC_LSR;
				break;
			case 0x02:
				instruction->operation = ARC_ASR;
				break;
			case 0x03:
				instruction->operation = ARC_ROR;
				break;
			case 0x04:
				instruction->operation = ARC_MUL64;
				break;
			case 0x05:
				instruction->operation = ARC_MULU64;
				break;
			case 0x06:
				instruction->operation = ARC_ADDS;
				break;
			case 0x07:
				instruction->operation = ARC_SUBS;
				break;
			case 0x0A:
				instruction->operation = ARC_DIVAW;
				break;
			case 0x0B:
				instruction->operation = ARC_ASLS;
				break;
			case 0x28:
				instruction->operation = ARC_ADDSDW;
				break;
			case 0x29:
				instruction->operation = ARC_SUBSDW;
				break;
			case 0x2F:
				return decompose_extension_single_operand(
					ins,
					instruction,
					version,
					address
				);

			default:
				return 1;
		}

		instruction->set_flag = decoded_ins.set_flag;

		decompose_left_right_operands(decoded_ins, instruction, true);

		return 0;
	}

	static uint32_t decompose_16bit_zero_regs(
			encoded_instruction ins,
			Instruction* __restrict instruction,
			uint32_t version,
			uint64_t address) {
		compact_general decoded_ins = ins.compact_general;

		switch (decoded_ins.b) {
			case 0x02:
			case 0x03:
				return 1;

			case 0x00:
				instruction->operation = ARC_NOP;
				break;
			case 0x01:
				instruction->operation = ARC_UNIMP;
				break;
			case 0x04:
				instruction->operation = ARC_J;
				instruction->condition = EQ;
				break;
			case 0x05:
				instruction->operation = ARC_J;
				instruction->condition = NE;
				break;
			case 0x06:
				instruction->operation = ARC_J;
				break;
			case 0x07:
				instruction->operation = ARC_J;
				instruction->delayed = true;
				break;
		}

		if (decoded_ins.b >= 0x04) {
			InstructionOperand* blink = &instruction->operands[0];
			ARG_REG(blink, REG_BLINK);
		}

		return 0;
	}

	static uint32_t decompose_16bit_single_reg(
			encoded_instruction ins,
			Instruction* __restrict instruction,
			uint32_t version,
			uint64_t address) {
		compact_general decoded_ins = ins.compact_general;

		switch (decoded_ins.single_reg.sub_opcode) {
			case 0x04:
			case 0x05:
				return 1;

			case 0x07:
				return decompose_16bit_zero_regs(
					ins,
					instruction,
					version,
					address
				);
			case 0x00:
				instruction->operation = ARC_J;
				break;
			case 0x01:
				instruction->operation = ARC_J;
				instruction->delayed = true;
				break;
			case 0x02:
				instruction->operation = ARC_JL;
				break;
			case 0x03:
				instruction->operation = ARC_JL;
				instruction->delayed = true;
				break;
			case 0x06:
				instruction->operation = ARC_SUB;
				instruction->condition = NE;
				break;
		}

		InstructionOperand* reg = &instruction->operands[0];
		ARG_REG_REDUCED(reg, decoded_ins.b);

		if (decoded_ins.single_reg.sub_opcode == 0x06) {
			ARG_REG(&instruction->operands[1], reg->reg);
			ARG_REG(&instruction->operands[2], reg->reg);
		}

		return 0;
	}

	static uint32_t decompose_16bit_general_instruction(
			encoded_instruction ins,
			Instruction* __restrict instruction,
			uint32_t version,
			uint64_t address) {
		compact_general decoded_ins = ins.compact_general;

		bool dst_is_src = true;

		switch (decoded_ins.double_regs.sub_opcode) {
			case 0x00:
				return decompose_16bit_single_reg(
					ins,
					instruction,
					version,
					address
				);
			case 0x01:
			case 0x03:
			case 0x08:
			case 0x09:
			case 0x0A:
			case 0x17:
				return 1;

			case 0x02:
				instruction->operation = ARC_SUB;
				break;
			case 0x04:
				instruction->operation = ARC_AND;
				break;
			case 0x05:
				instruction->operation = ARC_OR;
				break;
			case 0x06:
				instruction->operation = ARC_BIC;
				break;
			case 0x07:
				instruction->operation = ARC_XOR;
				break;
			case 0x0B:
				instruction->operation = ARC_TST;
				dst_is_src = false;
				break;
			case 0x0C:
				instruction->operation = ARC_MUL64;
				dst_is_src = false;
				break;
			case 0x0D:
				instruction->operation = ARC_SEX;
				instruction->data_size = BYTE;
				dst_is_src = false;
				break;
			case 0x0E:
				instruction->operation = ARC_SEX;
				instruction->data_size = WORD;
				dst_is_src = false;
				break;
			case 0x0F:
				instruction->operation = ARC_EXT;
				instruction->data_size = BYTE;
				dst_is_src = false;
				break;
			case 0x10:
				instruction->operation = ARC_EXT;
				instruction->data_size = WORD;
				dst_is_src = false;
				break;
			case 0x11:
				instruction->operation = ARC_ABS;
				dst_is_src = false;
				break;
			case 0x12:
				instruction->operation = ARC_NOT;
				dst_is_src = false;
				break;
			case 0x13:
				instruction->operation = ARC_NEG;
				dst_is_src = false;
				break;
			case 0x14:
				instruction->operation = ARC_ADD1;
				break;
			case 0x15:
				instruction->operation = ARC_ADD2;
				break;
			case 0x16:
				instruction->operation = ARC_ADD3;
				break;
			case 0x18:
				instruction->operation = ARC_ASL;
				break;
			case 0x19:
				instruction->operation = ARC_LSR;
				break;
			case 0x1A:
				instruction->operation = ARC_ASR;
				break;
			case 0x1B:
			case 0x1C:
			case 0x1D: {
				switch (decoded_ins.double_regs.sub_opcode) {
					case 0x1B:
						instruction->operation = ARC_ASL;
						break;
					case 0x1C:
						instruction->operation = ARC_ASR;
						break;
					case 0x1D:
						instruction->operation = ARC_LSR;
						break;
				}

				ARG_REG_REDUCED(&instruction->operands[0], decoded_ins.b);
				ARG_REG_REDUCED(&instruction->operands[1], decoded_ins.double_regs.right_reg);
				ARG_IMM(&instruction->operands[2], 1);

				return 0;
			}
			case 0x1E: {
				instruction->operation = ARC_TRAP;

				uint8_t source_value = (decoded_ins.b << 3) | decoded_ins.double_regs.right_reg;
				
				if (source_value == 0) {
					instruction->operation = ARC_SWI;
				} else {
					ARG_IMM(&instruction->operands[0], source_value);
				}

				return 0;
			}
			case 0x1F:
				instruction->operation = ARC_BRK;
				return 0;
		}

		InstructionOperand* dst = &instruction->operands[0];
		InstructionOperand* c_reg = &instruction->operands[1];

		ARG_REG_REDUCED(dst, decoded_ins.b);

		if (dst_is_src) {
			ARG_REG(&instruction->operands[1], dst->reg);
			c_reg = &instruction->operands[2];
		}

		ARG_REG_REDUCED(c_reg, decoded_ins.double_regs.right_reg);

		return 0;
	}

	uint32_t arcompact_decompose_instruction(
			encoded_instruction ins,
			Instruction* __restrict instruction,
			uint32_t version,
			uint64_t address)
	{
		if (version >= ARC_VERSION_END) {
			return 1;
		}

		instruction->condition = NONE;
		if (ins.compact.major_opcode >= 0xC) {
			instruction->compact = true;
			instruction->size = 2;
		} else {
			instruction->size = 4;
		}

		switch (ins.compact.major_opcode) {
			case 0x00: {
				b decoded_ins = ins.b;

				instruction->operation = ARC_B;

				InstructionOperand* target = &instruction->operands[0];
				int32_t offset = (decoded_ins.offset_upper << 11) | (decoded_ins.offset_lower << 1);
				if (decoded_ins.unconditional) {
					if (decoded_ins.condition_or_offset_far >> 4 == 1) {
						return 1;
					}

					offset |= (decoded_ins.condition_or_offset_far & 0xF) << 21;
					offset = SIMM(offset, 25);
				} else {
					if (version == ARC_700 && decoded_ins.condition_or_offset_far >= 0x12) {
						return 1;
					} else if (decoded_ins.condition_or_offset_far >= 0x10) {
						instruction->condition = NEVER;
					} else {
						instruction->condition = decoded_ins.condition_or_offset_far;
					}

					offset = SIMM(offset, 21);
				}

				ARG_LABEL(target, ALIGN32(address), offset);
				instruction->delayed = decoded_ins.execute_delay_slot;
			}
			break;
			case 0x01: {
				if (ins.br.one == 1) {
					br decoded_ins = ins.br;
					
					instruction->operation = ARC_BR;

					InstructionOperand* left_reg = &instruction->operands[0];
					InstructionOperand* right = &instruction->operands[1];
					InstructionOperand* target = &instruction->operands[2];

					ARG_REG(left_reg, _R((decoded_ins.left_reg_upper << 3) | decoded_ins.left_reg_lower));
					if (left_reg->reg == REG_R62) {
						instruction->has_long_imm = true;
					}

					if (decoded_ins.immediate) {
						ARG_IMM(right, decoded_ins.right);
					} else {
						ARG_REG(right, _R(decoded_ins.right));
						if (right->reg == REG_R62) {
							instruction->has_long_imm = true;
						}
					}

					ARG_LABEL(target, ALIGN32(address), SIMM((decoded_ins.offset_upper << 8) | (decoded_ins.offset_lower << 1), 9));

					if (decoded_ins.execute_delay_slot) {
						if (right->reg == REG_R62) {
							return 1;
						}

						instruction->delayed = true;
					}

					switch (decoded_ins.sub_opcode) {
						case 0x00:
							instruction->condition = EQ;
							break;
						case 0x01:
							instruction->condition = NE;
							break;
						case 0x02:
							instruction->condition = LT;
							break;
						case 0x03:
							instruction->condition = GE;
							break;
						case 0x04:
							instruction->condition = LO;
							break;
						case 0x05:
							instruction->condition = HS;
							break;
						case 0x0E:
							instruction->operation = ARC_BBIT0;
							break;
						case 0x0F:
							instruction->operation = ARC_BBIT1;
							break;
						default:
							return 1;
					}
				} else {
					bl decoded_ins = ins.bl;

					instruction->operation = ARC_BL;

					InstructionOperand* target = &instruction->operands[0];

					int32_t offset = (decoded_ins.offset_upper << 11) | (decoded_ins.offset_lower << 2);
					if (decoded_ins.unconditional) {
						offset |= (decoded_ins.condition_or_offset_far & 0xF) << 21;
						offset = SIMM(offset, 25);
					} else {
						if (version == ARC_700 && decoded_ins.condition_or_offset_far >= 0x12) {
							return 1;
						} else if (decoded_ins.condition_or_offset_far >= 0x10) {
							instruction->condition = NEVER;
						} else {
							instruction->condition = decoded_ins.condition_or_offset_far;
						}

						offset = SIMM(offset, 21);
					}

					ARG_LABEL(target, ALIGN32(address), offset);
					instruction->delayed = decoded_ins.execute_delay_slot;
				}
			}
			break;
			case 0x02: {
				ld decoded_ins = ins.ld;

				instruction->operation = ARC_LD;

				InstructionOperand* dst = &instruction->operands[0];
				InstructionOperand* src = &instruction->operands[1];

				if (decoded_ins.dst_reg >= 0x20 && decoded_ins.dst_reg <= 0x3B) {
					return 1;
				}
				if (decoded_ins.dst_reg == 0x3D || decoded_ins.dst_reg == 0x3F) {
					return 1;
				}
				ARG_REG(dst, _R(decoded_ins.dst_reg));

				if (decoded_ins.data_size == 0x3) {
					return 1;
				}
				instruction->data_size = decoded_ins.data_size;

				if (decoded_ins.sign_extend) {
					if (decoded_ins.data_size == 0x0) {
						return 1;
					}
					instruction->sign_extend = true;
				}

				ARG_REG_IMM_REL(
					src,
					_R((decoded_ins.base_reg_upper << 3) | decoded_ins.base_reg_lower),
					SIMM((decoded_ins.offset_upper << 8) | (decoded_ins.offset_lower), 9)
				);
				if (src->reg == REG_R62) {
					if (decoded_ins.address_writeback == 0x1 || decoded_ins.address_writeback == 0x2) {
						return 1;
					}

					instruction->has_long_imm = true;
				}

				instruction->address_writeback = decoded_ins.address_writeback;
				instruction->bypass_direct_data_cache = decoded_ins.bypass_direct_data_cache;
			}
			break;
			case 0x03: {
				st decoded_ins = ins.st;

				instruction->operation = ARC_ST;

				InstructionOperand* src = &instruction->operands[0];
				InstructionOperand* dst = &instruction->operands[1];

				ARG_REG(src, _R(decoded_ins.src_reg));
				if (src->reg == REG_R62) {
					instruction->has_long_imm = true;
				}

				if (decoded_ins.data_size == 0x3) {
					return 1;
				}
				instruction->data_size = decoded_ins.data_size;

				ARG_REG_IMM_REL(
					dst,
					_R((decoded_ins.base_reg_upper << 3) | decoded_ins.base_reg_lower),
					SIMM((decoded_ins.offset_upper << 8) | (decoded_ins.offset_lower), 9)
				);
				if (dst->reg == REG_R62) {
					if (decoded_ins.address_writeback == 0x1 || decoded_ins.address_writeback == 0x2) {
						return 1;
					}

					instruction->has_long_imm = true;
				}

				instruction->address_writeback = decoded_ins.address_writeback;
				instruction->bypass_direct_data_cache = decoded_ins.bypass_direct_data_cache;
			}
			break;
			case 0x04:
				return decompose_general_instruction(
					ins,
					instruction,
					version,
					address
				);
			case 0x05:
				return decompose_extension_instruction(ins, instruction, version, address);
			// User extensions
			case 0x07:
			case 0x08:
			// Market-specific extensions
			case 0x09:
			case 0x0A:
			case 0x0B:
				return 1;
			case 0x0C: {
				three_reg decoded_ins = ins.three_reg;

				InstructionOperand* b_reg = &instruction->operands[1];

				ARG_REG_REDUCED(&instruction->operands[0], decoded_ins.a);
				ARG_REG_REG_REL(b_reg, cvt_16bit_reg(decoded_ins.b), cvt_16bit_reg(decoded_ins.c));
				
				switch (decoded_ins.sub_opcode) {
					case 0x00:
						instruction->operation = ARC_LD;
						instruction->data_size = LONG_WORD;
						break;
					case 0x01:
						instruction->operation = ARC_LD;
						instruction->data_size = BYTE;
						break;
					case 0x02:
						instruction->operation = ARC_LD;
						instruction->data_size = WORD;
						break;
					case 0x03:
						instruction->operation = ARC_ADD;

						ARG_REG(&instruction->operands[2], b_reg->displacement_reg);
						ARG_REG(b_reg, b_reg->reg);
						break;
				}
			}
			case 0x0D: {
				two_reg_one_imm decoded_ins = ins.two_reg_one_imm;

				ARG_REG_REDUCED(&instruction->operands[0], decoded_ins.dst_reg);
				ARG_REG_REDUCED(&instruction->operands[1], decoded_ins.src_reg);
				ARG_IMM(&instruction->operands[2], decoded_ins.imm);

				switch (decoded_ins.sub_opcode) {
					case 0x00:
						instruction->operation = ARC_ADD;
						break;
					case 0x01:
						instruction->operation = ARC_SUB;
						break;
					case 0x02:
						instruction->operation = ARC_ASL;
						break;
					case 0x03:
						instruction->operation = ARC_ASR;
						break;
				}
			}
			break;
			case 0x0E: {
				one_reg_one_hreg decoded_ins = ins.one_reg_one_hreg;

				InstructionOperand* high_reg = &instruction->operands[1];

				switch (decoded_ins.sub_opcode) {
					case 0x00: {
						instruction->operation = ARC_ADD;

						InstructionOperand* dst = &instruction->operands[0];
						ARG_REG_REDUCED(dst, decoded_ins.b_reg);
						ARG_REG(&instruction->operands[1], dst->reg);

						high_reg = &instruction->operands[2];
					}
					break;
					case 0x01:
						instruction->operation = ARC_MOV;
						break;
					case 0x02:
						instruction->operation = ARC_CMP;
						break;
					case 0x03: {
						instruction->operation = ARC_MOV;
						high_reg = &instruction->operands[0];
					}
					break;
				}

				if (decoded_ins.sub_opcode != 0x00) {
					ARG_REG_REDUCED(
						&instruction->operands[
							(decoded_ins.sub_opcode != 0x03) ? 0 : 1
						],
						decoded_ins.b_reg
					);
				}

				ARG_REG(high_reg, _R((decoded_ins.h_reg_upper << 3) | decoded_ins.h_reg_lower));

				if (version == ARC_700 && high_reg->reg == REG_PCL) {
					return 1;
				}

				if (high_reg->reg == REG_R62) {
					instruction->has_long_imm = true;
				}
			}
			break;
			case 0x0F:
				return decompose_16bit_general_instruction(
					ins,
					instruction,
					version,
					address
				);
			case 0x10:
			case 0x11:
			case 0x12:
			case 0x13:
			case 0x14:
			case 0x15:
			case 0x16: {
				compact_ld_st decoded_ins = ins.compact_ld_st;

				InstructionOperand* c_reg = &instruction->operands[0];
				InstructionOperand* b_rel = &instruction->operands[1];

				ARG_REG_REDUCED(c_reg, ins.compact_ld_st.c_reg);

				uint8_t offset = ins.compact_ld_st.offset;
				switch (ins.compact.major_opcode) {
					case 0x10:
						instruction->operation = ARC_LD;
						instruction->data_size = LONG_WORD;
						offset <<= 2;
						break;
					case 0x11:
						instruction->operation = ARC_LD;
						instruction->data_size = BYTE;
						break;
					case 0x12:
						instruction->operation = ARC_LD;
						instruction->data_size = WORD;
						offset <<= 1;
						break;
					case 0x13:
						instruction->operation = ARC_LD;
						instruction->data_size = WORD;
						instruction->sign_extend = true;
						offset <<= 1;
						break;
					case 0x14:
						instruction->operation = ARC_ST;
						instruction->data_size = LONG_WORD;
						break;
					case 0x15:
						instruction->operation = ARC_ST;
						instruction->data_size = BYTE;
						break;
					case 0x16:
						instruction->operation = ARC_ST;
						instruction->data_size = WORD;
						break;
					default:
						return 1;
				}

				ARG_REG_IMM_REL(
					b_rel,
					cvt_16bit_reg(ins.compact_ld_st.b_reg),
					offset
				);
			}
			break;
			case 0x17: {
				one_reg_sub_one_imm decoded_ins = ins.one_reg_sub_one_imm;

				ARG_REG_REDUCED(&instruction->operands[0], decoded_ins.reg);

				if (decoded_ins.sub_opcode == 0x07) {
					instruction->operation = ARC_BTST;

					ARG_IMM(&instruction->operands[1], decoded_ins.imm);
				} else {
					ARG_REG_REDUCED(&instruction->operands[1], decoded_ins.reg);
					ARG_IMM(&instruction->operands[2], decoded_ins.imm);

					switch (decoded_ins.sub_opcode) {
						case 0x00:
							instruction->operation = ARC_ASL;
							break;
						case 0x01:
							instruction->operation = ARC_LSR;
							break;
						case 0x02:
							instruction->operation = ARC_ASR;
							break;
						case 0x03:
							instruction->operation = ARC_SUB;
							break;
						case 0x04:
							instruction->operation = ARC_BSET;
							break;
						case 0x05:
							instruction->operation = ARC_BCLR;
							break;
						case 0x06:
							instruction->operation = ARC_BMSK;
							break;
						default:
							return 1;
					}
				}
			}
			break;
			case 0x18: {
				one_reg_sub_one_imm decoded_ins = ins.one_reg_sub_one_imm;

				if (decoded_ins.sub_opcode == 0x4 || decoded_ins.sub_opcode == 0x5) {
					InstructionOperand* dst = &instruction->operands[0];
					InstructionOperand* src = &instruction->operands[1];
					InstructionOperand* imm = &instruction->operands[2];

					ARG_REG(src, REG_SP);

					if (decoded_ins.sub_opcode == 0x4) {
						ARG_REG_REDUCED(dst, decoded_ins.reg);
					} else {
						ARG_REG(dst, REG_SP);
						
						uint8_t sub_opcode = decoded_ins.reg;
						if (sub_opcode == 0b00) {
							instruction->operation = ARC_ADD;
						} else if (sub_opcode == 0b01) {
							instruction->operation = ARC_SUB;
						} else {
							return 1;
						}
					}

					ARG_IMM(imm, decoded_ins.imm << 2);
				} else if (decoded_ins.sub_opcode == 0x6 || decoded_ins.sub_opcode == 0x7) {
					instruction->operation = (decoded_ins.sub_opcode == 0x6) ? ARC_POP : ARC_PUSH;

					InstructionOperand* reg = &instruction->operands[0];
					uint8_t sub_opcode = decoded_ins.imm;
					if (sub_opcode == 0x01) {
						ARG_REG_REDUCED(reg, decoded_ins.reg);
					} else if (sub_opcode == 0x11) {
						ARG_REG(reg, REG_BLINK);
					} else {
						return 1;
					}
				} else {
					InstructionOperand* reg = &instruction->operands[0];
					InstructionOperand* sp_rel = &instruction->operands[1];

					ARG_REG_REDUCED(reg, decoded_ins.reg);

					ARG_REG_IMM_REL(sp_rel, REG_SP, decoded_ins.imm << 2);

					switch (decoded_ins.sub_opcode) {
						case 0x00:
							instruction->operation = ARC_LD;
							instruction->data_size = LONG_WORD;
							break;
						case 0x01:
							instruction->operation = ARC_LD;
							instruction->data_size = BYTE;
							break;
						case 0x02:
							instruction->operation = ARC_ST;
							instruction->data_size = LONG_WORD;
							break;
						case 0x03:
							instruction->operation = ARC_ST;
							instruction->data_size = BYTE;
							break;
						default:
							break;
					}
				}
			}
			break;
			case 0x19: {
				gp_relative decoded_ins = ins.gp_relative;

				instruction->operation = ARC_LD;

				InstructionOperand* reg = &instruction->operands[0];
				InstructionOperand* gp_rel = &instruction->operands[1];

				uint16_t encoded_offset = decoded_ins.offset;

				ARG_REG(reg, REG_R0);

				uint32_t offset;
				switch (decoded_ins.sub_opcode) {
					case 0b00:
						instruction->data_size = LONG_WORD;
						offset = encoded_offset << 2;
						break;
					case 0b01:
						instruction->data_size = BYTE;
						offset = encoded_offset;
						break;
					case 0b10:
						instruction->data_size = WORD;
						offset = encoded_offset << 1;
						break;
					case 0b11:
						instruction->operation = ARC_ADD;
						ARG_REG(gp_rel, REG_GP);
						ARG_IMM(&instruction->operands[2], encoded_offset << 2);
						return 0;
				}

				ARG_REG_IMM_REL(gp_rel, REG_GP, offset);
			}
			break;
			case 0x1A: {
				one_reg_one_imm decoded_ins = ins.one_reg_one_imm;

				instruction->operation = ARC_LD;
				instruction->data_size = LONG_WORD;

				ARG_REG_REDUCED(&instruction->operands[0], decoded_ins.reg);
				ARG_REG_IMM_REL(&instruction->operands[1], REG_PCL, ins.one_reg_one_imm.imm << 2);
			}
			break;
			case 0x1B: {
				one_reg_one_imm decoded_ins = ins.one_reg_one_imm;

				instruction->operation = ARC_MOV;

				ARG_REG_REDUCED(&instruction->operands[0], decoded_ins.reg);
				ARG_IMM(&instruction->operands[1], decoded_ins.imm);
			}
			break;
			case 0x1C: {
				one_reg_one_imm decoded_ins = ins.one_reg_one_imm;

				InstructionOperand* reg = &instruction->operands[0];
				InstructionOperand* imm = &instruction->operands[1];

				ARG_REG_REDUCED(reg, decoded_ins.reg);

				if (decoded_ins.sub_opcode == 0) {
					instruction->operation = ARC_ADD;

					InstructionOperand* second = imm;
					ARG_REG(imm, reg->reg);

					imm = &instruction->operands[2];
				} else {
					instruction->operation = ARC_CMP;
				}

				ARG_IMM(imm, decoded_ins.short_imm);
			}
			break;
			case 0x1D: {
				one_reg_one_imm decoded_ins = ins.one_reg_one_imm;

				instruction->operation = ARC_BR;

				InstructionOperand* reg = &instruction->operands[0];
				InstructionOperand* zero = &instruction->operands[1];
				InstructionOperand* target = &instruction->operands[2];

				ARG_IMM(zero, 0);

				ARG_REG_REDUCED(reg, decoded_ins.reg);

				if (decoded_ins.sub_opcode == 0) {
					instruction->condition = EQ;
				} else {
					instruction->condition = NE;
				}

				ARG_LABEL(target, ALIGN32(address), SIMM(decoded_ins.short_imm << 1, 8));
			}
			break;
			case 0x1E: {
				sub_one_imm decoded_ins = ins.sub_one_imm;

				instruction->operation = ARC_B;

				int32_t offset;
				if (decoded_ins.sub_opcode == 0b11) {
					offset = SIMM(ins.bc_compact.offset << 1, 7);
					switch (ins.bc_compact.sub_opcode) {
						case 0b000:
							instruction->condition = GT;
							break;
						case 0b001:
							instruction->condition = GE;
							break;
						case 0b010:
							instruction->condition = LT;
							break;
						case 0b011:
							instruction->condition = LE;
							break;
						case 0b100:
							instruction->condition = HI;
							break;
						case 0b101:
							instruction->condition = HS;
							break;
						case 0b110:
							instruction->condition = LO;
							break;
						case 0b111:
							instruction->condition = LS;
							break;
						default:
							break;
					}
				} else {
					offset = SIMM(decoded_ins.imm << 1, 10);
					switch (decoded_ins.sub_opcode) {
						case 0b00:
							break;
						case 0b01:
							instruction->condition = EQ;
							break;
						case 0b10:
							instruction->condition = NE;
							break;
						default:
							break;
					}
				}

				ARG_LABEL(&instruction->operands[0], ALIGN32(address), offset);
			}
			break;
			case 0x1F: {
				instruction->operation = ARC_BL;
				ARG_LABEL(&instruction->operands[0], ALIGN32(address), SIMM(ins.compact.raw << 2, 13));
			}
			break;
		}

		return 0;
	}

	uint32_t arcompact_decompose(
			const uint16_t* instructionValue,
			size_t maxSize,
			Instruction* __restrict instruction,
			uint32_t version,
			uint32_t address,
			uint32_t bigEndian) {
		encoded_instruction ins;
		if (instructionValue == NULL) {
			return 1;
		}

		if (bigEndian == 1) {
			ins.raw = bswap_16(instructionValue[0]) << 16;
			if (maxSize >= 4) {
				ins.raw |= bswap_16(instructionValue[1]);
			}
		} else {
			ins.raw = instructionValue[0] << 16;
			if (maxSize >= 4) {
				ins.raw |= instructionValue[1];
			}
		}

		uint32_t result = arcompact_decompose_instruction(ins, instruction, version, address);
		if (result != 0) {
			return result;
		}

		if (instruction->has_long_imm) {
			if (maxSize < instruction->size + 4) {
				return 1;
			}

			uint16_t long_imm_higher, long_imm_lower;
			if (instruction->size == 2) {
				long_imm_higher = instructionValue[1];
				long_imm_lower = instructionValue[2];
			} else {
				long_imm_higher = instructionValue[2];
				long_imm_lower = instructionValue[3];
			}

			instruction->size += 4;

			int32_t long_imm = 0;

			if (bigEndian == 1) {
				long_imm = bswap_16(long_imm_higher) << 16;
				long_imm |= bswap_16(long_imm_lower);
			} else {
				long_imm = long_imm_higher << 16;
				long_imm |= long_imm_lower;
			}


			for (int i = 0; i < MAX_OPERANDS; i++) {
				InstructionOperand* operand = &instruction->operands[i];
				if (operand->operand_class == REG && operand->reg == REG_R62) {
					ARG_IMM(operand, long_imm);
					if (instruction->operation == ARC_LP && i == 0) {
						ARG_LABEL(operand, ALIGN32(address), long_imm);
					}
				} else if (operand->operand_class == REG_IMM_REL && operand->reg == REG_R62) {
					ARG_IMM(operand, long_imm + operand->offset);
				} else if (operand->operand_class == REG_REG_REL && operand->reg == REG_R62) {
					if (operand->displacement_reg == REG_R62) {
						ARG_IMM(operand, long_imm * 2);
					} else {
						operand->operand_class = IMM_REG_REL;
						operand->reg = operand->displacement_reg;
						operand->immediate = long_imm;
					}
				}
			}

			if (instruction->operation == ARC_LR || instruction->operation == ARC_SR) {
				InstructionOperand* auxreg = &instruction->operands[1];
				switch (auxreg->operand_class) {
					case IMM:
						if (auxreg->immediate < 0) {
							return 1;
						}

						if (AUXREG_START + auxreg->immediate < END_REG) {
							ARG_REG(auxreg, Reg(AUXREG_START + auxreg->immediate));
						}
						break;
				}
			}
		}

		return result;
	}
}