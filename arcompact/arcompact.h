#pragma once
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_OPERANDS 3

namespace ArCompact {
#pragma pack(push, 1)
	struct b {
		uint8_t condition_or_offset_far:5;
		bool execute_delay_slot:1;
		uint16_t offset_upper:10;
		bool unconditional:1;
		uint16_t offset_lower:10;
		uint8_t major_opcode:5;
	};
	
	struct br {
		uint8_t sub_opcode:4;
		bool immediate:1;
		bool execute_delay_slot:1;
		uint8_t right:6;
		uint8_t left_reg_upper:3;
		uint8_t offset_upper:1;
		bool one:1;
		uint8_t offset_lower:7;
		uint8_t left_reg_lower:3;
		uint8_t major_opcode:5;
	};
	
	struct bl {
		uint8_t condition_or_offset_far:5;
		bool execute_delay_slot:1;
		uint16_t offset_upper:10;
		bool zero:1;
		bool unconditional:1;
		uint16_t offset_lower:9;
		uint8_t major_opcode:5;
	};
	
	struct ld {
		uint8_t dst_reg:6;
		bool sign_extend:1;
		uint8_t data_size:2;
		uint8_t address_writeback:2;
		bool bypass_direct_data_cache:1;
		uint8_t base_reg_upper:3;
		uint8_t offset_upper:1;
		uint8_t offset_lower:8;
		uint8_t base_reg_lower:3;
		uint8_t major_opcode:5;
	};
	
	struct st {
		uint8_t reserved:1;
		uint8_t data_size:2;
		uint8_t address_writeback:2;
		bool bypass_direct_data_cache:1;
		uint8_t src_reg:6;
		uint8_t base_reg_upper:3;
		uint8_t offset_upper:1;
		uint8_t offset_lower:8;
		uint8_t base_reg_lower:3;
		uint8_t major_opcode:5;
	};

	// also for extended	
	struct general {
		uint8_t a:6;
		uint8_t c:6;
		uint8_t b_upper:3;
		bool set_flag:1;
		uint8_t sub_opcode:6;
		uint8_t operand_format:2;
		uint8_t b_lower:3;
		uint8_t major_opcode:5;
	};
	
	struct ld_reg_reg {
		uint8_t dst:6;
		uint8_t offset:6;
		uint8_t base_upper:3;
		bool bypass_direct_data_cache:1;
		bool sign_extend:1;
		uint8_t data_size:2;
		uint8_t sub_opcode:3;
		uint16_t address_writeback:2;
		uint8_t base_lower:3;
		uint8_t major_opcode:5;
	};

	struct three_reg {
		uint16_t padding:16;
		uint8_t a:3;
		uint8_t sub_opcode:2;
		uint8_t c:3;
		uint8_t b:3;
		uint8_t major_opcode:5;
	};	
	
	struct two_reg_one_imm {
		uint16_t padding:16;
		uint8_t imm:3;
		uint8_t sub_opcode:2;
		uint8_t dst_reg:3;
		uint8_t src_reg:3;
		uint8_t major_opcode:5;
	};	
	
	struct one_reg_one_hreg {
		uint16_t padding:16;
		uint8_t h_reg_upper:3;
		uint8_t sub_opcode:2;
		uint8_t h_reg_lower:3;
		uint8_t b_reg:3;
		uint8_t major_opcode:5;
	};

	struct compact_general {
		uint16_t padding:16;
		union {
			struct {
				uint8_t sub_opcode:5;
				uint8_t right_reg:3;
			} double_regs;
			struct {
				uint8_t zero:5;
				uint8_t sub_opcode:3;
			} single_reg;
			struct {
				uint8_t zero:5;
				uint8_t seven:3;
			} zero_regs;
		};
		uint8_t b:3;
		uint8_t major_opcode:5;
	};

	struct compact_ld_st {
		uint16_t padding:16;
		uint8_t offset:5;
		uint8_t c_reg:3;
		uint8_t b_reg:3;
		uint8_t major_opcode:5;
	};

	struct one_reg_sub_one_imm {
		uint16_t padding:16;
		uint8_t imm:5;
		uint8_t sub_opcode:3;
		uint8_t reg:3;
		uint8_t major_opcode:5;
	};

	struct gp_relative {
		uint16_t padding:16;
		uint16_t offset:9;
		uint8_t sub_opcode:2;
		uint8_t major_opcode:5;
	};
	
	struct one_reg_one_imm {
		uint16_t padding:16;
		union {
			struct {
				uint8_t short_imm:7;
				uint8_t sub_opcode:1;
			};
			uint8_t imm:8;
		};
		uint8_t reg:3;
		uint8_t major_opcode:5;
	};
	
	struct sub_one_imm {
		uint16_t padding:16;
		uint16_t imm:9;
		uint8_t sub_opcode:2;
		uint8_t major_opcode:5;
	};
	
	struct bc_compact {
		uint16_t padding:16;
		uint16_t offset:6;
		uint8_t sub_opcode:3;
		uint8_t three:2;
		uint8_t major_opcode:5;
	};

	union encoded_instruction {
		struct {
			uint16_t padding:16;
			uint16_t raw:11;
			uint8_t major_opcode:5;
		} compact;
		struct {
			uint32_t raw:27;
			uint8_t major_opcode:5;
		} wide;

		struct b b;
		struct br br;
		struct bl bl;
		struct ld ld;
		struct st st;
		struct general general;
		struct ld_reg_reg ld_reg_reg;

		struct three_reg three_reg;
		struct two_reg_one_imm two_reg_one_imm;
		struct one_reg_one_hreg one_reg_one_hreg;
		struct compact_general compact_general;
		struct compact_ld_st compact_ld_st;
		struct one_reg_sub_one_imm one_reg_sub_one_imm;
		struct gp_relative gp_relative;
		struct one_reg_one_imm one_reg_one_imm;
		struct sub_one_imm sub_one_imm;
		struct bc_compact bc_compact;
		uint32_t raw;
	};

#pragma pack(pop)

	enum Operation {
		ARC_INVALID = 0,

		// Arithmetic & Logical
		ARC_ADD,
		ARC_ADC,
		ARC_SUB,
		ARC_SBC,
		ARC_AND,
		ARC_OR,
		ARC_BIC,
		ARC_XOR,
		ARC_MAX,
		ARC_MIN,
		ARC_MOV,
		ARC_TST,
		ARC_CMP,
		ARC_RCMP,
		ARC_RSUB,
		ARC_BSET,
		ARC_BCLR,
		ARC_BTST,
		ARC_BXOR,
		ARC_BMSK,
		ARC_ADD1,
		ARC_ADD2,
		ARC_ADD3,
		ARC_SUB1,
		ARC_SUB2,
		ARC_SUB3,
		ARC_ASL,
		ARC_ASR,
		ARC_LSR,
		ARC_ROR,

		ARC_SEX,
		ARC_EXT,
		ARC_NOT,
		ARC_NEG,
		ARC_ABS,
		ARC_FLAG,
		ARC_RLC,
		ARC_RRC,

		ARC_NOP,
		ARC_SLEEP,
		ARC_SWI,
		ARC_BRK,
		ARC_TRAP,
		ARC_UNIMP,
		ARC_RTIE,
		ARC_SYNC,

		ARC_USEXT,

		ARC_B,
		/*
		ARC_BEQ,
		ARC_BNE,
		ARC_BGT,
		ARC_BGE,
		ARC_BLT,
		ARC_BLE,
		ARC_BHI,
		ARC_BHS,
		ARC_BLO,
		ARC_BLS,
		*/

		ARC_BL,

		ARC_BR,
		/*
		ARC_BREQ,
		ARC_BRNE,
		ARC_BRLT,
		ARC_BRGE,
		ARC_BRLO,
		ARC_BRHS,
		*/
		ARC_BBIT0,
		ARC_BBIT1,

		ARC_J,
		/*
		ARC_JEQ,
		ARC_JNE,
		*/
		ARC_JL,

		ARC_LP,

		ARC_LR,
		ARC_SR,

		ARC_LD,
		ARC_ST,
		
		ARC_PUSH,
		ARC_POP,

		ARC_EX,

		ARC_MUL64,
		ARC_MULU64,
		ARC_MPY,
		ARC_MPYH,
		ARC_MPYHU,
		ARC_MPYU,

		ARC_NORM,
		ARC_SWAP,

		ARC_ADDS,
		ARC_SUBS,
		ARC_DIVAW,
		ARC_ASLS,
		ARC_ASRS,
		ARC_ADDSDW,
		ARC_SUBSDW,

		ARC_SAT16,
		ARC_RND16,
		ARC_ABSS,
		ARC_NEGS,

		ARC_OPERATION_END,
	};

	enum Reg {
		REG_R0,
		REG_R1,
		REG_R2,
		REG_R3,
		REG_R4,
		REG_R5,
		REG_R6,
		REG_R7,
		REG_R8,
		REG_R9,
		REG_R10,
		REG_R11,
		REG_R12,
		REG_R13,
		REG_R14,
		REG_R15,
		REG_R16,
		REG_R17,
		REG_R18,
		REG_R19,
		REG_R20,
		REG_R21,
		REG_R22,
		REG_R23,
		REG_R24,
		REG_R25,
		REG_R26, REG_GP = REG_R26,
		REG_R27, REG_FP = REG_R27,
		REG_R28, REG_SP = REG_R28,
		REG_R29, REG_ILINK1 = REG_R29,
		REG_R30, REG_ILINK2 = REG_R30,
		REG_R31, REG_BLINK  = REG_R31,

		// Extension Core Registers
		REG_R32,
		REG_R33,
		REG_R34,
		REG_R35,
		REG_R36,
		REG_R37,
		REG_R38,
		REG_R39,
		REG_R40,
		REG_R41,
		REG_R42,
		REG_R43,
		REG_R44,
		REG_R45,
		REG_R46,
		REG_R47,
		REG_R48,
		REG_R49,
		REG_R50,
		REG_R51,
		REG_R52,
		REG_R53,
		REG_R54,
		REG_R55,
		REG_R56,
		REG_R57,
		REG_R58,
		REG_R59,
		REG_R60, REG_LP_COUNT = REG_R60,
		REG_R61, // Reserved
		REG_R62, // Long immediate data indicator
		REG_R63, REG_PCL = REG_R63,

		// Auxiliary Register Set
		REG_STATUS, AUXREG_START = REG_STATUS,
		REG_SEMAPHORE,
		REG_LP_START,
		REG_LP_END,
		REG_IDENTITY,
		REG_DEBUG,
		REG_PC,
		REG_STATUS32 = AUXREG_START + 0xA,
		REG_STATUS32_L1,
		REG_STATUS32_L2,
		REG_MULHI,

		REG_COUNT0 = AUXREG_START + 0x21,
		REG_CONTROL0,
		REG_LIMIT0,

		REG_INT_VECTOR_BASE = AUXREG_START + 0x25,
		REG_AUX_MACMODE = AUXREG_START + 0x41,
		REG_AUX_IRQ_LV12,

		// Build Configuration Registers
		REG_BCR_VER = AUXREG_START + 0x60,
		REG_BTA_LINK_BUILD,
		REG_EA_BUILD,
		REG_VECBASE_AC_BUILD,
		REG_RF_BUILD,
		REG_TIMER_BUILD,
		REG_MULTIPLY_BUILD, 
		REG_SWAP_BUILD,
		REG_NORM_BUILD,
		REG_MINMAX_BUILD,
		REG_BARREL_BUILD,

		REG_COUNT1 = AUXREG_START + 0x100,
		REG_CONTROL1,
		REG_LIMIT1,

		AUX_IRQ_LEV = AUXREG_START + 0x200,
		AUX_IRQ_HINT,

		ERET = AUXREG_START + 0x400,
		ERBTA,
		ERSTATUS,
		ECR,
		EFA,
		ICAUSE1 = AUXREG_START + 0x40A,
		ICAUSE2,
		AUX_IENABLE,
		AUX_ITRIGGER,
		XPU = AUXREG_START + 0x410,
		BTA = AUXREG_START + 0x412,
		BTA_L1,
		BTA_L2,
		AUX_IRQ_PULSE_CANCEL = 0x415,
		AUX_IRQ_PENDING,

		// Last valid register
		END_REG,
	};

	enum Flag {
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
		
		// Last valid register
		END_FLAG,
	};

	enum OperandClass {
		EMPTY = 0,
		REG,
		IMM,
		LABEL,
		REG_IMM_REL,
		REG_REG_REL,
		IMM_REG_REL,
	};

	enum ConditionCode {
		NEVER = -2, NA = NEVER,
		NONE = -1,

		AL = 0, RA = AL, // Always
		EQ, Z = EQ, // Zero
		NE, NZ = NE, // Non-zero
		PL, P = PL, // Positive
		MI, N = MI, // Negative
		CS, C = CS, LO = CS, // Carry set, lower than (unsigned)
		CC, NC = CC, HS = CC, // Carry clear, higher or same (unsigned)
		VS, V = VS, // Over-flow set
		VC, NV = VC, // Over-flow clear
		GT, // Greater than (signed)
		GE, // Greater than or equal to (signed)
		LT, // Less than (signed)
		LE, // Less than or equal to (signed)
		HI, // Higher than (unsigned)
		LS, // Lower than or same (unsigned)
		PNZ, // Positive non-zero
		SS, S = SS, // Saturation set
		SC, NS = SC, // Saturation clear

		END_CONDITION,
	};
	
	enum AddressWriteback {
		NO_WRITEBACK = 0,
		AW,
		AB,
		AS,
	};

	enum DataSize {
		LONG_WORD = 0b00,
		WORD = 0b10,
		BYTE = 0b01,
	};

	enum ArcVersion {
		ARC_TANGENT_A5 = 1,
		ARC_600,
		ARC_700,

		ARC_VERSION_END,
	};

#ifndef __cplusplus
	typedef enum Operation Operation;
	typedef enum Reg Reg;
	typedef enum Flag Flag;
	typedef enum OperandClass OperandClass;
	typedef enum ConditionCode ConditionCode;
	typedef enum AddressWriteback AddressWriteback;
	typedef enum DataSize DataSize;
	typedef enum ArcVersion ArcVersion;
#endif

	struct InstructionOperand {
		uint32_t operand_class;
		uint32_t reg;
		union {
			int32_t immediate;
			int32_t offset;
			uint32_t address;
			uint32_t displacement_reg;
		};
	};

#ifndef __cplusplus
	typedef struct InstructionOperand InstructionOperand;
#endif

	struct Instruction{
		bool compact;

		Operation operation;

		uint32_t condition;
		bool set_flag;
		uint8_t address_writeback:2;
		bool delayed;
		bool bypass_direct_data_cache;
		bool sign_extend;
		uint8_t data_size:2;

		InstructionOperand operands[MAX_OPERANDS];
		bool has_long_imm;

		size_t size;
	};

#ifndef __cplusplus
	typedef struct Instruction Instruction;
	typedef struct b b;
	typedef struct bc bc;
	typedef struct bl bl;
	typedef struct ld ld;
	typedef struct st st;
	typedef struct general general;
	typedef struct ld_reg_reg ld_reg_reg;

	typedef struct three_reg three_reg;
	typedef struct two_reg_one_imm two_reg_one_imm;
	typedef struct one_reg_one_hreg one_reg_one_hreg;
	typedef struct compact_general compact_general;
	typedef struct compact_ld_st compact_ld_st;
	typedef struct one_reg_sub_one_imm one_reg_sub_one_imm;
	typedef struct gp_relative gp_relative;
	typedef struct one_reg_one_imm one_reg_one_imm;
	typedef struct sub_one_imm sub_one_imm;
	typedef struct bc_compact bc_compact;
	typedef union encoded_instruction encoded_instruction;
#endif

	//Given a uint16_t instructionValue decopose the instruction
	//into its components -> instruction
	uint32_t arcompact_decompose(
			const uint16_t* instructionValue,
			size_t maxSize,
			Instruction* __restrict instruction,
			uint32_t version,
			uint32_t address,
			uint32_t bigEndian);

	const char* get_operation(Operation operation);
	const char* get_register(Reg reg);
	const char* get_flag(Flag flag);
	const char* get_condition(ConditionCode condition);
}