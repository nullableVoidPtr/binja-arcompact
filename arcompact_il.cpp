#include "arcompact_il.h"
#include "arcompact.h"
#include "binaryninjaapi.h"
#include "binaryninjacore.h"
#include <cstdint>

using namespace BinaryNinja;
using namespace ArCompact;

#define ADDR_SZ 4
#define REG_SZ 4

static ExprId DirectJump(Architecture* arch, LowLevelILFunction& il, uint32_t target) {
	BNLowLevelILLabel* label = il.GetLabelForAddress(arch, target);
	if (label) {
		return il.Goto(*label);
	} else {
		return il.Jump(il.ConstPointer(ADDR_SZ, target));
	}
}


static ExprId GetILOperandMemoryAddress(LowLevelILFunction& il, const InstructionOperand& operand, uint32_t address) {
	ExprId offset = BN_INVALID_EXPR;

	ExprId reg;
	if (operand.reg == REG_PCL) {
		reg = il.Const(REG_SZ, (address >> 2) << 2);
	} else {
		reg = il.Register(REG_SZ, operand.reg);
	}

	if (operand.operand_class == REG_IMM_REL) {
		offset = il.Add(ADDR_SZ,
					reg,
					il.Const(ADDR_SZ, operand.immediate));
	} else if (operand.operand_class == IMM_REG_REL) {
		offset = il.Add(ADDR_SZ,
					il.Const(ADDR_SZ, operand.immediate),
					reg);
	} else if (operand.operand_class == REG_REG_REL) {
		offset = il.Add(ADDR_SZ,
					reg,
					il.Register(REG_SZ, operand.displacement_reg));
	}

	return offset;
}

static ExprId ReadILOperand(LowLevelILFunction& il,
	const InstructionOperand& operand,
	size_t index,
	uint32_t address,
	size_t opSize = SIZE_MAX,
	bool isAddress = false) {
	if (opSize == SIZE_MAX) {
		opSize = REG_SZ;
	}

	switch (operand.operand_class) {
		case REG:
			if (operand.reg == REG_PCL) {
				return il.Operand(index, il.Const(REG_SZ, (address >> 2) << 2));
			}
			return il.Operand(index, il.Register(opSize, operand.reg));
		case IMM:
			if (isAddress) {
				return il.Operand(index, il.ConstPointer(ADDR_SZ, operand.immediate));
			}

			return il.Operand(index, il.Const(opSize, operand.immediate));
		case LABEL:	
			return il.Operand(index, il.ConstPointer(ADDR_SZ, operand.address));
		case REG_IMM_REL:
		case IMM_REG_REL:
		case REG_REG_REL:
			return il.Operand(index, il.Load(opSize, GetILOperandMemoryAddress(il, operand, address)));
		default:
			return il.Undefined();
	}
}

static ExprId ReadPCLDisplacement(LowLevelILFunction& il,
	const InstructionOperand& operand,
	size_t index,
	uint32_t address,
	size_t opSize = SIZE_MAX) {
	if (opSize == SIZE_MAX) {
		opSize = REG_SZ;
	}

	ExprId expr;
	switch (operand.operand_class) {
		case REG:
			expr = il.Operand(index, il.Register(opSize, operand.reg));
		case IMM:
			expr = il.Operand(index, il.Const(opSize, operand.immediate));
		case LABEL:	// Already resolved
			return il.Operand(index, il.ConstPointer(ADDR_SZ, operand.address));
		case REG_IMM_REL:
		case IMM_REG_REL:
		case REG_REG_REL:
			expr = il.Operand(index, il.Load(opSize, GetILOperandMemoryAddress(il, operand, address)));
		default:
			return il.Undefined();
	}

	return il.Add(ADDR_SZ, il.Const(ADDR_SZ, (address >> 2) << 2), expr);
}

static ExprId WriteILOperand(LowLevelILFunction& il, const InstructionOperand& operand, size_t index, uint32_t address, size_t addrSize, ExprId expr, uint32_t flags = IL_FLAGWRITE_NONE) {
	switch (operand.operand_class) {
	case REG:
		if (operand.reg == REG_PCL) { // This shouldn't be supported
			return il.Operand(index, il.Jump(expr)); // TODO align to 32bit
		}
		return il.Operand(index, il.SetRegister(addrSize, operand.reg, expr, flags));
	case IMM:
		return il.Nop();
	case REG_IMM_REL:
	case IMM_REG_REL:
	case REG_REG_REL:
		return il.Operand(index, il.Store(addrSize, GetILOperandMemoryAddress(il, operand, address), expr));
	default:
		return il.Undefined();
	}
}

static ExprId GetCondition(LowLevelILFunction& il, uint32_t cond) {
	switch ((ConditionCode)cond)
	{
		default:
		case NEVER: return il.Const(0, 0);
	 	case AL: return il.Const(0, 1);
	 	case EQ: return il.FlagCondition(LLFC_E);
	 	case NE: return il.FlagCondition(LLFC_NE);
	 	case PL: return il.FlagCondition(LLFC_POS);
	 	case MI: return il.FlagCondition(LLFC_NEG);
	 	case CS: return il.FlagCondition(LLFC_UGE);
	 	case CC: return il.FlagCondition(LLFC_ULT);
	 	case VS: return il.FlagCondition(LLFC_O);
	 	case VC: return il.FlagCondition(LLFC_NO);
	 	case GT: return il.FlagCondition(LLFC_SGT);
	 	case GE: return il.FlagCondition(LLFC_SGE);
	 	case LT: return il.FlagCondition(LLFC_SLT);
	 	case LE: return il.FlagCondition(LLFC_SLE);
	 	case HI: return il.FlagCondition(LLFC_UGT);
	 	case LS: return il.FlagCondition(LLFC_ULE);
	 	case PNZ: return il.And(REG_SZ, il.FlagCondition(LLFC_NE), il.FlagCondition(LLFC_POS));
	}
}

static bool ExecuteConditionally(Architecture* arch, uint32_t addr, LowLevelILFunction& il, const Instruction& instruction, ExprId condition, ExprId trueCase, const Instruction* delaySlot) {
	bool result = true;
	LowLevelILLabel trueLabel, falseLabel;

	if (instruction.delayed) {
		if (delaySlot == nullptr) {
			return false;
		}

		il.AddInstruction(il.SetRegister(REG_SZ, LLIL_TEMP(0), condition));
		condition = il.Register(REG_SZ, LLIL_TEMP(0));

		il.SetCurrentAddress(arch, addr + instruction.size);
		result = GetLowLevelILForInstruction(arch, addr + instruction.size, il, *delaySlot, nullptr);
		if (!result) {
			il.AddInstruction(il.Undefined());
		}

		il.SetCurrentAddress(arch, addr);
	}

	il.AddInstruction(il.If(condition, trueLabel, falseLabel));
	il.MarkLabel(trueLabel);
	il.AddInstruction(trueCase);
	il.MarkLabel(falseLabel);

	return result;
}

static bool ExecuteCC(Architecture* arch, uint32_t addr, LowLevelILFunction& il, const Instruction& instruction, ExprId trueCase, const Instruction* delaySlot) {
	uint32_t condition = instruction.condition;

	if (condition == NONE || condition == AL) {
		bool result = true;
		if (instruction.delayed) {
			if (delaySlot == nullptr) {
				return false;
			}

			il.SetCurrentAddress(arch, addr + instruction.size);
			result = GetLowLevelILForInstruction(arch, addr + instruction.size, il, *delaySlot, nullptr);
			if (!result) {
				il.AddInstruction(il.Undefined());
			}

			il.SetCurrentAddress(arch, addr);
		}

		il.AddInstruction(trueCase);
		return result;
	}

	return ExecuteConditionally(arch, addr, il, instruction, GetCondition(il, condition), trueCase, delaySlot);
}

bool GetLowLevelILForInstruction(Architecture* arch, uint32_t addr, LowLevelILFunction& il, const Instruction& instruction, const Instruction* delaySlot) {
	switch (instruction.operation) {
		case ARC_BTST:
		case ARC_TST:
		case ARC_CMP:
		case ARC_RCMP: {
			uint32_t operation = instruction.operation;
			ExprId left = ReadILOperand(il, instruction.operands[0], 0, addr, REG_SZ);
			ExprId right = ReadILOperand(il, instruction.operands[1], 1, addr, REG_SZ);

			ExprId expr;
			switch (operation) {
				case ARC_BTST:
					expr = il.And(REG_SZ,
						left,
						il.ShiftLeft(REG_SZ,
							il.Const(REG_SZ, 1),
							il.And(REG_SZ, right, il.Const(REG_SZ, 31))),
						IL_FLAGWRITE_ZN);
				case ARC_TST:
					expr = il.And(REG_SZ, left, right, IL_FLAGWRITE_ZNCV);
					break;
				case ARC_CMP:
					expr = il.Sub(REG_SZ, left, right, IL_FLAGWRITE_ZNCV);
					break;
				case ARC_RCMP:
					expr = il.Sub(REG_SZ, right, left, IL_FLAGWRITE_ZNCV);
					break;
			}

			return ExecuteCC(arch, addr, il, instruction, expr, delaySlot);
		}
		break;

		// Unary operations
		case ARC_MOV:
		case ARC_EXT: 
		case ARC_SEX:
		case ARC_NOT:
		case ARC_RRC:
		case ARC_RLC:
		case ARC_NEG: 
		case ARC_ABS:
		case ARC_FLAG: {
			uint32_t operation = instruction.operation;

			const InstructionOperand& dst = instruction.operands[0];

			ExprId src;
			if (operation == ARC_EXT || operation == ARC_SEX) {
				src = ReadILOperand(il, instruction.operands[1], 1, addr, (instruction.data_size == BYTE) ? 1 : 2);
			} else {
				src = ReadILOperand(il, instruction.operands[1], 1, addr, REG_SZ);
			}

			uint32_t flags = IL_FLAGWRITE_NONE;
			if (instruction.set_flag) {
				switch (operation) {
					case ARC_MOV:
					case ARC_EXT:
					case ARC_SEX:
					case ARC_NOT:
						flags = IL_FLAGWRITE_ZN;
						break;
					case ARC_RRC:
					case ARC_RLC:
						flags = IL_FLAGWRITE_ZNC;
						break;
					case ARC_NEG:
					case ARC_ABS:
						flags = IL_FLAGWRITE_ZNCV;
						break;
					case ARC_FLAG:
						break;
				}
			}

			ExprId expr;
			switch (operation) {
				case ARC_MOV:
					expr = src;
					break;
				case ARC_EXT:
					expr = il.ZeroExtend(REG_SZ, src, flags);
					break;
				case ARC_SEX:
					expr = il.SignExtend(REG_SZ, src, flags);
					break;
				case ARC_NOT:
					expr = il.Not(REG_SZ, src, flags);
					break;
				case ARC_RRC:
					expr = il.RotateRightCarry(REG_SZ, src, il.Const(REG_SZ, 1), il.Flag(FLAG_STATUS_C), flags);
					break;
				case ARC_RLC:
					expr = il.RotateLeftCarry(REG_SZ, src, il.Const(REG_SZ, 1), il.Flag(FLAG_STATUS_C), flags);
					break;
				case ARC_NEG:
					expr = il.Neg(REG_SZ, src, flags);
					break;
				case ARC_ABS: // TODO
					return false;
				case ARC_FLAG: // TODO
					return false;
			}

			return ExecuteCC(arch, addr, il, instruction, WriteILOperand(
				il,
				dst,
				0,
				addr,
				REG_SZ,
				src,
				(operation == ARC_MOV) ? flags : IL_FLAGWRITE_NONE
			), delaySlot);
		}
		break;

		case ARC_DIVAW: {
			uint32_t operation = instruction.operation;

			const InstructionOperand& dst = instruction.operands[0];
			ExprId left = ReadILOperand(il, instruction.operands[1], 1, addr, REG_SZ);
			ExprId right = ReadILOperand(il, instruction.operands[2], 2, addr, REG_SZ);

			LowLevelILLabel zeroLabel, nonZeroLabel, higherLabel, lowerLabel, endLabel;

			il.AddInstruction(
				il.If(
					il.CompareEqual(REG_SZ, left, il.Const(REG_SZ, 0)),
					zeroLabel,
					nonZeroLabel
				)
			);

			il.MarkLabel(zeroLabel);
			il.AddInstruction(WriteILOperand(il, dst, 0, addr, REG_SZ, il.Const(REG_SZ, 0)));
			il.Goto(endLabel);

			il.MarkLabel(nonZeroLabel);
			il.AddInstruction(il.SetRegister(REG_SZ, LLIL_TEMP(0), il.ShiftLeft(
				REG_SZ,
				left,
				il.Const(REG_SZ, 1)
			)));

			il.AddInstruction(il.If(il.CompareSignedGreaterEqual(REG_SZ, LLIL_TEMP(0), right), higherLabel, lowerLabel));
			
			il.MarkLabel(higherLabel);
			il.AddInstruction(WriteILOperand(il, dst, 0, addr, REG_SZ, il.Or(
				REG_SZ,
				il.Sub(REG_SZ, LLIL_TEMP(0), right),
				il.Const(REG_SZ, 1)
			)));
			il.Goto(endLabel);

			il.MarkLabel(lowerLabel);
			il.AddInstruction(WriteILOperand(il, dst, 0, addr, REG_SZ, LLIL_TEMP(0)));
			il.MarkLabel(endLabel);
		}
		break;

		// Binary ALU operations
		default: {
			uint32_t operation = instruction.operation;

			const InstructionOperand& dst = instruction.operands[0];
			ExprId left = ReadILOperand(il, instruction.operands[1], 1, addr, REG_SZ);
			ExprId right = ReadILOperand(il, instruction.operands[2], 2, addr, REG_SZ);

			uint8_t shift = 0;
			switch (operation) {
				case ARC_ADD1:
				case ARC_SUB1:
					shift = 1;
					break;
				case ARC_ADD2:
				case ARC_SUB2:
					shift = 2;
					break;
				case ARC_ADD3:
				case ARC_SUB3:
					shift = 3;
					break;
				default:
					break;
			}

			if (shift > 0) {
				right = il.ShiftLeft(REG_SZ, right, il.Const(REG_SZ, shift));
			}

			uint32_t flags = IL_FLAGWRITE_NONE;
			if (instruction.set_flag) {
				switch (operation) {
					case ARC_ADD:
					case ARC_ADC:
					case ARC_SUB:
					case ARC_SBC:
					case ARC_MAX:
					case ARC_MIN:
					case ARC_ADD1:
					case ARC_ADD2:
					case ARC_ADD3:
					case ARC_SUB1:
					case ARC_SUB2:
					case ARC_SUB3:
					case ARC_ASL:
						flags = IL_FLAGWRITE_ZNCV;
						break;
					case ARC_AND:
					case ARC_OR:
					case ARC_BIC:
					case ARC_XOR:
					case ARC_BSET:
					case ARC_BCLR:
					case ARC_BXOR:
					case ARC_BMSK:
						flags = IL_FLAGWRITE_ZN;
						break;
					case ARC_MPY:
					case ARC_MPYH:
					case ARC_MPYU:
					case ARC_MPYHU:
						flags = IL_FLAGWRITE_ZNV;
					case ARC_ASR:
					case ARC_LSR:
					case ARC_ROR:
						flags = IL_FLAGWRITE_ZNC;
						break;
					default:
						return false;
				}
			}

			switch (operation) {
				case ARC_ASL: case ARC_ASR: case ARC_LSR: case ARC_ROR:
				case ARC_BSET: case ARC_BCLR: case ARC_BXOR: case ARC_BMSK:
					right = il.And(REG_SZ, right, il.Const(REG_SZ, 31));
					break;
				default:
					break;
			}

			ExprId expr;
			switch (operation) {
				case ARC_ADD:
				case ARC_ADD1:
				case ARC_ADD2:
				case ARC_ADD3:
					expr = il.Add(REG_SZ, left, right, flags);
					break;
				case ARC_ADC:
					expr = il.AddCarry(REG_SZ,
						left,
						right,
						il.Flag(FLAG_STATUS_C),
						flags);
					break;
				case ARC_SUB:
				case ARC_SUB1:
				case ARC_SUB2:
				case ARC_SUB3:
					expr = il.Sub(REG_SZ, left, right, flags);
					break;
				case ARC_SBC:
					expr = il.SubBorrow(REG_SZ,
						left,
						right,
						il.Flag(FLAG_STATUS_C),
						flags);
					break;
				case ARC_AND:
					expr = il.And(REG_SZ, left, right, flags);
					break;
				case ARC_OR:
					expr = il.Or(REG_SZ, left, right, flags);
					break;
				case ARC_BIC:
					expr = il.And(REG_SZ,left,	il.Not(REG_SZ, right), flags);
					break;
				case ARC_XOR:
					expr = il.Xor(REG_SZ, left, right, flags);
					break;
				case ARC_MAX: // TODO
					return false;
				case ARC_MIN:
					return false;
				case ARC_RSUB:
					expr = il.Sub(REG_SZ, right, left, flags);
					break;
				case ARC_BSET:
					expr = il.Or(REG_SZ,
						left,
						il.ShiftLeft(REG_SZ, il.Const(REG_SZ, 1), right),
						flags);
					break;
				case ARC_BCLR:
					expr = il.And(REG_SZ,
						left,
						il.Not(REG_SZ, 
							il.ShiftLeft(REG_SZ, il.Const(REG_SZ, 1), right)),
						flags);
					break;
				case ARC_BXOR:
					expr = il.Xor(REG_SZ,
						left,
						il.ShiftLeft(REG_SZ, il.Const(REG_SZ, 1), right),
						flags);
					break;
				case ARC_BMSK:
					expr = il.And(REG_SZ,
						left,
						il.Sub(REG_SZ,
							il.ShiftLeft(REG_SZ,
								il.Const(REG_SZ, 1),
								il.Add(REG_SZ,
									right,
									il.Const(REG_SZ, 1))),
							il.Const(REG_SZ, 1)),
						flags);
					break;
				case ARC_ASL:
					expr = il.ShiftLeft(REG_SZ, left, right, flags);
					break;
				case ARC_ASR:
					expr = il.ArithShiftRight(REG_SZ, left, right, flags);
					break;
				case ARC_LSR:
					expr = il.LogicalShiftRight(REG_SZ, left, right, flags);
					break;
				case ARC_ROR:
					expr = il.RotateRight(REG_SZ, left, right, flags);
					break;
				default:
					return false;
			}

			return ExecuteCC(arch, addr, il, instruction,
				WriteILOperand(
					il,
					dst,
					0,
					addr,
					REG_SZ,
					expr
				), delaySlot);
		}
		break;
		case ARC_B: {
			const InstructionOperand& target = instruction.operands[0];

			ExprId jump;
			if (target.operand_class == LABEL) {
				jump = DirectJump(arch, il, target.address);
			} else {
				jump = il.Jump(ReadPCLDisplacement(il, target, 0, addr));
			}

			return ExecuteCC(arch, addr, il, instruction, jump, delaySlot);
		}
		break;
		case ARC_BBIT0:
		case ARC_BBIT1: {
			ExprId left = ReadILOperand(il, instruction.operands[0], 0, addr, REG_SZ);
			ExprId right = ReadILOperand(il, instruction.operands[1], 1, addr, REG_SZ);
			const InstructionOperand& target = instruction.operands[2];

			ExprId condition = il.TestBit(REG_SZ,
				left,
				il.And(REG_SZ, right, il.Const(REG_SZ, 31)));

			if (instruction.operation == ARC_BBIT0) {
				condition = il.Not(REG_SZ, condition);
			}

			ExprId jump;
			if (target.operand_class == LABEL) {
				jump = DirectJump(arch, il, target.address);
			} else {
				jump = il.Jump(ReadPCLDisplacement(il, target, 0, addr));
			}

			return ExecuteConditionally(arch, addr, il, instruction, condition, jump, delaySlot);
		}
		break;
		case ARC_BL: {
			const InstructionOperand& target = instruction.operands[0];

			return ExecuteCC(
				arch,
				addr,
				il,
				instruction,
				il.Call(ReadPCLDisplacement(il, target, 0, addr)),
				delaySlot
			);
		}
		break;
		case ARC_BR: {
			if (instruction.condition == AL || instruction.condition == NONE) {
				if (instruction.operands[0].operand_class == LABEL) {
					il.AddInstruction(DirectJump(arch, il, instruction.operands[0].address));
				} else {
					il.AddInstruction(il.Jump(ReadPCLDisplacement(il, instruction.operands[0], 0, addr)));
				}
				return true;
			}

			ExprId left = ReadILOperand(il, instruction.operands[0], 0, addr, REG_SZ);
			ExprId right = ReadILOperand(il, instruction.operands[1], 1, addr, REG_SZ);
			ExprId target = ReadPCLDisplacement(il, instruction.operands[2], 2, addr);

			ExprId condition;
			switch ((ConditionCode)instruction.condition) {
				case EQ:
					condition = il.CompareEqual(REG_SZ, left, right);
					break;
				case NE:
					condition = il.CompareNotEqual(REG_SZ, left, right);
					break;
				case LT:
					condition = il.CompareSignedLessThan(REG_SZ, left, right);
					break;
				case GE:
					condition = il.CompareSignedGreaterEqual(REG_SZ, left, right);
					break;
				case LO:
					condition = il.CompareUnsignedLessThan(REG_SZ, left, right);
					break;
				case HS:
					condition = il.CompareUnsignedGreaterEqual(REG_SZ, left, right);
					break;
				default:
					return false;
			}

			ExprId jump;
			if (instruction.operands[2].operand_class == LABEL) {
				jump = DirectJump(arch, il, instruction.operands[2].address);
			} else {
				jump = il.Jump(target);
			}

			return ExecuteConditionally(arch, addr, il, instruction, condition, jump, delaySlot);
		}
		break;
		case ARC_J: {
			const InstructionOperand& target = instruction.operands[0];

			ExprId jump;
			if (target.operand_class == LABEL) {
				jump = DirectJump(arch, il, target.address);
			} else {
				jump = il.Jump(ReadILOperand(il, target, 0, addr, ADDR_SZ, true));
			}

			return ExecuteCC(arch, addr, il, instruction, jump, delaySlot);
		}
		break;
		case ARC_JL: {
			const InstructionOperand& target = instruction.operands[0];

			return ExecuteCC(
				arch,
				addr,
				il,
				instruction,
				il.Call(ReadILOperand(il, target, 0, addr, ADDR_SZ, true)),
				delaySlot
			);
		}
		break;
		case ARC_LD: {
			const InstructionOperand& dst = instruction.operands[0];
			const InstructionOperand& src = instruction.operands[1];

			ExprId address, writeback = BN_INVALID_EXPR;
			switch (instruction.address_writeback) {
				case NO_WRITEBACK:
					address = GetILOperandMemoryAddress(il, src, addr);
					break;
				case AW:
					writeback = GetILOperandMemoryAddress(il, src, addr);
					address = writeback;
					break;
				case AB:
					writeback = GetILOperandMemoryAddress(il, src, addr);
					address = il.Register(REG_SZ, src.reg);
					break;
				case AS:
					uint8_t shift;
					if (instruction.data_size == WORD) {
						shift = 1;
					} else if (instruction.data_size == LONG_WORD) {
						shift = 2;
					} else {
						return false;
					}

					ExprId reg;
					if (src.reg == REG_PCL) {
						reg = il.Const(REG_SZ, (address >> 2) << 2);
					} else {
						reg = il.Register(REG_SZ, src.reg);
					}

					if (src.operand_class == REG_IMM_REL) {
						address = il.Add(ADDR_SZ,
									il.ShiftLeft(ADDR_SZ, reg, il.Const(1, shift)),
									il.Const(ADDR_SZ, src.immediate));
					} else if (src.operand_class == IMM_REG_REL) {
						address = il.Add(ADDR_SZ,
									il.Const(ADDR_SZ, src.immediate),
									il.ShiftLeft(ADDR_SZ, reg, il.Const(1, shift)));
					} else if (src.operand_class == REG_REG_REL) {
						address = il.Add(ADDR_SZ,
									reg,
									il.ShiftLeft(
										REG_SZ,
										il.Register(REG_SZ, src.displacement_reg),
										il.Const(1, shift)));
					} else {
						return false;
					}
			}

			uint8_t load_size = 4;
			if (instruction.data_size == WORD) {
				load_size = 2;
			} else if (instruction.data_size == BYTE) {
				load_size = 1;
			}


			ExprId data = il.Operand(1, il.Load(load_size, address));
			/*
			if (instruction.sign_extend) {
				data = il.SignExtend(REG_SZ, data);
			}
			*/

			il.AddInstruction(WriteILOperand(il, dst, 0, addr,  REG_SZ, data));

			if (writeback != BN_INVALID_EXPR) {
				il.AddInstruction(il.SetRegister(REG_SZ, src.reg, writeback));
			}

			return true;
		}
		break;
		case ARC_PUSH: {
			const InstructionOperand& src = instruction.operands[0];
			if (src.operand_class != REG) {
				return false;
			}

			il.AddInstruction(il.Push(REG_SZ, ReadILOperand(il, src, 0, addr, REG_SZ)));
		}
		break;
		case ARC_POP: {
			const InstructionOperand& dst = instruction.operands[0];
			if (dst.operand_class != REG) {
				return false;
			}

			il.AddInstruction(WriteILOperand(il, dst, 0, addr, REG_SZ, il.Pop(REG_SZ)));
		}
		break;
		case ARC_ST: {
			const InstructionOperand& src = instruction.operands[0];
			const InstructionOperand& dst = instruction.operands[1];

			ExprId address, writeback = BN_INVALID_EXPR;
			switch (instruction.address_writeback) {
				case NO_WRITEBACK:
					address = GetILOperandMemoryAddress(il, dst, addr);
					break;
				case AW:
					writeback = GetILOperandMemoryAddress(il, dst, addr);
					address = writeback;
					break;
				case AB:
					writeback = GetILOperandMemoryAddress(il, dst, addr);
					address = il.Register(REG_SZ, dst.reg);
					break;
				case AS:
					uint8_t shift;
					if (instruction.data_size == WORD) {
						shift = 1;
					} else if (instruction.data_size == LONG_WORD) {
						shift = 2;
					} else {
						return false;
					}

					address = il.ShiftLeft(ADDR_SZ, il.Register(REG_SZ, dst.reg), il.Const(1, shift));
			}

			uint8_t store_size = 4;
			if (instruction.data_size == WORD) {
				store_size = 2;
			} else if (instruction.data_size == BYTE) {
				store_size = 1;
			}


			ExprId value = ReadILOperand(il, src, 0, addr);
			if (instruction.sign_extend) {
				value = il.SignExtend(store_size, value);
			}

			il.AddInstruction(il.Store(store_size, il.Operand(1, address), value));

			if (writeback != BN_INVALID_EXPR) {
				il.AddInstruction(il.SetRegister(REG_SZ, dst.reg, writeback));
			}
		}
		break;
		case ARC_EX: {
			const InstructionOperand& dst = instruction.operands[0];
			const InstructionOperand& src = instruction.operands[1];

			ExprId temp = LLIL_TEMP(0);
			il.AddInstruction(il.SetRegister(REG_SZ, temp, ReadILOperand(il, dst, 0, addr)));
			il.AddInstruction(WriteILOperand(il, dst, 0, addr, REG_SZ, ReadILOperand(il, src, 1, addr, REG_SZ, true)));
			il.AddInstruction(WriteILOperand(il,src, 0, addr, REG_SZ, temp));
		}
		break;
		case ARC_BRK: {
			il.AddInstruction(il.Breakpoint());
		}
		break;
		case ARC_SWI: {
			il.AddInstruction(il.Trap(0));
		}
		break;
		case ARC_TRAP: {
			const InstructionOperand& src = instruction.operands[0];
			if (src.operand_class != IMM) {
				return false;
			}

			il.AddInstruction(il.Trap(src.immediate));
		}
		break;
		case ARC_NOP: {
			il.AddInstruction(il.Nop());
		}
		break;
		case ARC_SAT16: {
			const InstructionOperand& dst = instruction.operands[0];
			ExprId src = ReadILOperand(il, instruction.operands[1], 1, addr);

			return false; // TODO
			// WriteILOperand(il, dst, 0, REG_SZ, , IL_FLAGWRITE_ZN)
		}
		break;
	}

	return true;
}