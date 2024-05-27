#pragma once

#include "binaryninjaapi.h"
#include "lowlevelilinstruction.h"
#include "arcompact.h"

enum FlagWrite {
	IL_FLAGWRITE_NONE,
	IL_FLAGWRITE_ZN,
	IL_FLAGWRITE_ZNC,
	IL_FLAGWRITE_ZNV,
	IL_FLAGWRITE_ZNCV,
	// IL_FLAGWRITE_ZNCVS,
};

bool GetLowLevelILForInstruction(
		BinaryNinja::Architecture* arch,
		uint32_t addr,
		BinaryNinja::LowLevelILFunction& il,
		const ArCompact::Instruction& instruction,
		const ArCompact::Instruction* delaySlot);

BinaryNinja::ExprId GetConditionForInstruction(
	BinaryNinja::LowLevelILFunction& il,
	ArCompact::Instruction& instr,
	size_t registerSize);