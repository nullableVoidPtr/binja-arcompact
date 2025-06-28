#include "arcompact.h"

int main(int argc, char **argv) {
	uint8_t code[] = {
		0x00, 0x16, 0x00, 0x70, 0x80, 0x00, 0xfc, 0x3f
	};

	ArCompact::Instruction output1 = { 0 };
	ArCompact::Instruction output2 = { 0 };

	int rc1 = ArCompact::arcompact_decompose(
		(uint16_t*)code,
		8,
		&output1,
		ArCompact::ARC_600,
		0x0,
		0
	);

	int rc2 = 0;
	return rc1 + rc2;
}