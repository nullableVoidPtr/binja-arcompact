#include "arcompact.h"

int main(int argc, char **argv) {
	uint8_t code[] = {
		0x40, 0x25, 0x05, 0x01
	};

	ArCompact::Instruction output1 = { 0 };
	ArCompact::Instruction output2 = { 0 };

	int rc1 = ArCompact::arcompact_decompose(
		(uint16_t*)code,
		4,
		&output1,
		ArCompact::ARC_600,
		0x0,
		0
	);

	int rc2 = 0;
	return rc1 + rc2;
}