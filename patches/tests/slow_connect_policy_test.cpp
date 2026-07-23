#include "mtproto/details/mtproto_slow_connect_policy.h"

#include <cassert>
#include <iostream>

using namespace MTP::details;

int main() {
	static_assert(kSlowConnectMaximumAdditionalDelayMs == 7500);
	static_assert(kSlowConnectMaximumPending == 16);
	static_assert(kSlowConnectMaximumSlots == 128);
	static_assert(kSlowConnectOverflowMinimumDelayMs == 100);
	static_assert(kSlowConnectOverflowMaximumDelayMs == 300);

	const auto normal = NormalizeSlowConnectPolicy(250, 150);
	assert(normal.delay == 250 && normal.jitter == 150);
	const auto capped = NormalizeSlowConnectPolicy(7000, 2000);
	assert(capped.delay == 7000 && capped.jitter == 500);
	const auto negative = NormalizeSlowConnectPolicy(-1, -2);
	assert(negative.delay == 0 && negative.jitter == 0);
	assert(SlowConnectMaximumAdditionalDelay(7000, 2000).count() == 7500);
	assert(NormalizeSlowConnectOverflowDelay(1) == 100);
	assert(NormalizeSlowConnectOverflowDelay(200) == 200);
	assert(NormalizeSlowConnectOverflowDelay(999) == 300);

	std::cout << "Production slow-connect policy tests passed.\n";
}
