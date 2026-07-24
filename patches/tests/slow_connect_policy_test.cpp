#include "mtproto/details/mtproto_slow_connect_policy.h"
#include "test_check.h"

#include <iostream>

using namespace MTP::details;

int main() {
	static_assert(kSlowConnectMaximumAdditionalDelayMs == 7500);
	static_assert(kSlowConnectSchedulingMarginMs == 500);
	static_assert(kSlowConnectMaximumTimeoutBudgetMs == 8000);
	static_assert(kSlowConnectMaximumPending == 16);
	static_assert(kSlowConnectMaximumSlots == 128);
	static_assert(kSlowConnectOverflowMinimumDelayMs == 100);
	static_assert(kSlowConnectOverflowMaximumDelayMs == 300);

	const auto normal = NormalizeSlowConnectPolicy(250, 150);
	TEST_CHECK(normal.delay == 250 && normal.jitter == 150);
	const auto capped = NormalizeSlowConnectPolicy(7000, 2000);
	TEST_CHECK(capped.delay == 7000 && capped.jitter == 500);
	const auto negative = NormalizeSlowConnectPolicy(-1, -2);
	TEST_CHECK(negative.delay == 0 && negative.jitter == 0);
	TEST_CHECK(SlowConnectMaximumAdditionalDelay(7000, 2000).count() == 7500);
	TEST_CHECK(NormalizeSlowConnectOverflowDelay(1) == 100);
	TEST_CHECK(NormalizeSlowConnectOverflowDelay(200) == 200);
	TEST_CHECK(NormalizeSlowConnectOverflowDelay(999) == 300);

	std::cout << "Production slow-connect policy tests passed.\n";
}
