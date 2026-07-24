#include "core/proxy_rotation_policy.h"
#include "test_check.h"

#include <iostream>

int main() {
	using namespace Core::details;

	auto stable = ProxyRotationHealth();
	stable = ProxyRotationRecordSuccess(stable, 110);
	stable = ProxyRotationRecordSuccess(stable, 112);
	stable = ProxyRotationRecordSuccess(stable, 108);
	TEST_CHECK(stable.smoothedPingX8 > 0);
	TEST_CHECK(stable.deviationX8 > 0);

	auto flaky = ProxyRotationHealth();
	flaky = ProxyRotationRecordSuccess(flaky, 80);
	flaky = ProxyRotationRecordFailure(flaky);
	flaky = ProxyRotationRecordFailure(flaky);
	flaky = ProxyRotationRecordSuccess(flaky, 80);

	const auto stableScore = ProxyRotationSelectionScore(stable, 0);
	const auto flakyScore = ProxyRotationSelectionScore(flaky, 0);
	TEST_CHECK(stableScore < flakyScore);
	TEST_CHECK(ProxyRotationSelectionScore(stable, 30) > stableScore);
	TEST_CHECK(
		ProxyRotationSelectionScore(stable, 21)
		> ProxyRotationSelectionScore(stable, 20));

	auto lowJitter = ProxyRotationHealth();
	lowJitter = ProxyRotationRecordSuccess(lowJitter, 100);
	lowJitter = ProxyRotationRecordSuccess(lowJitter, 101);
	TEST_CHECK(lowJitter.smoothedPingX8 == 802);
	TEST_CHECK(lowJitter.deviationX8 == 2);

	auto highJitter = ProxyRotationHealth();
	highJitter = ProxyRotationRecordSuccess(highJitter, 80);
	highJitter = ProxyRotationRecordSuccess(highJitter, 200);
	TEST_CHECK(
		ProxyRotationSelectionScore(stable, 0)
		< ProxyRotationSelectionScore(highJitter, 0));

	TEST_CHECK(ProxyRotationResultIsFresh(0));
	TEST_CHECK(ProxyRotationResultIsFresh(
		kProxyRotationMaximumResultAgeSeconds));
	TEST_CHECK(!ProxyRotationResultIsFresh(-1));
	TEST_CHECK(!ProxyRotationResultIsFresh(
		kProxyRotationMaximumResultAgeSeconds + 1));

	TEST_CHECK(ProxyRotationShouldKeepWaiting(true, 0));
	TEST_CHECK(ProxyRotationShouldKeepWaiting(
		true,
		kProxyRotationSelectionMaximumWaitMs - 1));
	TEST_CHECK(!ProxyRotationShouldKeepWaiting(
		true,
		kProxyRotationSelectionMaximumWaitMs));
	TEST_CHECK(!ProxyRotationShouldKeepWaiting(false, 0));

	std::cout << "Production proxy-rotation selection policy tests passed.\n";
}
