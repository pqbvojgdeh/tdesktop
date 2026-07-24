#include "core/proxy_rotation_policy.h"
#include "test_check.h"

#include <iostream>

int main() {
	using namespace Core::details;

	auto stable = ProxyRotationHealth();
	stable = ProxyRotationRecordSuccess(stable, 110);
	stable = ProxyRotationRecordSuccess(stable, 112);
	stable = ProxyRotationRecordSuccess(stable, 108);

	auto flaky = ProxyRotationHealth();
	flaky = ProxyRotationRecordSuccess(flaky, 80);
	flaky = ProxyRotationRecordFailure(flaky);
	flaky = ProxyRotationRecordFailure(flaky);
	flaky = ProxyRotationRecordSuccess(flaky, 80);

	const auto stableScore = ProxyRotationSelectionScore(stable, 110, 0);
	const auto flakyScore = ProxyRotationSelectionScore(flaky, 80, 0);
	TEST_CHECK(stableScore < flakyScore);
	TEST_CHECK(ProxyRotationSelectionScore(stable, 110, 30) > stableScore);

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
