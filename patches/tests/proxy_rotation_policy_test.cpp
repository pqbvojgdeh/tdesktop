#include "core/proxy_rotation_policy.h"

#include <cassert>
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
	assert(stableScore < flakyScore);
	assert(ProxyRotationSelectionScore(stable, 110, 30) > stableScore);

	assert(ProxyRotationShouldKeepWaiting(true, 0));
	assert(ProxyRotationShouldKeepWaiting(
		true,
		kProxyRotationSelectionMaximumWaitMs - 1));
	assert(!ProxyRotationShouldKeepWaiting(
		true,
		kProxyRotationSelectionMaximumWaitMs));
	assert(!ProxyRotationShouldKeepWaiting(false, 0));

	std::cout << "Production proxy-rotation selection policy tests passed.\n";
}
