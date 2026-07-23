#include "mtproto/details/mtproto_resolved_ip_policy.h"

#include <cassert>
#include <iostream>

int main() {
	using namespace MTP::details;
	using Origin = ResolvedIpFailureOrigin;

	assert(ShouldQuarantineResolvedIp(Origin::ConnectTimeout));
	assert(ShouldQuarantineResolvedIp(Origin::ExternalTimeout));
	assert(ShouldQuarantineResolvedIp(Origin::EarlyDisconnect));
	assert(ShouldQuarantineResolvedIp(
		Origin::ChildError,
		kSocketConnectionRefusedError));
	assert(ShouldQuarantineResolvedIp(
		Origin::ChildError,
		kSocketRemoteHostClosedError));
	assert(ShouldQuarantineResolvedIp(
		Origin::ChildError,
		kSocketProxyConnectionTimeoutError));

	// Generic application/configuration failures must not poison a resolved IP.
	assert(!ShouldQuarantineResolvedIp(Origin::ChildError, -499));
	assert(!ShouldQuarantineResolvedIp(Origin::ChildError, 2));
	assert(!ShouldQuarantineResolvedIp(Origin::ChildError, 3));
	assert(!ShouldQuarantineResolvedIp(Origin::ChildError, 7));
	assert(!ShouldQuarantineResolvedIp(Origin::ChildError, 13));

	std::cout << "Production resolved-IP failure policy tests passed.\n";
}
