#include "mtproto/details/mtproto_resolved_ip_policy.h"
#include "test_check.h"

#include <iostream>

int main() {
	using namespace MTP::details;
	using Origin = ResolvedIpFailureOrigin;

	TEST_CHECK(ShouldQuarantineResolvedIp(Origin::ConnectTimeout));
	TEST_CHECK(ShouldQuarantineResolvedIp(Origin::ExternalTimeout));
	TEST_CHECK(ShouldQuarantineResolvedIp(Origin::EarlyDisconnect));
	TEST_CHECK(ShouldQuarantineResolvedIp(
		Origin::ChildError,
		kSocketConnectionRefusedError));
	TEST_CHECK(ShouldQuarantineResolvedIp(
		Origin::ChildError,
		kSocketRemoteHostClosedError));
	TEST_CHECK(ShouldQuarantineResolvedIp(
		Origin::ChildError,
		kSocketTimeoutError));
	TEST_CHECK(ShouldQuarantineResolvedIp(
		Origin::ChildError,
		kSocketProxyConnectionRefusedError));
	TEST_CHECK(ShouldQuarantineResolvedIp(
		Origin::ChildError,
		kSocketProxyConnectionClosedError));
	TEST_CHECK(ShouldQuarantineResolvedIp(
		Origin::ChildError,
		kSocketProxyConnectionTimeoutError));

	// Generic application/configuration failures must not poison a resolved IP.
	TEST_CHECK(!ShouldQuarantineResolvedIp(Origin::ChildError));
	TEST_CHECK(!ShouldQuarantineResolvedIp(Origin::ChildError, -499));
	TEST_CHECK(!ShouldQuarantineResolvedIp(Origin::ChildError, 2));
	TEST_CHECK(!ShouldQuarantineResolvedIp(Origin::ChildError, 3));
	TEST_CHECK(!ShouldQuarantineResolvedIp(Origin::ChildError, 7));
	TEST_CHECK(!ShouldQuarantineResolvedIp(Origin::ChildError, 13));

	std::cout << "Production resolved-IP failure policy tests passed.\n";
}
