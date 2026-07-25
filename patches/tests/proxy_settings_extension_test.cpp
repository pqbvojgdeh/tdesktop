#include "core/proxy_settings_extension_policy.h"
#include "test_check.h"

#include <iostream>

int main() {
	using namespace Core::details;

	static_assert(kProxySettingsExtensionMagic == 0x54505831);
	static_assert(kProxySettingsLegacyExtensionVersion == 1);
	static_assert(kProxySettingsExtensionVersion == 2);
	static_assert(kProxySettingsExtensionFieldCount == 5);
	static_assert(kProxySettingsRandomClientHelloType == -1);
	static_assert(kProxySettingsMaximumClientHelloType == 5);

	const auto valid = ProxySettingsExtensionFields{
		.clientHelloType = kProxySettingsMaximumClientHelloType,
		.slowMode = 1,
		.slowDelay = 250,
		.slowJitter = 150,
		.preferIPv6 = 0,
	};
	TEST_CHECK(IsProxySettingsExtensionValid(valid));

	auto invalid = valid;
	invalid.slowMode = 2;
	TEST_CHECK(!IsProxySettingsExtensionValid(invalid));
	invalid = valid;
	invalid.preferIPv6 = -1;
	TEST_CHECK(!IsProxySettingsExtensionValid(invalid));
	invalid = valid;
	invalid.clientHelloType = kProxySettingsMaximumClientHelloType + 1;
	TEST_CHECK(!IsProxySettingsExtensionValid(invalid));
	invalid = valid;
	invalid.clientHelloType = kProxySettingsRandomClientHelloType - 1;
	TEST_CHECK(!IsProxySettingsExtensionValid(invalid));
	invalid = valid;
	invalid.slowDelay = -1;
	TEST_CHECK(!IsProxySettingsExtensionValid(invalid));

	std::cout << "Production proxy-settings extension policy tests passed.\n";
}
