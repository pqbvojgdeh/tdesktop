#include "core/proxy_settings_extension_policy.h"

#include <cassert>
#include <iostream>

int main() {
	using namespace Core::details;

	static_assert(kProxySettingsExtensionMagic == 0x54505831);
	static_assert(kProxySettingsLegacyExtensionVersion == 1);
	static_assert(kProxySettingsExtensionVersion == 2);
	static_assert(kProxySettingsExtensionFieldCount == 5);

	const auto valid = ProxySettingsExtensionFields{
		.clientHelloType = 5,
		.slowMode = 1,
		.slowDelay = 250,
		.slowJitter = 150,
		.preferIPv6 = 0,
	};
	assert(IsProxySettingsExtensionValid(valid));

	auto invalid = valid;
	invalid.slowMode = 2;
	assert(!IsProxySettingsExtensionValid(invalid));
	invalid = valid;
	invalid.preferIPv6 = -1;
	assert(!IsProxySettingsExtensionValid(invalid));
	invalid = valid;
	invalid.clientHelloType = 6;
	assert(!IsProxySettingsExtensionValid(invalid));
	invalid = valid;
	invalid.slowDelay = -1;
	assert(!IsProxySettingsExtensionValid(invalid));

	std::cout << "Production proxy-settings extension policy tests passed.\n";
}
