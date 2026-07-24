#pragma once

#include <cstdlib>
#include <iostream>

namespace PatchTests {

[[noreturn]] inline void Fail(
		const char *expression,
		const char *file,
		int line) {
	std::cerr
		<< file
		<< ':'
		<< line
		<< ": TEST_CHECK("
		<< expression
		<< ") failed.\n";
	std::exit(EXIT_FAILURE);
}

} // namespace PatchTests

#define TEST_CHECK(expression) \
	((expression) \
		? static_cast<void>(0) \
		: ::PatchTests::Fail(#expression, __FILE__, __LINE__))
