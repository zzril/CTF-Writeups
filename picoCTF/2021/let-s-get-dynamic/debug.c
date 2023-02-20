#include <stddef.h>
#include <unistd.h>

// --------

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
size_t strlen(const char *s) {
	return 0x31;
}
#pragma GCC diagnostic pop

int memcmp(const void *s1, const void *s2, size_t n) {
	write(1, s1, n);
	write(1, s2, n);
	return 0;
}


