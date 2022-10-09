#include "{file_path}"
/* Header file this harness is fuzzing against */
#include "musl/install/include/unistd.h"
__AFL_FUZZ_INIT();

/* Persistent-mode fuzzing ready harness, can't use this to debug the program */
int main() {

#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

    while (__AFL_LOOP(10000)) {
        char buf[1000];
        read(0,buf,1000);
{body}
	}
    return 0;
}
