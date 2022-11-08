#include "{file_path}"
/* Header file this harness is fuzzing against */
#include "musl/install/include/unistd.h"
#include "musl/install/include/stdio.h"

/* Function to run the  chosen MUSL libc function*/
int main() {

        char buf[1000];

        read(0,buf,1000);
{body}
	
    return 0;
}
