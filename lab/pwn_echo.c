/* Local stdin exercise; compile with -DFIXED for the repaired version.
 * Deliberately unsafe build is only for your own isolated practice environment. */
#include <stdio.h>
#include <string.h>

int main(void) {
    char name[32];
    puts("Name?");
#ifdef FIXED
    if (fgets(name, sizeof(name), stdin) == NULL) return 1;
    if (strchr(name, '\n') == NULL && !feof(stdin)) {
        fputs("Input too long\n", stderr);
        return 2;
    }
    name[strcspn(name, "\n")] = '\0';
#else
    /* Exercise: locate the input bound mismatch and repair it. */
    if (scanf("%s", name) != 1) return 1;
#endif
    printf("Hello, %s\n", name);
    return 0;
}
