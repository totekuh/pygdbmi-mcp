#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif

struct point {
    int x;
    int y;
    char label[16];
};

int add(int a, int b) {
    return a + b;
}

int factorial(int n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}

void fill_point(struct point *p, int x, int y, const char *label) {
    p->x = x;
    p->y = y;
    strncpy(p->label, label, sizeof(p->label) - 1);
    p->label[sizeof(p->label) - 1] = '\0';
}

int main(int argc, char **argv) {
#ifdef __linux__
    prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0);
#endif
    if (argc > 1 && strcmp(argv[1], "loop") == 0) {
        while (1) sleep(1);
    }
    if (argc > 1 && strcmp(argv[1], "crash") == 0) {
        *(volatile int *)0 = 1;
    }
    if (argc > 1 && strcmp(argv[1], "burst") == 0) {
        for (int i = 0; i < 20000; i++) putchar('Z');
        putchar('\n');
    }
    if (argc > 1 && strcmp(argv[1], "input") == 0) {
        char input[128];
        if (fgets(input, sizeof(input), stdin)) printf("ECHO:%s", input);
    }
    int result = add(3, 4);
    printf("add(3, 4) = %d\n", result);

    int fact = factorial(5);
    printf("factorial(5) = %d\n", fact);

    struct point p;
    fill_point(&p, 10, 20, "origin");
    printf("point: (%d, %d) label=%s\n", p.x, p.y, p.label);

    return 0;
}
