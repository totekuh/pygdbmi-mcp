#include <stdio.h>
#include <string.h>

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
    int result = add(3, 4);
    printf("add(3, 4) = %d\n", result);

    int fact = factorial(5);
    printf("factorial(5) = %d\n", fact);

    struct point p;
    fill_point(&p, 10, 20, "origin");
    printf("point: (%d, %d) label=%s\n", p.x, p.y, p.label);

    return 0;
}
