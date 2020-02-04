#include <assert.h>

int foo(int x, int y) {

    int a = x + 1;

    assert(y == x); // add constraint

    if (a == 0) return 0;
    else return 1;
}

int main() {
    foo(9, 9);
    return 0;
}