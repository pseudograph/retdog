#include <cstring>
#include <cstdio>

void vuln2(char* buf, char* input) {
    strcpy(buf, input);
}

void vuln(char* input) {
    char buf[52];
    vuln2(buf, input);
}

int main(int argc, char** argv) {
    if (argc > 1) {
        vuln(argv[1]);
    } else {
        char input[256];
        fgets(input, sizeof(input), stdin); // Read from stdin
        input[strcspn(input, "\n")] = 0; // Remove newline character
        vuln(input);
    }
    printf("overflow avoided\n");
    return 0;
}
