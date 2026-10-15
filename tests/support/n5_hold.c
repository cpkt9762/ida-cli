/* Deterministic artificial native section invoked through ctypes.PyDLL. */
#include <fcntl.h>
#include <unistd.h>
void n5_hold(const char *marker, const char *gate) {
    int fd = open(gate, O_RDWR);
    if (fd < 0) return;
    int out = open(marker, O_CREAT | O_WRONLY, 0600);
    if (out < 0) { close(fd); return; }
    close(out);
    char byte;
    (void)read(fd, &byte, 1);
    close(fd);
}

/* Independent real-function fixture for multi-slice search fairness. */
#define N5_FN(n) __attribute__((noinline)) int n5_function_##n(int x) { return x + n; }
N5_FN(0) N5_FN(1) N5_FN(2) N5_FN(3) N5_FN(4) N5_FN(5) N5_FN(6) N5_FN(7) N5_FN(8) N5_FN(9)
N5_FN(10) N5_FN(11) N5_FN(12) N5_FN(13) N5_FN(14) N5_FN(15) N5_FN(16) N5_FN(17) N5_FN(18) N5_FN(19)
N5_FN(20) N5_FN(21) N5_FN(22) N5_FN(23) N5_FN(24) N5_FN(25) N5_FN(26) N5_FN(27) N5_FN(28) N5_FN(29)
N5_FN(30) N5_FN(31) N5_FN(32) N5_FN(33) N5_FN(34) N5_FN(35) N5_FN(36) N5_FN(37) N5_FN(38) N5_FN(39)
N5_FN(40) N5_FN(41) N5_FN(42) N5_FN(43) N5_FN(44) N5_FN(45) N5_FN(46) N5_FN(47) N5_FN(48) N5_FN(49)
N5_FN(50) N5_FN(51) N5_FN(52) N5_FN(53) N5_FN(54) N5_FN(55) N5_FN(56) N5_FN(57) N5_FN(58) N5_FN(59)
N5_FN(60) N5_FN(61) N5_FN(62) N5_FN(63) N5_FN(64) N5_FN(65) N5_FN(66) N5_FN(67) N5_FN(68) N5_FN(69)
N5_FN(70) N5_FN(71) N5_FN(72) N5_FN(73) N5_FN(74) N5_FN(75) N5_FN(76) N5_FN(77) N5_FN(78) N5_FN(79)
