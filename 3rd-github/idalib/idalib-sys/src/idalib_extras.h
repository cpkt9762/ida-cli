#pragma once

#include "idalib.hpp"
#include "kernwin.hpp"

bool idalib_get_library_version(int *major, int *minor, int *build) {
  if (!get_library_version(*major, *minor, *build)) {
    return false;
  }

  // IDA 9.3's libidalib reports 9.0.260213 here; the kernel version string
  // ("9.3") carries the real major.minor, so prefer it when available.
  char kernel[32] = {0};
  int kernel_major = 0;
  int kernel_minor = 0;
  if (get_kernel_version(kernel, sizeof(kernel)) > 0 &&
      qsscanf(kernel, "%d.%d", &kernel_major, &kernel_minor) == 2) {
    *major = kernel_major;
    *minor = kernel_minor;
  }
  return true;
}
