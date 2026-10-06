#pragma once

#include "nalt.hpp"
#include "pro.h"

#include "cxx.h"

rust::String idalib_get_input_file_path() {
  char path[QMAXPATH] = {0};
  auto size = get_input_file_path(path, sizeof(path));

  if (size > 0) {
    // The stored blob may include the terminating NUL (seen on IDA 9.5), so
    // use the C string length rather than the returned size.
    return rust::String(path, ::qstrlen(path));
  } else {
    return rust::String();
  }
}
