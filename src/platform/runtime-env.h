#pragma once
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

/* Project boolean switches: unset/0 disable; only 1 enables. Paths and numbers use getenv directly. */
static inline bool fli_env_enabled(const char *name) {
  const char *value = getenv(name);
  return value && strcmp(value, "1") == 0;
}
