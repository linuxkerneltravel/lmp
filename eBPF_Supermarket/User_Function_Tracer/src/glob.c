#include "glob.h"

bool glob_match(const char *text, const char *pattern) {
  bool matched, complemented;

  while (*text != '\0' && *pattern != '\0') {
    switch (*pattern) {
      case '?':
        ++pattern;
        ++text;
        break;

      case '*':
        if (glob_match(text, pattern + 1)) return true;
        ++text;
        break;

      case '[':
        matched = complemented = false;

        ++pattern;

        if (*pattern == '!') {
          complemented = true;
          ++pattern;
        }

        if (*pattern == '\0') return false;

        char ch = *pattern;  // ch may be ']' or '-', just treat it normally
        matched |= (ch == *text);
        ++pattern;

        while (*pattern != ']') {
          switch (*pattern) {
            case '\0':
              return false;
            case '-':
              ++pattern;
              switch (*pattern) {
                case '\0':
                  return false;
                case ']':
                  matched |= ('-' == *text);
                  break;
                default:
                  matched |= (ch <= *text && *text <= *pattern);
                  ch = *pattern;
                  ++pattern;
              }
              break;
            default:
              ch = *pattern;
              matched |= (ch == *text);
              ++pattern;
          }
        }

        if (complemented) matched = !matched;
        if (!matched) return false;

        ++pattern;
        ++text;
        break;

      case '\\':
        ++pattern;
        if (*pattern == '\0') return false;

      default:
        if (*pattern == *text) {
          ++pattern;
          ++text;
        } else {
          return false;
        }
    }
  }

  if (*text == '\0') {
    while (*pattern == '*') ++pattern;
    if (*pattern == '\0') return true;
  }

  return false;
}
