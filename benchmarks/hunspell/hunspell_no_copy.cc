#include <string> 
#include <memory>
#include <cstring>
#include <iostream> 

inline std::unique_ptr<char[]> copy_and_verify_range_helper(std::size_t count, char* source_str) 
{
  auto target = std::make_unique<char[]>(count);
  // dont copy, just return.

  return target;
}

static auto __attribute__((noinline)) copy_and_verify_string(char* source_str)
{
  if (!source_str)
  {
    return std::unique_ptr<char[]>(nullptr);
  }

  auto str_len = std::strlen(source_str) + 1;
  std::unique_ptr<char[]> target = copy_and_verify_range_helper(strlen(source_str), source_str);

  if (target == nullptr)
  {
    return std::unique_ptr<char[]>(nullptr);
  }

  target[str_len - 1] = '\0';

  return target;
}

int main()
{
  char* source_str = "hello, world";

  auto copied_string = copy_and_verify_string(source_str);

  return 0;
}