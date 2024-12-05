#include <string> 
#include <memory>
#include <cstring>
#include <iostream> 
#include <time.h>

inline std::unique_ptr<char[]> copy_and_verify_range_helper(std::size_t count, const char* source_str) 
{
  auto target = std::make_unique<char[]>(count);
  // dont copy, just return.

  return target;
}

static auto __attribute__((noinline)) copy_and_verify_string(const char* source_str)
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
  std::string long_str(4097, 'a');
  struct timespec start, end;
  //warmup
  clock_gettime(CLOCK_MONOTONIC, &start);
  for (int i = 0; i < 10000; i++)
  {
    auto copied_string = copy_and_verify_string(long_str.c_str());
  }
  clock_gettime(CLOCK_MONOTONIC, &end);

  clock_gettime(CLOCK_MONOTONIC, &start);
  for (int i = 0; i < 100000; i++)
  {
    auto copied_string = copy_and_verify_string(long_str.c_str());
  }
  clock_gettime(CLOCK_MONOTONIC, &end);

  double elapsed_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

  std::cout << "Elapsed time: " << elapsed_time << " seconds\n";

  return 0;
}