#include <string>
#include <memory>
#include <cstring>
#include <iostream>

#include "../../../PTEditor/ptedit_header.h"
#define KERNEL_LAND (void *)0xffffffff80000000

#define PAGE_ALIGN(ptr, page_size) (void *)(((uintptr_t)ptr) & ~(page_size - 1))


inline std::unique_ptr<char[]> copy_and_verify_range_helper(std::size_t count, const char* source_str) 
{
  auto target = std::unique_ptr<char[]>(count);
  // instead of copying it over just do bounds verification
  auto str_len = std::strlen(source_str);
  if (source_str >= KERNEL_LAND || source_str + str_len >= KERNEL_LAND) 
  {
    return nullptr;
  }

  return target;
}

static auto __attribute__((noinline)) copy_and_verify_string(const char* source_str)
{
  if (!source_str)
  {
    return std::unique_ptr<char[]>(nullptr);
  }

  auto str_len = std::strlen(source_str) + 1;

  uintptr_t first_page = (uintptr_t) PAGE_ALIGN(source_str, 4096);
  uintptr_t last_page = (uintptr_t) PAGE_ALIGN(source_str + str_len, 4096);
  int idx = 0;

  for (uintptr_t addr = first_page; addr <= last_page; addr += 4096)
  {
    ptedit_pte_clear_bit((void*) addr, 0, PTEDIT_PAGE_BIT_RW);
    ptedit_invalidate_tlb((void*) addr);
  }

  std::unique_ptr<char[]> target = copy_and_verify_range_helper(strlen(source_str), source_str);

  if (target == nullptr)
  {
    return std::unique_ptr<char[]>(nullptr);
  }

  for (uintptr_t addr = first_page; addr <= last_page; addr += 4096)
  {
    ptedit_pte_set_bit((void*)addr, 0, PTEDIT_PAGE_BIT_RW);
    ptedit_invalidate_tlb((void*)addr);
  }

  target[str_len - 1] = '\0';

  return target;
}

int main()
{
  if (ptedit_init())
  {
    fprintf(stderr, "could not initialize pteditor, did you load the kernel module?\n");
    exit(1);
  }

  std::string source_str(4097, 'a');

  for (int i = 0; i < 100000; i++)
  {
    auto copied_string = copy_and_verify_string(source_str.c_str());
    if (copied_string == std::unique_ptr<char[]>(nullptr))
    {
      std::cout << "error, out of bounds" << std::endl;
    } 
  }
  

  ptedit_cleanup();

  return 0;
}