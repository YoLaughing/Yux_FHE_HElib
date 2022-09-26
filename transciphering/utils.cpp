#include <iostream>
#include <iomanip>
#include "utils.h"

void printState(NTL::Vec<uint8_t>& st)
{
  std::cerr << "[";
  for (long i=0; i<st.length() && i<32; i++) {
    std::cerr << std::hex << std::setw(2) << (long) st[i] << " ";
  }
  if (st.length()>32) std::cerr << "...";
  std::cerr << std::dec << "]";
}
