/******************************************************************************
Simple program that calls CPUID command with EAX and ECX from the command line
and output the following: INPUT_EAX,INPUT_ECX,EAX,EBX,ECX,EDX
*******************************************************************************/
#include <iostream>
#include <string>
#include <stdint.h>
#include <iomanip>
#include <sched.h>
#include <sstream>

using namespace std;

typedef unsigned int Registers[4];
typedef enum {
       EAX = 0, EBX = 1, ECX = 2, EDX = 3
} Register;

static inline void native_cpuid(unsigned int in_eax, unsigned int in_ecx,
	Registers out_regs) {
     asm volatile("cpuid"
         : "=a" (out_regs[EAX]),
           "=b" (out_regs[EBX]),
           "=c" (out_regs[ECX]),
           "=d" (out_regs[EDX])
         : "0" (in_eax), "2" (in_ecx)
         : "memory");
}

int main(int argc, char *argv[]) {
  if(argc < 3) {
  	cout << "First two parameters should be EAX and ECX as HEX." << endl;
    return 1;
  }

  unsigned int in_eax, in_ecx;
  Registers out_regs = {0};
  stringstream(argv[1]) >> hex >> in_eax;
  stringstream(argv[2]) >> hex >> in_ecx;

  native_cpuid(in_eax, in_ecx, out_regs);

  cout << hex << in_eax << "," << in_ecx << ","
  	   << out_regs[EAX] << ","
  	   << out_regs[EBX] << ","
  	   << out_regs[ECX] << ","
  	   << out_regs[EDX] << endl;

  return 0;
}
