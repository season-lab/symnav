#include <stdio.h>

int main(int argc, char const *argv[])
{
  char a;
  while((a = getchar()) != 'a');

  unsigned i, v;
  for(i=0; i<100; ++i)
    v += (unsigned)(getchar() ^ a);

  if (v != 0xbad)
    return 1;
  return 0;
}