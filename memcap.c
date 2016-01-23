
#include <stdio.h>
#include <string.h>

int main ()
{
  char buffer1[16] = "ffff880401975d00";
  char buffer2[16] = "ffff880401975ca0";

  int n;

  n=memcmp ( buffer1, buffer2, sizeof(buffer1)-4 );

  if (n>0) printf ("'%s' is greater than '%s'.\n",buffer1,buffer2);
  else if (n<0) printf ("'%s' is less than '%s'.\n",buffer1,buffer2);
  else printf ("'%s' is the same as '%s'.\n",buffer1,buffer2);

  return 0;
}
