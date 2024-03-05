#include <unistd.h>
#include <iostream>
#include <arpa/inet.h>

#include <osLayer.h>
#include <udpLayer.h>

using namespace std;
int main()
{
  osLayer os;
  os.init();

  dnsLayer dns;

  dns.setQR(0);
  dns.setOpCode(0);
  dns.setAA(0); //doesn't matter
  dns.setTC(0);
  dns.setRD(0);
  //dns.setRA(0);
  dns.setrCode(0);

  os.send();

  return EXIT_SUCCESS;
}
