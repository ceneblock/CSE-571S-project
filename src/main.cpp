#include <unistd.h>
#include <iostream>

#include <config.h>

#include <osLayer.h>
#include <dnsLayer.h>
#include <sqliteLayer.h>

using namespace std;

bool DEBUG = false;
unsigned int port;
bool server = false;
void print_help()
{
  std::cout << PACKAGE_STRING << std::endl;
  std::cout << "A program to test DNS exfiltration\n";
  std::cout << std::endl;
  std::cout << PACKAGE << " options\n";
  std::cout << "-h          display this message\n";
  std::cout << "-D          enable Debug mode\n";
  std::cout << "[-c | -s]   if we are a Client or Server\n";
  std::cout << "-p ###      what port to work with\n";
}

int main(int argc, char* argv[])
{
  int opt = -1;
  while((opt = getopt(argc, argv, "Dhp:cs")) != -1)
  {
    switch(opt)
    {
      case 'D':
        DEBUG = true;
        break;
      case 'h':
        print_help();
        break;
      case 'p':
        port = atoi(optarg);
        break;
      //It's your own fault if you try -c -s at the same time
      case 'c':
        server = false;
        break;
      case 's':
        server = true;
        break;
      default:
        std::cerr << "Unknown argument: " << opt << std::endl;
        print_help();
        break;
    }
  }

  osLayer os;
  os.init(DEBUG, port);

  dnsLayer dns;

  if(!server)
  {
    /*
    dns.setQR(0);
    dns.setOpCode(0);
    dns.setAA(0); //doesn't matter
    dns.setTC(0);
    dns.setRD(0);
    dns.setRA(0);
    dns.setrCode(0);
    */
    dns.setDomain("www.google.com");
    
    dns.parseDomain();

    os.setDNS(dns);
    os.sendDNSRequest();
  }
  else
  {
    sqlite sql;
    sql.init();
    
    os.setSqlite(&sql);
    while(true)
    {
      os.listenForDNSRequest();
    }
  }
  return EXIT_SUCCESS;
}
