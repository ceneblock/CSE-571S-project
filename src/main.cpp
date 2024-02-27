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

  os.send();


  //char str[80];
  //inet_ntop(AF_INET, &(_res.nsaddr_list[0].sin_addr), str, INET_ADDRSTRLEN);
  //cout << str << endl;
  return EXIT_SUCCESS;
}
