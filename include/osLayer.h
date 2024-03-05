#ifndef OSLAYER_H
#define OSLAYER_H
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <resolv.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <cstring>
#include <iostream>
#include <vector>

static int DNS_PORT=53;

class osLayer
{
  public:
    osLayer()
    {
    }

    ~osLayer()
    {
      for(auto &x : socketfd)
      {
        if(x >= 0)
        {
          close(x);
        }
      }
    }

    int init()
    {
      int rc = res_init();
      if(rc == -1)
      {
        std::cerr << "Unable to init!\n";
      }
      //_res is global and I don't particularly like it, so we're going to copy
      //it over
      sa = _res.nsaddr_list[0];
      return rc;
    }

    int send()
    {
      int rv = 0;

      //foolishly connect to the first DNS server
      int fd = socket(sa.sin_family, SOCK_DGRAM, 0);  
     
      if(fd < 0)
      { 
        std::cerr << strerror(errno) << std::endl;
        rv = -1;
      }
      
      socketfd.push_back(fd);

      uint16_t message[14];
      message[0]  = 0x0000; //transaction ID;
      message[1]  = 0x0100; //flags recursion desired
      message[2]  = 0x0100; //one question
      message[3]  = 0x0000; //answer rrs
      message[4]  = 0x0000; //authority rrs
      message[5]  = 0x0000; //additional rrs
      message[6]  = 0x6706; //6 characters (google) first one g is 67
      message[7]  = 0x6f6f; //oo
      message[8]  = 0x6c67; //gl
      message[9]  = 0x0365; //e 3 characters;
      message[10] = 0x6f63; //co
      message[11] = 0x006d; //m 0 characters
      message[12] = 0x0100; //A record
      message[13] = 0x0100; //IN

      sendto(fd, message, sizeof(message), 0, (struct sockaddr *) &sa, sizeof (sa));

      char buff[80];
      unsigned int slen = sizeof(sa);
      recvfrom(fd, buff, 80, 0, (struct sockaddr *)&sa, &slen);

      std::cout << buff << std::endl;
      return rv;
    }

    int read()
    {
      //mock
      return 0;
    }
  private:
    addrinfo hints, *servinfo;
    sockaddr_in sa;
    std::vector<int> socketfd;    
};

#endif
