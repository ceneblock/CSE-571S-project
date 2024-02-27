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

      sendto(fd, "Hello World\n", 12, 0, (struct sockaddr *) &sa, sizeof (sa));

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
