#ifndef OSLAYER_H
#define OSLAYER_H

#include <dnsLayer.h>

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
        return rv;
      }
     
      socketfd.push_back(fd);

      std::vector<uint8_t> message;
      //TODO: migrate over to udp class
      message.push_back(0xAA); message.push_back(0x55); //transaction ID;
      message.push_back(0x01); message.push_back(0x00); //flags recursion desired
      message.push_back(0x00); message.push_back(0x01); //one question
      message.push_back(0x00); message.push_back(0x00); //answer rrs
      message.push_back(0x00); message.push_back(0x00); //authority rrs
      message.push_back(0x00); message.push_back(0x00); //additional rrs
      
      dns.setDomain("google.com");
      dns.parseDomain();
      
      for(uint8_t c : dns.formatDomain())
      {
        message.push_back(c);
      }

      //TODO: enum
      message.push_back(0x00); message.push_back(0x01); //A reccord
      message.push_back(0x00); message.push_back(0x01); //IN

      rv = sendto(fd, message.data(), sizeof(uint8_t) * message.size(), 0, (struct sockaddr *) &sa, sizeof (sa));

      if(rv < 0)
      {
        return rv;
      }

      //Move to read function
      unsigned int bufferSize = 0;
      socklen_t optlen = sizeof(bufferSize);
      unsigned int slen = sizeof(sa);
      while(bufferSize == 0)
      {
        getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufferSize, &optlen);
      }
      uint8_t buff[bufferSize];
      rv = recvfrom(fd, buff, bufferSize, 0, (struct sockaddr *)&sa, &slen);

      dns.parseMessage(buff, rv);
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

    dnsLayer dns;
};

#endif
