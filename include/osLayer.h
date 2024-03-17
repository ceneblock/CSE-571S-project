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



class osLayer
{
  public:

    osLayer(bool DEBUG = false)
    {
      setDEBUG(DEBUG);
      DNS_PORT = 53;
      dnsSet = false;;
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
    
    unsigned int getMaxBufferSize(int fd)
    {
        unsigned int bufferSize = 0;
        socklen_t optlen = sizeof(bufferSize);
        unsigned int slen = sizeof(sa);
        while(bufferSize == 0)
        {
          getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufferSize, &optlen);
        }

        return bufferSize;
    }

    void setDEBUG(bool DEBUG)
    {
      this->DEBUG = DEBUG;
    }

    int init(bool DEBUG = false, unsigned int port = 53)
    {

      DNS_PORT = port;
      setDEBUG(DEBUG);

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

    void setDNS(const dnsLayer &dns)
    {
      dnsSet = true;
      this->dns = dns;
    }

    int listenForDNSRequest()
    {
      int rv = 0;
      int fd = -1;
      struct addrinfo hints, *servinfo, *p;
      int numbytes;
      struct sockaddr_storage their_addr;
      socklen_t addr_len;
      char s[INET6_ADDRSTRLEN];

      memset(&hints, 0, sizeof hints);
      hints.ai_family = AF_INET; // set to AF_INET6 to use IPv6
      hints.ai_socktype = SOCK_DGRAM;
      hints.ai_flags = AI_PASSIVE; // use my IP

      if ((rv = getaddrinfo(NULL, std::to_string(DNS_PORT).c_str(), &hints, &servinfo)) != 0) 
      {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
      }

      // loop through all the results and bind to the first we can
      for(p = servinfo; p != NULL; p = p->ai_next) 
      {
        if ((fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) 
        {
          std::cerr << "Unable to create socket\n";
          perror("listener: socket");
          continue;
        }

        if (bind(fd, p->ai_addr, p->ai_addrlen) == -1) 
        {
          close(fd);
          std::cerr << "Error binding. Check if you're using a privileged port\n";
          perror("listener: bind");
          continue;
        }

        break;
      }

      socketfd.push_back(fd);

      if (p == NULL) 
      {
        std::cerr << "Failed to bind socket\n";
        rv = 2;
      }

      freeaddrinfo(servinfo);

      unsigned int bufferSize = getMaxBufferSize(fd);
      uint8_t buff[bufferSize];

      if(DEBUG)
      {
        std::cout << "Busy Wait\n";
      }
      addr_len = sizeof(their_addr);
      if ((numbytes = recvfrom(fd, buff, bufferSize, 0,
          (struct sockaddr *)&their_addr, &addr_len)) == -1) 
      {
        std::cerr << "Error in recvfrom";
        exit(1);
      }

      /*
      printf("listener: got packet from %s\n",
          inet_ntop(their_addr.ss_family,
              get_in_addr((struct sockaddr *)&their_addr),
              s, sizeof s));
      */
      if(DEBUG)
      {
        std::cout << "packet is " << numbytes << " bytes long\n";
      }
      printf("listener: packet contains \"%s\"\n", buff);

      dns.parseQuery(buff, numbytes);
      dns.formAnswer(nullptr, 0);
      std::vector<uint8_t> originalQuery = dns.returnQueryByteArray();
      std::vector<uint8_t> formedAnswer = dns.returnAnswerByteArray();

      std::vector<uint8_t> message;
      message.insert(message.end(),originalQuery.begin(), originalQuery.end());
      message.insert(message.end(),formedAnswer.begin(), formedAnswer.end());
        
      rv = sendto(fd, message.data(), sizeof(uint8_t) * message.size(), MSG_CONFIRM, (struct sockaddr *) &their_addr, sizeof (their_addr));

      return rv;
    }

    int prepareDNSAnswer()
    {
      //mock
      return 0;
    }

    int sendDNSRequest()
    {
      int rv = 0;
      if(dnsSet)
      {

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
        unsigned int bufferSize = getMaxBufferSize(fd);
        uint8_t buff[bufferSize];
        unsigned int slen = sizeof(sa);
        rv = recvfrom(fd, buff, bufferSize, 0, (struct sockaddr *)&sa, &slen);

        dns.parseAnswer(buff, rv);
      }
      else
      {
        if(DEBUG)
        {
          std::cerr << "DNS object is not set. Cowardly refusing to do anything\n";
        }
        rv = -1;
      }
      return rv;
    }

    int read()
    {
      //mock
      return 0;
    }
  
  protected:
    bool DEBUG;
    unsigned int DNS_PORT;

  private:
    addrinfo hints, *servinfo;
    sockaddr_in sa;
    std::vector<int> socketfd;

    dnsLayer dns;

    bool dnsSet;
};

#endif
