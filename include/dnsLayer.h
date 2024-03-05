#ifndef DNSLAYER_H
#define DNSLAYER_H

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <cstring>
#include <string>
#include <vector>

typedef uint16_t dnsPacket[6];

class dnsLayer
{
  public:

    dnsLayer()
    {
      header = 0;
      //id = 0;
    }

    //foolishly using uint8_t even though team rocket could be blasting off
    //again (overflow)
    void setQR(uint8_t value)
    {
      header = (value << 15) || header;
    }

    void setOpCode(uint8_t value)
    {
      header = (value << 11) || header;
    }

    void setAA(uint8_t value)
    {
      header =  (value << 10) || header;
    }

    void setTC(uint8_t value)
    {
      header = (value << 9) || header;
    }

    void setRD(uint8_t value)
    {
      header = (value << 8)  || header;
    }

    //setZero isn't needed as it's reserved bits

    void setrCode(uint8_t value)
    {
      header = (value << 0) || header; //could just be header |= value, but
                                       //doing this for consistency
    }

    void setqType() //todo: use enum
    {
    }

    void setqClass() //This is always going to be 1.
    {
      qClass = 1;
    }

    dnsPacket *getPacket()
    {
      datagram[0] = header;
      datagram[1] = id;
      datagram[2] = questionCount;
      datagram[3] = answerCount;
      datagram[4] = authorityCount;
      datagram[5] = additionalCount;
      //datagram[6] = qType;
      //datagram[7] = qClass;
      return &datagram;
    }

    void setDomain(std::string domain) { this->domain = domain; }

    void parseDomain()
    {
      std::string parsed;

      char *pch;
      pch = strtok (const_cast<char *>(domain.c_str()),".");
      while (pch != NULL)
      {
        parsed = pch;
        //too lazy to optimize
        parsedDomain.push_back(parsed);
        pch = strtok (NULL, ".");
      }

      //make it one big string
      for(auto &string : parsedDomain)
      {
        byteDomain += string.length();
        for(char c : string)
        {
          byteDomain += c;
        }
      }
    }

    std::string formatDomain(std::string inDomain = "", bool addNull = true)
    {
      //Make it so I can reuse code
      if(inDomain.length() > 0)
      {
        byteDomain = inDomain;
      }

      for(int x = 2; x < byteDomain.length() / 2; x+=2)
      {
        std::swap(byteDomain[x], byteDomain[x + 1]);
      }

      if(addNull)
      {
        byteDomain.push_back(0x0000); //apparently += causes it to fail
      }

      if(byteDomain.length() % 2 == 0)
      {
        std::swap(byteDomain[byteDomain.length() - 1], byteDomain[byteDomain.length()]);
      }

      return byteDomain;
    }

    void parseMessage(uint8_t *message, unsigned int length)
    {
      id = (message[0] << 8) + message[1];
      header = (message[2] << 8) + message[3];
      questionCount = (message[4] << 8) + message[5];
      answerCount = (message[6] << 8) + message[7];

    }
  private:
    uint16_t id;
    uint16_t header;
    uint16_t questionCount;
    uint16_t answerCount;
    uint16_t authorityCount;
    uint16_t additionalCount;
    uint16_t qType;
    uint16_t qClass;

    dnsPacket datagram;

    std::string domain;
    std::vector<std::string> parsedDomain;
    std::string byteDomain;
};

#endif
