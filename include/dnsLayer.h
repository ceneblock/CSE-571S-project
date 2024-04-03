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

//shameless stolen from Wikipedia:
//https://en.wikipedia.org/wiki/List_of_DNS_record_types
enum RECORD_TYPES : uint16_t
{
  A          = 1,
  AAAA       = 28,
  AFSDB      = 18,
  APL        = 42,
  CAA        = 257,
  CDNSKEY    = 60,
  CDS        = 59,
  CERT       = 37,
  CNAME      = 5,
  CSYNC      = 62,
  DHCID      = 49,
  DLV        = 32769,
  DNAME      = 39,
  DNSKEY     = 48,
  DS         = 43,
  EUI48      = 108,
  EUI64      = 109,
  HINFO      = 13,
  HIP        = 55,
  HTTPS      = 65,
  IPSECKEY   = 45,
  KEY        = 25,
  KX         = 36,
  LOC        = 29,
  MX         = 15,
  NAPTR      = 35,
  NS         = 2,
  NSEC       = 47,
  NSEC3      = 50,
  NSEC3PARAM = 51,
  OPENPGPKEY = 61,
  PTR        = 12,
  RP         = 17,
  RRSIG      = 46,
  SIG        = 24,
  SMIMEA     = 53,
  SOA        = 6,
  SRV        = 33,
  SSHFP      = 44,
  SVCB       = 64,
  TA         = 32768,
  TKEY       = 52,
  TSIG       = 250,
  TXT        = 16,
  URI        = 256,
  ZONEMD     = 63
};

class dnsLayer
{
  public:

    dnsLayer()
    {
      q.qHeader = 0;
      //q.qId = 0;
    }

    //foolishly using uint8_t even though team rocket could be blasting off
    //again (overflow)
    void setQR(uint8_t value)
    {
      q.qHeader = (value << 15) || q.qHeader;
    }

    void setOpCode(uint8_t value)
    {
      q.qHeader = (value << 11) || q.qHeader;
    }

    void setAA(uint8_t value)
    {
      q.qHeader =  (value << 10) || q.qHeader;
    }

    void setTC(uint8_t value)
    {
      q.qHeader = (value << 9) || q.qHeader;
    }

    void setRD(uint8_t value)
    {
      q.qHeader = (value << 8)  || q.qHeader;
    }

    //setZero isn't needed as it's reserved bits

    void setrCode(uint8_t value)
    {
      q.qHeader = (value << 0) || q.qHeader; //could just be header |= value, but
                                       //doing this for consistency
    }

    void setqType() //todo: use enum
    {
    }

    void setqClass() //This is always going to be 1.
    {
      q.qClass = 1;
    }

    dnsPacket *getPacket()
    {
      datagram[0] = q.qHeader;
      datagram[1] = q.qId;
      datagram[2] = q.qQuestionCount;
      datagram[3] = q.qAnswerCount;
      datagram[4] = q.qAuthorityCount;
      datagram[5] = q.qAdditionalCount;
      //datagram[6] = qType;
      //datagram[7] = q.qClass;
      return &datagram;
    }

    void setDomain(std::string domain) { this->domain = domain; }

    void parseDomain()
    {
      parsedDomain.clear();
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
      byteDomain = "";
      for(auto &string : parsedDomain)
      {
        byteDomain += string.length();
        for(char c : string)
        {
          byteDomain += c;
        }
      }
      byteDomain.push_back(0x00);
    }

    std::string formatDomain(std::string inDomain = "", bool addNull = true)
    {
      //Make it so I can reuse code
      if(inDomain.length() > 0)
      {
        byteDomain = inDomain;
      }

      /*
      for(int x = 2; x < byteDomain.length() / 2; x+=2)
      {
        std::swap(byteDomain[x], byteDomain[x + 1]);
      }
      */

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

    void parseQuery(uint8_t *message, unsigned int length)
    {
      if(length < 12)
      {
        return;
      }

      unsigned int offset = 0;
      q.qId = (message[offset] << 8) + message[++offset];
      q.qHeader = (message[++offset] << 8) + message[++offset];
      q.qQuestionCount = (message[++offset] << 8) + message[++offset];
      q.qAnswerCount = (message[++offset] << 8) + message[++offset];
      q.qAuthorityCount = (message[++offset] << 8) + message[++offset];
      q.qAdditionalCount = (message[++offset] << 8) + message[++offset];

   
      unsigned int x = ++offset;
      uint8_t count = message[x];
      while(count != 0)
      { 
        offset+=count+1;
        count = message[offset];
        //don't replace it on the last instance
        if(message[offset] != 0)
        {
          message[offset] = '.';
        }
      }
      
      domain = (char *)&message[x+1];

//#ifdef DEBUG
      std::cout << "domain: " << domain << std::endl;
//#endif

      q.qType = (message[++offset] << 8) + message[++offset];
      q.qClass= (message[++offset] << 8) + message[++offset];

    }

    //Theoretically, I should use the original message, but I'm not going to
    void formAnswer(uint8_t *message, unsigned int length)
    {
      a.aName   = (0xc0 << 8) + 0x0c; //manually set it
      a.aType  = q.qType;
      a.aClass = q.qClass;
      a.aTTL   = 0x7FFFFFFF; //Max time
      a.aLength = 0x4; //Set it to IPv4
      //lol
      a.aAddress[0] = 127;
      a.aAddress[1] = 0;
      a.aAddress[2] = 0;
      a.aAddress[3] = 1;

      //IPv4
      if(a.aLength == 4)
      {
        for(uint16_t x = 0; x < a.aLength - 1; ++x)
        {
          a.address += std::to_string(a.aAddress[x]) + ".";
        }
        a.address += std::to_string(a.aAddress[a.aLength - 1]);
      }
      //TODO: IPv6 (I'm never going to do it because of compression)
#ifdef DEBUG
      std::cout << "Address: " << a.address << std::endl;
#endif
    }

    std::vector<uint8_t> returnQueryByteArray()
    {
      std::vector<uint8_t> message;
      message.push_back(q.qId >> 8);
      message.push_back(q.qId & 0xFF);

      message.push_back(0x81);
      message.push_back(0x00);
      //message.push_back(q.qHeader >> 8);
      //message.push_back(q.qHeader & 0xFF);

      message.push_back(q.qQuestionCount >> 8);
      message.push_back(q.qQuestionCount & 0xFF);

      message.push_back((q.qAnswerCount + 1) >> 8);
      message.push_back((q.qAnswerCount + 1) & 0xFF);

      message.push_back(q.qAuthorityCount >> 8);
      message.push_back(q.qAuthorityCount & 0xFF);

      message.push_back(0x00);
      message.push_back(0x00);
      //message.push_back(q.qAdditionalCount >> 8);
      //message.push_back(q.qAdditionalCount & 0xFF);

      parseDomain();

      for(char c : byteDomain)
      {
        message.push_back(c);
      }

      message.push_back(q.qType >> 8);
      message.push_back(q.qType & 0xFF);

      message.push_back(q.qClass >> 8);
      message.push_back(q.qClass & 0xFF);

      return message;
    }

    std::vector<uint8_t> returnAnswerByteArray()
    {
      std::vector<uint8_t> message;
      
      uint16_t aLength;  //how long is the address
      uint8_t  aAddress[16]; //the actual address
      std::string address; //human readable version

      message.push_back(a.aName >> 8);
      message.push_back(a.aName & 0xFF);

      message.push_back(a.aType >> 8);
      message.push_back(a.aType & 0xFF);

      message.push_back(a.aClass >> 8);
      message.push_back(a.aClass & 0xFF);

      message.push_back(a.aTTL >> 24);
      message.push_back(a.aTTL >> 16);
      message.push_back(a.aTTL >> 8);
      message.push_back(a.aTTL & 0xFF);

      message.push_back(a.aLength >> 8);
      message.push_back(a.aLength & 0xFF);

      for(uint16_t x = 0; x < a.aLength; ++x)
      {
        message.push_back(a.aAddress[x]);
      }

      return message;
    }


    void parseAnswer(uint8_t *message, unsigned int length)
    {
      if(length < 12)
      {
        return;
      }
      unsigned int offset = 0;
      q.qId = (message[offset] << 8) + message[++offset];
      q.qHeader = (message[++offset] << 8) + message[++offset];
      q.qQuestionCount = (message[++offset] << 8) + message[++offset];
      q.qAnswerCount = (message[++offset] << 8) + message[++offset];
      q.qAuthorityCount = (message[++offset] << 8) + message[++offset];
      q.qAdditionalCount = (message[++offset] << 8) + message[++offset];

   
      unsigned int x = ++offset;
      uint8_t count = message[x];
      while(count != 0)
      { 
        offset+=count+1;
        count = message[offset];
        //don't replace it on the last instance
        if(message[offset] != 0)
        {
          message[offset] = '.';
        }
      }
      
      domain = (char *)&message[x+1];

#ifdef DEBUG
      std::cout << "domain: " << domain << std::endl;
#endif

      q.qType = (message[++offset] << 8) + message[++offset];
      q.qClass= (message[++offset] << 8) + message[++offset];

      //At this point, message should point to the start of the response
      a.aName   = (message[++offset] << 8) + message[++offset];
      a.aType  = (message[++offset] << 8) + message[++offset];
      a.aClass = (message[++offset] << 8) + message[++offset];
      a.aTTL   = (message[++offset] << 24) + (message[++offset] << 16) + (message[++offset] << 8) + message[++offset];
      a.aLength = (message[++offset] << 8) + message[++offset];

      for(uint16_t x = a.aLength; x > 0; --x)
      {
        a.aAddress[a.aLength - x] = message[++offset];
      }

      //IPv4
      if(a.aLength == 4)
      {
        for(x = 0; x < a.aLength - 1; ++x)
        {
          a.address += std::to_string(a.aAddress[x]) + ".";
        }
        a.address += std::to_string(a.aAddress[a.aLength - 1]);
      }
      //TODO: IPv6 (I'm never going to do it because of compression)
#ifdef DEBUG
      std::cout << "Address: " << a.address << std::endl;
#endif
    }

    std::vector<std::string> getParsedDomain() { return parsedDomain; }
  private:

    struct query
    {
      uint16_t qId;
      uint16_t qHeader;
      uint16_t qQuestionCount;
      uint16_t qAnswerCount;
      uint16_t qAuthorityCount;
      uint16_t qAdditionalCount;
      uint16_t qType;
      uint16_t qClass;
    };

    struct answer
    {
      uint16_t aName;     //will always be c00c c0 represents the start and c0 is the
                         //the offset in the header
      uint16_t aType;    //likely will be 0x0001, but reality is it'll be qType
      uint16_t aClass;   //Similar to the above
      uint32_t aTTL;     //cache for how long
      uint16_t aLength;  //how long is the address
      uint8_t  aAddress[16]; //the actual address
      std::string address; //human readable version
    };

    answer a;
    query q;
    dnsPacket datagram;

    std::string domain;
    std::vector<std::string> parsedDomain;
    std::string byteDomain;
};

#endif
