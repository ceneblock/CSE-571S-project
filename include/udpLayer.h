#ifndef UDPLAYER_H
#define UDPLAYER_H

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

typedef uint16_t dnsPacket[8];

class dnsLayer
{
  public:

    dnsLayer()
    {
      header = 0;
      id = 0;
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
      datagram[6] = qType;
      datagram[7] = qClass;
      return &datagram;
    }

  private:
    uint16_t header;
    static uint16_t id;
    uint16_t questionCount;
    uint16_t answerCount;
    uint16_t authorityCount;
    uint16_t additionalCount;
    uint16_t qType;
    uint16_t qClass;

    dnsPacket datagram;
};

#endif
