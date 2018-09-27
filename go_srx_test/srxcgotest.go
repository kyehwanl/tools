package main

/*
#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <stdbool.h>
#define SKI_LENGTH                 20

typedef u_int32_t sca_status_t;

typedef struct
{
  u_int8_t* signaturePtr;
  u_int8_t* hashMessagePtr;
  u_int16_t hashMessageLength;
} SCA_HashMessagePtr;

typedef struct
{
  bool      ownedByAPI;
  u_int32_t bufferSize;
  u_int8_t* buffer;
  u_int16_t segmentCount;
  SCA_HashMessagePtr** hashMessageValPtr;
} SCA_HashMessage;


typedef struct
{
  bool      ownedByAPI;
  u_int8_t  algoID;
  u_int8_t  ski[SKI_LENGTH];
  u_int16_t sigLen;
  u_int8_t* sigBuff;
} SCA_Signature;


typedef struct {
  u_int8_t  pCount;
  u_int8_t  flags;
  u_int32_t asn;
} __attribute__((packed)) SCA_BGPSEC_SecurePathSegment;

void PrintPacked(SCA_BGPSEC_SecurePathSegment p){
     printf("From C\n  pCount:\t%d\n  flags:\t%x\n  asn:\t%d\n\n", p.pCount, p.flags, p.asn);
}

typedef struct
{
  u_int16_t afi;
  u_int8_t  safi;
  u_int8_t  length;
  union
  {
    struct in_addr  ipV4;
    struct in6_addr ipV6;
    u_int8_t ip[16];
  } addr;
} __attribute__((packed)) SCA_Prefix;


typedef struct
{
  __attribute__((deprecated))u_int32_t peerAS;
  __attribute__((deprecated))SCA_BGPSEC_SecurePathSegment* myHost;
  __attribute__((deprecated))SCA_Prefix* nlri;

  u_int32_t myASN;
  u_int8_t* ski;
  u_int8_t algorithmID;
  sca_status_t status;
  SCA_HashMessage*  hashMessage;

  SCA_Signature* signature;
} SCA_BGPSecSignData;

*/
import "C"

import (
        "fmt"
  //      "testing"
        "bytes"
        "encoding/binary"
        "unsafe"
)

type Go_SCA_BGPSEC_SecurePathSegment struct {
  pCount uint8
  flags uint8
  asn  uint32
}

func (g *Go_SCA_BGPSEC_SecurePathSegment) Pack (out unsafe.Pointer) {

    buf := &bytes.Buffer{}
    /*
    binary.Write(buf, binary.LittleEndian, g.pCount)
    binary.Write(buf, binary.LittleEndian, g.flags)
    binary.Write(buf, binary.LittleEndian, g.asn)
    */
    binary.Write(buf, binary.LittleEndian, g)

    // get the length of memory
    l := buf.Len()

    //Cast the point to byte slie to allow for direct memory manipulation
    o := (*[1 << 20]C.uchar)(out)

    //Write to memory
    for i := 0; i < l; i++ {
      b, _ := buf.ReadByte()
      o[i] = C.uchar(b)
    }
}

type Packed struct {
  T [100]byte
}

func main() {
  fmt.Printf("bgpsec sign data testing...\n\n")


  u := &Go_SCA_BGPSEC_SecurePathSegment {
    pCount : 1,
    flags : 0x90,
    asn : 60002,
  }
  sps := C.SCA_BGPSEC_SecurePathSegment{}

  // TODO: First way --> works !!
  ///*
  u.Pack (unsafe.Pointer(&sps))
  fmt.Printf("data:%#v\n\n", sps)
  fmt.Printf("data:%+v\n\n", sps)
  C.PrintPacked(sps)
  //*/

  // TODO: Second way --> not worked yet
  /*
  var buff = bytes.NewBuffer(make([]byte, 0, 100))
  if err := binary.Write(buff, binary.LittleEndian, u); err != nil {
    fmt.Println(err)
  }
  fmt.Println(buff)
  if err := binary.Read(buff, binary.LittleEndian, &sps); err != nil {
    fmt.Println(err)
  }
  fmt.Println ("u", u, "sps", sps)
  C.PrintPacked(sps)
  */





  //var t *testing.T
  var sigData C.SCA_Signature = C.SCA_Signature {
    ownedByAPI: true,
    sigLen: 70,
  }

  securePathSegment := C.SCA_BGPSEC_SecurePathSegment {
    pCount: 1,
    flags: 0x90,
    //asn: C.uint(65005),
  }

  var bgpsecData C.SCA_BGPSecSignData = C.SCA_BGPSecSignData {
        peerAS: 65005,
        myHost: &securePathSegment,
        myASN: 65011,
        algorithmID: 1,
        signature: &sigData,
  }

  fmt.Printf("data:%#v\n\n", bgpsecData)
  fmt.Printf("data. signature:%#v\n\n\n\n", bgpsecData.signature)

  fmt.Printf("data:%+v\n\n", bgpsecData)
  fmt.Printf("data. signature:%+v\n\n", bgpsecData.signature)



  /*
  var t *testing.T
  var evt C.SDL_KeyboardEvent
  C.makeEvent(&evt)
  if C.same(&evt, evt.typ, evt.which, evt.state, evt.keysym.scancode, evt.keysym.sym, evt.keysym.mod, evt.keysym.unicode) == 0 {
          t.Error("*** bad alignment")
          C.cTest(&evt)
          t.Errorf("Go: %#x %#x %#x %#x %#x %#x %#x\n",
                  evt.typ, evt.which, evt.state, evt.keysym.scancode,
                  evt.keysym.sym, evt.keysym.mod, evt.keysym.unicode)
          t.Error(evt)
  }
  */
}



