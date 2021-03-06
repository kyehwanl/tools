package main

/*
#cgo CFLAGS: -I.
#cgo LDFLAGS: -L. -lSRxBGPSecOpenSSL -lSRxCryptoAPI
#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdlib.h>
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

void PrintSCA_Prefix(SCA_Prefix p){
	printf("From C\n  afi:\t%d\n  safi:\t%d\n  length:\t%d\n  addr:\t%x\n\n",
		p.afi, p.safi, p.length, p.addr.ip);
}

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

typedef struct
{
  u_int32_t    myAS;
  sca_status_t status;
  u_int8_t*    bgpsec_path_attr;
  SCA_Prefix*  nlri;
  SCA_HashMessage*  hashMessage[2];
} SCA_BGPSecValidationData;

int _sign(SCA_BGPSecSignData* signData );
void printHex(int len, unsigned char* buff);
int init(const char* value, int debugLevel, sca_status_t* status);
int sca_SetKeyPath (char* key_path);
int validate(SCA_BGPSecValidationData* data);
*/
import "C"

import (
	"fmt"
	//      "testing"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"net"
	"unsafe"
)

type scaStatus uint32

type Go_SCA_BGPSEC_SecurePathSegment struct {
	pCount uint8
	flags  uint8
	asn    uint32
}

func (g *Go_SCA_BGPSEC_SecurePathSegment) Pack(out unsafe.Pointer) {

	buf := &bytes.Buffer{}
	/*
	   binary.Write(buf, binary.LittleEndian, g.pCount)
	   binary.Write(buf, binary.LittleEndian, g.flags)
	   binary.Write(buf, binary.LittleEndian, g.asn)
	*/
	//binary.Write(buf, binary.LittleEndian, g)
	binary.Write(buf, binary.BigEndian, g)

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

type Go_SCA_Prefix struct {
	afi    uint16
	safi   uint8
	length uint8
	addr   [16]uint8
}

func (g *Go_SCA_Prefix) Pack(out unsafe.Pointer) {

	buf := &bytes.Buffer{}
	binary.Write(buf, binary.LittleEndian, g)
	l := buf.Len()
	o := (*[1 << 20]C.uchar)(out)

	for i := 0; i < l; i++ {
		b, _ := buf.ReadByte()
		o[i] = C.uchar(b)
	}
}

type Packed struct {
	T [100]byte
}

func main() {
	// --------- call sca_SetKeyPath -----------------------
	fmt.Printf("+ setKey path call testing...\n\n")
	//sca_SetKeyPath needed in libSRxCryptoAPI.so

	//keyPath := C.CString("/home/kyehwanl/project/srx_test1/keys/")
	keyPath := C.CString("/opt/project/srx_test1/keys/")
	keyRet := C.sca_SetKeyPath(keyPath)
	fmt.Println("sca_SetKeyPath() return:", keyRet)
	if keyRet != 1 {
		fmt.Errorf("setKey failed")
	}

	// --------- call Init() function ---------------------
	fmt.Printf("+ Init call testing...\n\n")

	//str := C.CString("PRIV:/home/kyehwanl/project/srx_test1/keys/priv-ski-list.txt")
	//str := C.CString("PRIV:/opt/project/srx_test1/keys/priv-ski-list.txt")
	str := C.CString("PUB:/opt/project/srx_test1/keys/ski-list.txt;PRIV:/opt/project/srx_test1/keys/priv-ski-list.txt")
	fmt.Printf("str: %s\n", C.GoString(str))

	var stat *scaStatus
	initRet := C.init(str, C.int(7), (*C.uint)(stat))
	fmt.Println("Init() return:", initRet)
	if initRet != 1 {
		fmt.Errorf("init failed")
	}

	// --------- call _sign() function  ---------------------
	fmt.Printf("bgpsec sign data testing...\n\n")

	u := &Go_SCA_BGPSEC_SecurePathSegment{
		pCount: 1,
		flags:  0x90,
		asn:    65005,
	}
	sps := C.SCA_BGPSEC_SecurePathSegment{}

	// TODO: First way --> works !!
	///*
	fmt.Printf("total size of sizeof_SCA_BGPSEC_SecurePathSegmen : %d bytes \n", C.sizeof_SCA_BGPSEC_SecurePathSegment)
	u.Pack(unsafe.Pointer(&sps))
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

	ga := &Go_SCA_Prefix{
		afi:    1,
		safi:   1,
		length: 4,
		addr:   [16]byte{},
	}
	copy(ga.addr[:], "ABCD")
	ad := C.SCA_Prefix{}

	ga.Pack(unsafe.Pointer(&ad))
	C.PrintSCA_Prefix(ad)

	//var t *testing.T
	var sigData C.SCA_Signature = C.SCA_Signature{
		ownedByAPI: true,
		sigLen:     70,
	}

	hashData := C.SCA_HashMessage{
		ownedByAPI:        true,
		bufferSize:        100,
		buffer:            nil,
		segmentCount:      1,
		hashMessageValPtr: nil,
	}

	/* Library call: printHex function test */
	b := [...]byte{0x11, 0x22, 0x33}
	var cb [10]C.uchar
	cb[0] = C.uchar(b[0])
	cb[1] = C.uchar(b[1])
	cb[2] = C.uchar(b[2])
	//cb := C.uchar(b)
	C.printHex(C.int(10), &cb[0])

	/* Library call: _sign function testing */

	// ------------ CASE 0 --------------------
	// panic: runtime error: cgo argument has Go pointer to Go pointer
	// Reason: cgo doesn't recognize cgo's struct address circularily
	var ret C.int

	bgpsecData := C.SCA_BGPSecSignData{
		peerAS:      65011,
		myHost:      &sps,
		nlri:        &ad,
		myASN:       65005,
		ski:         nil,
		algorithmID: 1,
		status:      C.sca_status_t(3),
		hashMessage: &hashData,
		signature:   &sigData,
	}

	fmt.Printf("data:%#v\n\n", bgpsecData)
	fmt.Printf("data:%+v\n\n", bgpsecData)

	fmt.Printf("data. hash :%#v\n\n", bgpsecData.hashMessage)
	fmt.Printf("data. hash :%+v\n\n", bgpsecData.hashMessage)

	fmt.Printf("data. signature:%#v\n\n", bgpsecData.signature)
	fmt.Printf("data. signature:%+v\n\n", bgpsecData.signature)
	//ret = C._sign(&bgpsecData)  <-- Panic
	// -----------------------------------------

	// ------------ CASE 1 --------------------
	bgpsecData2 := C.SCA_BGPSecSignData{
		peerAS:      65011,
		myHost:      nil,
		nlri:        nil,
		myASN:       65005,
		ski:         nil,
		algorithmID: 1,
		status:      C.sca_status_t(3),
		hashMessage: nil,
		signature:   nil,
	}

	//ret = C._sign(&bgpsecData2) --> works
	/*
		fmt.Println("ret:", C.int(ret))
		if ret == 0 {
			fmt.Println("Failed")
		}
	*/
	// -----------------------------------------

	// ------------ CASE 2 --------------------
	sps2 := C.malloc(C.sizeof_SCA_BGPSEC_SecurePathSegment)
	defer C.free(unsafe.Pointer(sps2))
	o1 := (*[1000]C.uchar)(unsafe.Pointer(&sps))
	o2 := (*[1000]C.uchar)(sps2)

	for i := 0; i < C.sizeof_SCA_BGPSEC_SecurePathSegment; i++ {
		o2[i] = o1[i]
	}
	bgpsecData2.myHost = (*C.SCA_BGPSEC_SecurePathSegment)(sps2)
	//ret = C._sign(&bgpsecData2) --> works
	// -----------------------------------------

	// ------------ CASE 3 --------------------
	sps3 := (*C.SCA_BGPSEC_SecurePathSegment)(C.malloc(C.sizeof_SCA_BGPSEC_SecurePathSegment))
	defer C.free(unsafe.Pointer(sps3))
	u.Pack(unsafe.Pointer(sps3))
	//fmt.Printf("data:%#v\n\n", *sps3)
	//fmt.Printf("data:%+v\n\n", *sps3)
	//C.PrintPacked(*sps3)
	bgpsecData2.myHost = sps3
	//ret = C._sign(&bgpsecData2) --> works
	// -----------------------------------------

	//
	// ------------ CASE 4 (final) -------------
	//
	// ------ prefix handling ---------------
	prefix := (*C.SCA_Prefix)(C.malloc(C.sizeof_SCA_Prefix))
	defer C.free(unsafe.Pointer(prefix))
	ga.Pack(unsafe.Pointer(prefix))
	bgpsecData2.nlri = prefix

	// ------ ski handling ---------------
	skiData := C.CString("45CAD0AC44F77EFAA94602E9984305215BF47DCD")
	pski := unsafe.Pointer(skiData)
	bgpsecData2.ski = (*C.uchar)(pski)
	//skiData := (*C.uchar)(C.malloc(20))
	//bgpsecData2.ski = skiData

	bs, _ := hex.DecodeString("45CAD0AC44F77EFAA94602E9984305215BF47DCD")
	fmt.Printf("type of bs: %T\n", bs)
	fmt.Printf("string test: %02X \n", bs)

	cbuf := (*[20]C.uchar)(C.malloc(20))
	defer C.free(unsafe.Pointer(cbuf))
	cstr := (*[20]C.uchar)(unsafe.Pointer(&bs[0]))
	for i := 0; i < 20; i++ {
		cbuf[i] = cstr[i]
	}
	bgpsecData2.ski = (*C.uchar)(&cbuf[0])

	// ------ hash message handling  ---------------
	hash := C.malloc(C.sizeof_SCA_HashMessage)
	defer C.free(hash)
	h1 := (*[1000]C.uchar)(unsafe.Pointer(&hashData))
	h2 := (*[1000]C.uchar)(hash)
	for i := 0; i < C.sizeof_SCA_HashMessage; i++ {
		h2[i] = h1[i]
	}
	bgpsecData2.hashMessage = (*C.SCA_HashMessage)(hash)
	bgpsecData2.hashMessage = nil

	/* --> Do not put an allocated memory, otherwise fatal error occured on running _sign->freeSignature()
	//sig := (*C.SCA_Signature)(C.malloc(C.sizeof_SCA_Signature))
	//bgpsecData2.signature = sig
	*/

	bgpsecData2.signature = nil
	ret = C._sign(&bgpsecData2)

	fmt.Println("return: value:", ret, " and status: ", bgpsecData2.status)
	if ret == 1 {
		fmt.Println(" _sign function SUCCESS ...")

		if bgpsecData2.signature != nil {
			fmt.Printf("signature: %#v\n", bgpsecData2.signature)

			ret_array := func(sig_data *C.SCA_Signature) []uint8 {
				buf := make([]uint8, 0, uint(sig_data.sigLen))
				for i := 0; i < int(sig_data.sigLen); i++ {
					u8 := *(*uint8)(unsafe.Pointer(uintptr(unsafe.Pointer(sig_data.sigBuff)) + uintptr(i)))
					buf = append(buf, u8)
				}
				return buf
			}(bgpsecData2.signature)

			fmt.Println("ret:", ret_array)
		}

	} else if ret == 0 {
		fmt.Println(" _sign function Failed...")
		switch bgpsecData2.status {
		case 1:
			fmt.Println("signature error")
		case 2:
			fmt.Println("Key not found")
		case 0x10000:
			fmt.Println("no data")
		case 0x20000:
			fmt.Println("no prefix")
		case 0x40000:
			fmt.Println("Invalid key")
		}
	}

	/* ------------------------------------------
	 * Validation Test
	 * ------------------------------------------
	 */
	var myas uint32 = 65005
	big := make([]byte, 4, 4)
	for i := 0; i < 4; i++ {
		u8 := *(*uint8)(unsafe.Pointer(uintptr(unsafe.Pointer(&myas)) + uintptr(i)))
		big = append(big, u8)
	}

	valData := C.SCA_BGPSecValidationData{
		myAS:             C.uint(binary.BigEndian.Uint32(big[4:8])),
		status:           C.sca_status_t(0),
		bgpsec_path_attr: nil,
		nlri:             nil,
		hashMessage:      [2](*C.SCA_HashMessage){},
	}
	//valData.hashMessage[0] = nil
	//valData.hashMessage[1] = nil

	bs_path_attr := []byte{
		0x90, 0x21, 0x00, 0x68, 0x00, 0x08, 0x01, 0x00, 0x00, 0x00, 0xfd, 0xf3,
		0x00, 0x60, 0x01, 0x45, 0xca, 0xd0, 0xac, 0x44, 0xf7, 0x7e, 0xfa, 0xa9, 0x46, 0x02, 0xe9, 0x98,
		0x43, 0x05, 0x21, 0x5b, 0xf4, 0x7d, 0xcd, 0x00, 0x47, 0x30, 0x45, 0x02, 0x21, 0x00, 0xb3, 0xe8,
		0xcc, 0xd2, 0xcb, 0xba, 0x96, 0x47, 0xe3, 0x1f, 0x74, 0x97, 0xa3, 0x77, 0x74, 0x55, 0x86, 0x44,
		0x09, 0x67, 0xec, 0x02, 0x60, 0x3f, 0x05, 0xe2, 0x1b, 0x47, 0x62, 0xab, 0xde, 0xd9, 0x02, 0x20,
		0x05, 0x58, 0xe5, 0x72, 0xc5, 0x61, 0x91, 0x47, 0x99, 0x86, 0x16, 0x3e, 0x1e, 0x4a, 0x92, 0x5e,
		0xe8, 0x26, 0x03, 0x1f, 0x5d, 0x5a, 0x36, 0x92, 0x18, 0x1e, 0x8b, 0x3e, 0xa7, 0x26, 0x4b, 0x61,
	}

	/* signature  buffer handling*/
	bs_path_attr_length := 0x6c // 0x68 + 4
	pa := C.malloc(C.ulong(bs_path_attr_length))
	defer C.free(pa)

	buf := &bytes.Buffer{}
	binary.Write(buf, binary.BigEndian, bs_path_attr)
	bl := buf.Len()
	o := (*[1 << 20]C.uchar)(pa)

	for i := 0; i < bl; i++ {
		b, _ := buf.ReadByte()
		o[i] = C.uchar(b)
	}
	valData.bgpsec_path_attr = (*C.uchar)(pa)

	/* prefix handling */
	prefix2 := (*C.SCA_Prefix)(C.malloc(C.sizeof_SCA_Prefix))
	defer C.free(unsafe.Pointer(prefix2))
	px := &Go_SCA_Prefix{
		afi:    0x0100,
		safi:   1,
		length: 24,
		addr:   [16]byte{},
	}
	pxip := net.IP{0x64, 0x0a, 0x0a, 0x00} // 100.10.10.0/24
	copy(px.addr[:], pxip)
	px.Pack(unsafe.Pointer(prefix2))
	C.PrintSCA_Prefix(*prefix2)
	fmt.Printf("prefix2 : %#v\n", prefix2)

	valData.nlri = prefix2
	fmt.Printf(" valData : %#v\n", valData)
	fmt.Printf(" valData.bgpsec_path_attr : %#v\n", valData.bgpsec_path_attr)
	C.printHex(C.int(bs_path_attr_length), valData.bgpsec_path_attr)
	fmt.Printf(" valData.nlri : %#v\n", *valData.nlri)

	// call validate
	ret = C.validate(&valData)

	fmt.Println("return: value:", ret, " and status: ", valData.status)
	if ret == 1 {
		fmt.Println(" +++ Validation function SUCCESS ...")

	} else if ret == 0 {
		fmt.Println(" Validation function Failed...")
		switch valData.status {
		case 1:
			fmt.Println("Status Error: signature error")
		case 2:
			fmt.Println("Status Error: Key not found")
		case 0x10000:
			fmt.Println("Status Error: no data")
		case 0x20000:
			fmt.Println("Status Error: no prefix")
		case 0x40000:
			fmt.Println("Status Error: Invalid key")
		case 0x10000000:
			fmt.Println("Status Error: USER1")
		case 0x20000000:
			fmt.Println("Status Error: USER2")
		}
	}

	/* ------------------------------------------
	 * Test Module
	 * ------------------------------------------
	 */
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
