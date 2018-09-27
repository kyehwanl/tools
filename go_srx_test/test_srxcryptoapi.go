package main

/*
#cgo CFLAGS: -I.
#cgo LDFLAGS: -L. -lSRxBGPSecOpenSSL -lSRxCryptoAPI -Wl,-rpath -Wl,/home/kyehwanl/project/gowork/src/tools/go_srx_test
#include <stdio.h>
#include "srxcryptoapi.h"

void PrintPacked(SCA_BGPSEC_SecurePathSegment p){
     printf("From C\n  pCount:\t%d\n  flags:\t%x\n  asn:\t%d\n\n", p.pCount, p.flags, p.asn);
}

void PrintSCA_Prefix(SCA_Prefix p){
	printf("From C\n  afi:\t%d\n  safi:\t%d\n  length:\t%d\n  addr:\t%x\n\n",
		p.afi, p.safi, p.length, p.addr.ip);
}

int _sign(SCA_BGPSecSignData* signData );
void printHex(int len, unsigned char* buff);
int init(const char* value, int debugLevel, sca_status_t* status);
int sca_SetKeyPath (char* key_path);
*/
import "C"

import (
	"fmt"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"unsafe"
        "net"
        _ "os"
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


func main() {
	// --------- call sca_SetKeyPath -----------------------
	fmt.Printf("+ setKey path call testing...\n\n")
	//sca_SetKeyPath needed in libSRxCryptoAPI.so

	keyPath := C.CString("/home/kyehwanl/project/srx_test1/keys/")
	keyRet := C.sca_SetKeyPath(keyPath)
	fmt.Println("sca_SetKeyPath() return:", keyRet)
	if keyRet != 1 {
		fmt.Errorf("setKey failed")
	}

	// --------- call Init() function ---------------------
	fmt.Printf("+ Init call testing...\n\n")

	str := C.CString("PRIV:/home/kyehwanl/project/srx_test1/keys/priv-ski-list.txt")
	fmt.Printf("+ str: %s\n", C.GoString(str))

	var stat *scaStatus
	initRet := C.init(str, C.int(7), (*C.uint)(stat))
	fmt.Println("Init() return:", initRet)
	if initRet != 1 {
		fmt.Errorf("init failed")
	}

        //
	//  call _sign() function 
        //
	fmt.Printf("+ bgpsec sign data testing...\n\n")


	// ------ prefix handling ---------------
	ga := &Go_SCA_Prefix{
		afi:    1,
		safi:   1,
		length: 3,
		addr:   [16]byte{},
	}
	prefix := (*C.SCA_Prefix)(C.malloc(C.sizeof_SCA_Prefix))
	//ad := C.SCA_Prefix{}
        ipstr := "100.1.1.0"
        IPAddress := net.ParseIP(ipstr)
        //ipvalue = binary.BigEndian.Uint32(IPAddress[12:16])
        copy(ga.addr[:], IPAddress[12:16])

        /*
        fmt.Printf("ipaddress: %#v\n", IPAddress )
        fmt.Println("4-byte rep: ", IPAddress.To4())
        fmt.Println("ip: ", binary.BigEndian.Uint32(IPAddress[12:16]))
        */

	//ga.Pack(unsafe.Pointer(&ad))
	//C.PrintSCA_Prefix(ad)

	ga.Pack(unsafe.Pointer(prefix))
	C.PrintSCA_Prefix(*prefix)

        //os.Exit(3)


	// ------- Library call: printHex function test ----------
	b := [...]byte{0x11, 0x22, 0x33}
	var cb [10]C.uchar
	cb[0] = C.uchar(b[0])
	cb[1] = C.uchar(b[1])
	cb[2] = C.uchar(b[2])
	//cb := C.uchar(b)
	C.printHex(C.int(10), &cb[0])



	// ------ secure Path segment generation ---------------
	u := &Go_SCA_BGPSEC_SecurePathSegment{
		pCount: 1,
		flags:  0x90,
		asn:    65005,
	}
	sps := (*C.SCA_BGPSEC_SecurePathSegment)(C.malloc(C.sizeof_SCA_BGPSEC_SecurePathSegment))
	u.Pack(unsafe.Pointer(sps))

	//fmt.Printf("data:%#v\n\n", *sps)
	//fmt.Printf("data:%+v\n\n", *sps)
	C.PrintPacked(*sps)


	// ------ ski handling ---------------
	bs, _ := hex.DecodeString("45CAD0AC44F77EFAA94602E9984305215BF47DCD")
	fmt.Printf("type of bs: %T\n", bs)
	fmt.Printf("string test: %02X \n", bs)

	cbuf := (*[20]C.uchar)(C.malloc(20))
	cstr := (*[20]C.uchar)(unsafe.Pointer(&bs[0]))
	for i := 0; i < 20; i++ {
		cbuf[i] = cstr[i]
	}

	// ------ hash message handling  ---------------
	hashData := C.SCA_HashMessage{
		ownedByAPI:        true,
		bufferSize:        100,
		buffer:            nil,
		segmentCount:      1,
		hashMessageValPtr: nil,
	}
	hash := C.malloc(C.sizeof_SCA_HashMessage)
	h1 := (*[1000]C.uchar)(unsafe.Pointer(&hashData))
	h2 := (*[1000]C.uchar)(hash)
	for i := 0; i < C.sizeof_SCA_HashMessage; i++ {
		h2[i] = h1[i]
	}
	//bgpsecData.hashMessage = (*C.SCA_HashMessage)(hash)
	//bgpsecData.hashMessage = nil

	bgpsecData := C.SCA_BGPSecSignData{
		peerAS:      65011,
		myHost:      sps,
		nlri:        prefix,
		myASN:       65005,
		ski:         (*C.uchar)(&cbuf[0]),
		algorithmID: 1,
		status:      C.sca_status_t(0),
		hashMessage: nil,
		signature:   nil,
	}


        ret := C._sign(&bgpsecData)

	fmt.Println("return: value:", ret, " and status: ", bgpsecData.status)
	if ret == 1 {
		fmt.Println(" _sign function success...")
	} else if ret == 0 {
		fmt.Println(" _sign function failed...")
		switch bgpsecData.status {
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
}
