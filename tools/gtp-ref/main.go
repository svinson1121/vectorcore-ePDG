package main

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/wmnsk/go-gtp/gtpv2"
	"github.com/wmnsk/go-gtp/gtpv2/ie"
	"github.com/wmnsk/go-gtp/gtpv2/message"
)

type bearer struct {
	ebi  uint8
	teid uint32
}

func main() {
	const (
		controlTEID   uint32 = 0x487e8ee6
		sequence      uint32 = 126978
		localGTPUIPv4        = "10.90.250.55"
		fteidInstance uint8  = 1
	)
	bearers := []bearer{
		{ebi: 6, teid: 0xd32f5697},
		{ebi: 7, teid: 0xd295f438},
	}

	ies := []*ie.IE{ie.NewCause(gtpv2.CauseRequestAccepted, 0, 0, 0, nil)}
	for _, b := range bearers {
		ies = append(ies, ie.NewBearerContext(
			ie.NewCause(gtpv2.CauseRequestAccepted, 0, 0, 0, nil),
			ie.NewEPSBearerID(b.ebi),
			ie.NewFullyQualifiedTEID(gtpv2.IFTypeS2bUePDGGTPU, b.teid, localGTPUIPv4, "").
				WithInstance(fteidInstance),
		))
	}

	msg := message.NewCreateBearerResponse(controlTEID, sequence, ies...)
	encoded, err := msg.Marshal()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("message_type=%d\n", message.MsgTypeCreateBearerResponse)
	fmt.Printf("sequence=%d\n", sequence)
	fmt.Printf("teid=0x%08x\n", controlTEID)
	fmt.Printf("fteid_interface_type=%d\n", gtpv2.IFTypeS2bUePDGGTPU)
	fmt.Printf("fteid_interface_name=s2b_epdg_gtpu\n")
	fmt.Printf("fteid_ie_instance=%d\n", fteidInstance)
	fmt.Printf("encoded_hex=%s\n", hex.EncodeToString(encoded))

	for i, bc := range msg.BearerContexts {
		children, err := bc.BearerContext()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("bearer_context[%d].child_ie_types=", i)
		for j, child := range children {
			if j > 0 {
				fmt.Print(",")
			}
			fmt.Print(child.Type)
		}
		fmt.Println()
		for _, child := range children {
			if child.Type != ie.FullyQualifiedTEID {
				continue
			}
			fteid, err := child.FullyQualifiedTEID()
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("bearer_context[%d].fteid_instance=%d\n", i, child.Instance())
			fmt.Printf("bearer_context[%d].fteid_interface_type=%d\n", i, fteid.InterfaceType)
			fmt.Printf("bearer_context[%d].fteid_teid=0x%08x\n", i, fteid.TEIDGREKey)
			fmt.Printf("bearer_context[%d].fteid_ipv4=%s\n", i, fteid.IPv4Address)
		}
	}
}
