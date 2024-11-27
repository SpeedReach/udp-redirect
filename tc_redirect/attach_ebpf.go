package tc_redirect

import (
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type Attachment struct {
	Link    link.Link
	Objects tc_redirectObjects
}

func (a Attachment) Close() {
	defer a.Link.Close()
	defer a.Objects.Close()
}

func AttachEbpf() Attachment {

	if err := rlimit.RemoveMemlock(); err != nil {
		panic(err)
	}

	var objs tc_redirectObjects
	if err := loadTc_redirectObjects(&objs, nil); err != nil {
		panic(err)
	}
	ifname := "enp52s0" // Change this to an interface on your machine.
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		panic(err)
	}

	xdpLink, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.Tcdump,
		Attach:    ebpf.AttachTCXEgress,
	})

	if err != nil {
		panic(err)
	}

	return Attachment{Link: xdpLink, Objects: objs}
}
