package xdp_ack

import (
	"net"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type Attachment struct {
	Link    link.Link
	Objects xdp_ackObjects
}

func (a Attachment) Close() {
	defer a.Link.Close()
	defer a.Objects.Close()
}

func AttachEbpf() Attachment {

	if err := rlimit.RemoveMemlock(); err != nil {
		panic(err)
	}

	var objs xdp_ackObjects
	if err := loadXdp_ackObjects(&objs, nil); err != nil {
		panic(err)
	}
	ifname := "enp52s0" // Change this to an interface on your machine.
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		panic(err)
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Interface: iface.Index,
		Program:   objs.XdpAck,
	})

	if err != nil {
		panic(err)
	}

	return Attachment{Link: xdpLink, Objects: objs}
}
