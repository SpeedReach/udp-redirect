package main

import (
	"flag"
	"fmt"
	"net"
	"time"

	"github.com/SpeedReach/udp_redirect/tc_redirect"
)


const serverCount = 3
var serverIp =[serverCount]string{
	"192.168.50.224",
	"192.168.50.224",
	"192.168.50.224",
}

var serverPort = [serverCount]int{
	12346,
	12347,
	12348,
}

const redirectPort = 12345
const redirectIp = "192.168.50.230"

const ackPort = 12345
const ackIp = "192.168.50.213"

func main(){
	isServer := flag.Bool("server", false, "true")
	flag.Parse()
	if *isServer{
		for i := 0; i < serverCount; i++{
			server := NewServer(serverIp[i], serverPort[i])
			defer server.Close()
			go server.Start()
		}
		for {}
	} else{
		client := NewClient(ackIp, ackPort)
		defer client.Close()
		client.StartClient()
	}
}

type Client struct{
	broadcastConn []*net.UDPConn
	ackConn *net.UDPConn
	ebpfAttachment tc_redirect.Attachment
}

func NewClient(ackIp string, ackPort int) Client{
	link := tc_redirect.AttachEbpf()
	var broadcastConns []*net.UDPConn
	for i := 0; i < serverCount; i++{
		addr := net.UDPAddr{
			Port: redirectPort,
			IP:   net.ParseIP(redirectIp),
		}
		//addr := net.UDPAddr{
		//	Port: serverPort[i],
		//	IP:   net.ParseIP(serverIp[i]),
		//}
		broadcastConn, err := net.DialUDP("udp", nil, &addr)
		if err != nil{
			panic(err)
		}
		broadcastConns = append(broadcastConns, broadcastConn)
	}


	ackAddr := net.UDPAddr{
		Port: ackPort,
		IP:   net.ParseIP(ackIp),
	}

	ackConn, err := net.ListenUDP("udp", &ackAddr)
	if err != nil{
		panic(err)
	}

	return Client{
		ebpfAttachment: link,
		broadcastConn: broadcastConns,
		ackConn: ackConn,
	}
}

func (c Client) Close(){
	defer	c.ackConn.Close()
	defer	c.ebpfAttachment.Close()
	for _, conn := range c.broadcastConn{
		defer conn.Close()
	}
}


func (client Client) StartClient(){
	count := 0
	stopTimer := time.After(time.Minute)
	defer client.Close()
	for {
		for i := 0; i < serverCount; i++{
			_, err := client.broadcastConn[i].Write([]byte("Hiiiiiiiiiiiiiiiii"))
			if err != nil{
				panic(err)
			}
			break
		}
		//collect serverCount acks
		for i := 0; i < serverCount; i++{
			buffer := make([]byte, 1024)
			n, _, err := client.ackConn.ReadFromUDP(buffer)
			if err != nil{
				panic(err)
			}
			fmt.Printf("Received  %d ack %s\n", i, string(buffer[:n]))
		}
		count += 1
		select {
		case <-stopTimer:
			fmt.Printf("Sent %d messages\n", count)
			return
		default:
			continue
		}
	}
}


type Server struct{
	Ip string
	Port int
	conn *net.UDPConn
	ackConn *net.UDPConn
}

func NewServer(ip string, port int) Server{
	addr := net.UDPAddr{
		Port: port,
		IP:   net.ParseIP(ip),
	}

	conn, err := net.ListenUDP("udp", &addr)
	if err != nil{
		panic(err)
	}
	ackAddr := net.UDPAddr{
		Port: ackPort,
		IP:   net.ParseIP(ackIp),
	}
	ackConn, err := net.DialUDP("udp", nil, &ackAddr)
	if err != nil{
		panic(err)
	}
	return Server{
		Ip: ip,
		Port: port,
		conn: conn,
		ackConn: ackConn,
	}

}

func (s Server) Close(){
	s.conn.Close()
}

func (s Server) Start(){
	buffer := make([]byte, 1024)
	for {
		n, clientAddr, err := s.conn.ReadFromUDP(buffer)
		if err != nil{
			panic(err)
		}
		fmt.Printf("%d Received  message %s from %s\n",s.Port, string(buffer[:n]), clientAddr)

		_, err = s.ackConn.Write([]byte("Ack"))
		if err != nil{
			panic(err)
		}
	}
}

