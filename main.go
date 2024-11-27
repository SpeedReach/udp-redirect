package main

import (
	"flag"
	"fmt"
	"net"

	"github.com/SpeedReach/udp_redirect/tc_redirect"
)


const serverCount = 3
var serverIp =[serverCount]string{
	"192.168.50.224",
	"192.168.50.224",
	"192.168.50.224",
}

var serverPort = [serverCount]int{
	12345,
	12346,
	12347,
}

const redirectPort = 12345
const redirectIp = "192.168.50.224"

const ackPort = 12345
const ackIp = "192.168.50.213"

func main(){
	isServer := flag.Bool("server", false, "true")
	flag.Parse()
	if *isServer{
		StartServer()
	} else{
		client := NewClient(ackIp, ackPort)
		defer client.Close()
		client.StartClient()
	}
}

type Client struct{
	broadcastConn *net.UDPConn
	ackConn *net.UDPConn
	ebpfAttachment tc_redirect.Attachment
}

func NewClient(ackIp string, ackPort int) Client{
	link := tc_redirect.AttachEbpf()
	broadcastAddr := net.UDPAddr{
		Port: redirectPort,
		IP:   net.ParseIP(redirectIp),
	}
	broadcastConn, err := net.DialUDP("udp", nil, &broadcastAddr)
	if err != nil{
		panic(err)
	}
	ackAddr := net.UDPAddr{
		IP: net.IP(ackIp),
		Port: ackPort,
	}
	ackConn, err := net.ListenUDP("udp", &ackAddr)
	if err != nil{
		panic(err)
	}

	return Client{
		ebpfAttachment: link,
		broadcastConn: broadcastConn,
		ackConn: ackConn,
	}
}

func (c Client) Close(){
	c.broadcastConn.Close()
	c.ackConn.Close()
	c.ebpfAttachment.Close()
}


func (client Client) StartClient(){
	defer client.Close()
	for {
		_, err := client.broadcastConn.Write([]byte("Hiiiiiiiiiiiiiiiii"))
		if err != nil{
			panic(err)
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
		fmt.Printf("Received message %s from %s\n", string(buffer[:n]), clientAddr)

		_, err = s.ackConn.Write([]byte("Ack"))
		if err != nil{
			panic(err)
		}
	}
}


func StartServer(){
	servers := make([]Server, serverCount)
	for i := 0; i < serverCount; i++{
		servers[i] = NewServer(serverIp[i], serverPort[i])
		defer servers[i].Close()
		go servers[i].Start()
	}
	select{}
}
