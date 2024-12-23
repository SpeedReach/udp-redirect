package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"time"

	"github.com/SpeedReach/udp_redirect/tc_redirect"
	"github.com/SpeedReach/udp_redirect/tc_sequencer"
	"github.com/SpeedReach/udp_redirect/xdp_ack"
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
	if !*isServer{
		ebpf := tc_sequencer.AttachEbpf()
		defer ebpf.Close()
		println("Sequencer Attached.")
		for{}
	}else{
		go sequencerTestReceive()
		sequencerTestSend()
	}

	return
	if *isServer{
		//link := xdp_ack.AttachEbpf()

		for i := 0; i < serverCount; i++{
			server := NewServer(serverIp[i], serverPort[i])
			go func ()  {
				defer server.Close()
				server.Start()
			}()
		}
		//defer link.Close()
		for {}
	} else{
		client := NewClient(ackIp, ackPort, true)
		defer client.Close()
		client.StartClient()
	}
}


func sequencerTestSend(){
	//create udp conn and send to sequencer
	conn, err := net.Dial("udp", fmt.Sprintf("%s:%d", "192.168.50.213", 12345))
	if err != nil{
		panic(err)
	}
	defer conn.Close()
	payload := make([]byte, packetSize + 6)
	payload[0] = ' '
	payload[1] = ' '
	for i := 0; i < packetSize+2; i++{
		payload[i+2] = 'H'
	}
	payload[packetSize+2] = ' '
	payload[packetSize+3] = ' '
	payload[packetSize+4] = ' '
	payload[packetSize+5] = ' '

	for {
		conn.Write(payload)
		time.Sleep(time.Second)
	}
}

func sequencerTestReceive(){
	addr := net.UDPAddr{
		Port: 12346,
		IP:   net.ParseIP("192.168.50.224"),
	}
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil{
		panic(err)
	}
	defer conn.Close()
	
	for{
		buffer := make([]byte, packetSize + 1000)
		n, _, err := conn.ReadFromUDP(buffer)
		if err != nil{
			panic(err)
		}
		sequenceBytes := buffer[n-4:n]
		sequence := binary.LittleEndian.Uint32(sequenceBytes)
		fmt.Printf("Received sequence %d\n", sequence)
		fmt.Printf("Received message: %s", string(buffer[:n-4]))
		totalH := 0
		for i := 0; i < n ; i++{
			if buffer[i] != 'H'{
				println(fmt.Sprintf("Not H at %d but %d", i, buffer[i]))
			} else{
				totalH += 1
			}
		}
		fmt.Printf("Total H: %d\n", totalH)
	}
}


type Client struct{
	broadcastConn []*net.UDPConn
	ackConn *net.UDPConn
	ebpfAttachment tc_redirect.Attachment
	useEbpf bool
}

func NewClient(ackIp string, ackPort int, useEbpf bool) Client{
	link := tc_redirect.AttachEbpf()
	var broadcastConns []*net.UDPConn
	for i := 0; i < serverCount; i++{
		var addr net.UDPAddr
		if useEbpf{
			addr = net.UDPAddr{
				Port: redirectPort,
				IP:   net.ParseIP(redirectIp),
			}
		}else{
			addr = net.UDPAddr{
				Port: serverPort[i],
				IP:   net.ParseIP(serverIp[i]),
			}
		}
		
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
		useEbpf: useEbpf,
	}
}

func (c Client) Close(){
	defer	c.ackConn.Close()
	defer	c.ebpfAttachment.Close()
	for _, conn := range c.broadcastConn{
		defer conn.Close()
	}
}

const packetSize = 9000


func (client Client) StartClient(){
	count := 0
	stopTimer := time.After(time.Second * 10)
	defer client.Close()
	for {
		for i := 0; i < serverCount; i++{
			var arr = make([]byte, packetSize+6)
			arr[0] =' '
			arr[1] = ' '
			for j := 0; j < packetSize; j++{
				arr[j+2] = 'H'
			}
			arr[packetSize] = ' '
			arr[packetSize+1] = ' '
			arr[packetSize+2] = ' '
			arr[packetSize+3] = ' '
			_, err := client.broadcastConn[i].Write(arr)
			if err != nil{
				panic(err)
			}
			if client.useEbpf{
				break
			}
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
	ebpfAttachment xdp_ack.Attachment
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
	defer s.conn.Close()
	defer s.ackConn.Close()
	defer s.ebpfAttachment.Close()
}

func (s Server) Start(){

	buffer := make([]byte, packetSize)
	for {
		n, clientAddr, err := s.conn.ReadFromUDP(buffer)
		if err != nil{
			panic(err)
		}
		mes := string(buffer[:n])
		
		for i := 0; i < packetSize; i++{
			if(mes[i] != 'H'){
				panic(fmt.Sprintf("Not H at %d", i))
			}
		}

		println("Received message from ", clientAddr.String())

		_, err = s.ackConn.Write([]byte("Ack"))
		if err != nil{
			panic(err)
		}
	}
}

