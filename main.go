package main

import (
	"flag"
	"fmt"
	"net"
)

const serverIp = "192.168.50.224"
const serverPort = 12345

func main(){
	isServer := flag.Bool("server", false, "true")
	flag.Parse()
	if *isServer{
		StartServer()
	} else{
		StartClient()
	}
}

func StartClient(){
	addr := net.UDPAddr{
		Port: serverPort,
		IP:   net.ParseIP(serverIp),
	}

	conn, err := net.DialUDP("udp", nil, &addr)
	if err != nil{
		panic(err)
	}
	defer conn.Close()

	for {
		_, err = conn.Write([]byte("Hiiiiiiiiiiiiiiiii"))
		if err != nil{
			panic(err)
		}
	}

}

func StartServer(){
	addr := net.UDPAddr{
		Port: serverPort,
		IP:   net.ParseIP(serverIp),
	}

	conn, err := net.ListenUDP("udp", &addr)
	if err != nil{
		panic(err)
	}

	defer conn.Close()
	buffer := make([]byte, 1024)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buffer)
		if err != nil{
			panic(err)
		}
		fmt.Printf("Received message %s from %s\n", string(buffer[:n]), clientAddr)
	}

}
