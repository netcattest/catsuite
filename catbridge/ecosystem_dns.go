package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"golang.org/x/net/dns/dnsmessage"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func taskRPCClient() *http.Client {
	return &http.Client{Timeout: 8 * time.Second, Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "unix", "/ipc/broker.sock")
	}}}
}
func taskDNSPacket(ctx context.Context, packet []byte) []byte {
	var parser dnsmessage.Parser
	header, e := parser.Start(packet)
	if e != nil {
		return nil
	}
	question, e := parser.Question()
	if e != nil || question.Class != dnsmessage.ClassINET {
		return nil
	}
	if _, err := parser.Question(); err != dnsmessage.ErrSectionDone {
		return nil
	}
	kind := map[dnsmessage.Type]string{dnsmessage.TypeA: "A", dnsmessage.TypeAAAA: "AAAA", dnsmessage.TypeCNAME: "CNAME", dnsmessage.TypeMX: "MX", dnsmessage.TypeNS: "NS", dnsmessage.TypeTXT: "TXT"}[question.Type]
	answer := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: header.ID, Response: true, RecursionDesired: header.RecursionDesired, RecursionAvailable: true})
	answer.EnableCompression()
	answer.StartQuestions()
	answer.Question(question)
	answer.StartAnswers()
	if kind != "" {
		body, _ := json.Marshal(map[string]string{"name": strings.TrimSuffix(question.Name.String(), "."), "type": kind})
		request, _ := http.NewRequestWithContext(ctx, "POST", "http://catbridge.internal/_catsuite/dns", bytes.NewReader(body))
		reply, e := taskRPCClient().Do(request)
		if e == nil {
			defer reply.Body.Close()
			var result struct {
				Records []string `json:"records"`
			}
			if reply.StatusCode == 200 && json.NewDecoder(io.LimitReader(reply.Body, 256*1024)).Decode(&result) == nil {
				recordHeader := dnsmessage.ResourceHeader{Name: question.Name, Type: question.Type, Class: dnsmessage.ClassINET, TTL: 0}
				for _, value := range result.Records {
					switch question.Type {
					case dnsmessage.TypeA:
						if ip := net.ParseIP(value).To4(); ip != nil {
							var data [4]byte
							copy(data[:], ip)
							answer.AResource(recordHeader, dnsmessage.AResource{A: data})
						}
					case dnsmessage.TypeAAAA:
						if ip := net.ParseIP(value).To16(); ip != nil {
							var data [16]byte
							copy(data[:], ip)
							answer.AAAAResource(recordHeader, dnsmessage.AAAAResource{AAAA: data})
						}
					case dnsmessage.TypeCNAME:
						name, err := dnsmessage.NewName(strings.TrimSuffix(value, ".") + ".")
						if err == nil {
							answer.CNAMEResource(recordHeader, dnsmessage.CNAMEResource{CNAME: name})
						}
					case dnsmessage.TypeNS:
						name, err := dnsmessage.NewName(strings.TrimSuffix(value, ".") + ".")
						if err == nil {
							answer.NSResource(recordHeader, dnsmessage.NSResource{NS: name})
						}
					case dnsmessage.TypeMX:
						parts := strings.SplitN(value, " ", 2)
						if len(parts) == 2 {
							preference, _ := strconv.Atoi(parts[0])
							name, err := dnsmessage.NewName(strings.TrimSuffix(parts[1], ".") + ".")
							if err == nil {
								answer.MXResource(recordHeader, dnsmessage.MXResource{Pref: uint16(preference), MX: name})
							}
						}
					case dnsmessage.TypeTXT:
						parts := []string{}
						for len(value) > 255 {
							parts = append(parts, value[:255])
							value = value[255:]
						}
						parts = append(parts, value)
						answer.TXTResource(recordHeader, dnsmessage.TXTResource{TXT: parts})
					}
				}
			}
		}
	}
	result, e := answer.Finish()
	if e != nil || len(result) > 8192 {
		return nil
	}
	return result
}
func taskDNS(ctx context.Context) (func(), error) {
	udp, e := net.ListenPacket("udp", "127.0.0.1:53")
	if e != nil {
		return nil, e
	}
	tcp, e := net.Listen("tcp", "127.0.0.1:53")
	if e != nil {
		udp.Close()
		return nil, e
	}
	slots := make(chan struct{}, 4)
	go func() {
		for {
			buffer := make([]byte, 8192)
			count, address, e := udp.ReadFrom(buffer)
			if e != nil {
				return
			}
			select {
			case slots <- struct{}{}:
				go func(data []byte, peer net.Addr) {
					defer func() { <-slots }()
					if result := taskDNSPacket(ctx, data); len(result) > 0 {
						udp.WriteTo(result, peer)
					}
				}(buffer[:count], address)
			default:
			}
		}
	}()
	go func() {
		for {
			conn, e := tcp.Accept()
			if e != nil {
				return
			}
			select {
			case slots <- struct{}{}:
				go func() {
					defer conn.Close()
					defer func() { <-slots }()
					conn.SetDeadline(time.Now().Add(10 * time.Second))
					length := make([]byte, 2)
					if _, e := io.ReadFull(conn, length); e != nil {
						return
					}
					size := binary.BigEndian.Uint16(length)
					if size > 8192 {
						return
					}
					data := make([]byte, size)
					if _, e := io.ReadFull(conn, data); e != nil {
						return
					}
					result := taskDNSPacket(ctx, data)
					binary.BigEndian.PutUint16(length, uint16(len(result)))
					conn.Write(length)
					conn.Write(result)
				}()
			default:
				conn.Close()
			}
		}
	}()
	return func() { udp.Close(); tcp.Close() }, nil
}
