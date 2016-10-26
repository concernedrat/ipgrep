package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"github.com/miekg/dns"
	"regexp"
	"io/ioutil"
	"strings"
)

type Server struct {
	AAMatcher    *regexp.Regexp
	AAAAMatcher  *regexp.Regexp
	ExternalIpv4 string
	ExternalIpv6 string
}
func getExternalIpv4() string {
	resp, err := http.Get("http://ipv4.myexternalip.com/raw")
	if err != nil {
		log.Println(err)
		return ""
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println(err)
		return ""
	}
	return strings.TrimSpace(string(body))
}

func getExternalIpv6() string {
	resp, err := http.Get("http://ipv6.myexternalip.com/raw")
	if err != nil {
		log.Println(err)
		return ""
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println(err)
		return ""
	}
	return strings.TrimSpace(string(body))
}

func (s *Server) handleARecords(originalName string) []dns.RR {
	ip := s.AAMatcher.FindString(originalName)
	ret := []dns.RR{}
	if len(ip) == 0 {
		ip = s.ExternalIpv4
	}

	ret = append(ret, &dns.A{
		Hdr: dns.RR_Header{
			Name:   originalName,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    0,
		},
		A: net.ParseIP(ip),
	})

	return ret
}


func (s *Server) handleAAAARecords(originalName string) []dns.RR {
	ip := s.AAAAMatcher.FindString(originalName)
	ret := []dns.RR{}
	if len(ip) == 0 {
		ip = s.ExternalIpv6
	}
	ip = strings.Replace(ip, "-", ":", -1)
	ret = append(ret, &dns.AAAA{
		Hdr: dns.RR_Header{
			Name:   originalName,
			Rrtype: dns.TypeAAAA,
			Class:  dns.ClassINET,
			Ttl:    0,
		},
		AAAA: net.ParseIP(ip),
	})

	return ret
}


func (s *Server) handleQuestion(q dns.Question) []dns.RR {

	switch q.Qtype {

	case dns.TypeA:
		as := s.handleARecords(q.Name)
		return as
	case dns.TypeAAAA:
		as := s.handleAAAARecords(q.Name)
		return as
	default:
		return nil
	}

}

// HandleRequest is the main request handler. It recieves, parses and responds to the DNS queries.
func (s *Server)  HandleRequest(w dns.ResponseWriter, r *dns.Msg) {
	resp := &dns.Msg{}
	resp.SetReply(r)

	for _, q := range r.Question {
		ans := s.handleQuestion(q)
		if ans != nil {
			resp.Answer = append(resp.Answer, ans...)
		}
	}

	err := w.WriteMsg(resp)
	if err != nil {
		log.Println("ERROR : " + err.Error())
	}
	w.Close()

}

func NewServer() *Server {
	reg := regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)
	aaaareg := regexp.MustCompile(`(([0-9a-fA-F]{1,4}-){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}-){1,7}-|([0-9a-fA-F]{1,4}-){1,6}-[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}-){1,5}(-[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}-){1,4}(-[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}-){1,3}(-[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}-){1,2}(-[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}-((-[0-9a-fA-F]{1,4}){1,6})|-((-[0-9a-fA-F]{1,4}){1,7}|-)|fe80-(-[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|--(ffff(-0{1,4}){0,1}-){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}-){1,4}-((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))`)
	return &Server{AAMatcher: reg, AAAAMatcher: aaaareg, ExternalIpv4: getExternalIpv4(), ExternalIpv6: getExternalIpv6()}
}

func main() {
	http.Handle("/", http.FileServer(http.Dir("./static")))
	log.Println("HTTP Server listening")
	go http.ListenAndServe(":8080", nil)

	s := NewServer()
	dns.HandleFunc(".", s.HandleRequest)

	log.Println("DNS Server listening")
	server := &dns.Server{Net: "udp", Addr: ":5333"}
	err := server.ListenAndServe()
	fmt.Println(err)
}
