//
// Copyright (c) 2019 Gilles Chehade <gilles@poolp.org>
//
// Permission to use, copy, modify, and distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
//

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"encoding/json"
	"log"
	"net"
	"net/http"

	"github.com/poolpOrg/OpenSMTPD-framework/filter"
)

var rspamdURL *string
var unixSocketPath string
var rspamdSettingsId *string
var version string

var outputChannel chan string

type tx struct {
	msgid    string
	mailFrom string
	rcptTo   []string
	message  []string
	action   string
	response string
}

type session struct {
	id string

	rdns     string
	src      net.Addr
	heloName string
	userName string
	mtaName  string

	tx tx
}

type rspamd struct {
	Score         float32
	RequiredScore float32 `json:"required_score"`
	Subject       string
	Action        string
	Messages      struct {
		SMTP string `json:"smtp_message"`
	} `json:"messages"`
	DKIMSig interface{} `json:"dkim-signature"`
	Headers struct {
		Remove map[string]int8        `json:"remove_headers"`
		Add    map[string]interface{} `json:"add_headers"`
	} `json:"milter"`
	Symbols map[string]struct {
		Score float32
	} `json:"symbols"`
}

var sessions = make(map[string]*session)

func linkConnectCb(timestamp time.Time, sessionId string, rdns string, fcrdns string, src net.Addr, dest net.Addr) {
	s := &session{}
	s.id = sessionId
	sessions[s.id] = s

	s.rdns = rdns
	s.src = src
}

func linkDisconnectCb(timestamp time.Time, sessionId string) {
	delete(sessions, sessionId)
}

func linkGreetingCb(timestamp time.Time, sessionId string, hostname string) {
	s := sessions[sessionId]
	s.mtaName = hostname
}

func linkIdentifyCb(timestamp time.Time, sessionId string, method string, hostname string) {
	s := sessions[sessionId]
	s.heloName = hostname
}

func linkAuthCb(timestamp time.Time, sessionId string, result string, username string) {
	if result != "pass" {
		return
	}
	s := sessions[sessionId]
	s.userName = username
}

func txResetCb(timestamp time.Time, sessionId string, messageId string) {
	s := sessions[sessionId]
	s.tx = tx{}
}

func txBeginCb(timestamp time.Time, sessionId string, messageId string) {
	s := sessions[sessionId]
	s.tx.msgid = messageId
}

func txMailCb(timestamp time.Time, sessionId string, messageId string, result string, from string) {
	if result != "ok" {
		return
	}
	s := sessions[sessionId]
	s.tx.mailFrom = from
}

func txRcptCb(timestamp time.Time, sessionId string, messageId string, result string, to string) {
	if result != "ok" {
		return
	}

	s := sessions[sessionId]
	s.tx.rcptTo = append(s.tx.rcptTo, to)
}

func dataLine(timestamp time.Time, sessionId string, line string) []string {
	if line == "." {
		s := sessions[sessionId]
		return rspamdQuery(s)
	}

	// Input is raw SMTP data - unescape leading dots.
	line = strings.TrimPrefix(line, ".")
	s := sessions[sessionId]
	s.tx.message = append(s.tx.message, line)
	return []string{}
}

func dataCommit(timestamp time.Time, sessionId string) filter.Response {
	s := sessions[sessionId]
	switch s.tx.action {
	case "tempfail":
		if s.tx.response == "" {
			s.tx.response = "server internal error"
		}
		return filter.Reject("421 " + s.tx.response)

	case "reject":
		if s.tx.response == "" {
			s.tx.response = "message rejected"
		}
		return filter.Reject("550 " + s.tx.response)

	case "soft reject":
		if s.tx.response == "" {
			s.tx.response = "try again later"
		}
		return filter.Reject("451 " + s.tx.response)

	default:
		return filter.Proceed()
	}
}

func flushMessage(s *session) []string {
	return append(s.tx.message, ".")
}

func writeHeader(h string, t string) []string {
	ret := make([]string, 0)
	for i, line := range strings.Split(t, "\n") {
		if i == 0 {
			ret = append(ret, fmt.Sprintf("%s: %s", h, line))
		} else {
			ret = append(ret, fmt.Sprintf("%s", line))
		}
	}
	return ret
}

func rspamdTempFail(s *session, log string) []string {
	s.tx.action = "tempfail"
	s.tx.response = "server internal error"
	fmt.Fprintln(os.Stderr, log)
	return flushMessage(s)
}

func rspamdQuery(s *session) []string {

	ret := make([]string, 0)

	var client *http.Client
	var req *http.Request

	r := strings.NewReader(strings.Join(s.tx.message, "\n"))

	if len(unixSocketPath) > 0 {
		tr := new(http.Transport)
		tr.DisableCompression = true
		tr.Dial = nil
		tr.DialContext = func(_ context.Context, _, _ string) (net.Conn, error) {
			var u_addr *net.UnixAddr
			var err error
			network := "unix"
			u_addr, err = net.ResolveUnixAddr(network, unixSocketPath)
			if err != nil {
				rspamdTempFail(s, fmt.Sprintf("failed to resolve unix path '%s': %v\n", unixSocketPath, err))
				return nil, err
			} else {
				return net.DialUnix(network, nil, u_addr)
			}
		}
		client = &http.Client{Transport: tr}
	} else {
		client = &http.Client{}
	}
	var err error
	req, err = http.NewRequest("POST", fmt.Sprintf("%s/checkv2", *rspamdURL), r)
	if err != nil {
		return rspamdTempFail(s, fmt.Sprintf("failed to initialize HTTP request. err: '%s'", err))
	}

	req.Header.Add("Pass", "All")

	if addr, ok := s.src.(*net.TCPAddr); ok {
		req.Header.Add("Ip", addr.IP.String())
	} else {
		req.Header.Add("Ip", "127.0.0.1")
	}

	req.Header.Add("Hostname", s.rdns)
	req.Header.Add("Helo", s.heloName)
	req.Header.Add("MTA-Name", s.mtaName)
	req.Header.Add("Queue-Id", s.tx.msgid)
	req.Header.Add("From", s.tx.mailFrom)

	if *rspamdSettingsId != "" {
		req.Header.Add("Settings-ID", *rspamdSettingsId)
	}

	if s.userName != "" {
		req.Header.Add("User", s.userName)
	}

	for _, rcptTo := range s.tx.rcptTo {
		req.Header.Add("Rcpt", rcptTo)
	}

	resp, err := client.Do(req)
	if err != nil {
		return rspamdTempFail(s, fmt.Sprintf("failed to receive a response from daemon. err: '%s'", err))
	}

	defer resp.Body.Close()

	rr := &rspamd{}
	if err := json.NewDecoder(resp.Body).Decode(rr); err != nil {
		return rspamdTempFail(s, fmt.Sprintf("failed to decode JSON response, err: '%s'", err))
	}

	switch rr.Action {
	case "reject":
		fallthrough
	case "soft reject":
		s.tx.action = rr.Action
		s.tx.response = rr.Messages.SMTP
		return flushMessage(s)
	}

	switch v := rr.DKIMSig.(type) {
	case []interface{}:
		if len(v) > 0 {
			for _, h := range v {
				h, ok := h.(string)
				if ok && h != "" {
					ret = append(ret, writeHeader("DKIM-Signature", h)...)
				}
			}
		}
	case string:
		if v != "" {
			ret = append(ret, writeHeader("DKIM-Signature", v)...)
		}
	default:
	}

	if rr.Action == "add header" {
		ret = append(ret, fmt.Sprintf("X-Spam: %s", "yes"))
		ret = append(ret, fmt.Sprintf("X-Spam-Score: %.3f / %.3f", rr.Score, rr.RequiredScore))
		if len(rr.Symbols) != 0 {
			symbols := make([]string, len(rr.Symbols))
			buf := &strings.Builder{}
			i := 0

			ret = append(ret, fmt.Sprintf("X-Spam-Status: Yes, score=%.3f required=%.3f", rr.Score, rr.RequiredScore))
			for k := range rr.Symbols {
				symbols[i] = k
				i++
			}

			sort.Strings(symbols)

			buf.WriteString("tests=[")

			for i, k := range symbols {
				sym := fmt.Sprintf("%s=%.3f", k, rr.Symbols[k].Score)

				if buf.Len() > 0 && len(sym)+buf.Len() > 68 {
					ret = append(ret, fmt.Sprintf("\t%s", buf.String()))
					buf.Reset()
				}

				if buf.Len() > 0 && i > 0 {
					buf.WriteString(", ")
				}

				buf.WriteString(sym)
			}

			ret = append(ret, fmt.Sprintf("\t%s]", buf.String()))
			buf.Reset()
		}
	}

	if len(rr.Headers.Add) > 0 {
		authHeaders := map[string]string{}

		for h, t := range rr.Headers.Add {
			switch v := t.(type) {
			/**
			 * Authentication headers from Rspamd are in the form of:
			 * ARC-Seal : { order : 1, value : text }
			 * ARC-Message-Signature : { order : 1, value : text }
			 * Unfortunately they all have an order of 1, so we
			 * make a map of them and print them in proper order.
			 */
			case map[string]interface{}:
				if h != "" {
					v, ok := v["value"].(string)
					if ok {
						authHeaders[h] = v
					}
				}
			/**
			 * Regular X-Spam headers from Rspamd are plain strings.
			 * Insert these at the top.
			 */
			case string:
				ret = append(ret, writeHeader(h, v)...)
			default:
			}
		}

		/**
		 * Prefix auth headers to incoming mail in proper order.
		 */
		if len(authHeaders) > 0 {
			hdrs := []string{
				"ARC-Seal",
				"ARC-Message-Signature",
				"ARC-Authentication-Results",
				"Authentication-Results"}

			for _, h := range hdrs {
				if authHeaders[h] != "" {
					ret = append(ret, writeHeader(h, authHeaders[h])...)
				}
			}
		}
	}

	inhdr := true
	rmhdr := false

LOOP:

	for _, line := range s.tx.message {
		if line == "" {
			inhdr = false
			rmhdr = false
		}

		if inhdr && rmhdr && (strings.HasPrefix(line, "\t") ||
			strings.HasPrefix(line, " ")) {
			continue
		} else {
			rmhdr = false
		}

		if inhdr && len(rr.Headers.Remove) > 0 {
			for h := range rr.Headers.Remove {
				if strings.HasPrefix(line, fmt.Sprintf("%s:", h)) {
					rmhdr = true
					continue LOOP
				}
			}
		}
		if rr.Action == "rewrite subject" && inhdr && strings.HasPrefix(line, "Subject: ") {
			ret = append(ret, fmt.Sprintf("Subject: %s", rr.Subject))
		} else {
			escapePrefix := ""
			if strings.HasPrefix(line, ".") {
				escapePrefix = "."
			}
			ret = append(ret, escapePrefix+line)
		}
	}
	return append(ret, ".")
}

func main() {
	rspamdURL = flag.String("url", "http://localhost:11333", "rspamd base url (or path to unix socket)")
	rspamdSettingsId = flag.String("settings-id", "", "rspamd Settings-ID")

	flag.Parse()

	if err := PledgePromises("stdio rpath inet dns unix unveil"); err != nil {
		log.Fatalf("pledge promise err: %s", err)
	}

	if err := Unveil("/etc/resolv.conf", "r"); err != nil {
		log.Fatalf("unveil resolv err: %s", err)
	}

	if err := Unveil("/etc/hosts", "r"); err != nil {
		log.Fatalf("unveil hosts err: %s", err)
	}

	if !strings.HasPrefix(*rspamdURL, "http") {
		unixSocketPath = *rspamdURL
		*rspamdURL = "http://localhost"

		if err := Unveil(unixSocketPath, "rw"); err != nil {
			log.Fatalf("unveil '%s' err: %s", unixSocketPath, err)
		}

		if _, err := os.Stat(unixSocketPath); err != nil {
			log.Fatalf("unix socket stat '%s' err: '%s'", unixSocketPath, err)
		}

		c, err := net.Dial("unix", unixSocketPath)
		if err != nil {
			log.Fatalf("unix socket connect '%s' err: '%s'", unixSocketPath, err)
		}
		c.Close()
	}

	if err := UnveilBlock(); err != nil {
		log.Fatalf("unveil block err: %s", err)
	}

	filter.Init()

	filter.SMTP_IN.OnLinkConnect(linkConnectCb)
	filter.SMTP_IN.OnLinkDisconnect(linkDisconnectCb)
	filter.SMTP_IN.OnLinkGreeting(linkGreetingCb)
	filter.SMTP_IN.OnLinkIdentify(linkIdentifyCb)
	filter.SMTP_IN.OnLinkAuth(linkAuthCb)
	filter.SMTP_IN.OnTxReset(txResetCb)
	filter.SMTP_IN.OnTxBegin(txBeginCb)
	filter.SMTP_IN.OnTxMail(txMailCb)
	filter.SMTP_IN.OnTxRcpt(txRcptCb)

	filter.SMTP_IN.DataLineRequest(dataLine)
	filter.SMTP_IN.CommitRequest(dataCommit)

	filter.Dispatch()
}
