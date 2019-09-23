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
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"log"
	"net/http"
	"encoding/json"
)

var rspamdURL *string

type session struct {
	id string

	rdns string
	src string
	heloName string
	userName string
	mtaName string

	msgid string
	mailFrom string
	rcptTo []string
	message []string

	action string
	response string
}

type rspamd struct {
	Score         float32
	RequiredScore float32 `json:"required_score"`
	Subject       string
	Action        string
	Messages      struct {
		SMTP string `json:"smtp_message"`
	} `json:"messages"`
	DKIMSig       string `json:"dkim-signature"`
}

var sessions = make(map[string]session)

var reporters = map[string]func(string, []string) {
	"link-connect": linkConnect,
	"link-disconnect": linkDisconnect,
	"link-greeting": linkGreeting,
	"link-identify": linkIdentify,
	"link-auth": linkAuth,
	"tx-reset": txReset,
	"tx-begin": txBegin,
	"tx-mail": txMail,
	"tx-rcpt": txRcpt,
}

var filters = map[string]func(string, []string) {
	"data-line": dataLine,
	"commit": dataCommit,
}

func linkConnect(sessionId string, params []string) {
	if len(params) != 4 {
		log.Fatal("invalid input, shouldn't happen")
	}

	s := session{}
	s.id = sessionId
	s.rdns = params[0]
	s.src = params[2]
	sessions[s.id] = s
}

func linkDisconnect(sessionId string, params []string) {
	if len(params) != 0 {
		log.Fatal("invalid input, shouldn't happen")
	}
	delete(sessions, sessionId)
}

func linkGreeting(sessionId string, params []string) {
	if len(params) != 1 {
		log.Fatal("invalid input, shouldn't happen")
	}

	s := sessions[sessionId]
	s.mtaName = params[0]
	sessions[s.id] = s
}

func linkIdentify(sessionId string, params []string) {
	if len(params) != 2 {
		log.Fatal("invalid input, shouldn't happen")
	}

	s := sessions[sessionId]
	s.heloName = params[1]
	sessions[s.id] = s
}

func linkAuth(sessionId string, params []string) {
	if len(params) != 2 {
		log.Fatal("invalid input, shouldn't happen")
	}
	if params[1] != "pass" {
		return
	}
	s := sessions[sessionId]
	s.userName = params[0]
	sessions[s.id] = s
}

func txReset(sessionId string, params []string) {
	if len(params) != 1 {
		log.Fatal("invalid input, shouldn't happen")
	}

	s := sessions[sessionId]
	s.msgid = ""
	s.mailFrom = ""
	s.rcptTo = nil
	s.message = nil
	s.action = ""
	s.response = ""
	sessions[s.id] = s
}

func txBegin(sessionId string, params []string) {
	if len(params) != 1 {
		log.Fatal("invalid input, shouldn't happen")
	}

	s := sessions[sessionId]
	s.msgid = params[0]
	sessions[s.id] = s
}

func txMail(sessionId string, params []string) {
	if len(params) != 3 {
		log.Fatal("invalid input, shouldn't happen")
	}

	if params[2] != "ok" {
		return
	}

	s := sessions[sessionId]
	s.mailFrom = params[1]
	sessions[s.id] = s
}

func txRcpt(sessionId string, params []string) {
	if len(params) != 3 {
		log.Fatal("invalid input, shouldn't happen")
	}

	if params[2] != "ok" {
		return
	}

	s := sessions[sessionId]
	s.rcptTo = append(s.rcptTo, params[1])
	sessions[s.id] = s
}

func dataLine(sessionId string, params []string) {
	if len(params) < 2 {
		log.Fatal("invalid input, shouldn't happen")
	}
	token := params[0]
	line := strings.Join(params[1:], "|")

	s := sessions[sessionId]
	if line == "." {
		go rspamdQuery(s, token)
		return
	}
	s.message = append(s.message, line)
	sessions[sessionId] = s
}

func dataCommit(sessionId string, params []string) {
	if len(params) != 2 {
		log.Fatal("invalid input, shouldn't happen")
	}

	token := params[0]
	s := sessions[sessionId]
	sessions[sessionId] = s

	switch s.action {
	case "reject":
		if( s.response == "") {
			s.response = "message rejected"
		}
		fmt.Printf("filter-result|%s|%s|reject|550 %s\n", token, sessionId, s.response)
	case "greylist":
		if( s.response == "") {
			s.response = "try again later"
		}
		fmt.Printf("filter-result|%s|%s|reject|421 %s\n", token, sessionId, s.response)
	case "soft reject":
		if( s.response == "") {
			s.response = "try again later"
		}
		fmt.Printf("filter-result|%s|%s|reject|451 %s\n", token, sessionId, s.response)
	default:
		fmt.Printf("filter-result|%s|%s|proceed\n", token, sessionId)
	}
}

func filterInit() {
	for k := range reporters {
		fmt.Printf("register|report|smtp-in|%s\n", k)
	}
	for k := range filters {
		fmt.Printf("register|filter|smtp-in|%s\n", k)
	}
	fmt.Println("register|ready")
}

func flushMessage(s session, token string) {
	for _, line := range s.message {
		fmt.Printf("filter-dataline|%s|%s|%s\n", token, s.id, line)
	}
	fmt.Printf("filter-dataline|%s|%s|.\n", token, s.id)
}

func writeHeader(s session, token string, h string, t string ) {
	for i, line := range strings.Split( t, "\n") {
		if i == 0 {
			fmt.Printf("filter-dataline|%s|%s|%s: %s\n",
				token, s.id, h, line)
		} else {
			fmt.Printf("filter-dataline|%s|%s|%s\n",
				token, s.id, line)
		}
	}
}

func rspamdQuery(s session, token string) {
	r := strings.NewReader(strings.Join(s.message, "\n"))
	client := &http.Client{}
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/checkv2", *rspamdURL), r)
	if err != nil {
		flushMessage(s, token)
		return
	}

	req.Header.Add("Pass", "All")
	if !strings.HasPrefix(s.src, "unix:") {
		if s.src[0] == '[' {
			ip := strings.Split(strings.Split(s.src, "]")[0], "[")[1]
			req.Header.Add("Ip", ip)
		} else {
			ip := strings.Split(s.src, ":")[0]
			req.Header.Add("Ip", ip)
		}
	} else {
		req.Header.Add("Ip", "127.0.0.1")
	}

	req.Header.Add("Hostname", s.rdns)
	req.Header.Add("Helo", s.heloName)
	req.Header.Add("MTA-Name", s.mtaName)
	req.Header.Add("Queue-Id", s.msgid)
	req.Header.Add("From", s.mailFrom)

	if s.userName != "" {
		req.Header.Add("User", s.userName)
	}

	for _, rcptTo := range s.rcptTo {
		req.Header.Add("Rcpt", rcptTo)
	}

	resp, err := client.Do(req)
	if err != nil {
		flushMessage(s, token)
		return
	}
	defer resp.Body.Close()

	rr := &rspamd{}
	if err := json.NewDecoder(resp.Body).Decode(rr); err != nil {
		flushMessage(s, token)
		return
	}

	switch rr.Action {
	case "reject":
		fallthrough
	case "greylist":
		fallthrough
	case "soft reject":
		s.action = rr.Action
		s.response = rr.Messages.SMTP
		sessions[s.id] = s
		flushMessage(s, token)
		return
	}

	if rr.DKIMSig != "" {
		writeHeader(s, token, "DKIM-Signature", rr.DKIMSig)
	}

	if rr.Action == "add header" {
		fmt.Printf("filter-dataline|%s|%s|%s: %s\n",
			token, s.id, "X-Spam", "yes")
		fmt.Printf("filter-dataline|%s|%s|%s: %s\n",
			token, s.id, "X-Spam-Score",
			fmt.Sprintf("%v / %v",
				rr.Score, rr.RequiredScore))
	}

	inhdr := true
	for _, line := range s.message {
		if line == "" {
			inhdr = false
		}
		if rr.Action == "rewrite subject" && inhdr && strings.HasPrefix(line, "Subject: ") {
			fmt.Printf("filter-dataline|%s|%s|Subject: %s\n", token, s.id, rr.Subject)
		} else {
			fmt.Printf("filter-dataline|%s|%s|%s\n", token, s.id, line)
		}
	}
	fmt.Printf("filter-dataline|%s|%s|.\n", token, s.id)
	sessions[s.id] = s
}

func trigger(currentSlice map[string]func(string, []string), atoms []string) {
	found := false
	for k, v := range currentSlice {
		if k == atoms[4] {
			v(atoms[5], atoms[6:])
			found = true
			break
		}
	}
	if !found {
		os.Exit(1)
	}
}

func skipConfig(scanner *bufio.Scanner) {
	for {
		if !scanner.Scan() {
			os.Exit(0)
		}
		line := scanner.Text()
		if line == "config|ready" {
			return
		}
	}
}

func main() {
	rspamdURL = flag.String("url", "http://localhost:11333", "rspamd base url")
	flag.Parse()

	scanner := bufio.NewScanner(os.Stdin)

	skipConfig(scanner)

	filterInit()

	for {
		if !scanner.Scan() {
			os.Exit(0)
		}

		atoms := strings.Split(scanner.Text(), "|")
		if len(atoms) < 6 {
			os.Exit(1)
		}

		switch atoms[0] {
		case "report":
			trigger(reporters, atoms)
		case "filter":
			trigger(filters, atoms)
		default:
			os.Exit(1)
		}
	}
}
