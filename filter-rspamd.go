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

	"encoding/json"
	"log"
	"net/http"
)

var rspamdURL *string

type session struct {
	id string

	rdns     string
	src      string
	heloName string
	userName string
	mtaName  string

	msgid    string
	mailFrom string
	rcptTo   []string
	message  []string

	action   string
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
	DKIMSig string `json:"dkim-signature"`
	Headers struct {
		Remove map[string]int8        `json:"remove_headers"`
		Add    map[string]interface{} `json:"add_headers"`
	} `json:"milter"`
	Symbols map[string]interface{} `json:"symbols"`
}

var sessions = make(map[string]*session)

var reporters = map[string]func(*session, []string){
	"link-connect":    linkConnect,
	"link-disconnect": linkDisconnect,
	"link-greeting":   linkGreeting,
	"link-identify":   linkIdentify,
	"link-auth":       linkAuth,
	"tx-reset":        txReset,
	"tx-begin":        txBegin,
	"tx-mail":         txMail,
	"tx-rcpt":         txRcpt,
}

var filters = map[string]func(*session, []string){
	"data-line": dataLine,
	"commit":    dataCommit,
}

func linkConnect(s *session, params []string) {
	if len(params) != 4 {
		log.Fatal("invalid input, shouldn't happen")
	}

	s.rdns = params[0]
	s.src = params[2]
}

func linkDisconnect(s *session, params []string) {
	if len(params) != 0 {
		log.Fatal("invalid input, shouldn't happen")
	}
	delete(sessions, s.id)
}

func linkGreeting(s *session, params []string) {
	if len(params) != 1 {
		log.Fatal("invalid input, shouldn't happen")
	}

	s.mtaName = params[0]
}

func linkIdentify(s *session, params []string) {
	if len(params) != 2 {
		log.Fatal("invalid input, shouldn't happen")
	}

	s.heloName = params[1]
}

func linkAuth(s *session, params []string) {
	if len(params) != 2 {
		log.Fatal("invalid input, shouldn't happen")
	}
	if params[1] != "pass" {
		return
	}

	s.userName = params[0]
}

func txReset(s *session, params []string) {
	if len(params) != 1 {
		log.Fatal("invalid input, shouldn't happen")
	}

	s.msgid = ""
	s.mailFrom = ""
	s.rcptTo = nil
	s.message = nil
	s.action = ""
	s.response = ""
}

func txBegin(s *session, params []string) {
	if len(params) != 1 {
		log.Fatal("invalid input, shouldn't happen")
	}

	s.msgid = params[0]
}

func txMail(s *session, params []string) {
	if len(params) != 3 {
		log.Fatal("invalid input, shouldn't happen")
	}

	if params[2] != "ok" {
		return
	}

	s.mailFrom = params[1]
}

func txRcpt(s *session, params []string) {
	if len(params) != 3 {
		log.Fatal("invalid input, shouldn't happen")
	}

	if params[2] != "ok" {
		return
	}

	s.rcptTo = append(s.rcptTo, params[1])
}

func dataLine(s *session, params []string) {
	if len(params) < 2 {
		log.Fatal("invalid input, shouldn't happen")
	}
	token := params[0]
	line := strings.Join(params[1:], "|")

	if line == "." {
		go rspamdQuery(s, token)
		return
	}
	s.message = append(s.message, line)
}

func dataCommit(s *session, params []string) {
	if len(params) != 2 {
		log.Fatal("invalid input, shouldn't happen")
	}

	token := params[0]

	switch s.action {
	case "reject":
		if s.response == "" {
			s.response = "message rejected"
		}
		fmt.Printf("filter-result|%s|%s|reject|550 %s\n", token, s.id, s.response)
	case "greylist":
		if s.response == "" {
			s.response = "try again later"
		}
		fmt.Printf("filter-result|%s|%s|reject|421 %s\n", token, s.id, s.response)
	case "soft reject":
		if s.response == "" {
			s.response = "try again later"
		}
		fmt.Printf("filter-result|%s|%s|reject|451 %s\n", token, s.id, s.response)
	default:
		fmt.Printf("filter-result|%s|%s|proceed\n", token, s.id)
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

func flushMessage(s *session, token string) {
	for _, line := range s.message {
		fmt.Printf("filter-dataline|%s|%s|%s\n", token, s.id, line)
	}
	fmt.Printf("filter-dataline|%s|%s|.\n", token, s.id)
}

func writeHeader(s *session, token string, h string, t string) {
	for i, line := range strings.Split(t, "\n") {
		if i == 0 {
			fmt.Printf("filter-dataline|%s|%s|%s: %s\n",
				token, s.id, h, line)
		} else {
			fmt.Printf("filter-dataline|%s|%s|%s\n",
				token, s.id, line)
		}
	}
}

func rspamdQuery(s *session, token string) {
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

		if len(rr.Symbols) != 0 {
			buf := ""
			for k, _ := range rr.Symbols {
				if buf == "" {
					buf = fmt.Sprintf("%s%s", buf, k)
				} else {
					buf = fmt.Sprintf("%s,\n %s", buf, k)
				}
			}
			writeHeader(s, token, "X-Spam-Symbols", buf)
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
				writeHeader(s, token, h, v)
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
					writeHeader(s, token, h, authHeaders[h])
				}
			}
		}
	}

	inhdr := true
	rmhdr := false

LOOP:

	for _, line := range s.message {
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
			fmt.Printf("filter-dataline|%s|%s|Subject: %s\n", token, s.id, rr.Subject)
		} else {
			fmt.Printf("filter-dataline|%s|%s|%s\n", token, s.id, line)
		}
	}
	fmt.Printf("filter-dataline|%s|%s|.\n", token, s.id)
}

func trigger(actions map[string]func(*session, []string), atoms []string) {
	if atoms[4] == "link-connect" {
		// special case to simplify subsequent code
		s := session{}
		s.id = atoms[5]
		sessions[s.id] = &s
	}

	s := sessions[atoms[5]]
	if v, ok := actions[atoms[4]]; ok {
		v(s, atoms[6:])
	} else {
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
