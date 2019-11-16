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
	"sort"

	"encoding/json"
	"log"
	"net/http"
)

var rspamdURL *string

type tx struct {
	msgid    string
	mailFrom string
	rcptTo   []string
	message  []string
	action   string
	response string
}

type session struct {
	id       string

	rdns     string
	src      string
	heloName string
	userName string
	mtaName  string

	tx       tx
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
	Symbols map[string]struct{
		Score   float32
	} `json:"symbols"`
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

	s.tx = tx{}
}

func txBegin(s *session, params []string) {
	if len(params) != 1 {
		log.Fatal("invalid input, shouldn't happen")
	}

	s.tx.msgid = params[0]
}

func txMail(s *session, params []string) {
	if len(params) != 3 {
		log.Fatal("invalid input, shouldn't happen")
	}

	if params[2] != "ok" {
		return
	}

	s.tx.mailFrom = params[1]
}

func txRcpt(s *session, params []string) {
	if len(params) != 3 {
		log.Fatal("invalid input, shouldn't happen")
	}

	if params[2] != "ok" {
		return
	}

	s.tx.rcptTo = append(s.tx.rcptTo, params[1])
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

	// Input is raw SMTP data - unescape leading dots.
	line = strings.TrimPrefix(line, ".")

	s.tx.message = append(s.tx.message, line)
}

func dataCommit(s *session, params []string) {
	if len(params) != 2 {
		log.Fatal("invalid input, shouldn't happen")
	}

	token := params[0]

	switch s.tx.action {
	case "tempfail":
		if s.tx.response == "" {
			s.tx.response = "server internal error"
		}
		fmt.Printf("filter-result|%s|%s|reject|421 %s\n", token, s.id, s.tx.response)
	case "reject":
		if s.tx.response == "" {
			s.tx.response = "message rejected"
		}
		fmt.Printf("filter-result|%s|%s|reject|550 %s\n", token, s.id, s.tx.response)
	case "greylist":
		if s.tx.response == "" {
			s.tx.response = "try again later"
		}
		fmt.Printf("filter-result|%s|%s|reject|421 %s\n", token, s.id, s.tx.response)
	case "soft reject":
		if s.tx.response == "" {
			s.tx.response = "try again later"
		}
		fmt.Printf("filter-result|%s|%s|reject|451 %s\n", token, s.id, s.tx.response)
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
	for _, line := range s.tx.message {
		writeLine(s, token, line)
	}
	fmt.Printf("filter-dataline|%s|%s|.\n", token, s.id)
}

func writeLine(s *session, token string, line string) {
	prefix := ""
	// Output raw SMTP data - escape leading dots.
	if strings.HasPrefix(line, ".") {
		prefix = "."
	}
	fmt.Printf("filter-dataline|%s|%s|%s%s\n", token, s.id, prefix, line)
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

func rspamdTempFail(s *session, token string, log string) {
	s.tx.action   = "tempfail"
	s.tx.response = "server internal error"
	flushMessage(s, token)
	fmt.Fprintln(os.Stderr, log)
}

func rspamdQuery(s *session, token string) {
	r := strings.NewReader(strings.Join(s.tx.message, "\n"))
	client := &http.Client{}
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/checkv2", *rspamdURL), r)
	if err != nil {
		rspamdTempFail(s, token, "failed to initialize HTTP request")
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
	req.Header.Add("Queue-Id", s.tx.msgid)
	req.Header.Add("From", s.tx.mailFrom)

	if s.userName != "" {
		req.Header.Add("User", s.userName)
	}

	for _, rcptTo := range s.tx.rcptTo {
		req.Header.Add("Rcpt", rcptTo)
	}

	resp, err := client.Do(req)
	if err != nil {
		rspamdTempFail(s, token, "failed to receive a response from daemon")
		return
	}

	defer resp.Body.Close()

	rr := &rspamd{}
	if err := json.NewDecoder(resp.Body).Decode(rr); err != nil {
		rspamdTempFail(s, token, "failed to decode JSON response")
		return
	}

	switch rr.Action {
	case "reject":
		fallthrough
	case "greylist":
		fallthrough
	case "soft reject":
		s.tx.action   = rr.Action
		s.tx.response = rr.Messages.SMTP
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
			symbols := make([]string, len(rr.Symbols))
			buf     := &strings.Builder{}
			i       := 0

			fmt.Printf("filter-dataline|%s|%s|%s: %s, score=%.3f required=%.3f\n",
				token, s.id, "X-Spam-Status", "Yes", rr.Score, rr.RequiredScore)

			for k := range rr.Symbols {
				symbols[i] = k
				i++
			}
	
			sort.Strings(symbols)

			buf.WriteString("tests=[")

			for i, k := range symbols {
				sym := fmt.Sprintf("%s=%.3f", k, rr.Symbols[k].Score)

				if buf.Len() > 0 && len(sym) + buf.Len() > 68 {
					fmt.Printf("filter-dataline|%s|%s|\t%s\n",
						token, s.id, buf.String())
					buf.Reset()
				}

				if buf.Len() > 0 && i > 0 {
					buf.WriteString(", ")
				}

				buf.WriteString(sym)
			}

			fmt.Printf("filter-dataline|%s|%s|\t%s]\n",
				token, s.id, buf.String())

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
			fmt.Printf("filter-dataline|%s|%s|Subject: %s\n", token, s.id, rr.Subject)
		} else {
			writeLine(s, token, line)
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
