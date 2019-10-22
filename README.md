# filter-rspamd

## Description
This filter implements the Rspamd protocol and allows OpenSMTPD to request an Rspamd analysis
of an SMTP transaction before a message is committed to queue.


## Features
The filter currently supports:

- greylisting
- adding X-Spam related headers to a message
- rewriting Subject
- DKIM-signing message
- Rspamd-provided SMTP replies
- Allow Rspamd to add and remove headers


## Dependencies
The filter is written in Golang and doesn't have any dependencies beyond standard library.

It requires OpenSMTPD 6.6.0 or higher.


## How to install
Install from your operating system's preferred package manager if available.
On OpenBSD:
```
$ doas pkg_add opensmtpd-filter-rspamd
quirks-3.167 signed on 2019-08-11T14:18:58Z
opensmtpd-filter-rspamd-0.1.x: ok
$
```

Alternatively, clone the repository, build and install the filter:
```
$ cd filter-rspamd/
$ go build
$ doas install -m 0555 filter-rspamd /usr/local/libexec/smtpd/filter-rspamd
```


## How to configure
The filter itself requires no configuration.

It must be declared in smtpd.conf and attached to a listener for sessions to go through rspamd:
```
filter "rspamd" proc-exec "filter-rspamd"

listen on all filter "rspamd"
```

A remote rspamd instance can be specified by providing the -url parameter to the filter:
```
filter "rspamd" proc-exec "filter-rspamd -url http://example.org:11333"

listen on all filter "rspamd"
```


Any configuration with regard to thresholds or enabled modules must be done in rspamd itself.
