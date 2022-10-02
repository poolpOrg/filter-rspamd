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
The filter is written in Golang and doesn't have any dependencies beyond the Go extended standard library.

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

Install using Go:
```
$ GO111MODULE=on go get github.com/poolpOrg/filter-rspamd
$ doas install -m 0555 ~/go/bin/filter-rspamd /usr/local/libexec/smtpd/filter-rspamd
```

Alternatively, clone the repository, build and install the filter:
```
$ cd filter-rspamd/
$ go build
$ doas install -m 0555 filter-rspamd /usr/local/libexec/smtpd/filter-rspamd
```

On Ubuntu the directory to install to is different:
```
$ sudo install -m 0555 filter-rspamd /usr/libexec/opensmtpd/filter-rspamd
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

Optionally a `-settings-id` parameter can be used to select a specific rspamd
setting. One usecase is for example to apply different rspamd rules to incoming
and outgoing emails:

```
filter "rspamd-incoming" proc-exec "filter-rspamd"
filter "rspamd-outgoing" proc-exec "filter-rspamd -settings-id outgoing"

listen on all filter "rspamd-incoming"
listen on all port submission filter "rspamd-outgoing"
```

And in `rspamd/local.d/settings.conf`:

```
outgoing {
    id = "outgoing";
    apply {
        groups_enabled = ["dkim"];
        actions {
            reject = 100.0;
            greylist = 100.0;
            "add header" = 100.0;
        }
    }
}
```

Every email passed through the `rspamd-outgoing` filter will use the rspamd `outgoing` rule instead of the default rule.

Any configuration with regard to thresholds or enabled modules must be done in rspamd itself.
