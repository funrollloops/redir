package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	port    = 80
	dnsAddr = "8.8.8.8:53"
)

func Redirect(w http.ResponseWriter, URL string) {
	fmt.Fprintf(w, "<html><head><meta http-equiv=\"refresh\" content=\"0; url=%v\"></head></html>", URL)
}

type HostHandler func(http.ResponseWriter, *http.Request) error

func RedirectToUrls(params []string) HostHandler {
	return func(w http.ResponseWriter, r *http.Request) error {
		if err := r.ParseForm(); err != nil {
			fmt.Fprintf(w, "Error: %s\n\n", err)
			return err
		}
		for _, param := range params {
			url := r.Form[param]
			if len(url) > 0 {
				//Redirect(w, url[0])
				http.Redirect(w, r, url[0], http.StatusTemporaryRedirect)
				return nil
			}
		}
		return errors.New(fmt.Sprintf("Expected params not found: %v", params))
	}
}

func Proxy(w http.ResponseWriter, r *http.Request) error {
	/*
		if r.URL.Scheme == "" {
			r.URL.Scheme = "http"
		}
	*/
	host, err := Resolv(r.Host)
	if err != nil {
		return err
	}
	r.URL.Host = host
	//r.RequestURI = ""
	httputil.NewSingleHostReverseProxy(&url.URL{
		Scheme: "http",
		Host:   host,
	}).ServeHTTP(w, r)
	return nil
}

func StripCookies(cb HostHandler) HostHandler {
	return func(w http.ResponseWriter, r *http.Request) error {
		r.Header.Del("Cookie")
		return cb(w, r)
	}
}

func SetReferer(referer string, cb HostHandler) HostHandler {
	return func(w http.ResponseWriter, r *http.Request) error {
		r.Header.Set("Referer", referer)
		return cb(w, r)
	}
}

func ProxyNoJS(w http.ResponseWriter, r *http.Request) error {
	if strings.HasSuffix(r.URL.Path, ".js") {
		return nil
	}
	return Proxy(w, r)
}

func Resolv(host string) (string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), dns.TypeA)
	in, err := dns.Exchange(m, dnsAddr)
	if err != nil {
		return "", err
	}
	resolved := ""
	for _, r := range in.Answer {
		ss := strings.Split(r.String(), "\t")
		if resolved == "" || ss[3] == "A" {
			resolved = ss[4]
		}
	}
	if resolved == "" {
		return "", errors.New(fmt.Sprintf("No usable record in return: %v", in))
	}
	return resolved, nil
}

func Resolve(w http.ResponseWriter, r *http.Request) error {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(r.Host), dns.TypeA)
	in, err := dns.Exchange(m, "8.8.8.8:53")
	if err != nil {
		return err
	}
	resolved := ""
	for _, r := range in.Answer {
		fmt.Fprintf(w, "RR.String()=%v\n", r.String())
		ss := strings.Split(r.String(), "\t")
		if resolved == "" || ss[3] == "A" {
			resolved = ss[4]
		}
	}
	fmt.Fprintf(w, "Resolved: %v\n", resolved)
	b, err := json.MarshalIndent(in, "", "\t")
	if err != nil {
		return err
	}
	w.Write(b)
	return nil
}

func ProxyWithAmp(w http.ResponseWriter, r *http.Request) error {
	if strings.HasSuffix(r.URL.Path, "/") && !strings.HasSuffix(r.URL.Path, "/amp/") {
		r.URL.Path += "amp/"
	}
	return Proxy(w, r)
}

type Handler struct {
}

var RedirSpecs = map[string]HostHandler{
	"altfarm.mediaplex.com":     RedirectToUrls([]string{"DURL"}),
	"clickserve.dartsearch.net": RedirectToUrls([]string{"url", "ds_dest_url"}),
	"go.redirectingat.com":      RedirectToUrls([]string{"url"}),
	"ad.doubleclick.net":        RedirectToUrls([]string{"DURL"}),
	"www.forbes.com":            StripCookies(ProxyWithAmp),
	"i.forbesimg.com":           ProxyNoJS,
}

func redir(w http.ResponseWriter, r *http.Request) error {
	if fn, ok := RedirSpecs[r.Host]; ok {
		return fn(w, r)
	}
	return errors.New(fmt.Sprintf("No handler for host \"%v\"", r.Host))
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("Request for http://%v%v\n", r.Host, r.RequestURI)
	if err := redir(w, r); err != nil {
		if strings.HasSuffix(strings.ToLower(r.URL.Path), ".js") {
			fmt.Fprintf(w, "// Error: %v\n// URL: %v", err, r.URL)
			return
		}
		fmt.Fprintf(w, "<html><head><body>")
		defer func() { fmt.Fprintf(w, "</body></head></html>") }()
		fmt.Fprintf(w, "<h2>Request</h2><pre>%v</pre>", r)
		if form_err := r.ParseForm(); form_err != nil {
			fmt.Fprintf(w, "<h2>Form Parse Error</h2><p>%v</p>", form_err)
			return
		}
		fmt.Fprintf(w, "<h2>Form Values</h2><dl>")
		for key, values := range r.Form {
			fmt.Fprintf(w, "<dt>%v", key)
			for _, value := range values {
				if strings.HasPrefix(value, "http") {
					fmt.Fprintf(w, "<dd><a href=\"%v\">%v</a>", value, value)
				} else {
					fmt.Fprintf(w, "<dd>%v", value)
				}
			}
		}
		fmt.Fprintf(w, "</dl>")
	}
}

func main() {
	s := &http.Server{
		Addr:           fmt.Sprintf(":%v", port),
		Handler:        &Handler{},
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	log.Fatal(s.ListenAndServe())
}
