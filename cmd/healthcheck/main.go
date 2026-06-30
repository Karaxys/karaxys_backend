package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

func main() {
	url := flag.String("url", "", "HTTP URL to check")
	statuses := flag.String("statuses", "200", "comma-separated acceptable HTTP status codes")
	proc := flag.String("proc", "", "procfs status file to check")
	timeout := flag.Duration("timeout", 3*time.Second, "HTTP request timeout")
	flag.Parse()

	if *url != "" {
		if err := checkHTTP(*url, parseStatuses(*statuses), *timeout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	if *proc != "" {
		if _, err := os.Stat(*proc); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}

	fmt.Fprintln(os.Stderr, "healthcheck requires -url or -proc")
	os.Exit(2)
}

func parseStatuses(raw string) map[int]struct{} {
	allowed := make(map[int]struct{})
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		code, err := strconv.Atoi(part)
		if err == nil {
			allowed[code] = struct{}{}
		}
	}
	if len(allowed) == 0 {
		allowed[http.StatusOK] = struct{}{}
	}
	return allowed
}

func checkHTTP(url string, allowed map[int]struct{}, timeout time.Duration) error {
	client := http.Client{Timeout: timeout}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if _, ok := allowed[resp.StatusCode]; ok {
		return nil
	}
	return fmt.Errorf("unexpected HTTP status %d from %s", resp.StatusCode, url)
}
