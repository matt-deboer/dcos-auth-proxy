package main

import (
	"bufio"
	"io"
)

func newEventStreamBody(delegate io.ReadCloser) io.ReadCloser {
	return &eventStreamBody{delegate: delegate}
}

type eventStreamBody struct {
	delegate io.ReadCloser
}

func (esb *eventStreamBody) WriteTo(w io.Writer) (n int64, err error) {

	reader := bufio.NewReader(esb.delegate)
	var line []byte
	var written int

	for {
		line, err = reader.ReadBytes('\n')
		if err != nil {
			return
		}
		written, err = w.Write(line)
		if err != nil {
			return
		}
		n += int64(written)
	}
}

func (esb *eventStreamBody) Read(p []byte) (n int, err error) {
	return esb.delegate.Read(p)
}

func (esb *eventStreamBody) Close() error {
	return esb.delegate.Close()
}
