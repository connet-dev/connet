package cryptoc

import (
	"crypto/cipher"
	"encoding/binary"
	"io"
	"net"
	"slices"
	"time"
)

type asymStream struct {
	stream io.ReadWriter
	reader cipher.AEAD
	writer cipher.AEAD

	readBuffLen []byte
	readBuff    []byte
	readNonce   []byte

	readPlainBuff  []byte
	readPlainBegin int
	readPlainEnd   int

	writeBuff     []byte
	writeNonce    []byte
	writePlainMax int
}

const maxBuff = 65535

func NewStream(stream io.ReadWriter, reader cipher.AEAD, writer cipher.AEAD) net.Conn {
	return &asymStream{
		stream: stream,
		reader: reader,
		writer: writer,

		readBuffLen: make([]byte, 2),
		readBuff:    make([]byte, maxBuff),
		readNonce:   make([]byte, reader.NonceSize()),

		readPlainBuff:  make([]byte, maxBuff-reader.Overhead()),
		readPlainBegin: 0,
		readPlainEnd:   0,

		writeBuff:     make([]byte, maxBuff),
		writeNonce:    make([]byte, writer.NonceSize()),
		writePlainMax: maxBuff - writer.Overhead() - 2,
	}
}

func (s *asymStream) Read(p []byte) (int, error) {
	var err error
	if s.readPlainBegin >= s.readPlainEnd {
		if _, err := io.ReadFull(s.stream, s.readBuffLen); err != nil {
			return 0, err
		}

		readLen := int(binary.BigEndian.Uint16(s.readBuffLen))
		if n, err := io.ReadFull(s.stream, s.readBuff[:readLen]); err != nil {
			return 0, err
		} else {
			s.readBuff = s.readBuff[:n]
		}

		s.readPlainBuff = s.readPlainBuff[:cap(s.readPlainBuff)]
		s.readPlainBuff, err = s.reader.Open(s.readPlainBuff[:0], s.readNonce, s.readBuff, nil)
		if err != nil {
			return 0, err
		}

		incrementNonce(s.readNonce)

		s.readPlainBegin = 0
		s.readPlainEnd = len(s.readPlainBuff)
	}

	n := copy(p, s.readPlainBuff[s.readPlainBegin:s.readPlainEnd])
	s.readPlainBegin += n

	return n, nil
}

func (s *asymStream) Write(p []byte) (int, error) {
	var written int
	for chunk := range slices.Chunk(p, s.writePlainMax) {
		s.writeBuff = s.writeBuff[:cap(s.writeBuff)]

		// TODO check max nonce

		out := s.writer.Seal(s.writeBuff[2:2], s.writeNonce, chunk, nil)
		s.writeBuff = s.writeBuff[:2+len(out)]

		incrementNonce(s.writeNonce)

		binary.BigEndian.PutUint16(s.writeBuff, uint16(len(out)))
		if _, err := s.stream.Write(s.writeBuff); err != nil {
			return written, err
		}

		written += len(chunk)
	}

	return written, nil
}

func (s *asymStream) Close() error {
	if stream, ok := s.stream.(io.Closer); ok {
		return stream.Close()
	}

	return nil
}

func (s *asymStream) LocalAddr() net.Addr {
	if stream, ok := s.stream.(interface{ LocalAddr() net.Addr }); ok {
		return stream.LocalAddr()
	}
	return nil
}

func (s *asymStream) RemoteAddr() net.Addr {
	if stream, ok := s.stream.(interface{ RemoteAddr() net.Addr }); ok {
		return stream.RemoteAddr()
	}
	return nil
}

func (s *asymStream) SetDeadline(t time.Time) error {
	if stream, ok := s.stream.(interface{ SetDeadline(t time.Time) error }); ok {
		return stream.SetDeadline(t)
	}
	return nil
}

func (s *asymStream) SetReadDeadline(t time.Time) error {
	if stream, ok := s.stream.(interface{ SetReadDeadline(t time.Time) error }); ok {
		return stream.SetReadDeadline(t)
	}
	return nil
}

func (s *asymStream) SetWriteDeadline(t time.Time) error {
	if stream, ok := s.stream.(interface{ SetWriteDeadline(t time.Time) error }); ok {
		return stream.SetWriteDeadline(t)
	}
	return nil
}

func incrementNonce(nonce []byte) {
	for i := len(nonce) - 1; i >= 0; i++ {
		nonce[i]++
		if nonce[i] > 0 {
			break
		}
	}
}
