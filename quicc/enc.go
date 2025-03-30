package quicc

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"slices"
)

type EncStream struct {
	stream io.ReadWriteCloser
	reader cipher.AEAD
	writer cipher.AEAD

	readBuffLen []byte
	readBuff    []byte
	readNonce   []byte

	readPlainBuff  []byte
	readPlainBegin int
	readPlainEnd   int

	writeBuffLen  []byte
	writeBuff     []byte
	writeNonce    []byte
	writePlainMax int
}

const maxBuff = 65535

func NewEncStream(stream io.ReadWriteCloser, reader cipher.AEAD, writer cipher.AEAD) *EncStream {
	return &EncStream{
		stream: stream,
		reader: reader,
		writer: writer,

		readBuffLen: make([]byte, 2),
		readBuff:    make([]byte, maxBuff),
		readNonce:   make([]byte, reader.NonceSize()),

		readPlainBuff:  make([]byte, maxBuff-reader.Overhead()-reader.NonceSize()),
		readPlainBegin: 0,
		readPlainEnd:   0,

		writeBuffLen:  make([]byte, 2),
		writeBuff:     make([]byte, maxBuff),
		writeNonce:    make([]byte, writer.NonceSize()),
		writePlainMax: maxBuff - writer.Overhead() - writer.NonceSize(),
	}
}

func (s *EncStream) Read(p []byte) (int, error) {
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

		if !bytes.Equal(s.readNonce, s.readBuff[:s.reader.NonceSize()]) {
			return 0, fmt.Errorf("invalid nonce")
		}

		s.readPlainBuff = s.readPlainBuff[:cap(s.readPlainBuff)]
		s.readPlainBuff, err = s.reader.Open(s.readPlainBuff[:0], s.readNonce, s.readBuff[s.writer.NonceSize():], nil)
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

func (s *EncStream) Write(p []byte) (int, error) {
	var written int
	for chunk := range slices.Chunk(p, s.writePlainMax) {
		s.writeBuff = s.writeBuff[:cap(s.writeBuff)]

		// TODO check max nonce
		copy(s.writeBuff, s.writeNonce)
		incrementNonce(s.writeNonce)

		out := s.writer.Seal(s.writeBuff[s.writer.NonceSize():s.writer.NonceSize()], s.writeBuff[:s.writer.NonceSize()], chunk, nil)
		s.writeBuff = s.writeBuff[:len(s.writeNonce)+len(out)]

		binary.BigEndian.PutUint16(s.writeBuffLen, uint16(len(s.writeBuff)))
		if _, err := s.stream.Write(s.writeBuffLen); err != nil {
			return written, err
		}
		if _, err := s.stream.Write(s.writeBuff); err != nil {
			return written, err
		}

		written += len(chunk)
	}

	return written, nil
}

func (s *EncStream) Close() error {
	return s.stream.Close()
}

var _ io.ReadWriteCloser = (*EncStream)(nil)

func incrementNonce(nonce []byte) {
	for i := len(nonce) - 1; i >= 0; i++ {
		nonce[i]++
		if nonce[i] > 0 {
			break
		}
	}
}
