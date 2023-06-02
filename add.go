package shell

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	files "github.com/bittorrent/go-btfs-files"
)

type object struct {
	Hash string
}

type AddOpts = func(*RequestBuilder) error

func Meta(meta string) AddOpts {
	return func(rb *RequestBuilder) error {
		rb.Option("meta", meta)
		return nil
	}
}

func Chunker(chunker string) AddOpts {
	return func(rb *RequestBuilder) error {
		rb.Option("chunker", chunker)
		return nil
	}
}

func OnlyHash(enabled bool) AddOpts {
	return func(rb *RequestBuilder) error {
		rb.Option("only-hash", enabled)
		return nil
	}
}

func Pin(enabled bool) AddOpts {
	return func(rb *RequestBuilder) error {
		rb.Option("pin", enabled)
		return nil
	}
}

func Progress(enabled bool) AddOpts {
	return func(rb *RequestBuilder) error {
		rb.Option("progress", enabled)
		return nil
	}
}

func RawLeaves(enabled bool) AddOpts {
	return func(rb *RequestBuilder) error {
		rb.Option("raw-leaves", enabled)
		return nil
	}
}

// Hash allows for selecting the multihash type
func Hash(hash string) AddOpts {
	return func(rb *RequestBuilder) error {
		rb.Option("hash", hash)
		return nil
	}
}

// CidVersion allows for selecting the CID version that btfs should use.
func CidVersion(version int) AddOpts {
	return func(rb *RequestBuilder) error {
		rb.Option("v", version)
		return nil
	}
}

func (s *Shell) Add(r io.Reader, options ...AddOpts) (string, error) {
	fr := files.NewReaderFile(r)
	slf := files.NewSliceDirectory([]files.DirEntry{files.FileEntry("", fr)})
	fileReader := files.NewMultiFileReader(slf, true)

	var out object
	rb := s.Request("add")
	for _, option := range options {
		option(rb)
	}
	return out.Hash, rb.Body(fileReader).Exec(context.Background(), &out)
}

// AddNoPin adds a file to btfs without pinning it
// Deprecated: Use Add() with option functions instead
func (s *Shell) AddNoPin(r io.Reader) (string, error) {
	return s.Add(r, Pin(false))
}

// AddWithOpts adds a file to btfs with some additional options
// Deprecated: Use Add() with option functions instead
func (s *Shell) AddWithOpts(r io.Reader, pin bool, rawLeaves bool) (string, error) {
	return s.Add(r, Pin(pin), RawLeaves(rawLeaves))
}

func (s *Shell) AddLink(target string) (string, error) {
	link := files.NewLinkFile(target, nil)
	slf := files.NewSliceDirectory([]files.DirEntry{files.FileEntry("", link)})
	reader := files.NewMultiFileReader(slf, true)

	var out object
	return out.Hash, s.Request("add").Body(reader).Exec(context.Background(), &out)
}

func (s *Shell) AddDir(dir string) (string, error) {
	return s.AddSerialFileDir(dir, false)
}

// AddDir adds a directory recursively with all of the files under it
func (s *Shell) AddSerialFileDir(dir string, reedSolomon bool) (string, error) {
	stat, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}

	sf, err := files.NewSerialFile(dir, false, stat)
	if err != nil {
		return "", err
	}
	slf := files.NewSliceDirectory([]files.DirEntry{files.FileEntry(filepath.Base(dir), sf)})
	reader := files.NewMultiFileReader(slf, true)

	return s.addDirectoryFromReader(reader, reedSolomon)
}

func (s *Shell) AddSlicedDirectory(dir files.Directory, reedSolomon bool) (string, error) {
	reader := files.NewMultiFileReader(dir, true)
	return s.addDirectoryFromReader(reader, reedSolomon)
}

func (s *Shell) AddMultiPartFileDir(dir files.Directory, reedSolomon bool) (string, error) {
	reader := files.NewMultiFileReader(dir, true)
	return s.addDirectoryFromReader(reader, reedSolomon)
}

func (s *Shell) addDirectoryFromReader(dirReader *files.MultiFileReader, reedSolomon bool) (string, error) {
	request := s.Request("add").
		Option("recursive", true)
	if reedSolomon {
		request.Option("chunker", "reed-solomon")
	}
	resp, err := request.
		Body(dirReader).
		Send(context.Background())
	if err != nil {
		return "", err
	}

	defer resp.Close()

	if resp.Error != nil {
		return "", resp.Error
	}

	dec := json.NewDecoder(resp.Output)
	var final string
	for {
		var out object
		err = dec.Decode(&out)
		if err != nil {
			if err == io.EOF {
				break
			}
			return "", err
		}
		final = out.Hash
	}

	if final == "" {
		return "", errors.New("no results received")
	}

	return final, nil
}
