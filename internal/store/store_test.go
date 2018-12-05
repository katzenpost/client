package store

import (
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/stretchr/testify/assert"
	"github.com/ugorji/go/codec"
	"io/ioutil"
	"os"
	"testing"
)

func TestCreateStore(t *testing.T) {
	assert := assert.New(t)

	f, err := ioutil.TempFile("", "store.ns")
	assert.NoError(err)

	privKey, err := ecdh.NewKeypair(rand.Reader)
	assert.NoError(err)

	n, err := NewNoiseRW(f, privKey)
	assert.NoError(err)

	_, err = n.Write([]byte("FooBar"))
	assert.NoError(err)

	_, err = n.Write([]byte("FooBar"))
	assert.NoError(err)

	assert.Equal(12, len(n.buf))

	n.Close()

	f, err = os.Open(f.Name())
	assert.NoError(err)

	n, err = NewNoiseRW(f, privKey)
	assert.NoError(err)

	_, err = f.Stat()
	assert.NoError(err)
	buf := make([]byte, 100)
	_, err = n.Read(buf[:4])
	assert.NoError(err)
	i, err := n.Read(buf[4:])
	assert.NoError(err)
	assert.Equal(string(buf[:4+i]), "FooBarFooBar")
}

func TestStoreCBOR(t *testing.T) {
	assert := assert.New(t)

	privKey, err := ecdh.NewKeypair(rand.Reader)
	assert.NoError(err)

	f, err := ioutil.TempFile("", "store.ns")
	assert.NoError(err)

	n, err := NewNoiseRW(f, privKey)
	assert.NoError(err)

	cborHandle := new(codec.CborHandle)
	enc := codec.NewEncoder(n, cborHandle)
	blah := "Here's a nice string to encode"
	err = enc.Encode(blah)
	assert.NoError(err)

	n.Close() // flush ctext to disk

	f, err = os.Open(f.Name())
	assert.NoError(err)

	n, err = NewNoiseRW(f, privKey)
	assert.NoError(err)

	dec := codec.NewDecoder(n, cborHandle)
	blah2 := make([]byte, 0)
	err = dec.Decode(&blah2)
	assert.Equal(blah, string(blah2))
	t.Logf("blah %s", blah2)
	assert.NoError(err)
}
