package notify

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestUpdateOptNoUpdateDoesNotDeadlock(t *testing.T) {
	n := New(42)

	// UpdateOpt returns false (no update) — must not deadlock subsequent operations
	updated := n.UpdateOpt(func(v int) (int, bool) {
		return v, false
	})
	require.False(t, updated)

	// If the barrier was not returned, this Set would block forever
	done := make(chan struct{})
	go func() {
		n.Set(100)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("deadlock: Set blocked after UpdateOpt returned false")
	}

	v, ok := n.Peek()
	require.True(t, ok)
	require.Equal(t, 100, v)
}

func TestUpdateOptNoUpdateDoesNotDeadlockEmpty(t *testing.T) {
	n := NewEmpty[int]()

	// UpdateOpt on an empty value returns false — must not deadlock
	updated := n.UpdateOpt(func(v int) (int, bool) {
		return v, false
	})
	require.False(t, updated)

	done := make(chan struct{})
	go func() {
		n.Set(7)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("deadlock: Set blocked after UpdateOpt returned false on empty value")
	}

	v, ok := n.Peek()
	require.True(t, ok)
	require.Equal(t, 7, v)
}

func TestNV(t *testing.T) {
	n := NewEmpty[int]()

	go func() {
		for i := 0; i <= 1000; i++ {
			n.Set(i)
		}
	}()

	version := uint64(0)
	observed := 0
	for {
		v, next, err := n.Get(context.Background(), version)
		require.NoError(t, err)
		version = next
		observed++
		if v == 1000 {
			break
		}
	}
	fmt.Println("observed", observed)
}
