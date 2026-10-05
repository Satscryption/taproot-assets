package rpcserver

import (
	"encoding/binary"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var commitLockIDSeq atomic.Uint64

func testCommitLockID() []byte {
	id := make([]byte, lndLockIDLen)
	binary.BigEndian.PutUint64(id, commitLockIDSeq.Add(1))

	return id
}

func commitInputLockPresent(lockID []byte) bool {
	if len(lockID) != lndLockIDLen {
		return false
	}

	commitInputLockMu.Lock()
	defer commitInputLockMu.Unlock()

	_, ok := commitInputLocks[string(lockID)]

	return ok
}

// TestLockCommitInputsDropsIdleEntries tests that a lock ID mutex is
// removed once nobody holds or waits on it. Derived request IDs would
// otherwise leave one mutex in the process-global map forever.
func TestLockCommitInputsDropsIdleEntries(t *testing.T) {
	t.Parallel()

	id := testCommitLockID()
	unlock := lockCommitInputs(id)

	started := make(chan struct{})
	released := make(chan struct{})
	go func() {
		close(started)
		second := lockCommitInputs(id)
		second()
		close(released)
	}()

	<-started
	select {
	case <-released:
		t.Fatal("second attempt acquired the lock before release")
	case <-time.After(50 * time.Millisecond):
	}

	// The entry stays while the first attempt holds it and the second
	// waits. That is the FundPsbt-through-RPC exclusion.
	require.True(t, commitInputLockPresent(id))

	unlock()

	select {
	case <-released:
	case <-time.After(2 * time.Second):
		t.Fatal("waiter did not acquire the lock")
	}

	require.False(t, commitInputLockPresent(id))

	// A lock ID that is not 32 bytes does not take a mutex.
	shortID := []byte("short")
	lockCommitInputs(shortID)()
	require.False(t, commitInputLockPresent(shortID))

	var wg sync.WaitGroup
	ids := make([][]byte, 32)
	for i := range ids {
		ids[i] = testCommitLockID()
		wg.Add(1)
		go func(lockID []byte) {
			defer wg.Done()
			lockCommitInputs(lockID)()
		}(ids[i])
	}
	wg.Wait()

	for _, lockID := range ids {
		require.False(t, commitInputLockPresent(lockID))
	}
}
