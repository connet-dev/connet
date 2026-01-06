package reliable

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var errTest = errors.New("the error")

func testNoError(ctx context.Context) error {
	return nil
}

func testError(ctx context.Context) error {
	return errTest
}

func testWaitError(ctx context.Context) error {
	if err := Wait(ctx, 2*time.Nanosecond); err != nil {
		return err
	}
	return errTest
}

func testWait(ctx context.Context) error {
	return Wait(ctx, 2*time.Nanosecond)
}

func testLongWait(ctx context.Context) error {
	return Wait(ctx, 11*time.Second)
}

func TestGroup(t *testing.T) {
	err := RunGroup(context.Background(), testNoError)
	require.NoError(t, err)

	err = RunGroup(context.Background(), testError)
	require.ErrorIs(t, errTest, err)

	err = RunGroup(context.Background(), testError, testNoError)
	require.ErrorIs(t, errTest, err)

	err = RunGroup(context.Background(), testWait, testWait)
	require.NoError(t, err)

	err = RunGroup(context.Background(), testWait, testWaitError)
	require.ErrorIs(t, errTest, err)

	err = RunGroup(context.Background(), testWaitError, testLongWait)
	require.ErrorIs(t, errTest, err)
}
