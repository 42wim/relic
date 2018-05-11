// Copyright © SAS Institute Inc.
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// +build darwin dragonfly freebsd linux netbsd openbsd solaris

package activatecmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/sassoftware/relic/internal/closeonce"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
)

// Notification wraps a notify event from a child process
type Notification struct {
	PID   int  // PID is the process that originated the event
	Ready bool // Ready is true if the event was a "worker ready" type
}

// Listener implements a channel that receives ready notifications from spawned processes
type Listener struct {
	once   sync.Once
	closed closeonce.Closed
	c      chan Notification
	eg     *errgroup.Group
	ctx    context.Context
	cancel context.CancelFunc
}

func (l *Listener) initialize() {
	l.ctx, l.cancel = context.WithCancel(context.Background())
	l.eg, l.ctx = errgroup.WithContext(l.ctx)
	l.c = make(chan Notification, 10)
}

// Chan returns a channel that receives notifications from child processes
func (l *Listener) Chan() <-chan Notification {
	l.once.Do(l.initialize)
	return l.c
}

// Close shuts down all notification sockets
func (l *Listener) Close() error {
	l.once.Do(l.initialize)
	return l.closed.Close(func() error {
		l.cancel()
		err := l.eg.Wait()
		close(l.c)
		return err
	})
}

// Attach a notification socket to a new child process. The returned "detach"
// function must be invoked on cleanup, and should be invoked after Start()
// returns.
func (l *Listener) Attach(cmd *exec.Cmd) (detach func(), err error) {
	l.once.Do(l.initialize)
	if l.closed.Closed() {
		return nil, errors.New("listener is closed")
	}
	if cmd.Env == nil {
		cmd.Env = ClearEnv(os.Environ())
	}
	parentEnd, childEnd, err := socketpair()
	if err != nil {
		return nil, err
	}
	cmd.Env = append(cmd.Env, fmt.Sprintf("EINHORN_SOCK_FD=%d", 3+len(cmd.ExtraFiles)))
	cmd.ExtraFiles = append(cmd.ExtraFiles, childEnd)
	go func() {
		<-l.ctx.Done()
		parentEnd.Close()
	}()
	l.eg.Go(func() error { return l.listen(parentEnd) })
	detach = func() { childEnd.Close() }
	return detach, nil
}

// Consume packets from a socket and forward them to the main channel until ctx is cancelled
func (l *Listener) listen(sock net.PacketConn) error {
	buf := make([]byte, 4096)
	failures := 0
	var payload struct {
		Command string `json:"command"`
		PID     int    `json:"pid"`
	}
	for l.ctx.Err() == nil {
		n, _, err := sock.ReadFrom(buf)
		if err != nil {
			if l.ctx.Err() != nil {
				return nil
			}
			log.Printf("error: failed to read from notify socket: %s", err)
			failures++
			if failures > 100 {
				return err
			}
			time.Sleep(100 * time.Millisecond)
		}
		failures = 0
		if err := json.Unmarshal(buf[:n], &payload); err != nil {
			log.Printf("error: failed to decode notification: %s", err)
			continue
		}
		if payload.Command == "worker:ack" {
			l.c <- Notification{PID: payload.PID, Ready: true}
		}
	}
	return nil
}

// Create a socketpair with the parent end wrapped in a PacketConn and the child end as a plain *os.File
func socketpair() (parentEnd net.PacketConn, childEnd *os.File, err error) {
	files, err := socketpairFiles()
	if err != nil {
		return nil, nil, err
	}
	defer files[0].Close() // FilePacketConn will dup this so always close it
	childEnd = files[1]
	if err = unix.SetNonblock(int(files[0].Fd()), true); err == nil {
		parentEnd, err = net.FilePacketConn(files[0])
		if err == nil {
			return parentEnd, childEnd, nil
		}
	}
	files[1].Close()
	return nil, nil, err
}

// Create a socketpair as *os.File objects. must hold the fork lock to ensure that no file descriptors are leaked to a child process before CloseOnExec can be set.
func socketpairFiles() (files [2]*os.File, err error) {
	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err == nil {
		unix.CloseOnExec(fds[0])
		unix.CloseOnExec(fds[1])
		files[0] = os.NewFile(uintptr(fds[0]), "<socketpair>")
		files[1] = os.NewFile(uintptr(fds[1]), "<socketpair>")
	}
	return
}
