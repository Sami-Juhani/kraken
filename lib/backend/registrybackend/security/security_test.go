// Copyright (c) 2016-2019 Uber Technologies, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package security

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/docker/engine-api/types"
	"github.com/stretchr/testify/require"
)

func TestAuthenticateReleasesPingConnections(t *testing.T) {
	require := require.New(t)

	var open int64
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(registryVersionHeader, "registry/2.0")
		w.Header().Set("Www-Authenticate", `Basic realm="test"`)
		w.WriteHeader(http.StatusUnauthorized)
		if _, err := w.Write([]byte("unauthorized")); err != nil {
			t.Error(err)
		}
	}))
	server.Config.ConnState = func(c net.Conn, s http.ConnState) {
		switch s {
		case http.StateNew:
			atomic.AddInt64(&open, 1)
		case http.StateClosed, http.StateHijacked:
			atomic.AddInt64(&open, -1)
		}
	}
	server.StartTLS()
	defer server.Close()

	a, err := NewAuthenticator(strings.TrimPrefix(server.URL, "https://"), Config{
		BasicAuth: &types.AuthConfig{Username: "user", Password: "pass"},
	})
	require.NoError(err)
	impl, ok := a.(*authenticator)
	require.True(ok)
	impl.roundTripper = server.Client().Transport

	for i := 0; i < 20; i++ {
		_, err := a.Authenticate("repo")
		require.NoError(err)
	}
	require.Eventually(func() bool {
		return atomic.LoadInt64(&open) <= 1
	}, 5*time.Second, 10*time.Millisecond, "open connections: %d", atomic.LoadInt64(&open))
}
