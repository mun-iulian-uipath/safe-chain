import { describe, it, before, after } from "node:test";
import assert from "node:assert";
import net from "node:net";

import {
  createSafeChainProxy,
  mergeSafeChainProxyEnvironmentVariables,
} from "./registryProxy.js";

// stopServer must drain active connections instead of waiting for
// them to time out, and run cleanup exactly once. Without that, the
// close callback never fires while keep-alive sockets are open, so
// stopServer falls back to the SERVER_STOP_TIMEOUT_MS deadline
// (1000 ms) and the process exits with live sockets - which the
// kernel then RSTs, generating a wall of
// `Safe-chain: error connecting to ...` log noise.

const SERVER_STOP_TIMEOUT_MS = 1000;
const FAST_SHUTDOWN_MS = 250;

describe("registryProxy shutdown", () => {
  let proxy, proxyHost, proxyPort;

  before(async () => {
    proxy = createSafeChainProxy();
    await proxy.startServer();
    const env = mergeSafeChainProxyEnvironmentVariables([]);
    const url = new URL(env.HTTPS_PROXY);
    proxyHost = url.hostname;
    proxyPort = parseInt(url.port, 10);
  });

  after(async () => {
    // Best-effort - the test calls stopServer itself, this is just
    // defensive in case a test bails out early.
    try {
      await proxy.stopServer();
    } catch {
      /* noop */
    }
  });

  it("stopServer drains a stuck connection in well under SERVER_STOP_TIMEOUT_MS", async () => {
    // Send a half-formed HTTP request. The server tracks this socket as
    // an active connection but never finishes parsing headers, so plain
    // `server.close()` would block on it until SERVER_STOP_TIMEOUT_MS
    // (1000 ms) fires. With this fix the server actively destroys the
    // connection via closeAllConnections / closeIdleConnections and the
    // close callback fires immediately.
    //
    // Verified empirically: with this fix stopServer returns in ~1 ms;
    // reverted to the pre-this fix implementation it returns in ~1002 ms.
    const sock = await connectAndWait(proxyHost, proxyPort);
    sock.on("error", () => {}); // swallow the eventual RST
    try {
      sock.write("GET / HTTP/1.1\r\nHost: registry.npmjs.org\r\n");
      // Deliberately do NOT terminate headers - server holds the socket.
      await new Promise((r) => setTimeout(r, 50));

      const start = Date.now();
      await proxy.stopServer();
      const elapsed = Date.now() - start;

      assert.ok(
        elapsed < FAST_SHUTDOWN_MS,
        `stopServer should drain in <${FAST_SHUTDOWN_MS}ms, took ${elapsed}ms ` +
          `(SERVER_STOP_TIMEOUT_MS=${SERVER_STOP_TIMEOUT_MS}); this fix not active?`,
      );
    } finally {
      // Always tear down the socket regardless of assertion outcome -
      // otherwise on the failing path (without this fix) the leftover
      // open socket keeps the test runner's event loop alive forever.
      sock.destroy();
    }
  });
});

function connectAndWait(host, port) {
  return new Promise((resolve, reject) => {
    const sock = net.connect({ host, port });
    sock.once("connect", () => resolve(sock));
    sock.once("error", reject);
  });
}
