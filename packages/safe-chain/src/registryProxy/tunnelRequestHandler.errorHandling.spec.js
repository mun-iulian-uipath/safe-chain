import { describe, it, beforeEach, mock } from "node:test";
import assert from "node:assert";

// Drive the tunnel handler with a fully mocked net.connect so we can
// reliably exercise the error shapes the registry/CDN side actually
// produces (ECONNRESET with a message, low-level errors with no
// message at all). Real-network tests can't easily synthesize the
// no-message case, which is the one that produces empty
// `... :443 -<EOL>` log lines.

let lastServerSocket;
let lastClientSocket;

const errorLogs = [];
const verboseLogs = [];

mock.module("net", {
  defaultExport: makeNetMock(),
  namedExports: makeNetMock(),
});

mock.module("../environment/userInteraction.js", {
  namedExports: {
    ui: {
      writeError: (msg) => errorLogs.push(msg),
      writeVerbose: (msg) => verboseLogs.push(msg),
      writeWarning: () => {},
    },
  },
});

mock.module("./isImdsEndpoint.js", {
  namedExports: {
    isImdsEndpoint: () => false,
  },
});

mock.module("./getConnectTimeout.js", {
  namedExports: {
    getConnectTimeout: () => 60000,
  },
});

const { tunnelRequest } = await import("./tunnelRequestHandler.js");

describe("tunnelRequestHandler error handling", () => {
  beforeEach(() => {
    errorLogs.length = 0;
    verboseLogs.length = 0;
    lastServerSocket = null;
    lastClientSocket = makeFakeSocket();
    delete process.env.HTTPS_PROXY;
    delete process.env.https_proxy;
  });

  it("logs serverSocket errors at verbose, not error", async () => {
    // Before the fix this called ui.writeError, producing hundreds of red
    // herring lines at the end of any e2e/test run that opened keep-alive
    // sockets to non-MITM hosts. The errors are not actionable - we're
    // only acting as a transparent CONNECT tunnel for these hosts.
    runTunnel("example.com:443");

    const err = Object.assign(new Error("read ECONNRESET"), {
      code: "ECONNRESET",
    });
    lastServerSocket.emit("error", err);

    assert.equal(
      errorLogs.length,
      0,
      "tunnel teardown errors must not be at error level",
    );
    assert.ok(
      verboseLogs.some(
        (m) =>
          m.includes("example.com:443") && m.includes("read ECONNRESET"),
      ),
      "the error must still appear at verbose level",
    );
  });

  it("falls back to err.code when err.message is empty", async () => {
    // Some socket teardown paths in Node emit Error objects with no
    // message but a `code` set. Before the fix these produced
    // dangling `Safe-chain: error connecting to <host>:443 - <EOL>`
    // log lines.
    runTunnel("cdn.example.net:443");

    const codeOnly = Object.assign(new Error(), { code: "ECONNRESET" });
    lastServerSocket.emit("error", codeOnly);

    const line = verboseLogs.find((m) =>
      m.includes("cdn.example.net:443"),
    );
    assert.ok(line, "verbose log must mention the host");
    assert.ok(
      line.endsWith("ECONNRESET"),
      `log must include err.code as the detail, got: ${line}`,
    );
    assert.ok(
      !line.endsWith(" - "),
      "log must not end with a dangling separator",
    );
  });

  it("synthesizes 'unknown error' if neither message nor code is set", async () => {
    runTunnel("other.example.org:443");

    // Manufacture the worst-case error: no message, no code.
    const blank = new Error();
    blank.message = "";
    lastServerSocket.emit("error", blank);

    const line = verboseLogs.find((m) => m.includes("other.example.org:443"));
    assert.ok(line, "verbose log must mention the host");
    assert.ok(
      line.endsWith("unknown error"),
      `log must use the unknown-error fallback, got: ${line}`,
    );
  });

  it("still ends the client connection with 502 on tunnel error", async () => {
    // The log demotion must not change the client-facing behaviour:
    // failing tunnel attempts still close the client socket cleanly.
    runTunnel("other.example.org:443");
    lastServerSocket.emit("error", new Error("read ECONNRESET"));
    assert.ok(
      lastClientSocket.endCalls.some((arg) =>
        String(arg).includes("502 Bad Gateway"),
      ),
      "client must receive 502 on tunnel failure",
    );
  });

  it("post-connect tunnelRequestViaProxy errors are verbose, pre-connect stay error", async () => {
    // The pre-connect failure (couldn't reach the upstream system proxy
    // at all) is actionable for the user. The post-connect path is
    // teardown noise on someone else's HTTPS connection. Different log
    // levels for each case.
    process.env.HTTPS_PROXY = "http://proxy.example:8080";
    runTunnel("registry.npmjs.org:443");

    // Phase 1: pre-connect. Not "connected" yet (proxy CONNECT not yet
    // accepted), so an error here is at error level.
    lastServerSocket.emit("error", new Error("ECONNREFUSED"));
    assert.ok(
      errorLogs.some((m) => m.includes("error connecting to proxy")),
      "pre-connect tunnel-via-proxy errors must be at error level",
    );

    // Phase 2: simulate post-connect by having the proxy accept CONNECT
    // and then the socket erroring later.
    errorLogs.length = 0;
    verboseLogs.length = 0;
    runTunnel("registry.npmjs.org:443");
    lastServerSocket.emit(
      "data",
      Buffer.from("HTTP/1.1 200 Connection Established\r\n\r\n"),
    );
    lastServerSocket.emit("error", new Error("read ECONNRESET"));
    assert.equal(
      errorLogs.length,
      0,
      "post-connect tunnel-via-proxy errors must not be at error level",
    );
    assert.ok(
      verboseLogs.some((m) => m.includes("proxy socket error after connection")),
      "post-connect error must still appear at verbose level",
    );
  });
});

// --- helpers ---------------------------------------------------------------

function makeNetMock() {
  return {
    connect: (..._args) => {
      const sock = makeFakeSocket();
      lastServerSocket = sock;
      // Trigger 'connect' so the timer-arming code path runs but no real
      // socket activity happens. Tests then drive 'error'/'close'/'data'.
      queueMicrotask(() => sock.emit("connect"));
      return sock;
    },
  };
}

function makeFakeSocket() {
  const listeners = {};
  return {
    writable: true,
    listeners,
    on(event, handler) {
      (listeners[event] = listeners[event] || []).push(handler);
      return this;
    },
    once(event, handler) {
      const wrapped = (...args) => {
        handler(...args);
        const arr = listeners[event] || [];
        const i = arr.indexOf(wrapped);
        if (i >= 0) arr.splice(i, 1);
      };
      this.on(event, wrapped);
      return this;
    },
    emit(event, ...args) {
      (listeners[event] || []).slice().forEach((fn) => fn(...args));
    },
    write() {},
    end(arg) {
      this.endCalls = this.endCalls || [];
      this.endCalls.push(arg);
      this.writable = false;
    },
    pipe() {},
    destroy() {
      this.writable = false;
    },
    endCalls: [],
  };
}

function runTunnel(targetUrl) {
  lastClientSocket = makeFakeSocket();
  tunnelRequest({ url: targetUrl }, lastClientSocket, Buffer.alloc(0));
}
