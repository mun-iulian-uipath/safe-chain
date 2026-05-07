import { describe, it, beforeEach, mock } from "node:test";
import assert from "node:assert";

// Each test installs a function in `nextUpstream` that drives the mocked
// https.request. The function receives (options, callback) and must return
// an object that looks enough like a ClientRequest. Calling the callback with
// a fake IncomingMessage delivers a "response" to forwardRequest. This lets
// every test script the exact upstream behaviour it cares about (clean
// response, error after headers sent, premature close, oversize body, etc.)
// without spinning up a real HTTPS server.

/** @type {(options: any, callback: (proxyRes: any) => void) => any} */
let nextUpstream;

const errorLogs = [];
const verboseLogs = [];
const warningLogs = [];

mock.module("https", {
  defaultExport: {
    createServer: (_options, handler) => {
      capturedHandler = handler;
      return { on: () => {}, emit: () => {} };
    },
    request: (options, callback) => nextUpstream(options, callback),
  },
});

mock.module("./certUtils.js", {
  namedExports: {
    generateCertForHost: () => ({ privateKey: "key", certificate: "cert" }),
  },
});

mock.module("https-proxy-agent", {
  namedExports: { HttpsProxyAgent: class {} },
});

mock.module("../environment/userInteraction.js", {
  namedExports: {
    ui: {
      writeError: (msg) => errorLogs.push(msg),
      writeVerbose: (msg) => verboseLogs.push(msg),
      writeWarning: (msg) => warningLogs.push(msg),
    },
  },
});

let capturedHandler;
const { mitmConnect } = await import("./mitmRequestHandler.js");

describe("mitmRequestHandler error handling", () => {
  beforeEach(() => {
    nextUpstream = null;
    errorLogs.length = 0;
    verboseLogs.length = 0;
    warningLogs.length = 0;
  });
  it("does not double-write headers when proxyReq errors after headers sent", async () => {
    // Upstream delivers a status + headers
    // (res.writeHead is called and headersSent flips to true), then
    // errors out on the request stream. The pre-fix code unconditionally
    // called res.writeHead(502), throwing "Cannot write headers after they
    // are sent" - which the global uncaughtException handler turned into a
    // process.exit(1) that killed the proxy mid-install.
    const reqEvents = createEventBag();
    const proxyResEvents = createEventBag();

    nextUpstream = (_options, callback) => {
      // Deliver the response so res.writeHead runs, then schedule a
      // proxyReq error after a microtask so headersSent is already true.
      callback({
        statusCode: 200,
        headers: { "content-type": "application/octet-stream" },
        on: proxyResEvents.on,
        pipe: () => {},
      });
      return reqEvents.makeRequestObject();
    };

    const { req, res, resState } = makeMitmFlow();
    await capturedHandler(req, res);
    assert.equal(resState.headersSent, true, "headers should be sent first");

    // Emit the proxyReq error post-headers; before the fix this throws.
    assert.doesNotThrow(() =>
      reqEvents.emit("error", new Error("ECONNRESET")),
    );

    assert.equal(
      resState.writeHeadCalls.length,
      1,
      "writeHead must not be called a second time",
    );
    assert.equal(
      resState.destroyed,
      true,
      "client response must be torn down so npm sees a connection error",
    );
  });
});

// --- helpers --------------------------------------------------------------

function createEventBag() {
  const listeners = {};
  return {
    on: (event, handler) => {
      listeners[event] = handler;
    },
    emit: (event, ...args) => {
      listeners[event]?.(...args);
    },
    listeners,
    makeRequestObject() {
      return makeRequestObject(listeners);
    },
  };
}

function makeRequestObject(listeners) {
  // Stand-in for ClientRequest. forwardRequest installs an 'error' handler
  // and may call .write/.end/.destroy on it.
  const onMap = listeners ?? {};
  return {
    on: (event, handler) => {
      onMap[event] = handler;
    },
    write: () => {},
    end: () => {},
    destroy: () => {},
  };
}

function makeMitmFlow(interceptorOverride = {}) {
  const interceptor = {
    handleRequest: async () => ({
      blockResponse: undefined,
      modifyRequestHeaders: (h) => h,
      modifiesResponse: () => Boolean(interceptorOverride.modifiesResponse),
      modifyBody:
        interceptorOverride.modifyBody ??
        ((body) => body),
    }),
  };

  // Establish the MITM tunnel: this populates the captured handler closure.
  const clientSocket = {
    on: () => {},
    write: () => {},
    end: () => {},
    headersSent: false,
    writable: true,
  };
  mitmConnect({ url: "registry.npmjs.org:443" }, clientSocket, interceptor);

  // Build the synthetic req/res pair that the captured handler operates on.
  const resState = {
    headersSent: false,
    writableEnded: false,
    writeHeadCalls: [],
    writes: [],
    ended: false,
    endedWith: undefined,
    destroyed: false,
    destroyError: undefined,
  };

  const res = {
    get headersSent() {
      return resState.headersSent;
    },
    get writableEnded() {
      return resState.writableEnded;
    },
    writeHead(statusCode, headers) {
      resState.writeHeadCalls.push({ statusCode, headers });
      resState.headersSent = true;
    },
    write(chunk) {
      resState.writes.push(chunk);
    },
    end(body) {
      resState.ended = true;
      resState.writableEnded = true;
      resState.endedWith = body;
    },
    destroy(err) {
      resState.destroyed = true;
      resState.destroyError = err;
    },
  };

  const req = {
    url: "/-/foo-1.0.0.tgz",
    method: "GET",
    headers: {},
    on: (event, handler) => {
      // The handler subscribes to data / end / error; for these tests we
      // only need the body-less path so end fires immediately.
      if (event === "end") {
        queueMicrotask(handler);
      }
    },
  };

  return { req, res, resState };
}
