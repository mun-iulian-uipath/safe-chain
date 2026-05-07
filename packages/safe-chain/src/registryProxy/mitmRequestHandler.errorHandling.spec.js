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
  it("switches to passthrough when buffered body exceeds the cap", async () => {
    // For an interceptor that wants to rewrite the response, the proxy
    // buffers the whole body before parsing/modifying. Without a cap, a
    // single multi-hundred-MB metadata document (or many concurrent ones)
    // can OOM the proxy and crash the install. The fix switches to
    // streaming passthrough above MAX_MODIFY_BODY_BYTES (32 MB) and skip
    // modifyBody for that single response.
    const proxyResEvents = createEventBag();

    nextUpstream = (_options, callback) => {
      callback({
        statusCode: 200,
        headers: { "content-type": "application/json" },
        on: proxyResEvents.on,
        pipe: () => {},
      });
      return makeRequestObject();
    };

    let modifyBodyCalled = false;
    const { req, res, resState } = makeMitmFlow({
      modifiesResponse: true,
      modifyBody: () => {
        modifyBodyCalled = true;
        return Buffer.alloc(0);
      },
    });
    await capturedHandler(req, res);

    // 33 MB total - one byte over the 32 MB cap.
    const chunkSize = 1024 * 1024;
    const chunkCount = 33;
    const chunk = Buffer.alloc(chunkSize, 0x61);
    for (let i = 0; i < chunkCount; i++) {
      proxyResEvents.emit("data", chunk);
    }
    proxyResEvents.emit("end");

    assert.equal(
      modifyBodyCalled,
      false,
      "modifyBody must be skipped once we cross the buffering cap",
    );
    assert.equal(
      resState.headersSent,
      true,
      "passthrough must writeHead the upstream status/headers",
    );
    assert.ok(
      resState.writes.length >= chunkCount,
      `passthrough must stream every chunk - got ${resState.writes.length}`,
    );
    assert.equal(resState.ended, true, "res must be ended after upstream end");
    assert.ok(
      warningLogs.some((m) => m.includes("exceeded")),
      "the cap-tripped warning must be emitted",
    );
  });
  it("still rewrites bodies that fit under the cap", async () => {
    // Sanity check - small bodies still go through the rewrite path.
    const proxyResEvents = createEventBag();

    nextUpstream = (_options, callback) => {
      callback({
        statusCode: 200,
        headers: { "content-type": "application/json" },
        on: proxyResEvents.on,
        pipe: () => {},
      });
      return makeRequestObject();
    };

    let modifyBodyCalled = false;
    let receivedBody = null;
    const { req, res, resState } = makeMitmFlow({
      modifiesResponse: true,
      modifyBody: (body) => {
        modifyBodyCalled = true;
        receivedBody = body;
        return Buffer.from("rewritten");
      },
    });
    await capturedHandler(req, res);

    const small = Buffer.from('{"hello":"world"}');
    proxyResEvents.emit("data", small);
    proxyResEvents.emit("end");

    assert.equal(modifyBodyCalled, true, "modifyBody must run for small bodies");
    assert.deepEqual(receivedBody, small);
    assert.equal(resState.endedWith?.toString(), "rewritten");
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
