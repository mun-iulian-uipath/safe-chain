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
  it("ends client response cleanly when proxyRes errors mid-stream", async () => {
    // Tarball arrives, headers go out, then upstream RSTs and
    // proxyRes fires 'error: aborted'. Without the fix the response
    // sits half-open and npm waits its full fetch-timeout (5 min)
    // before giving up with EIDLETIMEOUT.
    //
    // With the fix, res is ended cleanly (not destroyed/RST). Combined
    // with the chunked-encoding pass through (writeHead site strips
    // content-length), this surfaces to npm as a complete-but-truncated
    // response. pacote sees an integrity mismatch (sha512 of partial
    // body != declared integrity) and refetches via EINTEGRITY - the
    // install completes via npm's built-in retry path.
    const proxyResEvents = createEventBag();

    nextUpstream = (_options, callback) => {
      callback({
        statusCode: 200,
        headers: { "content-length": "5000000" },
        on: proxyResEvents.on,
        pipe: () => {},
      });
      return makeRequestObject();
    };

    const { req, res, resState } = makeMitmFlow();
    await capturedHandler(req, res);

    const abortError = Object.assign(new Error("aborted"), { code: "aborted" });
    proxyResEvents.emit("error", abortError);

    assert.equal(
      resState.ended,
      true,
      "res.end must be called so npm sees a clean stream termination",
    );
    assert.equal(
      resState.destroyed,
      false,
      "res must NOT be destroyed (RST) - pacote does not retry ECONNRESET on tarballs",
    );
    assert.ok(
      errorLogs.some((m) => m.includes("Error reading upstream response")),
      "error must still be logged",
    );
  });

  it("ends client response when proxyRes closes prematurely", async () => {
    // Some upstream failures emit 'close' without 'error' and without a
    // clean 'end'. proxyRes.complete stays false. pipe doesn't catch it,
    // so we explicitly end res to give the client a clean termination.
    const proxyResEvents = createEventBag();

    nextUpstream = (_options, callback) => {
      callback({
        statusCode: 200,
        headers: { "content-length": "1000" },
        complete: false,
        on: proxyResEvents.on,
        pipe: () => {},
      });
      return makeRequestObject();
    };

    const { req, res, resState } = makeMitmFlow();
    await capturedHandler(req, res);

    proxyResEvents.emit("close");

    assert.equal(
      resState.ended,
      true,
      "res must be ended when upstream closes without complete",
    );
    assert.equal(
      resState.destroyed,
      false,
      "res must NOT be destroyed (RST) - that breaks pacote's EINTEGRITY retry path",
    );
  });

  it("leaves the response alone when proxyRes closes after a clean end", async () => {
    // Inverse of the previous test: complete=true means the body was fully
    // delivered. Don't double-end res - pipe already ended it via 'end'.
    const proxyResEvents = createEventBag();

    nextUpstream = (_options, callback) => {
      callback({
        statusCode: 200,
        headers: { "content-length": "1000" },
        complete: true,
        on: proxyResEvents.on,
        pipe: () => {},
      });
      return makeRequestObject();
    };

    const { req, res, resState } = makeMitmFlow();
    await capturedHandler(req, res);

    // Mark the client response as ended (mimics what proxyRes.pipe(res)
    // would do once the upstream end event propagates).
    resState.writableEnded = true;

    proxyResEvents.emit("close");

    assert.equal(
      resState.ended,
      false,
      "completed responses must not be re-ended by the close handler",
    );
    assert.equal(
      resState.destroyed,
      false,
      "completed responses must not be destroyed by the close handler",
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
