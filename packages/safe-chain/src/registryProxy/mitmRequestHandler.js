import https from "https";
import { generateCertForHost } from "./certUtils.js";
import { HttpsProxyAgent } from "https-proxy-agent";
import { ui } from "../environment/userInteraction.js";
import { gunzipSync } from "zlib";
import { omitHeaders } from "./http-utils.js";

/**
 * @typedef {import("./interceptors/interceptorBuilder.js").Interceptor} Interceptor
 */

/**
 * @param {import("http").IncomingMessage} req
 * @param {import("http").ServerResponse} clientSocket
 * @param {Interceptor} interceptor
 */
export function mitmConnect(req, clientSocket, interceptor) {
  ui.writeVerbose(`Safe-chain: Set up MITM tunnel for ${req.url}`);
  const { hostname, port } = new URL(`http://${req.url}`);

  clientSocket.on("error", (err) => {
    ui.writeVerbose(
      `Safe-chain: Client socket error for ${req.url}: ${err.message}`
    );
    // NO-OP
    // This can happen if the client TCP socket sends RST instead of FIN.
    // Not subscribing to 'close' event will cause node to throw and crash.
  });

  const server = createHttpsServer(hostname, port, interceptor);

  server.on("error", (err) => {
    ui.writeError(`Safe-chain: HTTPS server error: ${err.message}`);
    if (!clientSocket.headersSent) {
      clientSocket.end("HTTP/1.1 502 Bad Gateway\r\n\r\n");
    } else if (clientSocket.writable) {
      clientSocket.end();
    }
  });

  // Establish the connection
  clientSocket.write("HTTP/1.1 200 Connection Established\r\n\r\n");

  // Hand off the socket to the HTTPS server
  server.emit("connection", clientSocket);
}

/**
 * @param {string} hostname
 * @param {string} port
 * @param {Interceptor} interceptor
 * @returns {import("https").Server}
 */
function createHttpsServer(hostname, port, interceptor) {
  const cert = generateCertForHost(hostname);

  /**
   * @param {import("http").IncomingMessage} req
   * @param {import("http").ServerResponse} res
   *
   * @returns {Promise<void>}
   */
  async function handleRequest(req, res) {
    if (!req.url) {
      ui.writeError("Safe-chain: Request missing URL");
      res.writeHead(400, "Bad Request");
      res.end("Bad Request: Missing URL");
      return;
    }

    const pathAndQuery = getRequestPathAndQuery(req.url);
    const targetUrl = `https://${hostname}${pathAndQuery}`;

    const requestInterceptor = await interceptor.handleRequest(targetUrl);
    const blockResponse = requestInterceptor.blockResponse;

    if (blockResponse) {
      ui.writeVerbose(`Safe-chain: Blocking request to ${targetUrl}`);
      res.writeHead(blockResponse.statusCode, blockResponse.message);
      res.end(blockResponse.message);
      return;
    }

    // Collect request body
    forwardRequest(req, hostname, port, res, requestInterceptor);
  }

  const server = https.createServer(
    {
      key: cert.privateKey,
      cert: cert.certificate,
    },
    handleRequest
  );

  return server;
}

/**
 * @param {string} url
 * @returns {string}
 */
function getRequestPathAndQuery(url) {
  if (url.startsWith("http://") || url.startsWith("https://")) {
    const parsedUrl = new URL(url);
    return parsedUrl.pathname + parsedUrl.search + parsedUrl.hash;
  }
  return url;
}

/**
 * @param {import("http").IncomingMessage} req
 * @param {string} hostname
 * @param {string} port
 * @param {import("http").ServerResponse} res
 * @param {import("./interceptors/interceptorBuilder.js").RequestInterceptionHandler} requestHandler
 */
function forwardRequest(req, hostname, port, res, requestHandler) {
  const proxyReq = createProxyRequest(hostname, port, req, res, requestHandler);

  proxyReq.on("error", (err) => {
    ui.writeVerbose(
      `Safe-chain: Error occurred while proxying request to ${req.url} for ${hostname}: ${err.message}`
    );
    // The upstream connection can fail at any point, including after
    // we already started streaming the response back to the client.
    // Writing headers a second time would throw "Cannot write headers
    // after they are sent", which (via the global uncaughtException
    // handler) crashes the whole proxy in the middle of the package
    // manager's run.
    //
    // When headers were already sent, end res cleanly (paired with
    // the chunked-encoding pass through at the writeHead site below)
    // so npm sees a complete-but-truncated response. pacote then
    // retries via its EINTEGRITY path. Using destroy(err) instead
    // would surface as ECONNRESET, which pacote does not retry, so
    // the install would still fail.
    if (!res.headersSent) {
      res.writeHead(502);
      res.end("Bad Gateway");
    } else if (!res.writableEnded) {
      res.end();
    }
  });

  req.on("error", (err) => {
    ui.writeError(
      `Safe-chain: Error reading client request to ${req.url} for ${hostname}: ${err.message}`
    );
    proxyReq.destroy();
  });

  req.on("data", (chunk) => {
    proxyReq.write(chunk);
  });

  req.on("end", () => {
    ui.writeVerbose(
      `Safe-chain: Finished proxying request to ${req.url} for ${hostname}`
    );
    proxyReq.end();
  });
}

/**
 * @param {string} hostname
 * @param {string} port
 * @param {import("http").IncomingMessage} req
 * @param {import("http").ServerResponse} res
 * @param {import("./interceptors/interceptorBuilder.js").RequestInterceptionHandler} requestHandler
 *
 * @returns {import("http").ClientRequest}
 */
function createProxyRequest(hostname, port, req, res, requestHandler) {
  /** @type {NodeJS.Dict<string | string[]> | undefined} */
  let headers = { ...req.headers };
  // Remove the host header from the incoming request before forwarding.
  // Node's http module sets the correct host header for the target hostname automatically.
  if (headers.host) {
    delete headers.host;
  }
  headers = requestHandler.modifyRequestHeaders(headers);

  /** @type {import("http").RequestOptions} */
  const options = {
    hostname: hostname,
    port: port || 443,
    path: req.url,
    method: req.method,
    headers: { ...headers },
  };

  const httpsProxy = process.env.HTTPS_PROXY || process.env.https_proxy;
  if (httpsProxy) {
    options.agent = new HttpsProxyAgent(httpsProxy);
  }

  const proxyReq = https.request(options, (proxyRes) => {
    proxyRes.on("error", (err) => {
      ui.writeError(
        `Safe-chain: Error reading upstream response to ${req.url} for ${hostname}: ${err.message}`
      );
      // For the streaming branch (every tarball), res.writeHead runs
      // as soon as proxyRes arrives, so headersSent is true by the
      // time the upstream errors mid-stream. The 502 path is then a
      // no-op and proxyRes.pipe(res) does NOT propagate 'error' to
      // res - it only forwards 'end'. Without an explicit cleanup
      // here, res sits half-open with a partial body and no FIN/RST,
      // npm waits for more bytes that never come, and 5 minutes
      // later the install fails with EIDLETIMEOUT (build 11875450).
      //
      // We end res cleanly (not destroy/RST) - combined with the
      // chunked Transfer-Encoding we use for streamed responses
      // (see the writeHead site below where content-length is
      // stripped), this surfaces to npm as a complete-but-truncated
      // response. pacote then computes the integrity over the bytes
      // that did arrive, sees a sha512 mismatch, and refetches via
      // its built-in EINTEGRITY retry path. The install completes
      // even when the upstream registry RSTs a tarball mid-stream.
      // RSTing res (destroy(err)) would surface as ECONNRESET, which
      // pacote's tarball stream does NOT treat as retriable, so the
      // install would still fail.
      if (!res.headersSent) {
        res.writeHead(502);
        res.end("Bad Gateway");
      } else if (!res.writableEnded) {
        res.end();
      }
    });

    proxyRes.on("close", () => {
      // Some upstream failures emit 'close' without a preceding
      // 'error' and without a clean 'end'. pipe doesn't catch this
      // either. Same fix as above: end res cleanly so npm sees a
      // complete-but-truncated response and can retry on integrity.
      if (!proxyRes.complete && res.headersSent && !res.writableEnded) {
        res.end();
      }
    });

    if (!proxyRes.statusCode) {
      ui.writeError(
        `Safe-chain: Proxy response missing status code to ${req.url} for ${hostname}`
      );
      res.writeHead(500);
      res.end("Internal Server Error");
      return;
    }

    const { statusCode, headers } = proxyRes;

    if (requestHandler.modifiesResponse()) {
      /** @type {Array<any>} */
      let chunks = [];

      proxyRes.on("data", (chunk) => chunks.push(chunk));

      proxyRes.on("end", () => {
        /** @type {Buffer} */
        let buffer = Buffer.concat(chunks);

        if (proxyRes.headers["content-encoding"] === "gzip") {
          buffer = gunzipSync(buffer);
        }

        buffer = requestHandler.modifyBody(buffer, headers);

        // For rewritten responses, send the final body uncompressed.
        // This avoids mismatches between upstream compression metadata and the
        // rewritten payload on the wire.
        const rewrittenHeaders = omitHeaders(
          headers,
          ["content-length", "transfer-encoding", "content-encoding"],
          { caseInsensitive: true }
        ) || {};
        rewrittenHeaders["content-length"] = String(buffer.byteLength);
        res.writeHead(statusCode, rewrittenHeaders);
        res.end(buffer);
      });
    } else {
      // If the response is not being modified, we can just pipe
      // without buffering. We strip content-length and
      // transfer-encoding from the upstream headers so Node's http
      // server frames our response as chunked. This matters when
      // upstream errors mid-body: with the original content-length
      // forwarded, a short body would surface to the client as a
      // protocol-level abort (which pacote can't retry). Without
      // content-length, the truncation is invisible at the framing
      // level - the client sees a clean stream end, computes the
      // sha512 of what it got, finds a mismatch with the integrity
      // declared in the metadata, and retries via EINTEGRITY.
      const forwardHeaders = omitHeaders(
        headers,
        ["content-length", "transfer-encoding"],
        { caseInsensitive: true }
      ) || {};
      res.writeHead(statusCode, forwardHeaders);
      proxyRes.pipe(res);
    }
  });

  return proxyReq;
}
