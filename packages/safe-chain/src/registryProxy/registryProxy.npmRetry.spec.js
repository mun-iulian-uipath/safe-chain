import { describe, it, before, after, mock } from "node:test";
import assert from "node:assert";
import realHttps from "node:https";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import forge from "node-forge";

// When the upstream registry truncates a tarball response mid-body,
// the install must still complete via npm's built-in retry path.
//
// The test runs the *real* npm CLI against a controllable fake
// registry. The first tarball request returns a partial body whose
// sha512 doesn't match the integrity declared in the metadata;
// pacote classifies that as a retriable EINTEGRITY error and
// refetches. The second request returns the full, well-formed
// tarball and the install completes.
//
// Asserts:
//   - npm exits 0
//   - the tarball was requested at least twice (retry happened)
//   - node_modules contains the package
//
// The proxy can break the retry path by leaving the response stalled
// (no FIN/RST after partial body) or by RST-ing the client connection
// in a way pacote can't classify as retriable. Either of those
// regressions fail this test.

// Mock https so the proxy's outbound TLS handshake to our self-signed
// fake registry succeeds without setting NODE_TLS_REJECT_UNAUTHORIZED
// globally (which would also disable verification on every other test
// running concurrently in the same process).
mock.module("https", {
  defaultExport: {
    ...realHttps,
    request: (options, callback) => {
      const opts =
        typeof options === "string"
          ? new URL(options)
          : { ...options, rejectUnauthorized: false };
      return realHttps.request(opts, callback);
    },
    createServer: realHttps.createServer.bind(realHttps),
  },
});

const { createSafeChainProxy, mergeSafeChainProxyEnvironmentVariables } =
  await import("./registryProxy.js");

describe("registryProxy npm retry on truncated tarball", () => {
  let proxy;
  let fakeRegistry;
  let fakeRegistryUrl;
  let workdir;
  let tarballBuf;
  let tarballHits = 0;
  let savedNpmCustomRegistries;
  let safeChainCaPath;

  before(async () => {
    workdir = fs.mkdtempSync(path.join(os.tmpdir(), "safe-chain-retry-"));

    // Build a real tarball so npm's content-integrity check doesn't
    // reject the second (clean) response.
    const fixtures = path.join(workdir, "fixtures");
    fs.mkdirSync(path.join(fixtures, "package"), { recursive: true });
    fs.writeFileSync(
      path.join(fixtures, "package", "package.json"),
      JSON.stringify({
        name: "fake-pkg",
        version: "1.0.0",
        main: "index.js",
      }),
    );
    fs.writeFileSync(
      path.join(fixtures, "package", "index.js"),
      "module.exports = 1;\n",
    );
    const tarRes = spawnSync(
      "tar",
      ["-czf", "fake-pkg-1.0.0.tgz", "package"],
      { cwd: fixtures },
    );
    if (tarRes.status !== 0) {
      throw new Error(
        `tar failed: ${tarRes.stderr?.toString() ?? "(no stderr)"}`,
      );
    }
    tarballBuf = fs.readFileSync(path.join(fixtures, "fake-pkg-1.0.0.tgz"));

    const { certPem, keyPem } = generateLocalhostCert();

    savedNpmCustomRegistries = process.env.SAFE_CHAIN_NPM_CUSTOM_REGISTRIES;
    process.env.SAFE_CHAIN_NPM_CUSTOM_REGISTRIES = "localhost";

    fakeRegistry = realHttps.createServer(
      { key: keyPem, cert: certPem },
      (req, res) => {
        if (req.url === "/fake-pkg") {
          const body = Buffer.from(
            JSON.stringify(makePackument(tarballBuf, fakeRegistryUrl)),
          );
          res.writeHead(200, {
            "content-type": "application/json",
            "content-length": body.length,
          });
          res.end(body);
          return;
        }
        if (req.url === "/fake-pkg/-/fake-pkg-1.0.0.tgz") {
          tarballHits++;
          if (tarballHits === 1) {
            // Send headers with content-length, write half of the
            // body, then RST the underlying socket. This is the
            // upstream-abort-mid-stream shape we want the proxy to
            // tolerate.
            //
            // Without the fix the npm-side response is left half-open
            // with no FIN/RST: npm waits its full fetch-timeout (5 min)
            // and then fails with EIDLETIMEOUT, never getting the
            // chance to retry.
            //
            // With the fix the proxy strips upstream content-length
            // when forwarding (so npm's response is framed as chunked)
            // and ends res cleanly on upstream error. npm sees the
            // truncated body as a complete-but-corrupt response,
            // pacote computes a sha512 mismatch against the integrity
            // in the metadata, classifies it as EINTEGRITY, and
            // refetches. The second hit serves the full tarball; the
            // install completes.
            res.writeHead(200, {
              "content-type": "application/octet-stream",
              "content-length": tarballBuf.length,
            });
            res.write(
              tarballBuf.subarray(0, Math.floor(tarballBuf.length / 2)),
            );
            // Drop the underlying socket on the next tick so the body
            // bytes have a chance to flush before the FIN/RST.
            setImmediate(() => res.socket.destroy());
            return;
          }
          // Subsequent hits: serve the full tarball.
          res.writeHead(200, {
            "content-type": "application/octet-stream",
            "content-length": tarballBuf.length,
          });
          res.end(tarballBuf);
          return;
        }
        res.writeHead(404);
        res.end();
      },
    );
    await new Promise((r) => fakeRegistry.listen(0, "127.0.0.1", r));
    const port = fakeRegistry.address().port;
    fakeRegistryUrl = `https://localhost:${port}`;

    proxy = createSafeChainProxy();
    await proxy.startServer();

    const env = mergeSafeChainProxyEnvironmentVariables({});
    safeChainCaPath = env.NODE_EXTRA_CA_CERTS;
  });

  after(async () => {
    if (proxy) await proxy.stopServer();
    if (fakeRegistry) await new Promise((r) => fakeRegistry.close(r));
    if (workdir) fs.rmSync(workdir, { recursive: true, force: true });
    if (savedNpmCustomRegistries === undefined) {
      delete process.env.SAFE_CHAIN_NPM_CUSTOM_REGISTRIES;
    } else {
      process.env.SAFE_CHAIN_NPM_CUSTOM_REGISTRIES = savedNpmCustomRegistries;
    }
  });

  it("npm install succeeds through safe-chain when the first tarball is corrupted", async () => {
    const projectDir = path.join(workdir, "project");
    fs.mkdirSync(projectDir, { recursive: true });
    fs.writeFileSync(
      path.join(projectDir, "package.json"),
      JSON.stringify({
        name: "test-project",
        version: "1.0.0",
        dependencies: { "fake-pkg": "1.0.0" },
      }),
    );

    // Isolated npm cache so a stale cache entry can't affect the run.
    const npmCacheDir = path.join(workdir, "npm-cache");
    fs.mkdirSync(npmCacheDir, { recursive: true });

    const env = mergeSafeChainProxyEnvironmentVariables({
      ...process.env,
      NODE_TLS_REJECT_UNAUTHORIZED: undefined,
      npm_config_cache: npmCacheDir,
      npm_config_registry: `${fakeRegistryUrl}/`,
      npm_config_progress: "false",
      npm_config_loglevel: "warn",
      npm_config_audit: "false",
      npm_config_fund: "false",
      // Tight fetch-timeout so the test fails fast without the fix
      // instead of hanging on npm's default 5-minute idle timeout
      // before surfacing EIDLETIMEOUT.
      npm_config_fetch_timeout: "10000",
      npm_config_fetch_retries: "2",
      npm_config_fetch_retry_mintimeout: "100",
      npm_config_fetch_retry_maxtimeout: "500",
      NODE_EXTRA_CA_CERTS: safeChainCaPath,
    });

    tarballHits = 0;

    const start = Date.now();
    const result = await runNpm(
      ["install", "--no-audit", "--no-fund", "--no-package-lock"],
      projectDir,
      env,
    );
    const elapsed = Date.now() - start;

    assert.equal(
      result.code,
      0,
      `npm install must succeed end-to-end through the proxy. ` +
        `code=${result.code}, elapsed=${elapsed}ms\n` +
        `tarballHits=${tarballHits}\n` +
        `stderr:\n${result.stderr}\nstdout:\n${result.stdout}`,
    );
    assert.ok(
      tarballHits >= 2,
      `tarball must be requested at least twice (initial + retry); ` +
        `got ${tarballHits}. The retry path is the whole point of the test.`,
    );
    assert.ok(
      fs.existsSync(
        path.join(projectDir, "node_modules", "fake-pkg", "package.json"),
      ),
      "the package must end up installed in node_modules",
    );
    assert.ok(
      elapsed < 30000,
      `install must complete in <30s; took ${elapsed}ms`,
    );
  });
});

// --- helpers ---------------------------------------------------------------

function runNpm(args, cwd, env) {
  return new Promise((resolve) => {
    const child = spawn("npm", args, {
      cwd,
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d.toString()));
    child.stderr.on("data", (d) => (stderr += d.toString()));
    child.on("exit", (code) => resolve({ code, stdout, stderr }));
    child.on("error", (err) =>
      resolve({ code: -1, stdout, stderr: stderr + String(err) }),
    );
  });
}

function generateLocalhostCert() {
  const caKeys = forge.pki.rsa.generateKeyPair(2048);
  const ca = forge.pki.createCertificate();
  ca.publicKey = caKeys.publicKey;
  ca.serialNumber = "01";
  ca.validity.notBefore = new Date();
  ca.validity.notAfter = new Date();
  ca.validity.notAfter.setHours(ca.validity.notBefore.getHours() + 1);
  ca.setSubject([{ name: "commonName", value: "test-ca" }]);
  ca.setIssuer([{ name: "commonName", value: "test-ca" }]);
  ca.setExtensions([
    { name: "basicConstraints", cA: true, critical: true },
    { name: "keyUsage", keyCertSign: true, digitalSignature: true },
  ]);
  ca.sign(caKeys.privateKey, forge.md.sha256.create());

  const serverKeys = forge.pki.rsa.generateKeyPair(2048);
  const server = forge.pki.createCertificate();
  server.publicKey = serverKeys.publicKey;
  server.serialNumber = "02";
  server.validity.notBefore = new Date();
  server.validity.notAfter = new Date();
  server.validity.notAfter.setHours(server.validity.notBefore.getHours() + 1);
  server.setSubject([{ name: "commonName", value: "localhost" }]);
  server.setIssuer(ca.subject.attributes);
  server.setExtensions([
    {
      name: "subjectAltName",
      altNames: [
        { type: 7, ip: "127.0.0.1" },
        { type: 2, value: "localhost" },
      ],
    },
    { name: "keyUsage", digitalSignature: true, keyEncipherment: true },
    { name: "extKeyUsage", serverAuth: true },
  ]);
  server.sign(caKeys.privateKey, forge.md.sha256.create());

  return {
    certPem: forge.pki.certificateToPem(server),
    keyPem: forge.pki.privateKeyToPem(serverKeys.privateKey),
  };
}

function makePackument(tarballBuf, registryUrl) {
  const sha512 = crypto
    .createHash("sha512")
    .update(tarballBuf)
    .digest("base64");
  const shasum = crypto.createHash("sha1").update(tarballBuf).digest("hex");
  // Old enough to stay below safe-chain's minimum-package-age cutoff so
  // the metadata rewrite leaves the version in place.
  const oldDate = "2020-01-01T00:00:00.000Z";
  return {
    name: "fake-pkg",
    "dist-tags": { latest: "1.0.0" },
    versions: {
      "1.0.0": {
        name: "fake-pkg",
        version: "1.0.0",
        main: "index.js",
        dist: {
          tarball: `${registryUrl}/fake-pkg/-/fake-pkg-1.0.0.tgz`,
          shasum,
          integrity: `sha512-${sha512}`,
        },
      },
    },
    time: {
      created: oldDate,
      modified: oldDate,
      "1.0.0": oldDate,
    },
  };
}
