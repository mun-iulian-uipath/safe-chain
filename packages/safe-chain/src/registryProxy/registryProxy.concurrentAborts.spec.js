import { describe, it, before, after, mock } from "node:test";
import assert from "node:assert";
import realHttps from "node:https";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import crypto from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import forge from "node-forge";

// Two tarball requests both abort mid-stream during the same npm
// install. The proxy must keep both requests retriable so npm's
// built-in EINTEGRITY path can refetch each truncated tarball and
// the install completes in a single npm invocation - no external
// retry-driving.
//
// Asserts:
//   - npm exits 0
//   - each of the two tarballs was requested at least twice
//     (initial abort + retry)
//   - node_modules contains both packages
//
// Without the fix the install fails: the proxy either crashes on
// the post-headers write, leaves both responses half-open, or
// both - any of those turn into a non-zero npm exit code.

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

describe("registryProxy npm retry on two concurrent truncated tarballs", () => {
  let proxy;
  let fakeRegistry;
  let fakeRegistryUrl;
  let workdir;
  let tarballA, tarballB;
  /** @type {Map<string, number>} */
  const tarballHits = new Map();
  let savedNpmCustomRegistries;
  let safeChainCaPath;

  before(async () => {
    workdir = fs.mkdtempSync(
      path.join(os.tmpdir(), "safe-chain-concurrent-aborts-"),
    );

    tarballA = buildTarball(workdir, "pkg-a");
    tarballB = buildTarball(workdir, "pkg-b");

    const { certPem, keyPem } = generateLocalhostCert();

    savedNpmCustomRegistries = process.env.SAFE_CHAIN_NPM_CUSTOM_REGISTRIES;
    process.env.SAFE_CHAIN_NPM_CUSTOM_REGISTRIES = "localhost";

    fakeRegistry = realHttps.createServer(
      { key: keyPem, cert: certPem },
      (req, res) => {
        const metaMatch = req.url.match(/^\/(pkg-[ab])$/);
        if (metaMatch) {
          const name = metaMatch[1];
          const buf = name === "pkg-a" ? tarballA : tarballB;
          const body = Buffer.from(
            JSON.stringify(makePackument(name, buf, fakeRegistryUrl)),
          );
          res.writeHead(200, {
            "content-type": "application/json",
            "content-length": body.length,
          });
          res.end(body);
          return;
        }

        const tarMatch = req.url.match(/^\/(pkg-[ab])\/-\/\1-1\.0\.0\.tgz$/);
        if (tarMatch) {
          const name = tarMatch[1];
          const buf = name === "pkg-a" ? tarballA : tarballB;
          const hits = (tarballHits.get(name) ?? 0) + 1;
          tarballHits.set(name, hits);

          if (hits === 1) {
            // Send headers with content-length, write half the body,
            // then RST the socket. Both pkg-a and pkg-b hit this path
            // on their first request, ~simultaneously, so the proxy
            // has to handle two in-flight upstream aborts at once.
            res.writeHead(200, {
              "content-type": "application/octet-stream",
              "content-length": buf.length,
            });
            res.write(buf.subarray(0, Math.floor(buf.length / 2)));
            setImmediate(() => res.socket.destroy());
            return;
          }

          // Subsequent hits: serve the full tarball.
          res.writeHead(200, {
            "content-type": "application/octet-stream",
            "content-length": buf.length,
          });
          res.end(buf);
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

  it("npm install completes via retry when two tarballs abort concurrently", async () => {
    const projectDir = path.join(workdir, "project");
    fs.mkdirSync(projectDir, { recursive: true });
    fs.writeFileSync(
      path.join(projectDir, "package.json"),
      JSON.stringify({
        name: "test-project",
        version: "1.0.0",
        dependencies: { "pkg-a": "1.0.0", "pkg-b": "1.0.0" },
      }),
    );

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
      npm_config_fetch_timeout: "10000",
      npm_config_fetch_retries: "2",
      npm_config_fetch_retry_mintimeout: "100",
      npm_config_fetch_retry_maxtimeout: "500",
      NODE_EXTRA_CA_CERTS: safeChainCaPath,
    });

    tarballHits.clear();

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
        `tarballHits=${[...tarballHits.entries()]
          .map(([k, v]) => `${k}=${v}`)
          .join(", ")}\n` +
        `stderr:\n${result.stderr}\nstdout:\n${result.stdout}`,
    );
    assert.ok(
      (tarballHits.get("pkg-a") ?? 0) >= 2,
      `pkg-a tarball must be requested at least twice (initial + retry); ` +
        `got ${tarballHits.get("pkg-a") ?? 0}`,
    );
    assert.ok(
      (tarballHits.get("pkg-b") ?? 0) >= 2,
      `pkg-b tarball must be requested at least twice (initial + retry); ` +
        `got ${tarballHits.get("pkg-b") ?? 0}`,
    );
    assert.ok(
      fs.existsSync(
        path.join(projectDir, "node_modules", "pkg-a", "package.json"),
      ),
      "pkg-a must end up installed in node_modules",
    );
    assert.ok(
      fs.existsSync(
        path.join(projectDir, "node_modules", "pkg-b", "package.json"),
      ),
      "pkg-b must end up installed in node_modules",
    );
    assert.ok(
      elapsed < 30000,
      `install must complete in <30s; took ${elapsed}ms`,
    );
  });
});

// --- helpers ---------------------------------------------------------------

function buildTarball(workdir, name) {
  const fixtures = path.join(workdir, "fixtures", name);
  fs.mkdirSync(path.join(fixtures, "package"), { recursive: true });
  fs.writeFileSync(
    path.join(fixtures, "package", "package.json"),
    JSON.stringify({ name, version: "1.0.0", main: "index.js" }),
  );
  fs.writeFileSync(
    path.join(fixtures, "package", "index.js"),
    `module.exports = ${JSON.stringify(name)};\n`,
  );
  const tarRes = spawnSync("tar", ["-czf", `${name}-1.0.0.tgz`, "package"], {
    cwd: fixtures,
  });
  if (tarRes.status !== 0) {
    throw new Error(`tar failed: ${tarRes.stderr?.toString() ?? "(no stderr)"}`);
  }
  return fs.readFileSync(path.join(fixtures, `${name}-1.0.0.tgz`));
}

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

function makePackument(name, tarballBuf, registryUrl) {
  const sha512 = crypto
    .createHash("sha512")
    .update(tarballBuf)
    .digest("base64");
  const shasum = crypto.createHash("sha1").update(tarballBuf).digest("hex");
  const oldDate = "2020-01-01T00:00:00.000Z";
  return {
    name,
    "dist-tags": { latest: "1.0.0" },
    versions: {
      "1.0.0": {
        name,
        version: "1.0.0",
        main: "index.js",
        dist: {
          tarball: `${registryUrl}/${name}/-/${name}-1.0.0.tgz`,
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
