const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');

const target = 'https://tls.peet.ws/api/all';
const expected = {
  browserMajor: '151',
  ciphers: [
    'TLS_AES_128_GCM_SHA256',
    'TLS_AES_256_GCM_SHA384',
    'TLS_CHACHA20_POLY1305_SHA256',
    'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
    'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
    'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
    'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
    'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
    'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
    'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
    'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
    'TLS_RSA_WITH_AES_128_GCM_SHA256',
    'TLS_RSA_WITH_AES_256_GCM_SHA384',
    'TLS_RSA_WITH_AES_128_CBC_SHA',
    'TLS_RSA_WITH_AES_256_CBC_SHA',
  ],
  extensionIds: [
    0, 5, 10, 11, 13, 16, 18, 23, 27, 35, 43, 45, 51, 17613, 65037, 65281,
  ],
  signatureAlgorithms: [
    '0x904',
    '0x905',
    '0x906',
    'ecdsa_secp256r1_sha256',
    'rsa_pss_rsae_sha256',
    'rsa_pkcs1_sha256',
    'ecdsa_secp384r1_sha384',
    'rsa_pss_rsae_sha384',
    'rsa_pkcs1_sha384',
    'rsa_pss_rsae_sha512',
    'rsa_pkcs1_sha512',
  ],
  groups: ['X25519MLKEM768 (4588)', 'X25519 (29)', 'P-256 (23)', 'P-384 (24)'],
  freshJa4: 't13d1516h2_8daaf6152771_806a8c22fdea',
  resumedJa4: 't13d1517h2_8daaf6152771_a87ad97598a9',
  freshPeetprint: '67c3e9111bed9e7f03d2f21d6d88994b',
  resumedPeetprint: '35fc5e864929e3b01e9ba9eb41bc1360',
};

function isGrease(name) {
  return name.startsWith('TLS_GREASE ');
}

function extensionId(extension) {
  if (isGrease(extension.name)) return 'GREASE';
  const match = extension.name.match(/\((\d+)\)$/);
  assert(match, `extension has no numeric id: ${extension.name}`);
  return Number(match[1]);
}

function findExtension(tls, prefix) {
  return tls.extensions.find(({ name }) => name.startsWith(prefix));
}

function readU16(buffer, offset) {
  assert(offset + 2 <= buffer.length, 'truncated uint16');
  return buffer.readUInt16BE(offset);
}

function readU24(buffer, offset) {
  assert(offset + 3 <= buffer.length, 'truncated uint24');
  return (buffer[offset] << 16) | (buffer[offset + 1] << 8) | buffer[offset + 2];
}

function validatePsk(extension) {
  const data = Buffer.from(extension.data, 'hex');
  let offset = 0;
  const identitiesLength = readU16(data, offset);
  offset += 2;
  const identitiesEnd = offset + identitiesLength;
  assert(identitiesEnd + 2 <= data.length, 'truncated PSK identities');
  let identityCount = 0;
  let identityLength = 0;
  while (offset < identitiesEnd) {
    identityLength = readU16(data, offset);
    offset += 2;
    assert(identityLength > 0 && offset + identityLength + 4 <= identitiesEnd);
    offset += identityLength + 4;
    ++identityCount;
  }
  const bindersLength = readU16(data, offset);
  offset += 2;
  const bindersEnd = offset + bindersLength;
  assert.equal(bindersEnd, data.length, 'PSK binder vector length');
  let binderCount = 0;
  let binderLength = 0;
  while (offset < bindersEnd) {
    binderLength = data[offset++];
    assert(binderLength > 0 && offset + binderLength <= bindersEnd);
    offset += binderLength;
    ++binderCount;
  }
  assert.equal(identityCount, 1);
  assert.equal(binderCount, 1);
  assert.equal(identityLength, 113);
  assert.equal(binderLength, 32);
  return { identityLength, binderLength };
}

function validateTls(tls, resumed) {
  assert.equal(tls.tls_version_record, '771');
  assert.equal(tls.tls_version_negotiated, '772');
  assert(isGrease(tls.ciphers[0]), 'first cipher must be GREASE');
  assert.deepEqual(tls.ciphers.slice(1), expected.ciphers);

  const ids = tls.extensions.map(extensionId);
  assert.equal(ids[0], 'GREASE');
  assert.equal(ids[resumed ? ids.length - 2 : ids.length - 1], 'GREASE');
  if (resumed) {
    assert.equal(ids.at(-1), 41, 'pre_shared_key must be last');
  } else {
    assert(!ids.includes(41), 'fresh ClientHello must not contain a PSK');
  }
  const stableIds = ids.filter((id) => id !== 'GREASE' && id !== 41).sort((a, b) => a - b);
  assert.deepEqual(stableIds, expected.extensionIds);

  const signatures = findExtension(tls, 'signature_algorithms ');
  assert.deepEqual(signatures.signature_algorithms, expected.signatureAlgorithms);
  const groups = findExtension(tls, 'supported_groups ');
  assert(isGrease(groups.supported_groups[0]));
  assert.deepEqual(groups.supported_groups.slice(1), expected.groups);
  const versions = findExtension(tls, 'supported_versions ');
  assert(isGrease(versions.versions[0]));
  assert.deepEqual(versions.versions.slice(1), ['TLS 1.3', 'TLS 1.2']);
  assert.deepEqual(
    findExtension(tls, 'application_layer_protocol_negotiation ').protocols,
    ['h2', 'http/1.1'],
  );
  assert.deepEqual(findExtension(tls, 'application_settings ').protocols, ['h2']);

  const keyShare = findExtension(tls, 'key_share ');
  const shares = keyShare.shared_keys.map((entry) => Object.entries(entry)[0]);
  assert(isGrease(shares[0][0]));
  assert.equal(shares[0][1].length, 2);
  assert.equal(shares[1][0], 'X25519MLKEM768 (4588)');
  assert.equal(shares[1][1].length, 1216 * 2);
  assert.equal(shares[2][0], 'X25519 (29)');
  assert.equal(shares[2][1].length, 32 * 2);

  const psk = findExtension(tls, 'pre_shared_key ');
  const pskLengths = resumed ? validatePsk(psk) : null;
  assert.equal(tls.ja4, resumed ? expected.resumedJa4 : expected.freshJa4);
  assert.equal(
    tls.peetprint_hash,
    resumed ? expected.resumedPeetprint : expected.freshPeetprint,
  );
  return { ids, pskLengths };
}

function normalize(rawFiles) {
  const captures = [];
  let browserVersion = null;
  let capturedAt = null;
  for (let session = 0; session < rawFiles.length; ++session) {
    const raw = rawFiles[session];
    browserVersion ??= raw.browser_version;
    capturedAt ??= raw.captured_at;
    assert.equal(raw.browser_version, browserVersion);
    assert.equal(raw.target, target);
    assert.equal(raw.captures.length, 5);
    for (const capture of raw.captures) {
      const resumed = capture.label !== 'fresh';
      const checked = validateTls(capture.data.tls, resumed);
      captures.push({
        session: session + 1,
        label: capture.label,
        resumed,
        ja3_hash: capture.data.tls.ja3_hash,
        ja4: capture.data.tls.ja4,
        peetprint_hash: capture.data.tls.peetprint_hash,
        extensions: checked.ids,
        tls_record_length: capture.wire && capture.wire.tls_record_length,
        clienthello_handshake_length: capture.wire && capture.wire.clienthello_handshake_length,
        clienthello_sha256: capture.wire && capture.wire.clienthello_sha256,
      });
    }
  }
  assert.equal(browserVersion.split('.')[0], expected.browserMajor);
  assert.equal(new Set(captures.map(({ ja3_hash }) => ja3_hash)).size, captures.length);
  return {
    schema_version: 1,
    profile_id: 'chromium-151-windows-x64',
    browser_version: browserVersion,
    platform: `${os.type()} ${os.release()} ${os.arch()}`,
    captured_at: capturedAt,
    target,
    capture_transport: 'local SOCKS5 pass-through to tls.peet.ws:443; no TLS termination',
    source_capture_sha256: rawFiles.map((raw) =>
      crypto.createHash('sha256').update(JSON.stringify(raw)).digest('hex')),
    stable: {
      ciphers: expected.ciphers,
      extension_ids: expected.extensionIds,
      signature_algorithms: expected.signatureAlgorithms,
      supported_groups: expected.groups,
      fresh_ja4: expected.freshJa4,
      resumed_ja4: expected.resumedJa4,
      fresh_peetprint_hash: expected.freshPeetprint,
      resumed_peetprint_hash: expected.resumedPeetprint,
      psk_identity_length: 113,
      psk_binder_length: 32,
    },
    captures,
  };
}

function verifyEvidence(evidence) {
  assert.equal(evidence.schema_version, 1);
  assert.equal(evidence.profile_id, 'chromium-151-windows-x64');
  assert.equal(evidence.browser_version.split('.')[0], expected.browserMajor);
  assert.equal(evidence.target, target);
  assert.equal(evidence.capture_transport, 'local SOCKS5 pass-through to tls.peet.ws:443; no TLS termination');
  assert(!Number.isNaN(Date.parse(evidence.captured_at)));
  assert(evidence.source_capture_sha256.length >= 2);
  for (const hash of evidence.source_capture_sha256) {
    assert.match(hash, /^[0-9a-f]{64}$/);
  }
  assert.deepEqual(evidence.stable.ciphers, expected.ciphers);
  assert.deepEqual(evidence.stable.extension_ids, expected.extensionIds);
  assert.deepEqual(evidence.stable.signature_algorithms, expected.signatureAlgorithms);
  assert.deepEqual(evidence.stable.supported_groups, expected.groups);
  assert.equal(evidence.stable.fresh_ja4, expected.freshJa4);
  assert.equal(evidence.stable.resumed_ja4, expected.resumedJa4);
  assert.equal(evidence.stable.fresh_peetprint_hash, expected.freshPeetprint);
  assert.equal(evidence.stable.resumed_peetprint_hash, expected.resumedPeetprint);
  assert.equal(evidence.stable.psk_identity_length, 113);
  assert.equal(evidence.stable.psk_binder_length, 32);

  const fresh = evidence.captures.filter(({ resumed }) => !resumed);
  const repeated = evidence.captures.filter(({ resumed }) => resumed);
  assert(fresh.length >= 2);
  assert(repeated.length >= 8);
  for (const capture of evidence.captures) {
    assert.equal(capture.extensions[0], 'GREASE');
    assert.equal(capture.extensions[capture.resumed ? capture.extensions.length - 2 : capture.extensions.length - 1], 'GREASE');
    assert.equal(capture.extensions.includes(41), capture.resumed);
    if (capture.resumed) assert.equal(capture.extensions.at(-1), 41);
    const stableIds = capture.extensions
      .filter((id) => id !== 'GREASE' && id !== 41)
      .sort((a, b) => a - b);
    assert.deepEqual(stableIds, expected.extensionIds);
    assert.match(capture.ja3_hash, /^[0-9a-f]{32}$/);
    assert.equal(capture.ja4, capture.resumed ? expected.resumedJa4 : expected.freshJa4);
    assert.equal(
      capture.peetprint_hash,
      capture.resumed ? expected.resumedPeetprint : expected.freshPeetprint,
    );
    assert(Number.isInteger(capture.tls_record_length) && capture.tls_record_length > 0);
    assert(Number.isInteger(capture.clienthello_handshake_length) && capture.clienthello_handshake_length > 0);
    assert.equal(capture.tls_record_length, capture.clienthello_handshake_length + 4);
    assert.match(capture.clienthello_sha256, /^[0-9a-f]{64}$/);
  }
  assert.equal(new Set(evidence.captures.map(({ ja3_hash }) => ja3_hash)).size, evidence.captures.length);
  for (const session of new Set(evidence.captures.map(({ session }) => session))) {
    const captures = evidence.captures.filter((capture) => capture.session === session);
    assert.equal(captures.filter(({ resumed }) => !resumed).length, 1);
    assert.equal(captures.filter(({ resumed }) => resumed).length, 4);
  }
}

async function verifyPatchedSource(sourcePath) {
  const source = await fs.readFile(sourcePath, 'utf8');
  const start = source.indexOf('MTPTlsClientHello PrepareClientHelloRules_Chromium151');
  const end = source.indexOf('using Chromium151EndpointKey', start);
  assert(start >= 0 && end > start, 'Chromium 151 production profile was not found');
  const profile = source.slice(start, end);
  const required = [
    '\\x13\\x01\\x13\\x02\\x13\\x03\\xc0\\x2b\\xc0\\x2f\\xc0\\x2c\\xc0\\x30\\xcc\\xa9',
    '\\xcc\\xa8\\xc0\\x13\\xc0\\x14\\x00\\x9c\\x00\\x9d\\x00\\x2f\\x00\\x35',
    'S("\\x00\\x05\\x00\\x05\\x01\\x00\\x00\\x00\\x00"_q);',
    'S("\\x00\\x0a\\x00\\x0c\\x00\\x0a"_q);',
    'S("\\x11\\xec\\x00\\x1d\\x00\\x17\\x00\\x18"_q);',
    '\\x00\\x0d\\x00\\x18\\x00\\x16\\x09\\x04\\x09\\x05\\x09\\x06\\x04\\x03',
    '\\x08\\x04\\x04\\x01\\x05\\x03\\x08\\x05\\x05\\x01\\x08\\x06\\x06\\x01',
    '\\x00\\x10\\x00\\x0e\\x00\\x0c\\x02\\x68\\x32\\x08\\x68\\x74\\x74\\x70',
    'S("\\x00\\x12\\x00\\x00"_q);',
    'S("\\x00\\x17\\x00\\x00"_q);',
    'S("\\x00\\x1b\\x00\\x03\\x02\\x00\\x02"_q);',
    'S("\\x00\\x23\\x00\\x00"_q);',
    'S("\\x00\\x2b\\x00\\x07\\x06"_q);',
    'S("\\x00\\x2d\\x00\\x02\\x01\\x01"_q);',
    'S("\\x00\\x33\\x04\\xef\\x04\\xed"_q);',
    'S("\\x00\\x01\\x00\\x11\\xec\\x04\\xc0"_q);',
    'S("\\x00\\x1d\\x00\\x20"_q);',
    'S("\\x44\\xcd\\x00\\x05\\x00\\x03\\x02\\x68\\x32"_q);',
    'S("\\xfe\\x0d"_q);',
    'S("\\xff\\x01\\x00\\x01\\x00"_q);',
    'R(113);',
    'S("\\x00\\x21\\x20"_q);',
    'R(32);',
  ];
  for (const token of required) {
    assert(profile.includes(token), `production Chromium 151 profile drifted: ${token}`);
  }
  const compact = profile.replace(/\s+/g, '');
  assert(compact.includes('}ClosePermutation();G(3);S("\\x00\\x01\\x00"_q);if(resumed){S("\\x00\\x29"_q);'));
}

async function startCaptureProxy() {
  const hellos = [];
  const server = net.createServer((client) => {
    let upstream = null;
    let pending = Buffer.alloc(0);
    let state = 'greeting';
    let captured = false;
    const tunnel = (chunk) => {
      if (!captured) {
        pending = Buffer.concat([pending, chunk]);
        if (pending.length >= 5) {
          const total = 5 + readU16(pending, 3);
          if (pending.length >= total) {
            hellos.push(pending.subarray(0, total));
            captured = true;
          }
        }
      }
      upstream.write(chunk);
    };
    client.on('data', (chunk) => {
      if (state === 'tunnel') {
        tunnel(chunk);
        return;
      }
      pending = Buffer.concat([pending, chunk]);
      if (state === 'greeting') {
        if (pending.length < 2) return;
        const length = 2 + pending[1];
        if (pending.length < length) return;
        assert.equal(pending[0], 5, 'SOCKS version');
        assert(pending.subarray(2, length).includes(0), 'SOCKS no-auth method');
        pending = pending.subarray(length);
        client.write(Buffer.from([5, 0]));
        state = 'request';
      }
      if (state !== 'request' || pending.length < 5) return;
      assert.equal(pending[0], 5, 'SOCKS request version');
      assert.equal(pending[1], 1, 'SOCKS CONNECT command');
      const type = pending[3];
      let offset = 4;
      let host;
      if (type === 1) {
        if (pending.length < offset + 4 + 2) return;
        host = Array.from(pending.subarray(offset, offset + 4)).join('.');
        offset += 4;
      } else if (type === 3) {
        const length = pending[offset++];
        if (pending.length < offset + length + 2) return;
        host = pending.subarray(offset, offset + length).toString('utf8');
        offset += length;
      } else {
        throw new Error(`unsupported SOCKS address type: ${type}`);
      }
      const port = readU16(pending, offset);
      offset += 2;
      const remainder = pending.subarray(offset);
      pending = Buffer.alloc(0);
      assert.equal(host, 'tls.peet.ws');
      assert.equal(port, 443);
      upstream = net.connect(port, host, () => {
        client.write(Buffer.from([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]));
        state = 'tunnel';
        if (remainder.length) tunnel(remainder);
      });
      upstream.on('data', (data) => client.write(data));
      upstream.on('end', () => client.end());
      upstream.on('error', () => client.destroy());
    });
    client.on('end', () => upstream && upstream.end());
    client.on('error', () => upstream && upstream.destroy());
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return {
    hellos,
    port: server.address().port,
    close: () => new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve())),
  };
}

async function closeIdleSockets(context) {
  const page = await context.newPage();
  await page.goto('chrome://net-internals/#sockets');
  const button = page.locator('#sockets-view-close-idle-button');
  await button.waitFor({ state: 'visible', timeout: 10_000 });
  await button.click();
  await page.close();
}

async function captureSession(chromium, executablePath, proxy) {
  const browser = await chromium.launch({
    executablePath,
    headless: true,
    proxy: { server: `socks5://127.0.0.1:${proxy.port}` },
    args: [
      '--disable-quic',
      '--disable-background-networking',
      '--disable-component-update',
      '--no-default-browser-check',
      '--no-first-run',
    ],
  });
  const context = await browser.newContext();
  const captures = [];
  try {
    for (let index = 0; index < 5; ++index) {
      if (index) await closeIdleSockets(context);
      const label = index ? `repeat-${index}` : 'fresh';
      const helloIndex = proxy.hellos.length;
      const page = await context.newPage();
      const response = await page.goto(`${target}?run=${label}&t=${Date.now()}`, {
        waitUntil: 'domcontentloaded',
        timeout: 60_000,
      });
      assert(response && response.ok(), `${label}: HTTP ${response && response.status()}`);
      const data = JSON.parse(await page.locator('body').innerText());
      const clientHello = proxy.hellos.slice(helloIndex).find((hello) =>
        hello.subarray(11, 43).toString('hex') === data.tls.client_random);
      assert(clientHello, `${label}: no captured ClientHello matches the server observation`);
      assert.equal(clientHello[0], 0x16);
      assert.equal(clientHello[5], 0x01);
      assert.equal(5 + readU16(clientHello, 3), clientHello.length);
      assert.equal(9 + readU24(clientHello, 6), clientHello.length);
      await page.goto('about:blank');
      await page.close();
      captures.push({
        label,
        data,
        wire: {
          tls_record_length: readU16(clientHello, 3),
          clienthello_handshake_length: readU24(clientHello, 6),
          clienthello_sha256: crypto.createHash('sha256').update(clientHello).digest('hex'),
        },
      });
    }
    return {
      captured_at: new Date().toISOString(),
      browser_version: browser.version(),
      target,
      captures,
    };
  } finally {
    await browser.close();
  }
}

async function main() {
  const mode = process.argv[2] || '--verify';
  if (mode === '--verify') {
    const evidencePath = process.argv[3] || path.join(__dirname, 'chromium151_capture_evidence.json');
    verifyEvidence(JSON.parse(await fs.readFile(evidencePath, 'utf8')));
    if (process.argv[4]) await verifyPatchedSource(process.argv[4]);
    console.log('Chromium 151 capture evidence tests passed.');
    return;
  }
  if (mode === '--capture') {
    const executablePath = process.argv[3];
    const outputPath = process.argv[4];
    assert(executablePath && outputPath, 'usage: --capture CHROMIUM OUTPUT');
    const { chromium } = require('playwright');
    const raw = [];
    const proxy = await startCaptureProxy();
    try {
      for (let session = 0; session < 2; ++session) {
        raw.push(await captureSession(chromium, executablePath, proxy));
      }
    } finally {
      await proxy.close();
    }
    const evidence = normalize(raw);
    await fs.writeFile(outputPath, `${JSON.stringify(evidence, null, 2)}\n`, 'utf8');
    verifyEvidence(evidence);
    console.log(`Chromium 151 fresh/repeated tests passed; evidence saved to ${outputPath}.`);
    return;
  }
  throw new Error(`unknown mode: ${mode}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
