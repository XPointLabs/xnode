'use strict';
// Test-only transparent public origin. No native frame parsing or authority.
// Header hygiene matches the existing HAProxy policy; the real client checks
// every received header. Nothing writes request/response bytes or identifiers.
const http2 = require('node:http2');
const tls = require('node:tls');
const crypto = require('node:crypto');
const readline = require('node:readline');
if (Number(process.versions.node.split('.')[0]) < 22) process.exit(1);
const input = readline.createInterface({ input: process.stdin });
input.once('line', line => {
  const config = JSON.parse(line);
  const sessions = new Set();
  const server = http2.createSecureServer({ cert: config.cert, key: config.key, allowHTTP1: false });
  server.on('session', session => {
    sessions.add(session);
    session.on('close', () => sessions.delete(session));
    session.on('error', () => {});
  });
  server.on('stream', (incoming, headers) => {
    const managed = headers[':path'].split('?')[0].startsWith('/api/ingress/');
    const upstream = http2.connect(`https://127.0.0.1:${managed ? config.managedPort : config.peerPort}`, {
      ca: config.cert,
      checkServerIdentity: (host, certificate) => {
        const error = tls.checkServerIdentity(host, certificate);
        if (error) return error;
        const spki = new crypto.X509Certificate(certificate.raw).publicKey.export({ type: 'spki', format: 'der' });
        const pin = crypto.createHash('sha256').update(spki).digest('hex');
        if (pin !== config.pin) return new Error('Test ingress TLS pin mismatch.');
      }
    });
    const forwarded = { ...headers };
    if (managed) forwarded['x-forwarded-proto'] = 'https';
    const request = upstream.request(forwarded);
    const abort = () => { incoming.destroy(); upstream.destroy(); };
    upstream.on('error', abort);
    request.on('error', abort);
    incoming.on('error', () => upstream.destroy());
    incoming.on('close', () => upstream.destroy());
    request.on('response', response => {
      // Program can reject headers/size before reading a hostile body. Drain
      // only the public stream so its flow-control credit cannot deadlock the
      // client upload; do not keep sending that body to the rejecting listener.
      incoming.unpipe(request);
      if (!request.writableEnded) request.end();
      incoming.resume();
      const publicHeaders = { ...response, 'cache-control': 'no-store' };
      delete publicHeaders.date;
      delete publicHeaders.server;
      incoming.respond(publicHeaders, { sendDate: false });
      request.pipe(incoming);
    });
    incoming.pipe(request);
  });
  server.on('error', () => process.exit(1));
  server.listen(config.port, '127.0.0.1', () => process.stdout.write('ready\n'));
  input.on('close', () => {
    for (const session of sessions) session.destroy();
    server.close(() => process.exit(0));
  });
});
