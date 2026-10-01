'use strict';

// Minimal DNS wire-protocol client (RFC 1035 with EDNS0). It sends a query to one DNS server over
// UDP, retries over TCP when the answer is truncated, or uses a TCP connection supplied by the caller
// (for example a tunnel through a proxy), and decodes the reply. No dependencies.

const dgram = require('dgram');
const net = require('net');
const crypto = require('crypto');

const TYPE_CODES = { A: 1, NS: 2, CNAME: 5, PTR: 12, MX: 15, TXT: 16, AAAA: 28 };
const RCODE_NAMES = ['NOERROR', 'FORMERR', 'SERVFAIL', 'NXDOMAIN', 'NOTIMP', 'REFUSED'];

const timeoutError = () => Object.assign(new Error('timed out'), { code: 'ETIMEDOUT' });

// --- Encoding --------------------------------------------------------------

function encodeName(name) {
  const parts = [];
  for (const label of name.replace(/\.$/, '').split('.')) {
    const bytes = Buffer.from(label, 'utf8');
    if (bytes.length === 0 || bytes.length > 63) throw new Error('invalid DNS name');
    parts.push(Buffer.from([bytes.length]), bytes);
  }
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}

// Recursion desired, plus the AD bit so validating resolvers report DNSSEC status (RFC 6840).
function encodeQuery(id, name, typeCode, edns) {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(0x0120, 2);
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(edns ? 1 : 0, 10);
  const question = Buffer.concat([encodeName(name), Buffer.from([typeCode >> 8, typeCode & 255, 0, 1])]);
  // EDNS0 OPT record advertising a 1232-byte UDP payload (avoids most truncation).
  const opt = edns ? Buffer.from([0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]) : Buffer.alloc(0);
  return Buffer.concat([header, question, opt]);
}

// --- Decoding --------------------------------------------------------------

function readName(buf, offset) {
  const labels = [];
  let pos = offset;
  let end = -1;
  let hops = 0;
  for (;;) {
    if (pos >= buf.length) throw new Error('truncated name');
    const length = buf[pos];
    if (length === 0) {
      if (end < 0) end = pos + 1;
      break;
    }
    if ((length & 0xc0) === 0xc0) {
      if (pos + 1 >= buf.length) throw new Error('truncated name pointer');
      if (end < 0) end = pos + 2;
      if (++hops > 64) throw new Error('name compression loop');
      pos = ((length & 0x3f) << 8) | buf[pos + 1];
      continue;
    }
    if (length > 63 || pos + 1 + length > buf.length) throw new Error('bad label');
    labels.push(buf.toString('latin1', pos + 1, pos + 1 + length));
    pos += 1 + length;
  }
  return { name: labels.join('.'), next: end };
}

function formatIPv6(bytes) {
  const groups = [];
  for (let i = 0; i < 16; i += 2) groups.push(bytes.readUInt16BE(i).toString(16));
  // The URL serializer applies RFC 5952 compression (longest zero run, lowercase).
  return new URL(`http://[${groups.join(':')}]/`).hostname.slice(1, -1);
}

function parseRdata(buf, type, start, end) {
  switch (type) {
    case 1:
      if (end - start !== 4) throw new Error('bad A record');
      return [...buf.subarray(start, end)].join('.');
    case 28:
      if (end - start !== 16) throw new Error('bad AAAA record');
      return formatIPv6(buf.subarray(start, end));
    case 2:
    case 5:
    case 12:
      return readName(buf, start).name;
    case 15:
      return `${buf.readUInt16BE(start)} ${readName(buf, start + 2).name}`;
    case 16: {
      const strings = [];
      for (let pos = start; pos < end; pos += 1 + buf[pos]) strings.push(buf.subarray(pos + 1, pos + 1 + buf[pos]));
      return Buffer.concat(strings).toString('utf8');
    }
    default:
      return buf.subarray(start, end).toString('hex');
  }
}

function parseRecord(buf, offset) {
  const { name, next } = readName(buf, offset);
  if (next + 10 > buf.length) throw new Error('truncated record');
  const type = buf.readUInt16BE(next);
  const ttl = buf.readUInt32BE(next + 4);
  const start = next + 10;
  const end = start + buf.readUInt16BE(next + 8);
  if (end > buf.length) throw new Error('truncated record data');
  return { name, type, ttl, data: parseRdata(buf, type, start, end), next: end };
}

function decodeMessage(buf) {
  if (buf.length < 12) throw new Error('response too short');
  const flags = buf.readUInt16BE(2);
  const questionCount = buf.readUInt16BE(4);
  const answerCount = buf.readUInt16BE(6);
  let offset = 12;
  const questions = [];
  for (let i = 0; i < questionCount; i++) {
    const { name, next } = readName(buf, offset);
    if (next + 4 > buf.length) throw new Error('truncated question');
    questions.push({ name, type: buf.readUInt16BE(next) });
    offset = next + 4;
  }
  const answers = [];
  for (let i = 0; i < answerCount; i++) {
    const record = parseRecord(buf, offset);
    answers.push(record);
    offset = record.next;
  }
  return {
    id: buf.readUInt16BE(0),
    response: Boolean(flags & 0x8000),
    authoritative: Boolean(flags & 0x0400),
    truncated: Boolean(flags & 0x0200),
    recursionAvailable: Boolean(flags & 0x0080),
    authenticated: Boolean(flags & 0x0020),
    rcode: flags & 0x0f,
    questions,
    answers,
  };
}

// --- Transports ------------------------------------------------------------

function exchangeUdp(server, port, packet, timeoutMs, accept) {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket(net.isIPv6(server) ? 'udp6' : 'udp4');
    let settled = false;
    const finish = (settle, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        socket.close();
      } catch {
        // already closed
      }
      settle(value);
    };
    const timer = setTimeout(() => finish(reject, timeoutError()), timeoutMs);
    socket.on('error', (err) => finish(reject, err));
    // Connecting the socket makes the OS drop datagrams from any other address.
    socket.on('message', (message) => {
      if (accept(message)) finish(resolve, message);
    });
    socket.connect(port, server, (err) => {
      if (err) return finish(reject, err);
      socket.send(packet, (sendError) => sendError && finish(reject, sendError));
    });
  });
}

function exchangeTcp(socket, packet, timeoutMs) {
  return new Promise((resolve, reject) => {
    let received = Buffer.alloc(0);
    const cleanup = () => {
      clearTimeout(timer);
      socket.off('data', onData);
      socket.off('error', fail);
      socket.off('close', onClose);
    };
    const fail = (err) => {
      cleanup();
      reject(err);
    };
    const onClose = () => fail(new Error('connection closed by server'));
    const onData = (chunk) => {
      received = Buffer.concat([received, chunk]);
      if (received.length >= 2 && received.length >= 2 + received.readUInt16BE(0)) {
        cleanup();
        resolve(received.subarray(2, 2 + received.readUInt16BE(0)));
      }
    };
    const timer = setTimeout(() => fail(timeoutError()), timeoutMs);
    socket.on('data', onData);
    socket.on('error', fail);
    socket.on('close', onClose);
    const framed = Buffer.alloc(2 + packet.length);
    framed.writeUInt16BE(packet.length, 0);
    packet.copy(framed, 2);
    socket.write(framed);
  });
}

function connectDirect(host, port, timeoutMs) {
  return new Promise((resolve, reject) => {
    const socket = net.connect({ host, port });
    const timer = setTimeout(() => socket.destroy(timeoutError()), timeoutMs);
    socket.once('connect', () => {
      clearTimeout(timer);
      resolve(socket);
    });
    socket.once('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

// --- Public API ------------------------------------------------------------

// Resolves `name`/`type` against one DNS server. `connectTcp(host, port)` may supply a TCP socket
// (for example a proxy tunnel); without it the query goes over UDP with a TCP retry if truncated.
async function query({ server, port = 53, name, type, timeoutMs = 5000, connectTcp = null }) {
  const typeCode = TYPE_CODES[type];
  if (!typeCode) throw new Error(`unsupported record type ${type}`);

  const attempt = async (edns) => {
    const id = crypto.randomInt(0, 65536);
    const packet = encodeQuery(id, name, typeCode, edns);
    const accept = (message) => message.length >= 12 && message.readUInt16BE(0) === id && (message.readUInt16BE(2) & 0x8000) !== 0;
    let transport = connectTcp ? 'TCP' : 'UDP';
    let started;
    let raw;

    const overTcp = async () => {
      const socket = await (connectTcp ? connectTcp(server, port) : connectDirect(server, port, timeoutMs));
      try {
        started = process.hrtime.bigint();
        return await exchangeTcp(socket, packet, timeoutMs);
      } finally {
        socket.destroy();
      }
    };

    if (connectTcp) {
      raw = await overTcp();
    } else {
      for (let tries = 0; ; tries++) {
        started = process.hrtime.bigint();
        try {
          raw = await exchangeUdp(server, port, packet, Math.floor(timeoutMs / 2), accept);
          break;
        } catch (err) {
          if (err.code !== 'ETIMEDOUT' || tries >= 1) throw err; // one retry for a lost datagram
        }
      }
    }
    let message = decodeMessage(raw);
    if (message.truncated && !connectTcp) {
      transport = 'TCP';
      message = decodeMessage(await overTcp());
    }
    const ms = Number(process.hrtime.bigint() - started) / 1e6;

    const asked = message.questions[0];
    if (!message.response || message.id !== id || !asked || asked.type !== typeCode
      || asked.name.toLowerCase() !== name.replace(/\.$/, '').toLowerCase()) {
      throw new Error('reply does not match the question');
    }
    return { message, transport, ms };
  };

  let result = await attempt(true);
  // Very old servers reject EDNS; ask again without it.
  if (result.message.rcode === 1 || result.message.rcode === 4) result = await attempt(false);

  const { message, transport, ms } = result;
  return {
    rcode: message.rcode,
    rcodeName: RCODE_NAMES[message.rcode] ?? `rcode ${message.rcode}`,
    flags: { aa: message.authoritative, ra: message.recursionAvailable, ad: message.authenticated },
    transport,
    ms: Math.round(ms * 10) / 10,
    answers: message.answers.map(({ name: owner, type: code, ttl, data }) => ({ name: owner, type: code, ttl, data })),
  };
}

module.exports = { query, encodeQuery, decodeMessage, TYPE_CODES, RCODE_NAMES };
