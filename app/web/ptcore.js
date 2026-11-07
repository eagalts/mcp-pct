/* ptcore.js — ядро ptgen для браузера и node.
 * Twofish-EAX + обфускация + zlib (pako) для .pkt, сборка/экспорт схем
 * через DOM (DOMParser/XMLSerializer), YAML через js-yaml.
 * Порт ptcodec.py / ptgen.py, поведение совпадает.
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory;
  else root.PTCore = factory({ pako: root.pako, yaml: root.jsyaml,
    DOMParser: root.DOMParser, XMLSerializer: root.XMLSerializer });
})(typeof self !== "undefined" ? self : this, function (env) {
  "use strict";
  const pako = env.pako, YAML = env.yaml;

  // ------------------------------------------------------------ Twofish --
  const Q0T = [[8,1,7,13,6,15,3,2,0,11,5,9,14,12,10,4],[14,12,11,8,1,2,3,5,15,4,10,6,7,0,9,13],
               [11,10,5,14,6,13,9,0,12,8,15,3,2,4,7,1],[13,7,15,4,1,2,6,14,9,11,3,0,8,5,12,10]];
  const Q1T = [[2,8,11,13,15,7,6,14,3,1,9,4,0,10,12,5],[1,14,2,11,4,12,3,7,6,13,10,5,15,9,0,8],
               [4,12,7,5,1,6,9,10,0,14,13,8,2,11,3,15],[11,9,5,1,12,3,13,14,6,4,7,15,2,0,8,10]];
  const ror4 = (x, n) => ((x >> n) | (x << (4 - n))) & 15;
  function qperm(t, x) {
    const a0 = x >> 4, b0 = x & 15, a1 = a0 ^ b0, b1 = a0 ^ ror4(b0, 1) ^ ((8 * a0) & 15);
    const a2 = t[0][a1], b2 = t[1][b1], a3 = a2 ^ b2, b3 = a2 ^ ror4(b2, 1) ^ ((8 * a2) & 15);
    return (t[3][b3] << 4) | t[2][a3];
  }
  const Q0 = [], Q1 = [];
  for (let x = 0; x < 256; x++) { Q0.push(qperm(Q0T, x)); Q1.push(qperm(Q1T, x)); }
  function gfmul(a, b, poly) { let r = 0; while (b) { if (b & 1) r ^= a; a <<= 1; if (a & 256) a ^= poly; b >>= 1; } return r; }
  const MDS = [[1,0xEF,0x5B,0x5B],[0x5B,0xEF,0xEF,1],[0xEF,0x5B,1,0xEF],[0xEF,1,0xEF,0x5B]];
  const RS = [[1,0xA4,0x55,0x87,0x5A,0x58,0xDB,0x9E],[0xA4,0x56,0x82,0xF3,0x1E,0xC6,0x68,0xE5],
              [2,0xA1,0xFC,0xC1,0x47,0xAE,0x3D,0x19],[0xA4,0x55,0x87,0x5A,0x58,0xDB,0x9E,3]];
  const MDST = [0,1,2,3].map(j => { const t = new Uint32Array(256);
    for (let b = 0; b < 256; b++) { let w = 0; for (let i = 0; i < 4; i++) w |= gfmul(MDS[i][j], b, 0x169) << (8 * i); t[b] = w >>> 0; } return t; });
  const rol = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;
  const ror = (x, n) => ((x >>> n) | (x << (32 - n))) >>> 0;
  function sbox(y, L) {
    const k = L.length, lb = L.map(w => [w & 255, (w >>> 8) & 255, (w >>> 16) & 255, w >>> 24]);
    y = y.slice();
    if (k === 4) { y[0] = Q1[y[0]] ^ lb[3][0]; y[1] = Q0[y[1]] ^ lb[3][1]; y[2] = Q0[y[2]] ^ lb[3][2]; y[3] = Q1[y[3]] ^ lb[3][3]; }
    if (k >= 3) { y[0] = Q1[y[0]] ^ lb[2][0]; y[1] = Q1[y[1]] ^ lb[2][1]; y[2] = Q0[y[2]] ^ lb[2][2]; y[3] = Q0[y[3]] ^ lb[2][3]; }
    y[0] = Q1[Q0[Q0[y[0]] ^ lb[1][0]] ^ lb[0][0]];
    y[1] = Q0[Q0[Q1[y[1]] ^ lb[1][1]] ^ lb[0][1]];
    y[2] = Q1[Q1[Q0[y[2]] ^ lb[1][2]] ^ lb[0][2]];
    y[3] = Q0[Q1[Q1[y[3]] ^ lb[1][3]] ^ lb[0][3]];
    return y;
  }
  function h(x, L) { const y = sbox([x & 255, (x >>> 8) & 255, (x >>> 16) & 255, x >>> 24], L);
    return (MDST[0][y[0]] ^ MDST[1][y[1]] ^ MDST[2][y[2]] ^ MDST[3][y[3]]) >>> 0; }
  const rd32 = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
  function wr32(b, o, v) { b[o] = v & 255; b[o + 1] = (v >>> 8) & 255; b[o + 2] = (v >>> 16) & 255; b[o + 3] = v >>> 24; }

  function Twofish(key) {
    const k = key.length / 8, words = [];
    for (let i = 0; i < 2 * k; i++) words.push(rd32(key, 4 * i));
    const me = words.filter((_, i) => i % 2 === 0), mo = words.filter((_, i) => i % 2 === 1);
    let s = [];
    for (let i = 0; i < k; i++) { let w = 0;
      for (let r = 0; r < 4; r++) { let v = 0; for (let c = 0; c < 8; c++) v ^= gfmul(RS[r][c], key[8 * i + c], 0x14D); w |= v << (8 * r); }
      s.push(w >>> 0); }
    s = s.reverse();
    const K = new Uint32Array(40), rho = 0x01010101;
    for (let i = 0; i < 20; i++) {
      const a = h(Math.imul(2 * i, rho) >>> 0, me), b = rol(h(Math.imul(2 * i + 1, rho) >>> 0, mo), 8);
      K[2 * i] = (a + b) >>> 0; K[2 * i + 1] = rol((a + 2 * b) >>> 0, 9);
    }
    const T = [0, 1, 2, 3].map(() => new Uint32Array(256));
    for (let x = 0; x < 256; x++) { const y = sbox([x, x, x, x], s); for (let j = 0; j < 4; j++) T[j][x] = MDST[j][y[j]]; }
    const [T0, T1, T2, T3] = T;
    this.encryptBlock = function (inp, out) {
      let r0 = rd32(inp, 0) ^ K[0], r1 = rd32(inp, 4) ^ K[1], r2 = rd32(inp, 8) ^ K[2], r3 = rd32(inp, 12) ^ K[3];
      for (let rnd = 0; rnd < 16; rnd++) {
        const t0 = T0[r0 & 255] ^ T1[(r0 >>> 8) & 255] ^ T2[(r0 >>> 16) & 255] ^ T3[r0 >>> 24];
        const x = rol(r1 >>> 0, 8);
        const t1 = T0[x & 255] ^ T1[(x >>> 8) & 255] ^ T2[(x >>> 16) & 255] ^ T3[x >>> 24];
        const f0 = (t0 + t1 + K[2 * rnd + 8]) >>> 0, f1 = (t0 + 2 * (t1 >>> 0) + K[2 * rnd + 9]) >>> 0;
        const n2 = ror((r2 ^ f0) >>> 0, 1), n3 = (rol(r3 >>> 0, 1) ^ f1) >>> 0;
        r2 = r0; r3 = r1; r0 = n2; r1 = n3;
      }
      wr32(out, 0, (r2 ^ K[4]) >>> 0); wr32(out, 4, (r3 ^ K[5]) >>> 0);
      wr32(out, 8, (r0 ^ K[6]) >>> 0); wr32(out, 12, (r1 ^ K[7]) >>> 0);
      return out;
    };
  }

  // ---------------------------------------------------------------- EAX --
  function dbl(b) { const o = new Uint8Array(16); let c = 0;
    for (let i = 15; i >= 0; i--) { const v = (b[i] << 1) | c; o[i] = v & 255; c = b[i] >> 7; }
    if (b[0] & 128) o[15] ^= 0x87; return o; }
  function EAX(cipher) {
    const enc = (blk) => cipher.encryptBlock(blk, new Uint8Array(16));
    const k1 = dbl(enc(new Uint8Array(16))), k2 = dbl(k1);
    function cmac(data) {
      const n = Math.max(1, Math.ceil(data.length / 16)); let x = new Uint8Array(16);
      for (let i = 0; i < n - 1; i++) { for (let j = 0; j < 16; j++) x[j] ^= data[16 * i + j]; x = enc(x); }
      const last = data.subarray(16 * (n - 1)), blk = new Uint8Array(16);
      if (last.length === 16) for (let j = 0; j < 16; j++) blk[j] = last[j] ^ k1[j];
      else { blk.set(last); blk[last.length] = 0x80; for (let j = 0; j < 16; j++) blk[j] ^= k2[j]; }
      for (let j = 0; j < 16; j++) x[j] ^= blk[j];
      return enc(x);
    }
    const omac = (t, data) => { const b = new Uint8Array(16 + data.length); b[15] = t; b.set(data, 16); return cmac(b); };
    function ctr(n, data) {
      const c = n.slice(), out = new Uint8Array(data.length), ks = new Uint8Array(16);
      for (let i = 0; i < data.length; i += 16) {
        cipher.encryptBlock(c, ks);
        const m = Math.min(16, data.length - i);
        for (let j = 0; j < m; j++) out[i + j] = data[i + j] ^ ks[j];
        for (let j = 15; j >= 0; j--) { c[j] = (c[j] + 1) & 255; if (c[j]) break; }
      }
      return out;
    }
    this.encrypt = (nonce, data) => {
      const n = omac(0, nonce), hh = omac(1, new Uint8Array(0)), c = ctr(n, data), t = omac(2, c);
      const out = new Uint8Array(c.length + 16); out.set(c);
      for (let j = 0; j < 16; j++) out[c.length + j] = n[j] ^ hh[j] ^ t[j];
      return out;
    };
    this.decrypt = (nonce, data) => {
      const c = data.subarray(0, data.length - 16), tag = data.subarray(data.length - 16);
      const n = omac(0, nonce), hh = omac(1, new Uint8Array(0)), t = omac(2, c);
      for (let j = 0; j < 16; j++) if ((n[j] ^ hh[j] ^ t[j]) !== tag[j]) throw new Error("tag");
      return ctr(n, c);
    };
  }

  // ------------------------------------------------------- Packet Tracer --
  const KEY = new Uint8Array(16).fill(137), IV = new Uint8Array(16).fill(16);
  let _eax = null; const eax = () => (_eax = _eax || new EAX(new Twofish(KEY)));
  function obfOuterDecode(d) { const L = d.length, o = new Uint8Array(L);
    for (let i = 0; i < L; i++) o[i] = d[L - 1 - i] ^ ((L - i * L) & 255); return o; }
  function obfOuterEncode(d) { const L = d.length, o = new Uint8Array(L);
    for (let i = 0; i < L; i++) o[L - 1 - i] = d[i] ^ ((L - i * L) & 255); return o; }
  function obfInner(d) { const L = d.length, o = new Uint8Array(L);
    for (let i = 0; i < L; i++) o[i] = d[i] ^ ((L - i) & 255); return o; }
  function unzlib(d) {
    const size = ((d[0] << 24) | (d[1] << 16) | (d[2] << 8) | d[3]) >>> 0;
    const out = pako.inflate(d.subarray(4));
    if (out.length !== size) throw new Error("size mismatch");
    return out;
  }
  function packZlib(d) { const z = pako.deflate(d), o = new Uint8Array(z.length + 4);
    o[0] = d.length >>> 24; o[1] = (d.length >>> 16) & 255; o[2] = (d.length >>> 8) & 255; o[3] = d.length & 255;
    o.set(z, 4); return o; }

  // --- zip (только чтение .pkz и запись без сжатия) ---
  const CRC = (() => { const t = new Uint32Array(256);
    for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
  function crc32(d) { let c = 0xFFFFFFFF; for (let i = 0; i < d.length; i++) c = CRC[(c ^ d[i]) & 255] ^ (c >>> 8); return (c ^ 0xFFFFFFFF) >>> 0; }
  function readPkz(raw) {
    const dv = new DataView(raw.buffer, raw.byteOffset, raw.byteLength);
    let eocd = -1; for (let i = raw.length - 22; i >= 0; i--) if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
    if (eocd < 0) throw new Error("битый .pkz");
    let p = dv.getUint32(eocd + 16, true); const n = dv.getUint16(eocd + 10, true);
    for (let e = 0; e < n; e++) {
      const method = dv.getUint16(p + 10, true), csize = dv.getUint32(p + 20, true);
      const nl = dv.getUint16(p + 28, true), el = dv.getUint16(p + 30, true), cl = dv.getUint16(p + 32, true);
      const off = dv.getUint32(p + 42, true);
      const name = new TextDecoder().decode(raw.subarray(p + 46, p + 46 + nl));
      if (/\.pk[ta]$/i.test(name)) {
        const lnl = dv.getUint16(off + 26, true), lel = dv.getUint16(off + 28, true);
        const data = raw.subarray(off + 30 + lnl + lel, off + 30 + lnl + lel + csize);
        return method === 0 ? data : pako.inflateRaw(data);
      }
      p += 46 + nl + el + cl;
    }
    throw new Error("в .pkz нет .pkt/.pka");
  }
  function makeZip(files) { // [{name, data:Uint8Array}]
    const enc = new TextEncoder(), parts = [], central = []; let off = 0;
    const now = new Date(), dosT = (now.getHours() << 11) | (now.getMinutes() << 5) | (now.getSeconds() >> 1),
      dosD = ((now.getFullYear() - 1980) << 9) | ((now.getMonth() + 1) << 5) | now.getDate();
    for (const f of files) {
      const nm = enc.encode(f.name), crc = crc32(f.data);
      const lh = new Uint8Array(30 + nm.length), dv = new DataView(lh.buffer);
      dv.setUint32(0, 0x04034b50, true); dv.setUint16(4, 20, true); dv.setUint16(6, 0x0800, true); dv.setUint16(10, dosT, true); dv.setUint16(12, dosD, true);
      dv.setUint32(14, crc, true); dv.setUint32(18, f.data.length, true); dv.setUint32(22, f.data.length, true);
      dv.setUint16(26, nm.length, true); lh.set(nm, 30);
      const ch = new Uint8Array(46 + nm.length), cv = new DataView(ch.buffer);
      cv.setUint32(0, 0x02014b50, true); cv.setUint16(4, 20, true); cv.setUint16(6, 20, true); cv.setUint16(8, 0x0800, true); cv.setUint16(12, dosT, true); cv.setUint16(14, dosD, true);
      cv.setUint32(16, crc, true); cv.setUint32(20, f.data.length, true); cv.setUint32(24, f.data.length, true);
      cv.setUint16(28, nm.length, true); cv.setUint32(42, off, true); ch.set(nm, 46);
      parts.push(lh, f.data); central.push(ch); off += lh.length + f.data.length;
    }
    const cs = central.reduce((a, c) => a + c.length, 0), end = new Uint8Array(22), ev = new DataView(end.buffer);
    ev.setUint32(0, 0x06054b50, true); ev.setUint16(8, files.length, true); ev.setUint16(10, files.length, true);
    ev.setUint32(12, cs, true); ev.setUint32(16, off, true);
    const all = [...parts, ...central, end], out = new Uint8Array(all.reduce((a, c) => a + c.length, 0));
    let q = 0; for (const a of all) { out.set(a, q); q += a.length; } return out;
  }

  function decrypt(raw) {
    if (raw[0] === 0x50 && raw[1] === 0x4B) raw = readPkz(raw);
    try { return unzlib(obfInner(eax().decrypt(IV, obfOuterDecode(raw)))); }
    catch (e) { return unzlib(obfInner(raw)); }
  }
  const encrypt = (xml) => obfOuterEncode(eax().encrypt(IV, obfInner(packZlib(xml))));

  // ------------------------------------------------------------ DOM ----
  const kids = (el, tag) => { const r = []; for (let c = el.firstChild; c; c = c.nextSibling) if (c.nodeType === 1 && (!tag || c.nodeName === tag)) r.push(c); return r; };
  function q(el, path) { for (const t of path.split("/")) { if (!el) return null; el = kids(el, t)[0] || null; } return el; }
  const txt = (el, path) => { const e = path ? q(el, path) : el; return e ? e.textContent : null; };
  function setT(el, path, v) { const e = q(el, path); if (e) e.textContent = v; return e; }
  const all = (el, tag) => Array.from(el.getElementsByTagName(tag));

  function parseXml(bytes) {
    const s = new TextDecoder().decode(bytes);
    const doc = new env.DOMParser().parseFromString(s, "text/xml");
    if (doc.getElementsByTagName("parsererror").length) throw new Error("XML не разобрался");
    return doc;
  }
  const serialize = (doc) => new TextEncoder().encode(new env.XMLSerializer().serializeToString(doc));

  // --------------------------------------------------------- генератор --
  const ABBR = [["gigabitethernet","GigabitEthernet"],["fastethernet","FastEthernet"],["ethernet","Ethernet"],["serial","Serial"],
    ["gi","GigabitEthernet"],["g","GigabitEthernet"],["fa","FastEthernet"],["f","FastEthernet"],["se","Serial"],["s","Serial"],["eth","Ethernet"],["e","Ethernet"]];
  function normPort(p) {
    p = String(p).trim().replace(/\s+/g, "");
    const m = /^([A-Za-z]+)([\d/.]*)$/.exec(p); if (!m) return p;
    const pre = m[1].toLowerCase(); for (const [a, f] of ABBR) if (pre === a) return f + m[2];
    return p;
  }
  const range = (a, b) => Array.from({ length: b - a + 1 }, (_, i) => a + i);
  const PORTS = {
    "2960-24TT": range(1, 24).map(i => "FastEthernet0/" + i).concat(["GigabitEthernet0/1", "GigabitEthernet0/2"]),
    "1941": ["GigabitEthernet0/0", "GigabitEthernet0/1"],
    "2911": ["GigabitEthernet0/0", "GigabitEthernet0/1", "GigabitEthernet0/2"],
    "4331": ["GigabitEthernet0/0/0", "GigabitEthernet0/0/1", "GigabitEthernet0/0/2"],
    "PC-PT": ["FastEthernet0"], "Server-PT": ["FastEthernet0"], "Laptop-PT": ["FastEthernet0"],
  };
  const MDIX = new Set(["switch", "hub", "multilayerswitch"]);
  const PTYPE = { eCopperFastEthernet: "FastEthernet", eCopperGigabitEthernet: "GigabitEthernet", eCopperEthernet: "Ethernet",
    eSerial: "Serial", eFiberFastEthernet: "FastEthernet", eFiberGigabitEthernet: "GigabitEthernet",
    eCopperTenGigabitEthernet: "TenGigabitEthernet", eFiberTenGigabitEthernet: "TenGigabitEthernet" };
  /** Имена интерфейсов -> элементы PORT по дереву модулей (как в ptgen.py). */
  function portMap(dev) {
    const dtype = (txt(dev, "ENGINE/TYPE") || "").trim().toLowerCase(), root = q(dev, "ENGINE/MODULE"), out = {};
    if (!root) return out;
    const isSw = dtype === "switch" || dtype === "multilayerswitch";
    const host = ["pc", "server", "laptop", "printer", "cloud"].includes(dtype);
    kids(root, "SLOT").forEach((slot, si) => {
      const mod = q(slot, "MODULE"); if (!mod) return;
      let cnt = {};
      for (const p of kids(mod, "PORT")) { const t = PTYPE[txt(p, "TYPE")]; if (!t) continue;
        const n = cnt[t] || 0; cnt[t] = n + 1;
        const name = host ? t + si : `${t}${si}/${isSw ? n + 1 : n}`;
        if (!(name in out)) out[name] = p; }
      kids(mod, "SLOT").forEach((sub, sj) => { const sm = q(sub, "MODULE"); if (!sm) return; const c2 = {};
        for (const p of kids(sm, "PORT")) { const t = PTYPE[txt(p, "TYPE")]; if (!t) continue;
          const n = c2[t] || 0; c2[t] = n + 1; out[`${t}${si}/${sj}/${n}`] = p; } });
    });
    return out;
  }
  /** ip address / shutdown из running-config -> поля портов (PT хранит и там, и там). */
  function syncPorts(dev) {
    const rc = q(dev, "ENGINE/RUNNINGCONFIG"); if (!rc) return;
    const pm = portMap(dev);
    for (const [hh, sub] of sections(kids(rc, "LINE").map(l => l.textContent))) {
      if (!hh.startsWith("interface ")) continue;
      const p = pm[hh.slice(10).trim()]; if (!p) continue;
      let ip = "", mask = "";
      for (const s of sub) { const w = s.trim().split(/\s+/); if (w[0] === "ip" && w[1] === "address" && w.length >= 4 && w[2] !== "dhcp") { ip = w[2]; mask = w[3]; } }
      if (q(p, "IP")) { setT(p, "IP", ip); setT(p, "SUBNET", mask); }
      setT(p, "POWER", sub.some(x => x.trim() === "shutdown") ? "false" : "true");
    }
  }

  const rnd32 = () => { const a = new Uint32Array(1); (globalThis.crypto).getRandomValues(a); return a[0]; };
  const randMem = () => String(1000000000000 + Math.floor((rnd32() / 4294967296) * 1999999999999));
  const randRef = () => "save-ref-id:" + ((BigInt(rnd32() & 0x7FFFFFFF) << 32n) | BigInt(rnd32())).toString();
  const uuid4 = () => { const b = new Uint8Array(16); globalThis.crypto.getRandomValues(b); b[6] = (b[6] & 15) | 64; b[8] = (b[8] & 63) | 128;
    const h = Array.from(b, x => x.toString(16).padStart(2, "0")).join("");
    return `{${h.slice(0,8)}-${h.slice(8,12)}-${h.slice(12,16)}-${h.slice(16,20)}-${h.slice(20)}}`; };
  function macToLL(mac) {
    const h = mac.replace(/\./g, ""); const b = []; for (let i = 0; i < 12; i += 2) b.push(parseInt(h.slice(i, i + 2), 16));
    b[0] ^= 2; const e = b.slice(0, 3).concat([0xff, 0xfe], b.slice(3)); const g = [];
    for (let i = 0; i < 8; i += 2) g.push(((e[i] << 8) | e[i + 1]).toString(16).toUpperCase());
    return "FE80::" + g.join(":");
  }
  function ipIface(s) {
    const m = /^(\d+)\.(\d+)\.(\d+)\.(\d+)\/(\d+)$/.exec(String(s).trim());
    if (!m || +m[5] > 32 || m.slice(1, 5).some(x => +x > 255)) throw new Error("неверный IP: " + s + " (нужно вида 10.0.0.5/24)");
    const p = +m[5], mask = p ? (0xFFFFFFFF << (32 - p)) >>> 0 : 0;
    return { ip: m.slice(1, 5).join("."), mask: [24, 16, 8, 0].map(sh => (mask >>> sh) & 255).join(".") };
  }
  const maskLen = (m) => m.split(".").reduce((a, o) => a + ((+o).toString(2).match(/1/g) || []).length, 0);

  function Template(xmlBytes) {
    this.doc = parseXml(xmlBytes);
    const root = this.doc.documentElement;
    this.root = root; this.devs = q(root, "NETWORK/DEVICES"); this.links = q(root, "NETWORK/LINKS");
    this.pw = q(root, "PHYSICALWORKSPACE"); this.nodes = {};
    for (const n of all(this.pw, "NODE")) { const u = txt(n, "UUID_STR"); if (u) this.nodes[u] = n; }
    this.proto = {};
    for (const d of kids(this.devs, "DEVICE")) { const m = q(d, "ENGINE/TYPE").getAttribute("model"); if (!(m in this.proto)) this.proto[m] = d; }
    this.linkProto = kids(this.links, "LINK")[0] || null;
  }
  const devType = (d) => (txt(d, "ENGINE/TYPE") || "").trim().toLowerCase();
  const physUuid = (d) => { const p = txt(d, "WORKSPACE/PHYSICAL") || ""; return p ? p.split(",").pop() : null; };

  // --- конфиг ---
  function sections(lines) { const out = [];
    for (const l of lines) { if (l.startsWith(" ") && out.length && !["!", ""].includes(out[out.length - 1][0])) out[out.length - 1][1].push(l); else out.push([l, []]); }
    return out; }
  function subkey(l) {
    const s = l.trim(); if (s === "shutdown" || s === "no shutdown") return "shutdown";
    let w = s.split(/\s+/); if (w[0] === "no") w = w.slice(1);
    const two = w.slice(0, 2).join(" ");
    if (["ip address", "switchport mode", "ipv6 address"].includes(two)) return two;
    if (["switchport access", "switchport trunk"].includes(two)) return w.slice(0, 3).join(" ");
    return s;
  }
  function mergeConfig(lines, userCfg) {
    const base = sections(lines), user = sections(userCfg.split(/\r?\n/).map(l => l.replace(/\s+$/, "")).filter(l => l.trim()));
    const index = {}; for (const [hh, s] of base) if (!["!", ""].includes(hh)) index[hh] = s;
    let ins = base.findIndex(([hh]) => hh.startsWith("line ") || hh.trim() === "end"); if (ins < 0) ins = base.length;
    const nw = [];
    for (const [hh, sub] of user) {
      if (hh in index) { const t = index[hh];
        for (const u of sub) { const k = subkey(u); const keep = t.filter(x => subkey(x) !== k); t.length = 0; t.push(...keep); if (u.trim() !== "no shutdown") t.push(" " + u.trim()); } }
      else if (hh.startsWith("hostname ")) continue;
      else { const s = sub.filter(x => x.trim() !== "no shutdown").map(x => " " + x.trim()); nw.push([hh, s], ["!", []]); index[hh] = s; }
    }
    base.splice(ins, 0, ...nw);
    return base.flatMap(([hh, s]) => [hh, ...s]);
  }
  function applyConfig(doc, eng, name, userCfg) {
    const rc = q(eng, "RUNNINGCONFIG"); if (!rc) return;
    let lines = kids(rc, "LINE").map(l => l.textContent); if (!lines.length) return;
    lines = lines.map(l => l.startsWith("hostname ") ? "hostname " + name : l);
    if (userCfg) lines = mergeConfig(lines, userCfg);
    while (rc.firstChild) rc.removeChild(rc.firstChild);
    for (const l of lines) { const e = doc.createElement("LINE"); e.textContent = l; rc.appendChild(e); }
  }

  function cloneDevice(T, spec, x, y) {
    const model = String(spec.model);
    if (!(model in T.proto)) throw new Error(`модели «${model}» нет в шаблоне. Есть: ${Object.keys(T.proto).join(", ")}`);
    const proto = T.proto[model], d = proto.cloneNode(true), eng = q(d, "ENGINE"), name = String(spec.name);
    setT(eng, "NAME", name); setT(eng, "SYS_NAME", name);
    const ref = randRef(); setT(eng, "SAVE_REF_ID", ref);
    const sn = q(eng, "SERIALNUMBER");
    if (sn && sn.textContent) { const A = "0123456789ABCDEFGHJKLMNPQRSTUVWXYZ"; let s = sn.textContent.slice(0, 3);
      for (let i = 3; i < sn.textContent.length; i++) s += A[rnd32() % A.length]; sn.textContent = s; }
    const lg = q(d, "WORKSPACE/LOGICAL"); setT(lg, "X", String(x)); setT(lg, "Y", String(y)); setT(lg, "MEM_ADDR", randMem());
    const devAddr = randMem(); setT(lg, "DEV_ADDR", devAddr);
    for (const port of all(d, "PORT")) {
      const me = q(port, "MACADDRESS"); if (!me || !me.textContent) continue;
      let mac = me.textContent.replace(/\./g, "").slice(0, 6) + (rnd32() & 0xFFFFFF).toString(16).toUpperCase().padStart(6, "0");
      mac = mac.slice(0, 4) + "." + mac.slice(4, 8) + "." + mac.slice(8);
      me.textContent = mac; setT(port, "BIA", mac);
      const ll = macToLL(mac); setT(port, "IPV6_LINK_LOCAL", ll); setT(port, "IPV6_DEFAULT_LINK_LOCAL", ll);
    }
    const ipPort = all(d, "PORT").find(p => q(p, "IP"));
    if (spec.ip != null) {
      if (!ipPort) throw new Error(`${name}: у модели ${model} нет IP-полей на порту — задайте IP через config`);
      const f = ipIface(spec.ip); setT(ipPort, "IP", f.ip); setT(ipPort, "SUBNET", f.mask); setT(ipPort, "PORT_DHCP_ENABLE", "false");
      if (spec.gateway) setT(ipPort, "PORT_GATEWAY", String(spec.gateway));
      if (spec.dns) setT(ipPort, "PORT_DNS", String(spec.dns));
    } else if (spec.dhcp && ipPort) setT(ipPort, "PORT_DHCP_ENABLE", "true");
    applyConfig(T.doc, eng, name, spec.config);
    syncPorts(d);
    if (spec.config && spec.save !== false) { const rc = q(eng, "RUNNINGCONFIG"), sc = q(eng, "STARTUPCONFIG");
      if (rc && sc) { while (sc.firstChild) sc.removeChild(sc.firstChild);
        for (const l of kids(rc, "LINE")) { const e = T.doc.createElement("LINE"); e.textContent = l.textContent; sc.appendChild(e); } } }
    const ou = physUuid(proto);
    if (ou && T.nodes[ou]) {
      const node = T.nodes[ou].cloneNode(true), nu = uuid4();
      setT(node, "UUID_STR", nu); setT(node, "NAME", name); T.nodes[ou].parentNode.appendChild(node);
      const path = txt(d, "WORKSPACE/PHYSICAL"); setT(d, "WORKSPACE/PHYSICAL", path.slice(0, path.lastIndexOf(",")) + "," + nu);
    }
    return { d, ref, devAddr };
  }

  function autoLayout(specs, links) {
    const adj = {}, kind = {}; specs.forEach(s => { adj[s.name] = []; kind[s.name] = String(s.model).toUpperCase(); });
    links.forEach(([a, , b]) => { adj[a].push(b); adj[b].push(a); });
    const rank = (n) => /^(PC|SERVER|LAPTOP|PRINTER)/.test(kind[n]) ? 2 : /^(2960|3560|3650|SWITCH)/.test(kind[n]) ? 1 : 0;
    const names = specs.map(s => s.name), level = {};
    const roots = names.slice().sort((a, b) => rank(a) - rank(b));
    for (const r of roots) { if (r in level) continue; level[r] = rank(r); const qq = [r];
      while (qq.length) { const u = qq.shift(); for (const v of adj[u]) if (!(v in level)) { level[v] = Math.max(level[u] + 1, rank(v)); qq.push(v); } } }
    const rows = {}; names.forEach(n => (rows[level[n]] = rows[level[n]] || []).push(n));
    const pos = {};
    for (const lv in rows) { const row = rows[lv], per = 12, w = Math.min(row.length, per);
      row.forEach((n, i) => { const sub = Math.floor(i / per), col = i % per;
        pos[n] = [Math.round((100 + (col + 0.5) * (1400 / w)) * 10) / 10, 100 + lv * 220 + sub * 90]; }); }
    return pos;
  }

  function parseLinks(raw) {
    return (raw || []).map(l => {
      if (l && !Array.isArray(l)) l = [l.a, l.a_port, l.b, l.b_port];
      if (!Array.isArray(l) || l.length !== 4) throw new Error("линк должен быть [устройство, порт, устройство, порт]: " + JSON.stringify(l));
      return [String(l[0]), normPort(l[1]), String(l[2]), normPort(l[3])];
    });
  }
  function validate(specs, links, portsOf) {
    const errs = [], names = {};
    specs.forEach((s, i) => {
      if (!s || !s.name || !s.model) { errs.push(`устройство №${i + 1}: нужны name и model`); return; }
      s.name = String(s.name);
      if (s.name in names) errs.push("дублируется имя устройства " + s.name);
      names[s.name] = String(s.model);
    });
    const used = {};
    for (const [a, pa, b, pb] of links) for (const [dv, pt] of [[a, pa], [b, pb]]) {
      if (!(dv in names)) { errs.push("линк ссылается на неизвестное устройство " + dv); continue; }
      const known = (portsOf && portsOf[names[dv]]) || PORTS[names[dv]];
      if (known && !known.includes(pt)) errs.push(`${dv} (${names[dv]}): нет порта ${pt}`);
      if (used[dv + "|" + pt]) errs.push(`${dv} ${pt} занят дважды`);
      used[dv + "|" + pt] = 1;
    }
    return errs;
  }

  function build(topo, templateRaw) {
    if (!topo || typeof topo !== "object") throw new Error("YAML пустой или не объект");
    const T = new Template(decrypt(templateRaw));
    const specs = topo.devices || [], links = parseLinks(topo.links);
    const portsOf = Object.fromEntries(Object.entries(T.proto).map(([m, d]) => [m, Object.keys(portMap(d))]));
    const errs = validate(specs, links, portsOf); if (errs.length) { const e = new Error("Ошибки в YAML"); e.details = errs; throw e; }
    const auto = autoLayout(specs, links);
    const oldDevs = kids(T.devs, "DEVICE").filter(d => q(d, "ENGINE/TYPE").getAttribute("model") !== "Power Distribution Device");
    const oldU = oldDevs.map(physUuid);
    if (!T.linkProto && links.length) throw new Error("в шаблоне нет ни одного кабеля — добавьте хотя бы один");
    const lp = T.linkProto ? T.linkProto.cloneNode(true) : null;
    const info = {}, nd = [];
    for (const s of specs) {
      let x = s.x, y = s.y; if (x == null || y == null) [x, y] = auto[s.name];
      const r = cloneDevice(T, s, x, y); info[s.name] = [r.ref, r.devAddr, devType(r.d)]; nd.push(r.d);
    }
    oldDevs.forEach(d => T.devs.removeChild(d));
    oldU.forEach(u => { if (u && T.nodes[u] && T.nodes[u].parentNode) T.nodes[u].parentNode.removeChild(T.nodes[u]); });
    kids(T.links, "LINK").forEach(l => T.links.removeChild(l));
    nd.forEach(d => T.devs.appendChild(d));
    for (const [a, pa, b, pb] of links) {
      const l = lp.cloneNode(true), c = q(l, "CABLE");
      setT(c, "FROM", info[a][0]); setT(c, "TO", info[b][0]);
      const ps = kids(c, "PORT"); ps[0].textContent = pa; ps[1].textContent = pb;
      setT(c, "FROM_DEVICE_MEM_ADDR", info[a][1]); setT(c, "TO_DEVICE_MEM_ADDR", info[b][1]);
      setT(c, "FROM_PORT_MEM_ADDR", randMem()); setT(c, "TO_PORT_MEM_ADDR", randMem());
      const same = MDIX.has(info[a][2]) === MDIX.has(info[b][2]);
      setT(c, "TYPE", same ? "eCrossOver" : "eStraightThrough");
      T.links.appendChild(l);
    }
    return { pkt: encrypt(serialize(T.doc)), devices: specs.length, links: links.length };
  }

  const BOILER = /^(!|version |no service |service |spanning-tree mode|spanning-tree extend|license udi|ip cef|no ipv6 cef|end$|line |boot-start|boot-end|ip classless|ip flow-export)/;
  const SUBDEF = /^\s*(no ip address|duplex auto|speed auto|login)$/;
  function exportTopo(raw) {
    const T = new Template(decrypt(raw)), byRef = {}, devices = [];
    for (const d of kids(T.devs, "DEVICE")) {
      const eng = q(d, "ENGINE"), model = q(eng, "TYPE").getAttribute("model");
      if (model === "Power Distribution Device") continue;
      const name = txt(eng, "NAME"); byRef[txt(eng, "SAVE_REF_ID")] = name;
      const lg = q(d, "WORKSPACE/LOGICAL");
      const e = { name, model, x: parseFloat(txt(lg, "X")), y: parseFloat(txt(lg, "Y")) };
      const port = all(d, "PORT").find(p => txt(p, "IP"));
      if (port && ["pc", "server", "laptop"].includes(devType(d))) {
        e.ip = txt(port, "IP") + "/" + maskLen(txt(port, "SUBNET") || "0.0.0.0");
        if (txt(port, "PORT_GATEWAY")) e.gateway = txt(port, "PORT_GATEWAY");
      }
      const rc = q(eng, "RUNNINGCONFIG");
      if (rc) { const keep = [];
        for (const [hh, sub0] of sections(kids(rc, "LINE").map(l => l.textContent))) {
          if (BOILER.test(hh) || hh.startsWith("hostname") || !hh.trim()) continue;
          const sub = sub0.filter(s => !SUBDEF.test(s));
          if (/^(interface |router |vlan |ip dhcp pool )/.test(hh)) { if (sub.length) keep.push(hh, ...sub); } else keep.push(hh, ...sub);
        }
        if (keep.length) e.config = keep.join("\n") + "\n"; }
      devices.push(e);
    }
    const links = kids(T.links, "LINK").map(l => { const c = q(l, "CABLE"), p = kids(c, "PORT").map(x => x.textContent);
      return [byRef[txt(c, "FROM")] || "?", p[0], byRef[txt(c, "TO")] || "?", p[1]]; });
    return { devices, links };
  }
  function toYaml(t) {
    const out = ["devices:"];
    for (const d of t.devices) {
      out.push(`  - name: ${JSON.stringify(d.name)}`, `    model: ${JSON.stringify(d.model)}`, `    x: ${d.x}`, `    y: ${d.y}`);
      if (d.ip) out.push(`    ip: ${d.ip}`); if (d.gateway) out.push(`    gateway: ${d.gateway}`);
      if (d.config) { out.push("    config: |"); d.config.replace(/\n$/, "").split("\n").forEach(l => out.push("      " + l)); }
    }
    out.push("links:"); for (const l of t.links) out.push(`  - [${l.map(x => JSON.stringify(x)).join(", ")}]`);
    return out.join("\n") + "\n";
  }
  function models(raw) { const T = new Template(decrypt(raw));
    return Object.entries(T.proto).filter(([m]) => m !== "Power Distribution Device").map(([m, d]) => ({ model: m, type: txt(d, "ENGINE/TYPE"), ports: Object.keys(portMap(d)) })); }
  function version(raw) { const x = new TextDecoder().decode(decrypt(raw).subarray(0, 400)); const m = /<VERSION>([^<]*)/.exec(x); return m ? m[1] : "?"; }

  function selftest() {
    const tf = new Twofish(new Uint8Array(16)), o = tf.encryptBlock(new Uint8Array(16), new Uint8Array(16));
    const hx = Array.from(o, b => b.toString(16).padStart(2, "0")).join("").toUpperCase();
    if (hx !== "9F589F5CF6122C32B6BFEC2F2AE8C35A") throw new Error("twofish selftest");
    return true;
  }

  /** Проверка + раскладка для предпросмотра, без сборки. modelTypes: {model: type}. */
  function inspect(topo, modelTypes, portsOf) {
    if (!topo || typeof topo !== "object" || Array.isArray(topo)) return { errors: ["YAML должен содержать devices и links"], nodes: [], links: [] };
    const specs = Array.isArray(topo.devices) ? topo.devices : [];
    let links; try { links = parseLinks(topo.links); } catch (e) { return { errors: [e.message], nodes: [], links: [] }; }
    const errors = validate(specs, links, portsOf);
    const okSpecs = specs.filter(s => s && s.name && s.model);
    for (const s of okSpecs) if (modelTypes && !(String(s.model) in modelTypes))
      errors.push(`${s.name}: модели «${s.model}» нет в шаблоне`);
    const names = new Set(okSpecs.map(s => String(s.name)));
    const goodLinks = links.filter(([a, , b]) => names.has(a) && names.has(b));
    const pos = autoLayout(okSpecs, goodLinks);
    const type = (m) => ((modelTypes && modelTypes[String(m)]) || "").toLowerCase();
    const kindOf = {};
    const nodes = okSpecs.map(s => { const t = type(s.model); const [ax, ay] = pos[s.name];
      kindOf[s.name] = t;
      return { name: String(s.name), model: String(s.model), type: t,
        x: s.x != null ? +s.x : ax, y: s.y != null ? +s.y : ay }; });
    const lk = goodLinks.map(([a, pa, b, pb]) => ({ a, pa, b, pb,
      cross: MDIX.has(kindOf[a]) === MDIX.has(kindOf[b]) }));
    return { errors, nodes, links: lk };
  }

  return { decrypt, encrypt, build, exportTopo, inspect, toYaml, models, version, makeZip, normPort, PORTS, selftest,
           parseYaml: (s) => YAML.load(s) };
});
