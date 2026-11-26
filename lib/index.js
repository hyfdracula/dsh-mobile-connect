import { createCipheriv, createDecipheriv, createHash, createHmac, createPrivateKey, createPublicKey, diffieHellman, generateKeyPairSync, getCiphers, randomBytes, randomInt, randomUUID, timingSafeEqual } from "node:crypto";
import { EventEmitter } from "node:events";
import { chmodSync, closeSync, createReadStream, existsSync, lstatSync, mkdirSync, openSync, readFileSync, readSync, readdirSync, realpathSync, renameSync, rmdirSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { createServer, request } from "node:http";
import { homedir, hostname, networkInterfaces } from "node:os";
import { basename, delimiter, dirname, extname, join, resolve, sep } from "node:path";
import { Readable } from "node:stream";
import { fileURLToPath } from "node:url";
import { appendFile, mkdir, rename, stat, unlink, writeFile } from "node:fs/promises";
import { execFile, spawn } from "node:child_process";
import * as zlib from "node:zlib";
import { StringDecoder } from "node:string_decoder";
import { request as request$1 } from "node:https";
import { connect } from "node:net";
import { connect as connect$1 } from "node:tls";
//#region src/crypto/chacha20poly1305.ts
const TAG_LEN$1 = 16;
const POLY_P = (1n << 130n) - 5n;
const POLY_R_MASK = 21267647620597763993911028882763415551n;
const MASK_128 = (1n << 128n) - 1n;
const CHACHA_CONST_0 = 1634760805;
const CHACHA_CONST_1 = 857760878;
const CHACHA_CONST_2 = 2036477234;
const CHACHA_CONST_3 = 1797285236;
function readU32LE(buf, off) {
	return (buf[off] | buf[off + 1] << 8 | buf[off + 2] << 16 | buf[off + 3] << 24) >>> 0;
}
function writeU32LE(buf, off, val) {
	buf[off] = val & 255;
	buf[off + 1] = val >>> 8 & 255;
	buf[off + 2] = val >>> 16 & 255;
	buf[off + 3] = val >>> 24 & 255;
}
function rotl32(v, n) {
	return (v << n | v >>> 32 - n) >>> 0;
}
function quarterRound(s, a, b, c, d) {
	s[a] = s[a] + s[b] >>> 0;
	s[d] = rotl32(s[d] ^ s[a], 16);
	s[c] = s[c] + s[d] >>> 0;
	s[b] = rotl32(s[b] ^ s[c], 12);
	s[a] = s[a] + s[b] >>> 0;
	s[d] = rotl32(s[d] ^ s[a], 8);
	s[c] = s[c] + s[d] >>> 0;
	s[b] = rotl32(s[b] ^ s[c], 7);
}
/** RFC 8439 Section 2.3: single 64-byte ChaCha20 block. */
function chacha20Block(key, counter, nonce) {
	if (key.length !== 32) throw new Error("ChaCha20 key must be 32 bytes");
	if (nonce.length !== 12) throw new Error("ChaCha20 nonce must be 12 bytes");
	const init = /* @__PURE__ */ new Uint32Array(16);
	init[0] = CHACHA_CONST_0;
	init[1] = CHACHA_CONST_1;
	init[2] = CHACHA_CONST_2;
	init[3] = CHACHA_CONST_3;
	for (let i = 0; i < 8; i += 1) init[4 + i] = readU32LE(key, i * 4);
	init[12] = counter >>> 0;
	init[13] = readU32LE(nonce, 0);
	init[14] = readU32LE(nonce, 4);
	init[15] = readU32LE(nonce, 8);
	const state = new Uint32Array(init);
	for (let round = 0; round < 10; round += 1) {
		quarterRound(state, 0, 4, 8, 12);
		quarterRound(state, 1, 5, 9, 13);
		quarterRound(state, 2, 6, 10, 14);
		quarterRound(state, 3, 7, 11, 15);
		quarterRound(state, 0, 5, 10, 15);
		quarterRound(state, 1, 6, 11, 12);
		quarterRound(state, 2, 7, 8, 13);
		quarterRound(state, 3, 4, 9, 14);
	}
	const out = /* @__PURE__ */ new Uint8Array(64);
	for (let i = 0; i < 16; i += 1) writeU32LE(out, i * 4, state[i] + init[i] >>> 0);
	init.fill(0);
	state.fill(0);
	return out;
}
/** RFC 8439 Section 2.4: ChaCha20 XOR stream cipher. */
function chacha20Xor(key, initialCounter, nonce, input) {
	const out = Buffer.allocUnsafe(input.length);
	let counter = initialCounter >>> 0;
	let offset = 0;
	while (offset < input.length) {
		const keystream = chacha20Block(key, counter, nonce);
		const take = Math.min(64, input.length - offset);
		for (let i = 0; i < take; i += 1) out[offset + i] = input[offset + i] ^ keystream[i];
		keystream.fill(0);
		offset += take;
		counter = counter + 1 >>> 0;
	}
	return out;
}
function leBytesToBigInt(bytes) {
	let acc = 0n;
	for (let i = bytes.length - 1; i >= 0; i -= 1) acc = acc << 8n | BigInt(bytes[i]);
	return acc;
}
/** RFC 8439 Section 2.5: Poly1305 one-time authenticator. */
function poly1305Mac(otk, msg) {
	if (otk.length !== 32) throw new Error("Poly1305 key must be 32 bytes");
	const r = leBytesToBigInt(otk.subarray(0, 16)) & POLY_R_MASK;
	const s = leBytesToBigInt(otk.subarray(16, 32));
	let acc = 0n;
	for (let off = 0; off < msg.length; off += 16) {
		const chunk = msg.subarray(off, Math.min(off + 16, msg.length));
		const n = leBytesToBigInt(chunk) + (1n << BigInt(chunk.length * 8));
		acc = (acc + n) * r % POLY_P;
	}
	let finalVal = acc + s & MASK_128;
	const tag = Buffer.alloc(TAG_LEN$1);
	for (let i = 0; i < TAG_LEN$1; i += 1) {
		tag[i] = Number(finalVal & 255n);
		finalVal >>= 8n;
	}
	return tag;
}
function buildAeadMacInput(aad, ciphertext) {
	const aadPad = (16 - aad.length % 16) % 16;
	const ctPad = (16 - ciphertext.length % 16) % 16;
	const macData = Buffer.alloc(aad.length + aadPad + ciphertext.length + ctPad + 16);
	let pos = 0;
	if (aad.length > 0) Buffer.from(aad).copy(macData, pos);
	pos += aad.length + aadPad;
	if (ciphertext.length > 0) Buffer.from(ciphertext).copy(macData, pos);
	pos += ciphertext.length + ctPad;
	macData.writeBigUInt64LE(BigInt(aad.length), pos);
	macData.writeBigUInt64LE(BigInt(ciphertext.length), pos + 8);
	return macData;
}
/** RFC 8439 Section 2.8: AEAD_CHACHA20_POLY1305 encryption (`ciphertext || 16B tag`). */
function chacha20Poly1305Seal(key, nonce, aad, plaintext) {
	if (key.length !== 32) throw new Error("ChaCha20-Poly1305 key must be 32 bytes");
	if (nonce.length !== 12) throw new Error("ChaCha20-Poly1305 nonce must be 12 bytes");
	const otkBlock = chacha20Block(key, 0, nonce);
	const otk = otkBlock.subarray(0, 32);
	try {
		const ct = chacha20Xor(key, 1, nonce, plaintext);
		const macInput = buildAeadMacInput(aad, ct);
		const tag = poly1305Mac(otk, macInput);
		macInput.fill(0);
		return Buffer.concat([ct, tag]);
	} finally {
		otkBlock.fill(0);
	}
}
/** RFC 8439 Section 2.8: AEAD_CHACHA20_POLY1305 authenticated decryption. */
function chacha20Poly1305Open(key, nonce, aad, ciphertextWithTag) {
	if (key.length !== 32) throw new Error("ChaCha20-Poly1305 key must be 32 bytes");
	if (nonce.length !== 12) throw new Error("ChaCha20-Poly1305 nonce must be 12 bytes");
	if (ciphertextWithTag.byteLength < TAG_LEN$1) throw new Error("Ciphertext too short");
	const splitAt = ciphertextWithTag.byteLength - TAG_LEN$1;
	const ct = ciphertextWithTag.subarray(0, splitAt);
	const tag = ciphertextWithTag.subarray(splitAt);
	const otkBlock = chacha20Block(key, 0, nonce);
	const otk = otkBlock.subarray(0, 32);
	try {
		const macInput = buildAeadMacInput(aad, ct);
		const expectedTag = poly1305Mac(otk, macInput);
		macInput.fill(0);
		if (!timingSafeEqual(expectedTag, tag)) throw new Error("ChaCha20-Poly1305 authentication failed");
		return chacha20Xor(key, 1, nonce, ct);
	} finally {
		otkBlock.fill(0);
	}
}
//#endregion
//#region src/crypto/noise.ts
/**
* 标准 Noise Protocol Framework (Revision 34) `Noise_IK_25519_ChaChaPoly_SHA256` 实现。
* 密码原语全部委托 Node 内置 `node:crypto`（X25519 / ChaCha20-Poly1305 / SHA-256 / HMAC），零外部依赖。
*/
const NOISE_IK_PROTOCOL = "Noise_IK_25519_ChaChaPoly_SHA256";
const KEY_LEN = 32;
const TAG_LEN = 16;
const MAX_NONCE = 18446744073709551615n;
const EMPTY_BUF = Buffer.alloc(0);
const HAS_NATIVE_CHACHA = getCiphers().includes("chacha20-poly1305");
const X25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
const X25519_SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");
var NoiseError = class extends Error {
	code;
	constructor(code, message) {
		super(message);
		this.code = code;
	}
};
/** 兼容标准 Base64 与 Base64Url 解码字节序列。 */
function decodeBase64Flexible(input) {
	const cleaned = input.trim().replace(/-/g, "+").replace(/_/g, "/");
	if (cleaned.length === 0) return Buffer.alloc(0);
	const pad = cleaned.length % 4;
	if (pad === 1) throw new NoiseError("INVALID_BASE64", "Invalid base64 encoding");
	const padded = pad === 0 ? cleaned : cleaned + "=".repeat(4 - pad);
	if (!/^[A-Za-z0-9+/]+={0,2}$/.test(padded)) throw new NoiseError("INVALID_BASE64", "Invalid base64 characters");
	return Buffer.from(padded, "base64");
}
/** 校验并拷贝 32 字节 X25519 密钥。 */
function requireKey32(key, label = "key") {
	const buf = typeof key === "string" ? decodeBase64Flexible(key) : Buffer.from(key);
	if (buf.length !== KEY_LEN) throw new NoiseError("INVALID_KEY", `${label} must be exactly 32 bytes`);
	return Buffer.from(buf);
}
/** 生成 32 字节原始 X25519 密钥对。 */
function generateX25519Keypair() {
	const { privateKey, publicKey } = generateKeyPairSync("x25519");
	const pkcs8 = privateKey.export({
		type: "pkcs8",
		format: "der"
	});
	const spki = publicKey.export({
		type: "spki",
		format: "der"
	});
	return {
		privateKey: Buffer.from(pkcs8.subarray(pkcs8.length - KEY_LEN)),
		publicKey: Buffer.from(spki.subarray(spki.length - KEY_LEN))
	};
}
/** 从 32 字节 X25519 原始私钥推导 32 字节原始公钥。 */
function x25519PublicFromPrivate(priv) {
	const rawPriv = requireKey32(priv, "private key");
	const spki = createPublicKey(createPrivateKey({
		key: Buffer.concat([X25519_PKCS8_PREFIX, rawPriv]),
		format: "der",
		type: "pkcs8"
	})).export({
		type: "spki",
		format: "der"
	});
	return Buffer.from(spki.subarray(spki.length - KEY_LEN));
}
function dh(priv, pub) {
	const shared = diffieHellman({
		privateKey: createPrivateKey({
			key: Buffer.concat([X25519_PKCS8_PREFIX, priv]),
			format: "der",
			type: "pkcs8"
		}),
		publicKey: createPublicKey({
			key: Buffer.concat([X25519_SPKI_PREFIX, pub]),
			format: "der",
			type: "spki"
		})
	});
	let nonZero = 0;
	for (let i = 0; i < shared.length; i += 1) nonZero |= shared[i];
	if (nonZero === 0) throw new NoiseError("WEAK_DH", "X25519 shared secret is all zeros");
	return shared;
}
function sha256(data) {
	return createHash("sha256").update(data).digest();
}
function hmacSha256(key, data) {
	return createHmac("sha256", key).update(data).digest();
}
function hkdf2(chainingKey, ikm) {
	const tempKey = hmacSha256(chainingKey, ikm);
	const output1 = hmacSha256(tempKey, Buffer.from([1]));
	const output2 = hmacSha256(tempKey, Buffer.concat([output1, Buffer.from([2])]));
	tempKey.fill(0);
	return [output1, output2];
}
function encodeNonce(n) {
	const nonce = Buffer.alloc(12);
	nonce.writeBigUInt64LE(n, 4);
	return nonce;
}
function aeadEncrypt(key, nonce, ad, plaintext) {
	const nonceBuf = encodeNonce(nonce);
	if (!HAS_NATIVE_CHACHA) return chacha20Poly1305Seal(key, nonceBuf, ad, plaintext);
	const cipher = createCipheriv("chacha20-poly1305", key, nonceBuf, { authTagLength: TAG_LEN });
	if (ad.byteLength > 0) cipher.setAAD(ad, { plaintextLength: plaintext.byteLength });
	const head = cipher.update(plaintext);
	const tail = cipher.final();
	const tag = cipher.getAuthTag();
	return Buffer.concat([
		head,
		tail,
		tag
	]);
}
function aeadDecrypt(key, nonce, ad, ciphertext) {
	if (ciphertext.byteLength < TAG_LEN) throw new NoiseError("DECRYPT_FAILED", "Ciphertext too short");
	const nonceBuf = encodeNonce(nonce);
	if (!HAS_NATIVE_CHACHA) try {
		return chacha20Poly1305Open(key, nonceBuf, ad, ciphertext);
	} catch {
		throw new NoiseError("DECRYPT_FAILED", "ChaCha20-Poly1305 authentication failed");
	}
	const ctBuf = Buffer.from(ciphertext);
	const body = ctBuf.subarray(0, ctBuf.length - TAG_LEN);
	const tag = ctBuf.subarray(ctBuf.length - TAG_LEN);
	try {
		const decipher = createDecipheriv("chacha20-poly1305", key, nonceBuf, { authTagLength: TAG_LEN });
		decipher.setAuthTag(tag);
		if (ad.byteLength > 0) decipher.setAAD(ad, { plaintextLength: body.byteLength });
		const head = decipher.update(body);
		const tail = decipher.final();
		return Buffer.concat([head, tail]);
	} catch {
		throw new NoiseError("DECRYPT_FAILED", "ChaCha20-Poly1305 authentication failed");
	}
}
/** Noise CipherState：维护单个方向的 32 字节对称密钥与 64 位单调递增 Nonce。 */
var NoiseCipherState = class {
	key = null;
	n = 0n;
	constructor(key) {
		if (key !== void 0) this.initializeKey(key);
	}
	initializeKey(key) {
		if (this.key !== null) this.key.fill(0);
		this.key = key === null ? null : Buffer.from(key);
		this.n = 0n;
	}
	hasKey() {
		return this.key !== null;
	}
	get nonce() {
		return this.n;
	}
	encryptWithAd(ad, plaintext) {
		if (this.key === null) return Buffer.from(plaintext);
		if (this.n >= MAX_NONCE) throw new NoiseError("NONCE_EXHAUSTED", "Noise cipher nonce exhausted");
		const out = aeadEncrypt(this.key, this.n, ad, plaintext);
		this.n += 1n;
		return out;
	}
	decryptWithAd(ad, ciphertext) {
		if (this.key === null) return Buffer.from(ciphertext);
		if (this.n >= MAX_NONCE) throw new NoiseError("NONCE_EXHAUSTED", "Noise cipher nonce exhausted");
		const out = aeadDecrypt(this.key, this.n, ad, ciphertext);
		this.n += 1n;
		return out;
	}
	encrypt(plaintext) {
		return this.encryptWithAd(EMPTY_BUF, plaintext);
	}
	decrypt(ciphertext) {
		return this.decryptWithAd(EMPTY_BUF, ciphertext);
	}
	destroy() {
		if (this.key !== null) {
			this.key.fill(0);
			this.key = null;
		}
	}
};
var SymmetricState = class {
	cipher = new NoiseCipherState();
	ck;
	h;
	constructor(protocolName) {
		const nameBytes = Buffer.from(protocolName, "ascii");
		if (nameBytes.length <= KEY_LEN) {
			this.h = Buffer.alloc(KEY_LEN);
			nameBytes.copy(this.h);
		} else this.h = sha256(nameBytes);
		this.ck = Buffer.from(this.h);
	}
	mixKey(ikm) {
		const [nextCk, tempK] = hkdf2(this.ck, ikm);
		this.ck.fill(0);
		this.ck = nextCk;
		this.cipher.initializeKey(tempK);
		tempK.fill(0);
	}
	mixHash(data) {
		this.h = sha256(Buffer.concat([this.h, Buffer.from(data)]));
	}
	encryptAndHash(plaintext) {
		const ct = this.cipher.encryptWithAd(this.h, plaintext);
		this.mixHash(ct);
		return ct;
	}
	decryptAndHash(ciphertext) {
		const pt = this.cipher.decryptWithAd(this.h, ciphertext);
		this.mixHash(ciphertext);
		return pt;
	}
	split() {
		const [k1, k2] = hkdf2(this.ck, EMPTY_BUF);
		this.ck.fill(0);
		this.cipher.destroy();
		const c1 = new NoiseCipherState(k1);
		const c2 = new NoiseCipherState(k2);
		k1.fill(0);
		k2.fill(0);
		return [c1, c2];
	}
};
/**
* Noise_IK 发起端（手机 / 客户端）：已知服务端静态公钥 `remoteStaticPub`。
*/
var NoiseInitiator = class {
	sPriv;
	sPub;
	rsPub;
	sym;
	ePriv = null;
	step = 0;
	constructor(options) {
		this.sPriv = requireKey32(options.localStaticPriv, "initiator static private key");
		this.sPub = options.localStaticPub !== void 0 ? requireKey32(options.localStaticPub, "initiator static public key") : x25519PublicFromPrivate(this.sPriv);
		this.rsPub = requireKey32(options.remoteStaticPub, "responder static public key");
		this.sym = new SymmetricState(NOISE_IK_PROTOCOL);
		this.sym.mixHash(options.prologue ?? EMPTY_BUF);
		this.sym.mixHash(this.rsPub);
	}
	/** 生成首条握手消息 `-> e, es, s, ss`（可注入确定性临时私钥用于金标向量测试）。 */
	writeMessage1(payload = EMPTY_BUF, ephemeralPriv) {
		if (this.step !== 0) throw new NoiseError("HANDSHAKE_ORDER", "writeMessage1 already called");
		const eph = ephemeralPriv !== void 0 ? {
			privateKey: requireKey32(ephemeralPriv, "ephemeral private key"),
			publicKey: x25519PublicFromPrivate(ephemeralPriv)
		} : generateX25519Keypair();
		this.ePriv = eph.privateKey;
		this.sym.mixHash(eph.publicKey);
		this.sym.mixKey(dh(this.ePriv, this.rsPub));
		const encS = this.sym.encryptAndHash(this.sPub);
		this.sym.mixKey(dh(this.sPriv, this.rsPub));
		const encPayload = this.sym.encryptAndHash(payload);
		this.step = 1;
		return Buffer.concat([
			eph.publicKey,
			encS,
			encPayload
		]);
	}
	/** 校验服务端响应 `<- e, ee, se` 并切入双向传输态。 */
	readMessage2(msg2) {
		if (this.step !== 1 || this.ePriv === null) throw new NoiseError("HANDSHAKE_ORDER", "readMessage2 called out of order");
		const buf = Buffer.from(msg2);
		if (buf.length < 48) throw new NoiseError("INVALID_MESSAGE", "Handshake message 2 too short");
		const rePub = buf.subarray(0, KEY_LEN);
		this.sym.mixHash(rePub);
		this.sym.mixKey(dh(this.ePriv, rePub));
		this.sym.mixKey(dh(this.sPriv, rePub));
		const payload = this.sym.decryptAndHash(buf.subarray(KEY_LEN));
		const [sendCipher, recvCipher] = this.sym.split();
		this.ePriv.fill(0);
		this.ePriv = null;
		this.step = 2;
		return {
			sendCipher,
			recvCipher,
			remoteStatic: Buffer.from(this.rsPub),
			payload
		};
	}
};
/**
* Noise_IK 响应端（电脑端网关）：接收 `msg1`，解密校验客户端静态公钥，生成 `msg2` 并产出双向 CipherState。
*/
var NoiseResponder = class {
	sPriv;
	sPub;
	prologue;
	constructor(options) {
		this.sPriv = requireKey32(options.localStaticPriv, "responder static private key");
		this.sPub = options.localStaticPub !== void 0 ? requireKey32(options.localStaticPub, "responder static public key") : x25519PublicFromPrivate(this.sPriv);
		this.prologue = Buffer.from(options.prologue ?? EMPTY_BUF);
	}
	/** 接受客户端 `msg1` 并一次性完成响应 `msg2` 构造与传输态切分。 */
	accept(msg1, responsePayload = EMPTY_BUF, ephemeralPriv) {
		const buf = Buffer.from(msg1);
		if (buf.length < 96) throw new NoiseError("INVALID_MESSAGE", "Handshake message 1 too short");
		const sym = new SymmetricState(NOISE_IK_PROTOCOL);
		sym.mixHash(this.prologue);
		sym.mixHash(this.sPub);
		const rePub = buf.subarray(0, KEY_LEN);
		sym.mixHash(rePub);
		sym.mixKey(dh(this.sPriv, rePub));
		const rsPub = sym.decryptAndHash(buf.subarray(KEY_LEN, 80));
		if (rsPub.length !== KEY_LEN) throw new NoiseError("INVALID_KEY", "Decrypted remote static key has invalid length");
		sym.mixKey(dh(this.sPriv, rsPub));
		const payload = sym.decryptAndHash(buf.subarray(80));
		const eph = ephemeralPriv !== void 0 ? {
			privateKey: requireKey32(ephemeralPriv, "ephemeral private key"),
			publicKey: x25519PublicFromPrivate(ephemeralPriv)
		} : generateX25519Keypair();
		sym.mixHash(eph.publicKey);
		sym.mixKey(dh(eph.privateKey, rePub));
		sym.mixKey(dh(eph.privateKey, rsPub));
		const encRespPayload = sym.encryptAndHash(responsePayload);
		eph.privateKey.fill(0);
		const [recvCipher, sendCipher] = sym.split();
		return {
			msg2: Buffer.concat([eph.publicKey, encRespPayload]),
			sendCipher,
			recvCipher,
			remoteStatic: rsPub,
			payload
		};
	}
};
/** 常量时间比较两个 32 字节密钥是否一致。 */
function keysEqual(a, b) {
	if (a.byteLength !== b.byteLength) return false;
	return timingSafeEqual(a, b);
}
//#endregion
//#region src/http-util.ts
/** 普通请求体上限 1 MiB；上传路由显式传入更大限额。 */
const DEFAULT_BODY_BYTES = 1 << 20;
/** 带 HTTP 状态码的请求错误，供顶层路由直接返回对应状态码。 */
var HttpError = class extends Error {
	status;
	constructor(status, message) {
		super(message);
		this.status = status;
	}
};
/** 枚举本机所有非回环 IPv4 与全局可达 IPv6 地址。 */
function lanAddresses() {
	const out = [];
	const nets = networkInterfaces();
	for (const entries of Object.values(nets)) {
		if (entries === void 0) continue;
		for (const entry of entries) {
			if (entry.internal) continue;
			const v4 = entry.family === "IPv4";
			const v6 = entry.family === "IPv6";
			if (v4) {
				out.push(entry.address);
				continue;
			}
			if (v6 && !entry.address.startsWith("fe80")) out.push(entry.address);
		}
	}
	return out;
}
/** 为 IPv6 字面量补上方括号后拼接端口。 */
function hostPort(address, port) {
	return address.includes(":") ? `[${address}]:${String(port)}` : `${address}:${String(port)}`;
}
/**
* 判断请求是否经由本机或局域网 Host 头到达。
* Cloudflare 等隧道从 127.0.0.1 转发，因此依据 Host 头而非 socket 对端区分内外网。
*/
function isLocalHostHeader(host) {
	if (typeof host !== "string" || host.length === 0) return true;
	const bracketed = host.startsWith("[") ? host.slice(1, host.indexOf("]") >= 0 ? host.indexOf("]") : void 0) : "";
	const bare = bracketed !== "" ? bracketed : host.split(":")[0] ?? "";
	if (bare === "localhost" || bare === "127.0.0.1" || bare === "::1" || bare === "0.0.0.0") return true;
	if (bare.includes(":")) return /^f[cd]/i.test(bare) || /^fe80/i.test(bare);
	const parts = bare.split(".").map((part) => Number.parseInt(part, 10));
	if (parts.length !== 4) return false;
	if (parts.some((part) => !Number.isFinite(part))) return false;
	const a = parts[0];
	const b = parts[1];
	if (a === 127) return true;
	if (a === 10) return true;
	if (a === 192 && b === 168) return true;
	if (a === 172 && b >= 16 && b <= 31) return true;
	return false;
}
/**
* 对局域网候选地址或完整 http(s) URL 按手机可达性排序，越小越优先。
* 同时识别裸 IP、host:port 以及 http:// / https:// 域名或地址。
*/
function lanRank(input) {
	const raw = input.trim();
	let host = raw;
	let scheme = "";
	if (/^https?:\/\//i.test(raw)) try {
		const parsed = new URL(raw);
		scheme = parsed.protocol.toLowerCase();
		host = parsed.hostname;
	} catch {
		return 8;
	}
	else if (raw.startsWith("[")) {
		const close = raw.indexOf("]");
		host = close > 1 ? raw.slice(1, close) : raw;
	} else if ((raw.match(/:/g) ?? []).length === 1) host = raw.split(":")[0] ?? raw;
	if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1);
	if (host.includes(":")) return 9;
	if (host.startsWith("192.168.")) return host.startsWith("192.168.56.") ? 6 : 0;
	if (host.startsWith("10.")) return host.startsWith("10.0.2.") ? 7 : 1;
	if (host.startsWith("172.")) {
		const second = Number.parseInt(host.split(".")[1] ?? "", 10);
		return second >= 16 && second <= 31 ? 5 : 2;
	}
	if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) return 3;
	return scheme === "https:" ? 2 : 3;
}
/**
* 校验公网访问地址：允许空字符串（表示清空）；非空时必须为合法的 http:// 或 https:// URL。
*/
function validatePublicUrl(raw) {
	const trimmed = raw.trim();
	if (trimmed === "") return {
		ok: true,
		url: ""
	};
	if (/\s/.test(trimmed)) return {
		ok: false,
		error: "公网地址不能包含空格"
	};
	if (!/^https?:\/\//i.test(trimmed)) return {
		ok: false,
		error: "公网地址必须以 http:// 或 https:// 开头"
	};
	try {
		const parsed = new URL(trimmed);
		if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return {
			ok: false,
			error: "公网地址协议仅支持 http:// 或 https://"
		};
		if (!parsed.hostname || parsed.hostname.length === 0) return {
			ok: false,
			error: "公网地址缺少有效的主机名或域名"
		};
		const cleanPath = parsed.pathname === "/" ? "" : parsed.pathname.replace(/\/+$/, "");
		return {
			ok: true,
			url: `${parsed.origin}${cleanPath}`
		};
	} catch {
		return {
			ok: false,
			error: "公网地址格式不合法，请填写完整的 http:// 或 https:// 地址"
		};
	}
}
/**
* 校验并归一化允许预览的本机开发端口列表（支持数组或逗号分隔字符串，范围 1..65535）。
*/
function parsePreviewPorts(raw) {
	const tokens = Array.isArray(raw) ? raw : typeof raw === "string" ? raw.split(/[,，\s]+/).filter((s) => s.length > 0) : [];
	if (!Array.isArray(raw) && typeof raw !== "string") return {
		ok: false,
		error: "previewPorts 必须是端口数组或逗号分隔的端口字符串"
	};
	const seen = /* @__PURE__ */ new Set();
	const ports = [];
	for (const item of tokens) {
		const str = String(item).trim();
		if (str === "") continue;
		if (!/^\d+$/.test(str)) return {
			ok: false,
			error: `端口号「${str}」不合法，请填写 1 到 65535 之间的整数`
		};
		const n = Number.parseInt(str, 10);
		if (!Number.isInteger(n) || n < 1 || n > 65535) return {
			ok: false,
			error: `端口号 ${String(n)} 超出范围（允许 1..65535）`
		};
		if (!seen.has(n)) {
			seen.add(n);
			ports.push(n);
		}
		if (ports.length > 64) return {
			ok: false,
			error: "最多允许配置 64 个预览端口"
		};
	}
	return {
		ok: true,
		ports
	};
}
/** 常量时间字符串比较，防时序侧信道。 */
function tokenMatches(given, expected) {
	if (given.length === 0 || expected.length === 0) return false;
	const a = Buffer.from(given, "utf8");
	const b = Buffer.from(expected, "utf8");
	if (a.length !== b.length) return false;
	return timingSafeEqual(a, b);
}
/** 从 Authorization: Bearer 头或查询参数 ?t= 提取访问令牌。 */
function presentedToken(req, url) {
	const header = req.headers.authorization;
	if (typeof header === "string" && header.toLowerCase().startsWith("bearer ")) return header.slice(7).trim();
	const query = url.searchParams.get("t");
	return query === null ? "" : query.trim();
}
/** 读取并解析有界 JSON 对象请求体；超限抛出 status=413 的 HttpError。 */
async function readJson(req, limit = DEFAULT_BODY_BYTES) {
	const chunks = [];
	let size = 0;
	for await (const chunk of req) {
		const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
		size += buf.length;
		if (size > limit) {
			req.resume();
			throw new HttpError(413, `body too large (limit ${String(limit)} bytes)`);
		}
		chunks.push(buf);
	}
	if (size === 0) return {};
	const text = Buffer.concat(chunks).toString("utf8");
	let parsed;
	try {
		parsed = JSON.parse(text);
	} catch {
		throw new HttpError(400, "body must be valid JSON");
	}
	if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new HttpError(400, "body must be a JSON object");
	return parsed;
}
/** 发送 JSON 或纯文本响应（若响应头已发送则安全忽略）。 */
const send = (res, status, body) => {
	if (res.headersSent) return;
	const text = typeof body === "string" ? body : JSON.stringify(body);
	const headers = {
		"content-type": typeof body === "string" ? "text/plain; charset=utf-8" : "application/json; charset=utf-8",
		"content-length": String(Buffer.byteLength(text)),
		"access-control-allow-origin": "*",
		"access-control-allow-headers": "authorization,content-type,idempotency-key",
		"access-control-allow-methods": "GET,HEAD,POST,PATCH,OPTIONS",
		"cache-control": "no-store"
	};
	if (status === 413) headers.connection = "close";
	res.writeHead(status, headers);
	res.end(text);
};
//#endregion
//#region src/state.ts
/**
* 插件持久化状态、路径解析、原子落盘、日志轮转与配对码防爆破管理。
*/
const VERSION = "3.0.0";
const PAIR_TTL_MS = 900 * 1e3;
const PAIR_LOCK_MS = 300 * 1e3;
const PRESENCE_TTL_MS = 15 * 1e3;
const PAIR_FAIL_MAP_CAP = 256;
const PAIR_FAIL_EXPIRE_MS = 600 * 1e3;
const MAX_LOG_BYTES = 5 * 1024 * 1024;
/** 统一解析 DSH 主目录，尊重 `DSH_HOME` 环境变量覆盖。 */
function dshHome() {
	const override = process.env.DSH_HOME;
	return override !== void 0 && override.length > 0 ? override : join(homedir(), ".dsh");
}
const statePath = () => join(dshHome(), "dsh-mobile.json");
/**
* 原子写入文件：先写入带 pid 与随机后缀的同目录临时文件，再 rename 覆盖目标。
*/
function atomicWriteSync(file, content, mode) {
	const temp = `${file}.${String(process.pid)}.${randomBytes(4).toString("hex")}.tmp`;
	try {
		mkdirSync(dirname(file), { recursive: true });
		if (mode !== void 0) writeFileSync(temp, content, {
			encoding: "utf8",
			mode
		});
		else writeFileSync(temp, content, "utf8");
		renameSync(temp, file);
		if (mode !== void 0) try {
			chmodSync(file, mode);
		} catch {}
	} catch (error) {
		try {
			unlinkSync(temp);
		} catch {}
		throw error;
	}
}
let stateCache = null;
/** 读取持久化状态（内存缓存 + mtime/size 校验，避免每次请求 readFileSync）。 */
function readState() {
	const file = statePath();
	let mtimeMs = -1;
	let size = -1;
	try {
		const st = statSync(file);
		mtimeMs = st.mtimeMs;
		size = st.size;
	} catch {
		stateCache = {
			file,
			mtimeMs: -1,
			size: -1,
			data: {}
		};
		return {};
	}
	if (stateCache !== null && stateCache.file === file && stateCache.mtimeMs === mtimeMs && stateCache.size === size) return stateCache.data;
	try {
		const parsed = JSON.parse(readFileSync(file, "utf8"));
		const data = parsed !== null && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
		stateCache = {
			file,
			mtimeMs,
			size,
			data
		};
		return data;
	} catch {
		return {};
	}
}
/** 合并补丁并原子写回 `dsh-mobile.json`（权限 0600），同步刷新内存缓存；永不覆盖丢失既有身份字段。 */
function writeState(patch, onError) {
	const file = statePath();
	const existing = readState();
	const cleanPatch = {};
	for (const [k, v] of Object.entries(patch)) if (v !== void 0) cleanPatch[k] = v;
	const next = {
		...existing,
		...cleanPatch
	};
	try {
		atomicWriteSync(file, `${JSON.stringify(next, null, 2)}\n`, 384);
		try {
			const st = statSync(file);
			stateCache = {
				file,
				mtimeMs: st.mtimeMs,
				size: st.size,
				data: next
			};
		} catch {
			stateCache = {
				file,
				mtimeMs: Date.now(),
				size: 0,
				data: next
			};
		}
		return true;
	} catch (error) {
		onError?.(error);
		return false;
	}
}
/** 当前配对偏好（默认开启局域网与公网开关，兼容已有升级用户）。 */
function pairPrefs() {
	const raw = readState().pair;
	const envPublic = process.env.DSH_MOBILE_PUBLIC_URL;
	return {
		allowLan: raw?.allowLan !== false,
		allowRemote: raw?.allowRemote !== false,
		publicUrl: typeof raw?.publicUrl === "string" ? raw.publicUrl : typeof envPublic === "string" ? envPublic : ""
	};
}
/** 当前提问回答模式（默认 `phone`）。 */
function answerMode() {
	return readState().answerMode === "desktop" ? "desktop" : "phone";
}
/** 是否允许手机使用远程交互终端（默认 `true`）。 */
function allowTerminal() {
	return readState().allowTerminal !== false;
}
/** 允许手机预览的本机 127.0.0.1 端口白名单（默认 `[]`）。 */
function previewPorts() {
	const raw = readState().previewPorts;
	if (!Array.isArray(raw)) return [];
	const out = [];
	const seen = /* @__PURE__ */ new Set();
	for (const item of raw) {
		const n = Number(item);
		if (Number.isInteger(n) && n >= 1 && n <= 65535 && !seen.has(n)) {
			seen.add(n);
			out.push(n);
		}
	}
	return out;
}
/** 读取已启用的外部 Agent 后端开关（默认全部关闭，保障本机权限边界）。 */
function enabledBackends() {
	const raw = readState().enabledBackends;
	if (!raw || typeof raw !== "object") return {};
	const out = {};
	for (const [k, v] of Object.entries(raw)) if (v === true) out[k] = true;
	return out;
}
/** 持久化某个外部 Agent 后端的开关状态。 */
function setBackendEnabled(id, enabled) {
	const next = enabledBackends();
	next[id] = enabled;
	writeState({ enabledBackends: next });
}
/** 读取或首次铸造 Bearer 令牌（绝不向日志打印明文）。 */
function resolveToken(fromConfig) {
	if (fromConfig !== void 0 && fromConfig.length > 0) return fromConfig;
	const env = process.env.DSH_MOBILE_TOKEN;
	if (env !== void 0 && env.length > 0) return env;
	const existing = readState().token;
	if (typeof existing === "string" && existing.length >= 16) return existing;
	const token = randomBytes(24).toString("base64url");
	writeState({ token });
	return token;
}
/** 读取或首次生成持久 `hostId`（UUID v4，后续永久不变）。 */
function resolveHostId() {
	const existing = readState().hostId;
	if (typeof existing === "string" && existing.trim().length > 0) return existing.trim();
	const hostId = randomUUID();
	writeState({ hostId });
	return hostId;
}
/** 读取或首次生成 32 字节 X25519 静态密钥对（标准 Base64 落盘）。 */
function resolveE2eeKeypair() {
	const state = readState();
	if (typeof state.e2eePriv === "string" && state.e2eePriv.trim().length > 0) try {
		const privBuf = decodeBase64Flexible(state.e2eePriv);
		if (privBuf.length === 32) {
			const priv = privBuf.toString("base64");
			const pub = x25519PublicFromPrivate(privBuf).toString("base64");
			if (state.e2eePriv !== priv || state.e2eePub !== pub) writeState({
				e2eePriv: priv,
				e2eePub: pub
			});
			return {
				priv,
				pub
			};
		}
	} catch {}
	const pair = generateX25519Keypair();
	const priv = pair.privateKey.toString("base64");
	const pub = pair.publicKey.toString("base64");
	writeState({
		e2eePriv: priv,
		e2eePub: pub
	});
	return {
		priv,
		pub
	};
}
const MAX_PAIRED_DEVICES = 64;
/** 读取已配对设备列表（按最近活跃时间倒序）。 */
function pairedDevices() {
	const raw = readState().devices;
	if (!Array.isArray(raw)) return [];
	const out = [];
	for (const item of raw) {
		if (item === null || typeof item !== "object") continue;
		const r = item;
		const deviceId = typeof r.deviceId === "string" ? r.deviceId.trim() : "";
		const pubKey = typeof r.pubKey === "string" ? r.pubKey.trim() : "";
		if (deviceId === "" || pubKey === "") continue;
		out.push({
			deviceId,
			pubKey,
			name: typeof r.name === "string" && r.name.trim() !== "" ? r.name.trim() : "未命名设备",
			createdAt: typeof r.createdAt === "number" && Number.isFinite(r.createdAt) ? r.createdAt : 0,
			lastSeenAt: typeof r.lastSeenAt === "number" && Number.isFinite(r.lastSeenAt) ? r.lastSeenAt : 0,
			revoked: r.revoked === true
		});
	}
	out.sort((a, b) => b.lastSeenAt - a.lastSeenAt);
	return out;
}
/** 写入或更新已配对设备记录。 */
function upsertPairedDevice(entry) {
	const list = pairedDevices();
	const idx = list.findIndex((d) => d.deviceId === entry.deviceId);
	if (idx >= 0) list[idx] = {
		...list[idx],
		...entry
	};
	else list.push({ ...entry });
	list.sort((a, b) => b.lastSeenAt - a.lastSeenAt);
	const bounded = list.slice(0, MAX_PAIRED_DEVICES);
	writeState({ devices: bounded });
	return bounded;
}
/** 撤销或恢复指定设备授权。 */
function setDeviceRevoked(deviceId, revoked) {
	const list = pairedDevices();
	const idx = list.findIndex((d) => d.deviceId === deviceId);
	if (idx < 0) return { ok: false };
	list[idx] = {
		...list[idx],
		revoked
	};
	writeState({ devices: list });
	return {
		ok: true,
		devices: list
	};
}
/** 生成 6 位密码学随机数字码。 */
function freshPairCode() {
	return String(randomInt(0, 1e6)).padStart(6, "0");
}
/** 生成二维码承载的 `dshmobile://pair?...` 深链，公网隧道优先排在首个备选。 */
function pairPayload(base, code, alts = []) {
	const list = alts.filter((one) => one.length > 0 && one !== base);
	const tunnel = list.find((one) => {
		if (/^https:\/\//i.test(one)) return true;
		if (/^http:\/\//i.test(one)) try {
			return !isLocalHostHeader(new URL(one).host);
		} catch {
			return false;
		}
		return false;
	}) ?? "";
	const kept = list.filter((one) => one !== tunnel).slice(0, tunnel !== "" ? 3 : 4);
	const extra = (tunnel !== "" ? [tunnel, ...kept] : kept).map((one) => `&a=${encodeURIComponent(one)}`).join("");
	return `dshmobile://pair?b=${encodeURIComponent(base)}&c=${encodeURIComponent(code)}${extra}`;
}
/** 计算本机局域网可拨号的基础 URL 列表（IPv4 按可达性排前，IPv6 兜底）。 */
function lanBases(port) {
	const all = lanAddresses();
	const v6 = all.filter((address) => address.includes(":") && !/^f[cd]/i.test(address));
	return [...all.filter((address) => !address.includes(":")).sort((left, right) => lanRank(left) - lanRank(right)), ...v6].map((address) => `http://${hostPort(address, port)}`);
}
/** 追加诊断日志；超过 5 MiB 自动轮转为 `.1`。 */
async function record(file, line) {
	if (file.length === 0) return;
	try {
		await mkdir(dirname(file), { recursive: true });
		try {
			if ((await stat(file)).size >= MAX_LOG_BYTES) {
				const backup = `${file}.1`;
				await unlink(backup).catch(() => void 0);
				await rename(file, backup).catch(() => void 0);
			}
		} catch {}
		await appendFile(file, `${(/* @__PURE__ */ new Date()).toISOString()} pid=${String(process.pid)} ${line}\n`, "utf8");
	} catch {}
}
/**
* 配对状态与防爆破控制器：
* 1) `pairFails` 有界（上限 256 + 10 分钟过期清理）；
* 2) 每个 6 位配对码自身记录 `fails`，累计错满 8 次立即作废并自动旋转新码；
* 3) 远程隧道经 127.0.0.1 转发时优先按转发头识别来源，避免把本机回环整体锁死。
*/
var PairingRuntime = class {
	pairCode = null;
	pairFails = /* @__PURE__ */ new Map();
	phoneSeenAt = 0;
	port;
	logFile;
	constructor(port, logFile) {
		this.port = port;
		this.logFile = logFile;
	}
	pruneFails(now) {
		for (const [peer, item] of this.pairFails) if (now - item.updatedAt > PAIR_FAIL_EXPIRE_MS && item.until <= now) this.pairFails.delete(peer);
		while (this.pairFails.size > PAIR_FAIL_MAP_CAP) {
			const oldest = this.pairFails.keys().next().value;
			if (oldest === void 0) break;
			this.pairFails.delete(oldest);
		}
	}
	/** 解析限流键：若经本机回环代理外网隧道请求，结合转发客户端 IP 区分来源。 */
	peerKey(remoteAddress, local, headers) {
		const rawPeer = remoteAddress ?? "?";
		if (!local && (rawPeer === "127.0.0.1" || rawPeer === "::1" || rawPeer === "::ffff:127.0.0.1")) {
			const cf = headers["cf-connecting-ip"];
			if (typeof cf === "string" && cf.trim().length > 0) return `cf:${cf.trim()}`;
			const xff = headers["x-forwarded-for"];
			if (typeof xff === "string" && xff.trim().length > 0) {
				const first = xff.split(",")[0]?.trim() ?? "";
				if (first.length > 0) return `xff:${first}`;
			}
			return `tunnel:${String(headers.host ?? "remote")}`;
		}
		return rawPeer;
	}
	/** 获取当前有效配对码（过期则自动换新）。 */
	ensurePair() {
		if (this.pairCode === null || this.pairCode.expiresAt <= Date.now()) {
			this.pairCode = {
				code: freshPairCode(),
				expiresAt: Date.now() + PAIR_TTL_MS,
				fails: 0
			};
			record(this.logFile, `pair code minted ttl=${String(PAIR_TTL_MS)}`);
		}
		return this.pairCode;
	}
	/** 立即作废旧码并铸造新 6 位配对码。 */
	rotatePair(clearPeerLocks = false) {
		this.pairCode = {
			code: freshPairCode(),
			expiresAt: Date.now() + PAIR_TTL_MS,
			fails: 0
		};
		if (clearPeerLocks) this.pairFails.clear();
		record(this.logFile, "pair code rotated");
		return this.pairCode;
	}
	/** 检查该 peer 是否处于冷却锁定期。 */
	lockedUntil(peer, now = Date.now()) {
		this.pruneFails(now);
		const gate = this.pairFails.get(peer);
		return gate !== void 0 && gate.until > now ? gate.until : 0;
	}
	/** 在读取请求体前预占一次尝试计数，防止并发猜码共享同一次计数。 */
	reserveAttempt(peer, now = Date.now()) {
		this.pruneFails(now);
		const gate = this.pairFails.get(peer);
		const expired = gate !== void 0 && gate.until !== 0 && gate.until <= now;
		const attempt = gate === void 0 || expired ? {
			n: 1,
			until: 0,
			updatedAt: now
		} : {
			n: gate.n + 1,
			until: 0,
			updatedAt: now
		};
		this.pairFails.delete(peer);
		this.pairFails.set(peer, attempt);
		this.pruneFails(now);
		return attempt;
	}
	/**
	* 核验配对码：
	* - 成功：旋转新码并清除该 peer 失败记录；
	* - 失败：累增 peer 失败次数与配对码自身 `fails`，满 8 次立即作废旧码并旋转新码。
	*/
	verifyClaim(peer, attempt, given, isLoopbackTunnel) {
		const pending = this.ensurePair();
		if (given.length === 6 && tokenMatches(given, pending.code)) {
			this.rotatePair(false);
			this.pairFails.delete(peer);
			this.phoneSeenAt = Date.now();
			return { ok: true };
		}
		pending.fails += 1;
		let rotated = false;
		if (pending.fails >= 8) {
			this.rotatePair(false);
			rotated = true;
			record(this.logFile, `pair code burned after ${String(8)} wrong claims; rotated`);
		}
		const lockPeer = !isLoopbackTunnel && attempt.n >= 8;
		const next = {
			n: attempt.n,
			until: lockPeer ? Date.now() + PAIR_LOCK_MS : 0,
			updatedAt: Date.now()
		};
		this.pairFails.set(peer, next);
		const codeLeft = Math.max(0, 8 - pending.fails);
		const peerLeft = Math.max(0, 8 - next.n);
		return {
			ok: false,
			left: rotated ? 0 : Math.min(codeLeft, peerLeft),
			rotated
		};
	}
	/** 构造桌面设置面板与 `/api/pair/state` 共享的状态快照（不含明文 token）。 */
	snapshot() {
		const prefs = pairPrefs();
		const pending = this.ensurePair();
		const lan = lanBases(this.port);
		const primary = prefs.allowLan && lan.length > 0 ? lan[0] : prefs.publicUrl;
		const tunnelUrl = prefs.allowRemote ? prefs.publicUrl : "";
		const restLan = lan.slice(1).filter((one) => one !== primary);
		const v4rest = restLan.filter((one) => !one.includes("["));
		const v6rest = restLan.filter((one) => one.includes("["));
		const alts = [
			tunnelUrl,
			...v4rest,
			...v6rest
		].filter((one) => one.length > 0 && one !== primary);
		return {
			ok: true,
			host: hostname(),
			hostId: resolveHostId(),
			e2ee: true,
			e2eePub: resolveE2eeKeypair().pub,
			devices: pairedDevices(),
			version: VERSION,
			port: this.port,
			code: pending.code,
			expiresAt: pending.expiresAt,
			allowLan: prefs.allowLan,
			allowRemote: prefs.allowRemote,
			publicUrl: prefs.publicUrl,
			answerMode: answerMode(),
			allowTerminal: allowTerminal(),
			previewPorts: previewPorts(),
			lan,
			alts,
			base: primary,
			phoneSeenAt: this.phoneSeenAt,
			phoneOnline: this.phoneSeenAt > 0 && Date.now() - this.phoneSeenAt < 6e5,
			sessions: true
		};
	}
};
/** 幂等请求体摘要（SHA-256 前 32 位十六进制）。 */
const hashText = (text) => createHash("sha256").update(text).digest("hex").slice(0, 32);
//#endregion
//#region src/projections.ts
/**
* 会话投影、模型目录、预设列表、定时任务归一与有界 deepContext 缓存。
*/
/** 提取子智能体列表与团队任务板快照。 */
function agentsOf(values) {
	const catalog = values?.subagentCatalog ?? [];
	const subagents = (Array.isArray(catalog) ? catalog : []).map((s) => ({
		id: String(s.id ?? ""),
		label: String(s.label ?? s.description ?? ""),
		mode: String(s.mode ?? ""),
		createdAt: Number(s.createdAt ?? 0) || 0
	}));
	const team = values?.agentTeam ?? {};
	const rawTasks = team.tasks ?? [];
	const tasks = (Array.isArray(rawTasks) ? rawTasks : []).map((t) => ({
		id: String(t.id ?? ""),
		subject: String(t.subject ?? t.title ?? ""),
		status: String(t.status ?? ""),
		owner: String(t.ownerName ?? t.ownerId ?? "")
	}));
	return {
		enabled: team.enabled === true,
		tasks,
		subagents
	};
}
/** 归一化宿主提问列表。 */
function normalizeQuestions(raw) {
	return (Array.isArray(raw) ? raw : []).map((q) => {
		const options = (Array.isArray(q.options) ? q.options : []).map((o) => ({
			label: String(o.label ?? ""),
			description: o.description === void 0 ? "" : String(o.description)
		})).filter((o) => o.label !== "");
		const one = {
			id: String(q.id ?? ""),
			prompt: String(q.question ?? q.prompt ?? ""),
			options,
			multiSelect: q.multiSelect === true
		};
		if (typeof q.header === "string" && q.header !== "") one.header = q.header;
		if (typeof q.detail === "string" && q.detail !== "") one.detail = q.detail;
		return one;
	});
}
/** 归一化手机端提交的回答列表。 */
function normalizeAskAnswers(raw) {
	const list = Array.isArray(raw) ? raw : [];
	const answers = [];
	for (const item of list) {
		const id = String(item?.id ?? "");
		if (id === "") continue;
		const one = {
			id,
			selected: (Array.isArray(item?.selected) ? item.selected : []).map((value) => String(value)).filter((value) => value !== "")
		};
		if (typeof item?.custom === "string" && item.custom !== "") one.custom = item.custom;
		answers.push(one);
	}
	return answers;
}
/** 提取上下文窗口占用投影。 */
function contextOf(values) {
	const raw = values?.contextPressure ?? {};
	const used = Number(raw.projectedTokens ?? raw.pressureTokens);
	const window = Number(raw.contextWindow);
	if (!Number.isFinite(used) || used <= 0) return null;
	if (!Number.isFinite(window) || window <= 0) return null;
	return {
		used: Math.trunc(used),
		window: Math.trunc(window)
	};
}
/** 提取投影中的挂起与已完成提问。 */
function asksOf(values) {
	const raw = values?.userQuestions ?? {};
	const activeRaw = Array.isArray(raw.active) ? raw.active : [];
	const settledRaw = Array.isArray(raw.settled) ? raw.settled : [];
	const active = [];
	for (const entry of activeRaw) {
		const callId = String(entry.callId ?? "");
		const list = Array.isArray(entry.questions) ? entry.questions : [];
		if (callId === "" || list.length === 0) continue;
		const questions = normalizeQuestions(list);
		active.push({
			callId,
			questions,
			state: String(entry.state ?? "open"),
			synthetic: false
		});
	}
	return {
		active,
		settled: settledRaw
	};
}
/** 提取累计 Token 统计。 */
function tokensOf(values) {
	const raw = values?.tokenUsage ?? {};
	const num = (v) => {
		const n = Number(v ?? 0);
		return Number.isFinite(n) && n > 0 ? n : 0;
	};
	return {
		uncachedInputTokens: num(raw.uncachedInputTokens),
		outputTokens: num(raw.outputTokens),
		cacheReadTokens: num(raw.cacheReadTokens),
		cacheWriteTokens: num(raw.cacheWriteTokens)
	};
}
/** 提取会话计划模式状态投影。 */
function planOf(values) {
	const raw = values?.plan ?? {};
	return {
		active: raw.active === true,
		pending: raw.pending === true
	};
}
/** 提取会话当前选中的模型引用。 */
function modelOf(values) {
	const selection = values?.modelSelection ?? {};
	const next = selection.next ?? selection.lastUsed ?? null;
	if (next === null || typeof next !== "object") return null;
	const provider = String(next.provider ?? "");
	const model = String(next.model ?? "");
	if (provider === "" || model === "") return null;
	return {
		provider,
		model,
		reasoningEffort: String(next.reasoningEffort ?? "")
	};
}
/** 从 `ctl.list` 返回结构中取出数组主体。 */
function rowsOf(payload) {
	if (Array.isArray(payload)) return payload;
	if (payload !== null && typeof payload === "object") {
		const items = payload.items;
		if (Array.isArray(items)) return items;
	}
	return [];
}
/** 将宿主会话列表投影为手机端统一行结构（过滤空白与子智能体壳会话）。 */
function projectSessions(payload, liveAsking) {
	const rows = [];
	for (const item of rowsOf(payload)) {
		if (item === null || typeof item !== "object") continue;
		const s = item;
		if (s.__blank === true) continue;
		if (s.origin !== void 0 && s.origin !== null && String(s.origin) === "subagent") continue;
		const id = String(s.sessionId ?? s.id ?? "");
		if (id.length === 0) continue;
		const projectedValues = s.projections?.values;
		const projectedTitle = projectedValues?.title;
		const title = typeof projectedTitle === "string" && projectedTitle.length > 0 ? projectedTitle : typeof s.title === "string" && s.title.length > 0 ? s.title : "(untitled)";
		const updated = Number(s.updatedAt ?? 0);
		rows.push({
			id,
			title,
			updatedAt: Number.isFinite(updated) ? updated : 0,
			cwd: String(s.cwd ?? ""),
			running: s.running === true,
			asking: (liveAsking?.has(id) ?? false) || asksOf(projectedValues).active.length > 0,
			archived: false,
			pinned: projectedValues?.pinned === true,
			tokens: tokensOf(projectedValues),
			context: contextOf(projectedValues),
			model: modelOf(projectedValues),
			agents: agentsOf(projectedValues),
			plan: planOf(projectedValues)
		});
	}
	rows.sort((a, b) => b.updatedAt - a.updatedAt);
	return rows;
}
/** 归一化模型目录结构。 */
function normalizeCatalog(raw) {
	let value = raw;
	if (typeof value === "string") try {
		value = JSON.parse(value);
	} catch {
		value = null;
	}
	let v = value ?? {};
	if (v.value !== null && typeof v.value === "object") v = v.value;
	if (v.catalog !== null && typeof v.catalog === "object") v = v.catalog;
	const currentRaw = v.current;
	const current = currentRaw !== null && typeof currentRaw === "object" ? {
		provider: String(currentRaw.provider ?? ""),
		model: String(currentRaw.model ?? ""),
		reasoningEffort: String(currentRaw.reasoningEffort ?? "")
	} : null;
	const groups = (v.groups ?? []).map((g) => ({
		id: String(g.id ?? ""),
		name: String(g.name ?? g.id ?? ""),
		models: (g.models ?? []).map((m) => {
			const reasoning = m.reasoning ?? {};
			const efforts = (reasoning.efforts ?? []).map((e) => ({
				id: String(e.id ?? ""),
				name: String(e.name ?? e.id ?? "")
			}));
			return {
				id: String(m.id ?? ""),
				name: String(m.name ?? m.id ?? ""),
				description: String(m.description ?? ""),
				efforts,
				defaultEffort: String(reasoning.defaultEffort ?? "")
			};
		})
	}));
	const failures = (v.failures ?? []).map((f) => ({
		id: String(f.id ?? ""),
		name: String(f.name ?? ""),
		message: String(f.message ?? "")
	}));
	return {
		current,
		routable: v.routable !== false,
		groups,
		failures
	};
}
/** 读取当前选中的智能体预设 ID。 */
function presetCurrent(svc) {
	const norm = (raw) => {
		if (raw === null || raw === void 0) return "";
		if (typeof raw === "function") return "";
		if (typeof raw === "string") return raw;
		if (typeof raw === "number") return String(raw);
		if (typeof raw === "object") {
			const o = raw;
			return String(o.id ?? o.name ?? "");
		}
		return "";
	};
	try {
		const v = norm(svc.current ?? svc.selected);
		if (v !== "") return v;
	} catch {}
	try {
		const v = norm(svc.defaultId);
		if (v !== "") return v;
	} catch {}
	try {
		const cfg = svc.config;
		if (cfg !== void 0 && cfg !== null) {
			const raw = cfg.selectedDefault;
			const v = norm(typeof raw?.get === "function" ? raw.get() : raw);
			if (v !== "") return v;
			const d = norm(cfg.default);
			if (d !== "") return d;
		}
	} catch {}
	return "";
}
/** 归一化智能体预设列表。 */
function presetRows(raw, currentId) {
	let list = [];
	if (Array.isArray(raw)) list = raw;
	else if (raw !== null && typeof raw === "object") {
		const o = raw;
		if (Array.isArray(o.presets)) list = o.presets;
		else if (Array.isArray(o.items)) list = o.items;
	}
	const out = [];
	for (const item of list) {
		if (item === null || typeof item !== "object") continue;
		const r = item;
		const id = String(r.id ?? "");
		const name = String(r.name ?? "");
		if (id === "" && name === "") continue;
		out.push({
			id,
			name: name === "" ? id : name,
			description: String(r.description ?? ""),
			isDefault: r.isDefault === void 0 ? currentId !== "" && id === currentId : r.isDefault === true,
			broken: r.broken === void 0 || r.broken === null ? "" : String(r.broken)
		});
	}
	return out;
}
/** 归一化宿主定时任务记录。 */
function normalizeScheduleTask(raw) {
	const bag = raw !== null && typeof raw === "object" ? raw : {};
	const inner = bag.record !== null && typeof bag.record === "object" ? bag.record : bag;
	const target = inner.target !== null && typeof inner.target === "object" ? inner.target : {};
	const status = String(inner.status ?? "");
	return {
		id: String(inner.id ?? bag.id ?? ""),
		title: String(inner.title ?? inner.name ?? "未命名任务"),
		kind: String(inner.kind ?? inner.type ?? ""),
		when: String(inner.nextRunAt ?? inner.nextAt ?? inner.next ?? inner.scheduledAt ?? inner.when ?? ""),
		active: inner.active === true || status === "active" || status === "scheduled",
		status,
		sessionId: String(target.sessionId ?? inner.sessionId ?? "")
	};
}
const DEEP_CACHE_CAP = 128;
const DEEP_TTL_MS = 15e3;
/**
* 有界化（LRU 128）的会话深层投影缓存，用于读取 `ctl.list()` 摘要中不含的 `contextPressure`。
*/
function createDeepContextReader(service, logFile) {
	const deepCache = /* @__PURE__ */ new Map();
	return (sessionId) => {
		const now = Date.now();
		const hit = deepCache.get(sessionId);
		if (hit !== void 0 && now - hit.at < DEEP_TTL_MS) {
			deepCache.delete(sessionId);
			deepCache.set(sessionId, hit);
			return hit.value;
		}
		let value = null;
		try {
			const registry = service("sessionProjections");
			const sessions = service("sessions");
			const live = sessions !== null && typeof sessions.get === "function" ? sessions.get(sessionId) : void 0;
			if (registry !== null && live !== void 0 && typeof registry.snapshot === "function") value = contextOf(registry.snapshot(live)?.values ?? {});
		} catch (error) {
			record(logFile, `deep context failed: ${String(error)}`);
		}
		deepCache.delete(sessionId);
		deepCache.set(sessionId, {
			at: now,
			value
		});
		while (deepCache.size > DEEP_CACHE_CAP) {
			const oldest = deepCache.keys().next().value;
			if (oldest === void 0) break;
			deepCache.delete(oldest);
		}
		return value;
	};
}
/** 读取宿主归档与置顶标记并附加到会话列表。 */
function createWorkspaceFlags(service) {
	const readIdSet = (field) => {
		const reg = service("workspaceRegistry");
		if (reg === null) return null;
		try {
			const raw = reg[field];
			if (Array.isArray(raw)) return raw.map((x) => String(x)).filter(Boolean);
			if (raw && typeof raw.has === "function" && typeof raw.size === "number") return Array.from(raw, (x) => String(x)).filter(Boolean);
			return null;
		} catch {
			return null;
		}
	};
	const archivedIds = () => readIdSet("archivedSessionIds");
	const pinnedIds = () => readIdSet("pinnedSessionIds");
	const markArchived = (rows) => {
		const set = archivedIds();
		if (set === null) return rows;
		const lookup = new Set(set);
		return rows.map((row) => ({
			...row,
			archived: lookup.has(row.id)
		}));
	};
	const markPinned = (rows) => {
		const set = pinnedIds();
		if (set === null) return rows;
		const lookup = new Set(set);
		return rows.map((row) => ({
			...row,
			pinned: lookup.has(row.id)
		}));
	};
	return {
		archivedIds,
		pinnedIds,
		markArchived,
		markPinned
	};
}
//#endregion
//#region src/ask-bridge.ts
/**
* 宿主 `user-questions/request` 拦截桥接：
* 在 `phone` 模式下挂起提问交由手机作答；切回 `desktop` 或插件卸载时同步将所有挂起提问交还桌面。
*/
function createAskBridge(ctx, logFile) {
	const liveAsks = /* @__PURE__ */ new Map();
	let syntheticSeq = 0;
	try {
		ctx.on?.("user-questions/request", (request, next) => {
			const questions = normalizeQuestions(request?.questions);
			if (questions.length === 0) return next();
			if (answerMode() === "desktop") {
				record(logFile, "ask desktop-only, delegate");
				return next();
			}
			const agent = request?.agent;
			const sessionId = String(request?.sessionId ?? agent?.session?.id ?? "");
			const hostCallId = request?.wait?.callId === void 0 ? "" : String(request.wait.callId);
			const synthetic = hostCallId === "";
			let callId = hostCallId;
			if (synthetic) {
				syntheticSeq += 1;
				callId = `q-${sessionId.replace(/[^0-9A-Za-z]/g, "").slice(0, 8) || "anon"}-${Date.now().toString(36)}-${String(syntheticSeq)}`;
			}
			if (!synthetic && request?.wait?.timed === true) {
				record(logFile, `ask timed, delegate session=${sessionId} call=${callId}`);
				return next();
			}
			const askSessionId = sessionId === "" ? "*" : sessionId;
			const signal = request?.signal !== void 0 && typeof request.signal.addEventListener === "function" ? request.signal : void 0;
			record(logFile, `ask pending session=${sessionId} call=${callId} synthetic=${String(synthetic)} q=${String(questions.length)}`);
			return new Promise((resolve, reject) => {
				let done = false;
				const cleanup = () => {
					if (liveAsks.get(callId) === entry) liveAsks.delete(callId);
					if (signal !== void 0) signal.removeEventListener("abort", onAbort);
				};
				const handOver = (reason) => {
					if (done) return;
					done = true;
					cleanup();
					record(logFile, `${reason} session=${sessionId} call=${callId}`);
					Promise.resolve().then(() => next()).then(resolve, reject);
				};
				const onAbort = () => handOver("ask aborted");
				if (signal !== void 0) {
					if (signal.aborted) {
						record(logFile, `ask already aborted session=${sessionId} call=${callId}`);
						Promise.resolve().then(() => next()).then(resolve, reject);
						return;
					}
					signal.addEventListener("abort", onAbort, { once: true });
				}
				const entry = {
					sessionId: askSessionId,
					callId,
					questions,
					createdAt: Date.now(),
					synthetic,
					resolve: (answer) => {
						if (done) return;
						done = true;
						cleanup();
						record(logFile, `ask answered session=${sessionId} call=${callId}`);
						resolve(answer);
					},
					delegate: () => handOver("ask delegate")
				};
				liveAsks.set(callId, entry);
			});
		}, { prepend: true });
		record(logFile, "ask hook registered (prepend)");
	} catch (error) {
		record(logFile, `ask hook skipped: ${String(error)}`);
	}
	const liveAsking = () => {
		const out = /* @__PURE__ */ new Set();
		for (const ask of liveAsks.values()) if (ask.sessionId !== "*") out.add(ask.sessionId);
		return out;
	};
	const pendingAsks = (listed, sessionId) => {
		const proj = rowsOf(listed).find((item) => {
			const r = item;
			return String(r.sessionId ?? r.id ?? "") === sessionId;
		})?.projections;
		const fromProjection = asksOf(proj?.values);
		const seen = new Set(fromProjection.active.map((a) => a.callId));
		for (const ask of liveAsks.values()) {
			if (ask.sessionId !== sessionId && ask.sessionId !== "*") continue;
			if (seen.has(ask.callId)) continue;
			fromProjection.active.push({
				callId: ask.callId,
				questions: ask.questions,
				state: "open",
				synthetic: ask.synthetic
			});
		}
		return fromProjection;
	};
	const answer = (sessionId, callId, payload) => {
		const live = liveAsks.get(callId);
		if (live === void 0 || live.sessionId !== sessionId && live.sessionId !== "*") return { ok: false };
		const synthetic = live.synthetic;
		live.resolve(payload);
		return {
			ok: true,
			synthetic
		};
	};
	const delegateAll = (reason = "delegate-all") => {
		const items = [...liveAsks.values()];
		if (items.length > 0) record(logFile, `ask releasing ${String(items.length)} pending questions (${reason})`);
		for (const item of items) try {
			item.delegate();
		} catch {}
		return items.length;
	};
	return {
		liveAsks,
		liveAsking,
		pendingAsks,
		answer,
		delegateAll
	};
}
//#endregion
//#region src/backends/process-util.ts
/**
* 跨平台（重点适配 Windows + Electron）安全子进程工具：
* - 解析 npm `.cmd` shim 直接定位 `.exe` 或 `node.exe + .js`，彻底杜绝 `shell: true` 注入；
* - 强制真实 Node 可执行文件（避免 Electron 宿主下误用 Electron 二进制跑 CLI）；
* - Windows 进程树清理（`taskkill /PID <pid> /T /F`）防止孤儿进程残留；
* - 工作目录 `realpathSync` 校验。
*/
const cliCache = /* @__PURE__ */ new Map();
const versionCache = /* @__PURE__ */ new Map();
const VERSION_TTL_MS = 300 * 1e3;
let cachedNodeExe = null;
/** 解析系统真实 `node` 可执行文件（Electron 内 `process.execPath` 不是纯 Node）。 */
function resolveNodeExecutable() {
	if (cachedNodeExe !== null) return cachedNodeExe;
	if (!(typeof process.versions.electron === "string") && existsSync(process.execPath)) {
		cachedNodeExe = process.execPath;
		return cachedNodeExe;
	}
	const isWin = process.platform === "win32";
	const candidates = [];
	if (process.env.NODE_HOME) candidates.push(join(process.env.NODE_HOME, isWin ? "node.exe" : "bin/node"));
	if (isWin) candidates.push(join(process.env.ProgramFiles || "C:\\Program Files", "nodejs", "node.exe"), join(process.env["ProgramFiles(x86)"] || "C:\\Program Files (x86)", "nodejs", "node.exe"), join(process.env.LOCALAPPDATA || "", "Programs", "nodejs", "node.exe"));
	else candidates.push("/usr/local/bin/node", "/usr/bin/node", "/opt/homebrew/bin/node");
	const pathEnv = process.env.PATH || process.env.Path || "";
	for (const dir of pathEnv.split(delimiter)) {
		if (!dir) continue;
		candidates.push(join(dir, isWin ? "node.exe" : "node"));
	}
	for (const c of candidates) try {
		if (c && existsSync(c) && statSync(c).isFile()) {
			cachedNodeExe = c;
			return cachedNodeExe;
		}
	} catch {}
	cachedNodeExe = isWin ? "node.exe" : "node";
	return cachedNodeExe;
}
/** 解析 Windows npm `.cmd` shim 指向的真实 `.exe` 或 `.js` 入口，免走 `cmd.exe`。 */
function parseWindowsCmdShim(cmdFile) {
	try {
		const raw = readFileSync(cmdFile, "utf8");
		const dp0 = dirname(cmdFile);
		const exeMatch = /"%dp0%\\([^"]+\.exe)"/i.exec(raw);
		if (exeMatch) {
			const target = resolve(dp0, exeMatch[1]);
			if (existsSync(target)) return {
				command: target,
				prefixArgs: [],
				displayPath: target
			};
		}
		const jsMatch = /"%dp0%\\([^"]+\.(?:m?js|cjs))"/i.exec(raw);
		if (jsMatch) {
			const target = resolve(dp0, jsMatch[1]);
			if (existsSync(target)) return {
				command: resolveNodeExecutable(),
				prefixArgs: [target],
				displayPath: target
			};
		}
	} catch {}
	return null;
}
/** 按白名单名称解析本机 CLI（禁止传入含路径分隔符或特殊字符的任意命令）。 */
function resolveCliCommand(name, force = false) {
	if (!/^[a-z0-9._-]+$/i.test(name)) return null;
	if (!force && cliCache.has(name)) return cliCache.get(name) ?? null;
	const isWin = process.platform === "win32";
	const searchDirs = [];
	if (isWin && process.env.APPDATA) searchDirs.push(join(process.env.APPDATA, "npm"));
	if (isWin && process.env.LOCALAPPDATA) searchDirs.push(join(process.env.LOCALAPPDATA, "agy", "bin"));
	if (isWin && process.env.USERPROFILE) {
		searchDirs.push(join(process.env.USERPROFILE, ".local", "bin"));
		searchDirs.push(join(process.env.USERPROFILE, ".antigravity", "bin"));
	}
	const pathEnv = process.env.PATH || process.env.Path || "";
	for (const d of pathEnv.split(delimiter)) if (d && !searchDirs.includes(d)) searchDirs.push(d);
	for (const dir of searchDirs) {
		if (!dir) continue;
		if (isWin) {
			const directExe = join(dir, `${name}.exe`);
			if (existsSync(directExe)) {
				const res = {
					command: directExe,
					prefixArgs: [],
					displayPath: directExe
				};
				cliCache.set(name, res);
				return res;
			}
			const cmdShim = join(dir, `${name}.cmd`);
			if (existsSync(cmdShim)) {
				const parsed = parseWindowsCmdShim(cmdShim);
				if (parsed) {
					cliCache.set(name, parsed);
					return parsed;
				}
			}
		} else {
			const direct = join(dir, name);
			try {
				if (existsSync(direct) && statSync(direct).isFile()) {
					const res = {
						command: direct,
						prefixArgs: [],
						displayPath: direct
					};
					cliCache.set(name, res);
					return res;
				}
			} catch {}
		}
	}
	cliCache.set(name, null);
	return null;
}
/** 以非 shell 方式安全拉起已解析的白名单 CLI。 */
function spawnCli(cli, args, opts) {
	const fullArgs = [...cli.prefixArgs, ...args];
	const env = {
		...process.env,
		...opts?.env ?? {}
	};
	delete env.ELECTRON_RUN_AS_NODE;
	return spawn(cli.command, fullArgs, {
		cwd: opts?.cwd,
		env,
		shell: false,
		windowsHide: true,
		stdio: [
			"pipe",
			"pipe",
			"pipe"
		]
	});
}
/** 清理整个子进程树（Windows 用 `taskkill /T /F`，防止孙子进程残留占用文件锁）。 */
function killProcessTree$1(child) {
	if (!child || child.killed) return;
	const pid = child.pid;
	if (pid === void 0 || pid <= 0) {
		try {
			child.kill();
		} catch {}
		return;
	}
	if (process.platform === "win32") try {
		execFile("taskkill", [
			"/PID",
			String(pid),
			"/T",
			"/F"
		], {
			windowsHide: true,
			timeout: 4e3
		}, () => {});
	} catch {}
	try {
		child.kill("SIGTERM");
	} catch {}
}
/** 校验并规范化工作目录；若为空或不存在，回退到用户主目录或抛错。 */
function validateWorkingDir(cwd, fallbackHome = true) {
	const raw = typeof cwd === "string" ? cwd.trim() : "";
	if (raw === "") {
		if (fallbackHome) return homedir();
		throw new Error("工作目录不能为空");
	}
	if (raw.includes("\0")) throw new Error("非法工作目录路径");
	const real = realpathSync(raw);
	if (!statSync(real).isDirectory()) throw new Error("指定路径不是目录");
	return real;
}
/** 探测 CLI 版本号（带 5 分钟缓存，避免频繁拉起进程）。 */
async function probeCliVersion(cli, force = false) {
	const key = cli.displayPath;
	const cached = versionCache.get(key);
	if (!force && cached && Date.now() - cached.at < VERSION_TTL_MS) return cached.version;
	const version = await new Promise((resolveVer) => {
		let out = "";
		let settled = false;
		const finish = (v) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			resolveVer(v);
		};
		const child = spawnCli(cli, ["--version"]);
		const timer = setTimeout(() => {
			killProcessTree$1(child);
			finish("");
		}, 4500);
		child.stdout?.on("data", (d) => {
			out += d.toString("utf8");
		});
		child.stderr?.on("data", (d) => {
			out += d.toString("utf8");
		});
		child.on("error", () => finish(""));
		child.on("exit", () => {
			const firstLine = out.split(/\r?\n/).map((s) => s.trim()).find((s) => s.length > 0);
			finish(firstLine ? firstLine.slice(0, 64) : "");
		});
	});
	versionCache.set(key, {
		version,
		at: Date.now()
	});
	return version;
}
//#endregion
//#region src/backends/acp-client.ts
const DEFAULT_IDLE_MS = 3600 * 1e3;
var AcpClient = class {
	cli;
	extraArgs;
	cwd;
	hooks;
	child = null;
	stdoutBuf = "";
	stderrTail = [];
	nextId = 1;
	pending = /* @__PURE__ */ new Map();
	initPromise = null;
	initResult = null;
	lastActivity = Date.now();
	idleTimer = null;
	activeTurns = 0;
	constructor(cli, extraArgs, cwd, hooks = {}) {
		this.cli = cli;
		this.extraArgs = extraArgs;
		this.cwd = cwd;
		this.hooks = hooks;
	}
	get capabilities() {
		const caps = this.initResult?.agentCapabilities;
		return caps !== null && typeof caps === "object" ? caps : {};
	}
	ensureProcess() {
		if (this.child && !this.child.killed && this.child.exitCode === null) return;
		this.stdoutBuf = "";
		const child = spawnCli(this.cli, this.extraArgs, { cwd: this.cwd });
		this.child = child;
		this.lastActivity = Date.now();
		child.stdout?.on("data", (chunk) => {
			this.lastActivity = Date.now();
			this.stdoutBuf += chunk.toString("utf8");
			let nl;
			while ((nl = this.stdoutBuf.indexOf("\n")) >= 0) {
				const line = this.stdoutBuf.slice(0, nl).trim();
				this.stdoutBuf = this.stdoutBuf.slice(nl + 1);
				if (!line) continue;
				this.handleLine(line);
			}
		});
		child.stderr?.on("data", (chunk) => {
			const lines = chunk.toString("utf8").split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
			for (const l of lines) {
				this.stderrTail.push(l.slice(0, 240));
				if (this.stderrTail.length > 12) this.stderrTail.shift();
			}
		});
		child.on("exit", (code, signal) => {
			const tail = this.stderrTail.length > 0 ? ` :: ${this.stderrTail.slice(-2).join(" | ")}` : "";
			const reason = `ACP process exited (code=${String(code)}, signal=${String(signal)})${tail}`;
			this.failAllPending(reason);
			this.child = null;
			this.initPromise = null;
			this.initResult = null;
			this.hooks.onClose?.(reason);
		});
		child.on("error", (err) => {
			this.failAllPending(err.message);
			this.child = null;
			this.initPromise = null;
			this.initResult = null;
			this.hooks.onClose?.(err.message);
		});
		if (!this.idleTimer) {
			this.idleTimer = setInterval(() => {
				if (this.activeTurns === 0 && this.child && Date.now() - this.lastActivity > DEFAULT_IDLE_MS) this.dispose();
			}, 6e4);
			this.idleTimer.unref?.();
		}
	}
	failAllPending(reason) {
		for (const [, p] of this.pending) {
			clearTimeout(p.timer);
			p.reject(new Error(reason));
		}
		this.pending.clear();
	}
	writeFrame(frame) {
		this.ensureProcess();
		if (!this.child?.stdin || this.child.stdin.destroyed) throw new Error("ACP stdin is not writable");
		this.lastActivity = Date.now();
		this.child.stdin.write(JSON.stringify(frame) + "\n");
	}
	handleLine(line) {
		let msg;
		try {
			const parsed = JSON.parse(line);
			if (parsed === null || typeof parsed !== "object") return;
			msg = parsed;
		} catch {
			return;
		}
		if (msg.id !== void 0 && msg.method === void 0) {
			const id = Number(msg.id);
			const p = this.pending.get(id);
			if (!p) return;
			this.pending.delete(id);
			clearTimeout(p.timer);
			if (msg.error !== void 0 && msg.error !== null) {
				const errObj = msg.error;
				const detail = typeof errObj.message === "string" ? errObj.message : JSON.stringify(errObj);
				p.reject(new Error(detail));
			} else p.resolve(msg.result);
			return;
		}
		if (msg.id !== void 0 && typeof msg.method === "string") {
			const rpcId = msg.id;
			const params = msg.params !== null && typeof msg.params === "object" ? msg.params : {};
			if (msg.method === "session/request_permission") {
				const sid = typeof params.sessionId === "string" ? params.sessionId : "";
				const tc = params.toolCall !== null && typeof params.toolCall === "object" ? params.toolCall : {};
				const title = typeof tc.title === "string" && tc.title.trim() !== "" ? tc.title : typeof tc.kind === "string" ? `允许执行 ${tc.kind} 操作？` : "允许 Agent 执行此操作？";
				const rawOpts = Array.isArray(params.options) ? params.options : [];
				const options = [];
				for (const item of rawOpts) if (item && typeof item === "object") {
					const o = item;
					const oid = typeof o.optionId === "string" ? o.optionId : "";
					const name = typeof o.name === "string" ? o.name : oid;
					if (oid) options.push({
						optionId: oid,
						name,
						kind: typeof o.kind === "string" ? o.kind : void 0
					});
				}
				if (this.hooks.onPermissionRequest) this.hooks.onPermissionRequest({
					rpcId,
					sessionId: sid,
					title,
					toolCallId: typeof tc.toolCallId === "string" ? tc.toolCallId : void 0,
					rawInput: tc.rawInput,
					options
				});
				else this.replyPermission(rpcId, null);
				return;
			}
			try {
				this.writeFrame({
					jsonrpc: "2.0",
					id: rpcId,
					error: {
						code: -32601,
						message: `Unsupported client method: ${msg.method}`
					}
				});
			} catch {}
			return;
		}
		if (typeof msg.method === "string") {
			const params = msg.params !== null && typeof msg.params === "object" ? msg.params : {};
			if (msg.method === "session/update") {
				const sid = typeof params.sessionId === "string" ? params.sessionId : "";
				const update = params.update !== null && typeof params.update === "object" ? params.update : {};
				this.hooks.onSessionUpdate?.({
					sessionId: sid,
					update
				});
			}
		}
	}
	/** 回应 `session/request_permission`：传 `optionId` 选中，传 `null` 取消拒绝。 */
	replyPermission(rpcId, optionId) {
		const outcome = optionId !== null && optionId !== "" ? {
			outcome: "selected",
			optionId
		} : { outcome: "cancelled" };
		this.writeFrame({
			jsonrpc: "2.0",
			id: rpcId,
			result: { outcome }
		});
	}
	async initialize() {
		if (this.initResult && this.child && this.child.exitCode === null) return this.initResult;
		if (this.initPromise) return this.initPromise;
		this.initPromise = this.request("initialize", {
			protocolVersion: 1,
			clientCapabilities: {},
			clientInfo: {
				name: "agent-mobile",
				version: "3.0.0"
			}
		}, 2e4).then((res) => {
			this.initResult = res !== null && typeof res === "object" ? res : {};
			return this.initResult;
		}).catch((err) => {
			this.initPromise = null;
			throw err;
		});
		return this.initPromise;
	}
	async request(method, params, timeoutMs = 3e4) {
		this.ensureProcess();
		const id = this.nextId++;
		return await new Promise((resolveReq, rejectReq) => {
			const timer = setTimeout(() => {
				this.pending.delete(id);
				rejectReq(/* @__PURE__ */ new Error(`ACP request timeout: ${method}`));
			}, timeoutMs);
			this.pending.set(id, {
				resolve: resolveReq,
				reject: rejectReq,
				timer
			});
			try {
				this.writeFrame({
					jsonrpc: "2.0",
					id,
					method,
					params
				});
			} catch (err) {
				clearTimeout(timer);
				this.pending.delete(id);
				rejectReq(err instanceof Error ? err : new Error(String(err)));
			}
		});
	}
	notify(method, params) {
		this.writeFrame({
			jsonrpc: "2.0",
			method,
			params
		});
	}
	async listSessions(cwd) {
		await this.initialize();
		const params = {};
		if (cwd) params.cwd = cwd;
		try {
			const res = await this.request("session/list", params, 2e4);
			return (res && Array.isArray(res.sessions) ? res.sessions : []).filter((x) => x !== null && typeof x === "object");
		} catch (err) {
			const msg = err instanceof Error ? err.message.toLowerCase() : String(err).toLowerCase();
			if (msg.includes("not found") || msg.includes("unsupported") || msg.includes("-32601")) return [];
			throw err;
		}
	}
	async setModel(sessionId, modelId) {
		await this.initialize();
		try {
			await this.request("session/set_model", {
				sessionId,
				modelId
			}, 15e3);
			return true;
		} catch (err) {
			const msg = err instanceof Error ? err.message.toLowerCase() : String(err).toLowerCase();
			if (msg.includes("not found") || msg.includes("unsupported") || msg.includes("-32601")) return false;
			throw err;
		}
	}
	async newSession(cwd) {
		await this.initialize();
		const res = await this.request("session/new", {
			cwd,
			mcpServers: []
		}, 25e3);
		const sessionId = typeof res?.sessionId === "string" ? res.sessionId : "";
		if (!sessionId) throw new Error("ACP session/new 未返回 sessionId");
		return {
			sessionId,
			raw: res
		};
	}
	async loadSession(sessionId, cwd) {
		await this.initialize();
		const res = await this.request("session/load", {
			sessionId,
			cwd,
			mcpServers: []
		}, 45e3);
		return res !== null && typeof res === "object" ? res : {};
	}
	async resumeSession(sessionId, cwd) {
		await this.initialize();
		const res = await this.request("session/resume", {
			sessionId,
			cwd,
			mcpServers: []
		}, 3e4);
		return res !== null && typeof res === "object" ? res : {};
	}
	async prompt(sessionId, promptBlocks) {
		await this.initialize();
		this.activeTurns++;
		try {
			const res = await this.request("session/prompt", {
				sessionId,
				prompt: promptBlocks
			}, 1800 * 1e3);
			return res !== null && typeof res === "object" ? res : {};
		} finally {
			this.activeTurns = Math.max(0, this.activeTurns - 1);
		}
	}
	cancel(sessionId) {
		if (!this.child || this.child.exitCode !== null) return;
		try {
			this.notify("session/cancel", { sessionId });
		} catch {}
	}
	dispose() {
		if (this.idleTimer) {
			clearInterval(this.idleTimer);
			this.idleTimer = null;
		}
		this.failAllPending("ACP client disposed");
		killProcessTree$1(this.child);
		this.child = null;
		this.initPromise = null;
		this.initResult = null;
	}
};
//#endregion
//#region src/backends/types.ts
const EXTERNAL_BACKEND_IDS = [
	"codex",
	"claude",
	"opencode",
	"antigravity"
];
const PREFIX_RE = /^(codex|claude|opencode|antigravity):(.+)$/;
/** 解析带前缀的跨后端会话 ID；无已知前缀时默认归属 DSH，保证老路径 100% 兼容。 */
function parseSessionId(sid) {
	const m = PREFIX_RE.exec(sid);
	if (!m) return {
		backend: "dsh",
		rawId: sid
	};
	return {
		backend: m[1],
		rawId: m[2]
	};
}
/** 生成对外统一的会话 ID：DSH 保持原样，外部后端使用 `<backend>:<rawId>`。 */
function formatSessionId(backend, rawId) {
	if (backend === "dsh") return rawId;
	return `${backend}:${rawId}`;
}
const DSH_CAPABILITIES = {
	listExistingSessions: true,
	historyReplay: true,
	streamDelta: true,
	approval: true,
	abort: true,
	images: true,
	files: true,
	modelSwitch: true,
	reasoningEffort: true,
	planMode: true,
	goalMode: true,
	compact: true,
	fork: true,
	archivePin: true,
	webConsole: true
};
//#endregion
//#region src/backends/acp-backend.ts
/**
* 通用 ACP 会话后端基类：
* 统一实现基于 ACP（JSON-RPC 2.0 over stdio）的探测、会话列表、历史重放、流式增量、
* 工具审批、模型切换（当后端能力支持时）与安全中断。
*/
var AcpSessionBackend = class {
	client = null;
	resolvedSpec = null;
	sessions = /* @__PURE__ */ new Map();
	listeners = /* @__PURE__ */ new Map();
	replayingSessions = /* @__PURE__ */ new Set();
	inflightLoads = /* @__PURE__ */ new Map();
	loadChain = Promise.resolve();
	cachedModels = [];
	inflightList = null;
	inflightModels = null;
	autoInitForList() {
		return false;
	}
	async listViaCliFallback(_limit) {
		return [];
	}
	async listModelsViaCliFallback() {
		return [];
	}
	normalizeSessionCwd(raw) {
		const trimmed = raw.trim();
		if (!trimmed) return homedir();
		if (process.platform === "win32") {
			const m = /^\/([A-Za-z]:[\\/].*)$/.exec(trimmed);
			if (m) return m[1].replace(/\//g, "\\");
		}
		return trimmed;
	}
	ensureSpec(force = false) {
		if (!force && this.resolvedSpec) return this.resolvedSpec;
		this.resolvedSpec = this.resolveSpec(force);
		return this.resolvedSpec;
	}
	ensureClient() {
		if (this.client) return this.client;
		const spec = this.ensureSpec();
		if (!spec) throw new Error(this.missingCliMessage());
		this.client = new AcpClient(spec.cli, spec.args, homedir(), {
			onSessionUpdate: (ev) => this.handleUpdate(ev),
			onPermissionRequest: (req) => this.handlePermission(req),
			onClose: () => {
				for (const s of this.sessions.values()) {
					s.boundToProcess = false;
					if (s.running) {
						s.running = false;
						this.emit(s.rawId, {
							type: "done",
							running: false
						});
					}
					if (s.pendingAsk) {
						s.pendingAsk = null;
						this.emit(s.rawId, {
							type: "ask",
							asking: false,
							ask: null
						});
					}
				}
			}
		});
		return this.client;
	}
	defaultSessionTitle(isNew = false) {
		return isNew ? `${this.label} 新会话` : `${this.label} 会话`;
	}
	getOrCreateCache(rawId, cwd, title) {
		let s = this.sessions.get(rawId);
		if (!s) {
			s = {
				rawId,
				title: title && title.trim() !== "" ? title.trim() : this.defaultSessionTitle(false),
				cwd: cwd || homedir(),
				updatedAt: Date.now(),
				model: "",
				messages: [],
				loaded: false,
				boundToProcess: false,
				running: false,
				activeAssistant: null,
				pendingAsk: null
			};
			this.sessions.set(rawId, s);
		} else {
			if (cwd && cwd.trim() !== "") s.cwd = cwd;
			if (title && title.trim() !== "") s.title = title.trim();
		}
		return s;
	}
	emit(rawId, ev) {
		const set = this.listeners.get(rawId);
		if (!set) return;
		for (const fn of set) try {
			fn(ev);
		} catch {}
	}
	ensureActiveAssistant(s) {
		if (!s.activeAssistant) {
			const m = {
				seq: s.messages.length + 1,
				role: "assistant",
				text: "",
				thinking: "",
				tools: [],
				time: Date.now()
			};
			s.messages.push(m);
			s.activeAssistant = m;
		}
		return s.activeAssistant;
	}
	extractChunkText(update) {
		const content = update.content;
		if (typeof content === "string") return content;
		if (content && typeof content === "object") {
			const c = content;
			if (typeof c.text === "string") return c.text;
		}
		if (typeof update.text === "string") return update.text;
		return "";
	}
	captureModelsMetadata(cache, raw) {
		if (typeof raw.model === "string" && raw.model.trim() !== "") cache.model = raw.model.trim();
		if (raw.models && typeof raw.models === "object") {
			const m = raw.models;
			if (typeof m.currentModelId === "string" && m.currentModelId.trim() !== "") cache.model = m.currentModelId.trim();
			if (Array.isArray(m.availableModels)) {
				const parsed = m.availableModels.filter((x) => x !== null && typeof x === "object").map((x) => ({
					id: String(x.modelId ?? x.id ?? ""),
					name: String(x.name ?? x.modelId ?? x.id ?? ""),
					provider: this.id,
					description: typeof x.description === "string" ? x.description : void 0
				})).filter((x) => x.id !== "");
				if (parsed.length > 0) this.cachedModels = parsed;
			}
		}
	}
	handleUpdate(ev) {
		const sid = ev.sessionId || (this.replayingSessions.size === 1 ? [...this.replayingSessions][0] : "");
		if (!sid) return;
		const s = this.getOrCreateCache(sid);
		const u = ev.update;
		const kind = typeof u.sessionUpdate === "string" ? u.sessionUpdate : "";
		const isReplay = this.replayingSessions.has(sid);
		if (kind === "user_message_chunk") {
			const txt = this.extractChunkText(u);
			if (!txt) return;
			s.activeAssistant = null;
			const last = s.messages[s.messages.length - 1];
			if (isReplay && last && last.role === "user") last.text += txt;
			else s.messages.push({
				seq: s.messages.length + 1,
				role: "user",
				text: txt,
				time: Date.now()
			});
			return;
		}
		if (kind === "agent_thought_chunk") {
			const delta = this.extractChunkText(u);
			if (!delta) return;
			const a = this.ensureActiveAssistant(s);
			a.thinking = (a.thinking ?? "") + delta;
			s.updatedAt = Date.now();
			if (!isReplay) this.emit(sid, {
				type: "thinking",
				thinking: delta,
				running: true
			});
			return;
		}
		if (kind === "agent_message_chunk") {
			const delta = this.extractChunkText(u);
			if (!delta) return;
			const a = this.ensureActiveAssistant(s);
			a.text += delta;
			s.updatedAt = Date.now();
			if (!isReplay) this.emit(sid, {
				type: "delta",
				text: delta,
				running: true
			});
			return;
		}
		if (kind === "tool_call" || kind === "tool_call_update") {
			const a = this.ensureActiveAssistant(s);
			if (!a.tools) a.tools = [];
			const callId = typeof u.toolCallId === "string" ? u.toolCallId : `tool-${a.tools.length}`;
			const name = typeof u.title === "string" && u.title.trim() !== "" ? u.title : typeof u.kind === "string" ? u.kind : "tool";
			const rawStatus = typeof u.status === "string" ? u.status : "";
			const status = rawStatus === "failed" || rawStatus === "error" ? "error" : rawStatus === "completed" || rawStatus === "done" ? "done" : "running";
			let existing = a.tools.find((t) => t.id === callId);
			const inputStr = u.rawInput !== void 0 ? JSON.stringify(u.rawInput).slice(0, 200) : "";
			const outStr = u.rawOutput !== void 0 ? JSON.stringify(u.rawOutput).slice(0, 200) : "";
			const summary = inputStr || outStr || name;
			const traceStatus = status === "error" ? "err" : status === "done" ? "ok" : "run";
			if (!existing) {
				existing = {
					id: callId,
					name,
					summary,
					status: traceStatus
				};
				a.tools.push(existing);
			} else {
				if (name && name !== "tool") existing.name = name;
				if (summary) existing.summary = summary;
				existing.status = traceStatus;
			}
			if (!isReplay) this.emit(sid, {
				type: "tool",
				toolId: callId,
				toolName: existing.name,
				toolInput: inputStr,
				toolOutput: outStr,
				toolStatus: status,
				running: true
			});
		}
	}
	autoApprovePermissions() {
		return false;
	}
	pickAutoApproveOptionId(req) {
		const opts = req.options;
		const allowAlways = opts.find((o) => o.kind === "allow_always");
		if (allowAlways) return allowAlways.optionId;
		const allowOnce = opts.find((o) => o.kind === "allow_once");
		if (allowOnce) return allowOnce.optionId;
		const allowAny = opts.find((o) => typeof o.kind === "string" && o.kind.toLowerCase().includes("allow"));
		if (allowAny) return allowAny.optionId;
		const nonReject = opts.find((o) => !(typeof o.kind === "string" && o.kind.toLowerCase().includes("reject")) && !o.name.toLowerCase().includes("reject") && !o.name.toLowerCase().includes("deny") && !o.name.includes("拒绝"));
		if (nonReject) return nonReject.optionId;
		return opts[0]?.optionId ?? "allow";
	}
	handlePermission(req) {
		const sid = req.sessionId;
		if (!sid) {
			this.client?.replyPermission(req.rpcId, null);
			return;
		}
		if (this.autoApprovePermissions()) {
			const chosen = this.pickAutoApproveOptionId(req);
			this.client?.replyPermission(req.rpcId, chosen);
			return;
		}
		const s = this.getOrCreateCache(sid);
		const askId = `${this.id}-ask-${randomUUID().slice(0, 8)}`;
		const opts = req.options.map((o) => ({
			label: o.name,
			description: o.kind ?? "",
			value: o.optionId
		}));
		if (opts.length === 0) opts.push({
			label: "允许",
			value: "allow"
		}, {
			label: "拒绝",
			value: ""
		});
		const inputPreview = req.rawInput !== void 0 ? `\n${JSON.stringify(req.rawInput).slice(0, 260)}` : "";
		const ask = {
			askId,
			sessionId: formatSessionId(this.id, sid),
			createdAt: Date.now(),
			questions: [{
				header: `${this.label} 权限审批`,
				question: `${req.title}${inputPreview}`,
				multiSelect: false,
				options: opts
			}]
		};
		s.pendingAsk = {
			ask,
			rpcId: req.rpcId,
			optionIds: opts.map((o) => o.value ?? "")
		};
		this.emit(sid, {
			type: "ask",
			asking: true,
			ask
		});
	}
	async probe(force = false) {
		const spec = this.ensureSpec(force);
		if (!spec) return {
			installed: false,
			version: "",
			binaryPath: "",
			error: this.missingCliMessage()
		};
		return {
			installed: true,
			version: await probeCliVersion(spec.cli, force) || "installed",
			binaryPath: spec.cli.displayPath
		};
	}
	async fetchAcpSessions() {
		if (this.inflightList) return await this.inflightList;
		const p = (async () => {
			try {
				const client = this.client ?? (this.autoInitForList() && this.ensureSpec() ? this.ensureClient() : null);
				if (!client) return [];
				return await client.listSessions();
			} catch {
				return [];
			} finally {
				this.inflightList = null;
			}
		})();
		this.inflightList = p;
		return await p;
	}
	async listSessions(limit = 40) {
		let rawList = [];
		if (this.client) rawList = await this.fetchAcpSessions();
		if (rawList.length === 0) rawList = await this.listViaCliFallback(limit);
		if (rawList.length === 0 && !this.client && this.autoInitForList()) rawList = await this.fetchAcpSessions();
		const rows = [];
		const seen = /* @__PURE__ */ new Set();
		for (const item of rawList) {
			const rawId = typeof item.sessionId === "string" ? item.sessionId : typeof item.id === "string" ? item.id : "";
			if (!rawId || seen.has(rawId)) continue;
			seen.add(rawId);
			const title = typeof item.title === "string" && item.title.trim() !== "" ? item.title.trim() : this.defaultSessionTitle(false);
			const cwdRaw = typeof item.cwd === "string" ? item.cwd : typeof item.directory === "string" ? item.directory : homedir();
			const cwd = this.normalizeSessionCwd(cwdRaw);
			const updatedRaw = item.updatedAt ?? item.updated ?? item.created ?? Date.now();
			const updatedAt = typeof updatedRaw === "number" ? updatedRaw : typeof updatedRaw === "string" ? Date.parse(updatedRaw) || Date.now() : Date.now();
			const cache = this.getOrCreateCache(rawId, cwd, title);
			if (updatedAt > cache.updatedAt) cache.updatedAt = updatedAt;
			rows.push({
				id: formatSessionId(this.id, rawId),
				rawId,
				backend: this.id,
				title: cache.title,
				cwd: cache.cwd,
				updatedAt: cache.updatedAt,
				running: cache.running,
				asking: cache.pendingAsk !== null,
				model: cache.model ? {
					provider: this.id,
					model: cache.model,
					reasoningEffort: ""
				} : null
			});
		}
		for (const cache of this.sessions.values()) {
			if (seen.has(cache.rawId)) continue;
			rows.push({
				id: formatSessionId(this.id, cache.rawId),
				rawId: cache.rawId,
				backend: this.id,
				title: cache.title,
				cwd: cache.cwd,
				updatedAt: cache.updatedAt,
				running: cache.running,
				asking: cache.pendingAsk !== null,
				model: cache.model ? {
					provider: this.id,
					model: cache.model,
					reasoningEffort: ""
				} : null
			});
		}
		rows.sort((a, b) => b.updatedAt - a.updatedAt);
		return rows.slice(0, limit);
	}
	async loadHistoryOnce(rawId, cache) {
		if (cache.loaded || cache.running) return;
		const existing = this.inflightLoads.get(rawId);
		if (existing) {
			await existing;
			return;
		}
		const run = async () => {
			if (cache.loaded || cache.running) return;
			const client = this.ensureClient();
			const prevMessages = cache.messages.slice();
			cache.messages = [];
			cache.activeAssistant = null;
			this.replayingSessions.add(rawId);
			try {
				const res = await client.loadSession(rawId, cache.cwd);
				this.captureModelsMetadata(cache, res);
				cache.boundToProcess = true;
				if (cache.messages.length === 0 && prevMessages.length > 0) cache.messages = prevMessages;
				cache.loaded = true;
			} catch {
				if (cache.messages.length === 0 && prevMessages.length > 0) cache.messages = prevMessages;
				try {
					const res = await client.resumeSession(rawId, cache.cwd);
					this.captureModelsMetadata(cache, res);
					cache.boundToProcess = true;
				} catch {}
			} finally {
				this.replayingSessions.delete(rawId);
				cache.activeAssistant = null;
			}
		};
		let releaseQueue = () => {};
		const prevChain = this.loadChain;
		this.loadChain = new Promise((resolve) => {
			releaseQueue = resolve;
		});
		let task;
		task = (async () => {
			await prevChain;
			try {
				await run();
			} finally {
				releaseQueue();
				if (this.inflightLoads.get(rawId) === task) this.inflightLoads.delete(rawId);
			}
		})();
		this.inflightLoads.set(rawId, task);
		await task;
	}
	async ensureSessionBound(rawId, cache) {
		if (cache.boundToProcess) return;
		const client = this.ensureClient();
		if (!cache.loaded) {
			await this.loadHistoryOnce(rawId, cache);
			if (cache.boundToProcess) return;
		}
		try {
			const res = await client.resumeSession(rawId, cache.cwd);
			this.captureModelsMetadata(cache, res);
			cache.boundToProcess = true;
			return;
		} catch {}
		const prevMessages = cache.messages.slice();
		this.replayingSessions.add(rawId);
		try {
			cache.messages = [];
			cache.activeAssistant = null;
			const res = await client.loadSession(rawId, cache.cwd);
			this.captureModelsMetadata(cache, res);
			cache.boundToProcess = true;
			if (cache.messages.length === 0 && prevMessages.length > 0) cache.messages = prevMessages;
			if (cache.messages.length > 0) cache.loaded = true;
		} finally {
			this.replayingSessions.delete(rawId);
			cache.activeAssistant = null;
		}
	}
	async getMessages(rawId, opts) {
		const cache = this.getOrCreateCache(rawId);
		const isLightPreviewProbe = opts?.compact === true && opts?.limit === 1;
		if (!cache.loaded && !cache.running && !isLightPreviewProbe) await this.loadHistoryOnce(rawId, cache);
		const all = cache.messages;
		const lim = opts?.limit && opts.limit > 0 ? opts.limit : all.length;
		const start = Math.max(0, all.length - lim);
		return {
			messages: all.slice(start),
			total: all.length,
			hasMore: start > 0,
			model: cache.model || void 0,
			cwd: cache.cwd,
			running: cache.running,
			asking: cache.pendingAsk !== null
		};
	}
	async createSession(cwd, opts) {
		const safeCwd = validateWorkingDir(cwd, true);
		const client = this.ensureClient();
		const { sessionId, raw } = await client.newSession(safeCwd);
		const cache = this.getOrCreateCache(sessionId, safeCwd, opts?.title || this.defaultSessionTitle(true));
		cache.loaded = true;
		cache.boundToProcess = true;
		cache.updatedAt = Date.now();
		this.captureModelsMetadata(cache, raw);
		if (opts?.model && opts.model.trim() !== "" && this.capabilities.modelSwitch) try {
			if (await client.setModel(sessionId, opts.model.trim())) cache.model = opts.model.trim();
		} catch {}
		return {
			id: formatSessionId(this.id, sessionId),
			rawId: sessionId,
			backend: this.id,
			title: cache.title,
			cwd: cache.cwd,
			updatedAt: cache.updatedAt,
			running: false,
			asking: false,
			model: cache.model ? {
				provider: this.id,
				model: cache.model,
				reasoningEffort: ""
			} : null
		};
	}
	async sendMessage(rawId, text, opts) {
		const cache = this.getOrCreateCache(rawId, opts?.cwd);
		if (cache.running) throw new Error(`${this.label} 当前会话正在运行，请等待完成或先中断`);
		const client = this.ensureClient();
		await this.ensureSessionBound(rawId, cache);
		if (opts?.model && opts.model.trim() !== "" && opts.model.trim() !== cache.model && this.capabilities.modelSwitch) try {
			if (await client.setModel(rawId, opts.model.trim())) cache.model = opts.model.trim();
		} catch {}
		const promptBlocks = [];
		if (text.trim() !== "") promptBlocks.push({
			type: "text",
			text
		});
		if (opts?.images && opts.images.length > 0) for (const img of opts.images) promptBlocks.push({
			type: "image",
			mimeType: img.mime || "image/jpeg",
			data: img.data
		});
		if (promptBlocks.length === 0) throw new Error("消息内容不能为空");
		const runId = `${this.id}-${Date.now()}`;
		cache.messages.push({
			seq: cache.messages.length + 1,
			role: "user",
			text,
			time: Date.now()
		});
		if (cache.title === this.defaultSessionTitle(true) || cache.title === this.defaultSessionTitle(false)) cache.title = text.trim().slice(0, 36) || cache.title;
		cache.activeAssistant = null;
		cache.running = true;
		cache.updatedAt = Date.now();
		this.emit(rawId, {
			type: "status",
			running: true
		});
		const runPrompt = async () => {
			try {
				await client.prompt(rawId, promptBlocks);
			} catch (firstErr) {
				const msg1 = firstErr instanceof Error ? firstErr.message : String(firstErr);
				if (!(!cache.activeAssistant && /not\s+found|not\s+loaded|unknown\s+session|exited|closed|stdin/i.test(msg1))) throw firstErr;
				cache.boundToProcess = false;
				await this.ensureSessionBound(rawId, cache);
				await this.ensureClient().prompt(rawId, promptBlocks);
			}
		};
		runPrompt().then(() => {
			cache.running = false;
			cache.activeAssistant = null;
			cache.updatedAt = Date.now();
			this.emit(rawId, {
				type: "done",
				running: false
			});
		}).catch((err) => {
			cache.running = false;
			const msg = err instanceof Error ? err.message : String(err);
			const a = this.ensureActiveAssistant(cache);
			const notice = `[${this.label} 执行中断] ${msg}`;
			a.text = a.text.trim() !== "" ? `${a.text}\n\n${notice}` : notice;
			cache.activeAssistant = null;
			cache.updatedAt = Date.now();
			this.emit(rawId, {
				type: "error",
				error: msg,
				running: false
			});
			this.emit(rawId, {
				type: "done",
				running: false
			});
		});
		return {
			ok: true,
			runId,
			status: "started"
		};
	}
	async abort(rawId) {
		const cache = this.sessions.get(rawId);
		if (this.client) this.client.cancel(rawId);
		if (cache) {
			if (cache.pendingAsk) {
				this.client?.replyPermission(cache.pendingAsk.rpcId, null);
				cache.pendingAsk = null;
				this.emit(rawId, {
					type: "ask",
					asking: false,
					ask: null
				});
			}
			cache.running = false;
			cache.activeAssistant = null;
			this.emit(rawId, {
				type: "done",
				running: false
			});
		}
		return true;
	}
	subscribe(rawId, listener) {
		let set = this.listeners.get(rawId);
		if (!set) {
			set = /* @__PURE__ */ new Set();
			this.listeners.set(rawId, set);
		}
		set.add(listener);
		return () => {
			const s = this.listeners.get(rawId);
			if (!s) return;
			s.delete(listener);
			if (s.size === 0) this.listeners.delete(rawId);
		};
	}
	getAsk(rawId) {
		return { pending: this.sessions.get(rawId)?.pendingAsk?.ask ?? null };
	}
	async answerAsk(rawId, askId, answers) {
		const s = this.sessions.get(rawId);
		if (!s?.pendingAsk) return false;
		if (askId && s.pendingAsk.ask.askId !== askId) return false;
		const pending = s.pendingAsk;
		s.pendingAsk = null;
		const chosenLabel = Object.values(answers)[0] ?? "";
		const q = pending.ask.questions[0];
		let chosenOptionId = null;
		if (q) {
			const idx = q.options.findIndex((o) => o.label === chosenLabel || o.value === chosenLabel);
			if (idx >= 0) {
				const oid = pending.optionIds[idx];
				chosenOptionId = oid && oid.trim() !== "" ? oid : null;
			}
		}
		this.client?.replyPermission(pending.rpcId, chosenOptionId);
		this.emit(rawId, {
			type: "ask",
			asking: false,
			ask: null
		});
		return true;
	}
	async listModels() {
		if (this.cachedModels.length > 0) return this.cachedModels;
		if (this.inflightModels) return await this.inflightModels;
		const p = (async () => {
			try {
				const list = await this.listModelsViaCliFallback();
				if (list.length > 0) this.cachedModels = list;
				return this.cachedModels;
			} catch {
				return this.cachedModels;
			} finally {
				this.inflightModels = null;
			}
		})();
		this.inflightModels = p;
		return await p;
	}
	async setModel(rawId, model) {
		if (!this.capabilities.modelSwitch) return false;
		const client = this.ensureClient();
		const cache = this.getOrCreateCache(rawId);
		if (!cache.loaded) await this.getMessages(rawId, { limit: 1 });
		const ok = await client.setModel(rawId, model);
		if (ok) cache.model = model;
		return ok;
	}
	isRunning(rawId) {
		return this.sessions.get(rawId)?.running === true;
	}
	dispose() {
		this.client?.dispose();
		this.client = null;
		this.inflightList = null;
		this.inflightModels = null;
		this.cachedModels = [];
		this.sessions.clear();
		this.listeners.clear();
	}
};
//#endregion
//#region src/backends/antigravity-backend.ts
/**
* Antigravity CLI 后端适配器（基于通用 ACP 引擎驱动 `agy acp` / `agy_acp_server`）：
* - 按官方白名单顺序探测 `agy` -> `antigravity` -> `agy_acp_server` -> `antigravity-acp`；
* - 通过 ACP stdio 协议完成会话新建、历史重放、流式增量输出、权限审批与模型切换；
* - 无私有磁盘结构强依赖，完全遵循 ACP v1 规范。
*/
const ANTIGRAVITY_CAPABILITIES = {
	listExistingSessions: true,
	historyReplay: true,
	streamDelta: true,
	approval: true,
	abort: true,
	images: true,
	files: false,
	modelSwitch: true,
	reasoningEffort: false,
	planMode: false,
	goalMode: false,
	compact: false,
	fork: false,
	archivePin: false,
	webConsole: false
};
var AntigravityBackend = class extends AcpSessionBackend {
	id = "antigravity";
	label = "Antigravity";
	capabilities = ANTIGRAVITY_CAPABILITIES;
	autoApprovePermissions() {
		return true;
	}
	autoInitForList() {
		return true;
	}
	async listModelsViaCliFallback() {
		const spec = this.ensureSpec();
		if (!spec || spec.args[0] !== "acp") return [];
		return await new Promise((resolveModels) => {
			let out = "";
			let done = false;
			const finish = (items) => {
				if (done) return;
				done = true;
				clearTimeout(timer);
				resolveModels(items);
			};
			const child = spawnCli(spec.cli, ["models"]);
			const timer = setTimeout(() => {
				killProcessTree$1(child);
				finish([]);
			}, 12e3);
			child.stdout?.on("data", (d) => {
				out += d.toString("utf8");
			});
			child.on("error", () => finish([]));
			child.on("exit", () => {
				const parsed = [];
				const seen = /* @__PURE__ */ new Set();
				for (const rawLine of out.split(/\r?\n/)) {
					const line = rawLine.trim();
					if (!line) continue;
					const tabIdx = line.indexOf("	");
					let id = "";
					let name = "";
					if (tabIdx > 0) {
						id = line.slice(0, tabIdx).trim();
						name = line.slice(tabIdx + 1).trim();
					} else if (/^[a-z0-9][a-z0-9._-]{2,}$/i.test(line)) {
						id = line;
						name = line;
					} else continue;
					if (!id || seen.has(id)) continue;
					seen.add(id);
					parsed.push({
						id,
						name: name || id,
						provider: this.id
					});
				}
				finish(parsed);
			});
		});
	}
	resolveSpec(force = false) {
		const agy = resolveCliCommand("agy", force);
		if (agy) return {
			cli: agy,
			args: ["acp", "--dangerously-skip-permissions"]
		};
		const antigravity = resolveCliCommand("antigravity", force);
		if (antigravity) return {
			cli: antigravity,
			args: ["acp", "--dangerously-skip-permissions"]
		};
		const server = resolveCliCommand("agy_acp_server", force);
		if (server) return {
			cli: server,
			args: ["--dangerously-skip-permissions"]
		};
		const hyphenServer = resolveCliCommand("antigravity-acp", force);
		if (hyphenServer) return {
			cli: hyphenServer,
			args: ["--dangerously-skip-permissions"]
		};
		return null;
	}
	missingCliMessage() {
		return "未检测到 agy 命令（安装 Antigravity CLI 并执行 agy acp --login 后可用）";
	}
};
//#endregion
//#region src/backends/claude-backend.ts
const CLAUDE_CAPABILITIES = {
	listExistingSessions: true,
	historyReplay: true,
	streamDelta: true,
	approval: false,
	abort: true,
	images: false,
	files: false,
	modelSwitch: true,
	reasoningEffort: false,
	planMode: false,
	goalMode: false,
	compact: false,
	fork: false,
	archivePin: false,
	webConsole: false
};
const DEFAULT_CLAUDE_MODELS = [
	{
		id: "sonnet",
		name: "Claude Sonnet (默认)",
		provider: "claude"
	},
	{
		id: "opus",
		name: "Claude Opus",
		provider: "claude"
	},
	{
		id: "haiku",
		name: "Claude Haiku",
		provider: "claude"
	}
];
function claudeProjectsDir() {
	return join(homedir(), ".claude", "projects");
}
function decodeProjectDirName(dirName) {
	const winDrive = /^([A-Za-z])--(.*)$/.exec(dirName);
	if (winDrive) return `${winDrive[1]}:\\${winDrive[2].replace(/-/g, "\\")}`;
	return dirName;
}
function extractUserText(content) {
	if (typeof content === "string") return content;
	if (!Array.isArray(content)) return "";
	const out = [];
	for (const item of content) if (typeof item === "string") out.push(item);
	else if (item && typeof item === "object") {
		const o = item;
		if (o.type === "text" && typeof o.text === "string") out.push(o.text);
	}
	return out.join("\n");
}
function parseClaudeJsonl(filePath, fullHistory) {
	const sessionId = basename(filePath, ".jsonl");
	let title = "";
	let cwd = "";
	let model = "";
	let preview = "";
	const messages = [];
	const toolIndex = /* @__PURE__ */ new Map();
	let raw = "";
	try {
		raw = readFileSync(filePath, "utf8");
	} catch {
		return {
			sessionId,
			title: "Claude 会话",
			cwd: homedir(),
			model: "",
			preview: "",
			messages: []
		};
	}
	const lines = raw.split(/\r?\n/);
	let seq = 0;
	for (const line of lines) {
		if (!line.trim()) continue;
		let o;
		try {
			const p = JSON.parse(line);
			if (!p || typeof p !== "object") continue;
			o = p;
		} catch {
			continue;
		}
		if (typeof o.cwd === "string" && o.cwd.trim() !== "") cwd = o.cwd.trim();
		const typ = typeof o.type === "string" ? o.type : "";
		if (typ === "ai-title" && typeof o.aiTitle === "string" && o.aiTitle.trim() !== "") {
			title = o.aiTitle.trim();
			continue;
		}
		if (typ === "last-prompt" && typeof o.lastPrompt === "string" && !title) {
			title = o.lastPrompt.replace(/\s+/g, " ").trim().slice(0, 48);
			continue;
		}
		const msgObj = o.message && typeof o.message === "object" ? o.message : null;
		if (!msgObj) continue;
		const tMs = typeof o.timestamp === "string" ? Date.parse(o.timestamp) || Date.now() : Date.now();
		if (typ === "user") {
			const content = msgObj.content;
			if (Array.isArray(content)) {
				let onlyToolResults = true;
				for (const block of content) if (block && typeof block === "object") {
					const b = block;
					if (b.type === "tool_result") {
						const tid = typeof b.tool_use_id === "string" ? b.tool_use_id : "";
						const tc = tid ? toolIndex.get(tid) : void 0;
						if (tc) tc.status = b.is_error === true ? "err" : "ok";
					} else if (b.type === "text" && typeof b.text === "string" && b.text.trim() !== "") onlyToolResults = false;
				}
				if (onlyToolResults) continue;
			}
			const txt = extractUserText(content).trim();
			if (!txt) continue;
			if (!title) title = txt.replace(/\s+/g, " ").slice(0, 48);
			if (!preview) preview = txt.replace(/\s+/g, " ").slice(0, 120);
			if (fullHistory) messages.push({
				seq: ++seq,
				role: "user",
				text: txt,
				time: tMs
			});
			continue;
		}
		if (typ === "assistant") {
			if (typeof msgObj.model === "string" && msgObj.model.trim() !== "") model = msgObj.model.trim();
			const content = msgObj.content;
			let text = "";
			let thinking = "";
			const tools = [];
			if (typeof content === "string") text = content;
			else if (Array.isArray(content)) for (const block of content) {
				if (!block || typeof block !== "object") continue;
				const b = block;
				if (b.type === "thinking" && typeof b.thinking === "string") thinking = thinking ? `${thinking}\n${b.thinking}` : b.thinking;
				else if (b.type === "text" && typeof b.text === "string") text = text ? `${text}\n${b.text}` : b.text;
				else if (b.type === "tool_use") {
					const tid = typeof b.id === "string" ? b.id : `cl-t-${seq}`;
					const name = typeof b.name === "string" ? b.name : "tool";
					const tc = {
						id: tid,
						name,
						summary: b.input !== void 0 ? JSON.stringify(b.input).slice(0, 200) : name,
						status: "ok"
					};
					tools.push(tc);
					toolIndex.set(tid, tc);
				}
			}
			if (text.trim() !== "") preview = text.replace(/\s+/g, " ").trim().slice(0, 120);
			if (fullHistory && (text.trim() !== "" || thinking.trim() !== "" || tools.length > 0)) {
				const prev = messages[messages.length - 1];
				if (prev && prev.role === "assistant" && !text && !thinking && tools.length > 0) prev.tools = [...prev.tools ?? [], ...tools];
				else messages.push({
					seq: ++seq,
					role: "assistant",
					text,
					thinking,
					tools,
					time: tMs
				});
			}
		}
	}
	return {
		sessionId,
		title: title || "Claude 会话",
		cwd,
		model,
		preview,
		messages
	};
}
var ClaudeBackend = class {
	id = "claude";
	label = "Claude Code";
	capabilities = CLAUDE_CAPABILITIES;
	cli = null;
	runtime = /* @__PURE__ */ new Map();
	listeners = /* @__PURE__ */ new Map();
	ensureCli(force = false) {
		if (!force && this.cli) return this.cli;
		this.cli = resolveCliCommand("claude", force);
		return this.cli;
	}
	emit(rawId, ev) {
		const set = this.listeners.get(rawId);
		if (!set) return;
		for (const fn of set) try {
			fn(ev);
		} catch {}
	}
	scanSessionFiles() {
		const root = claudeProjectsDir();
		if (!existsSync(root)) return [];
		const found = [];
		try {
			for (const projDir of readdirSync(root)) {
				const fullDir = join(root, projDir);
				let st;
				try {
					st = statSync(fullDir);
				} catch {
					continue;
				}
				if (!st.isDirectory()) continue;
				for (const name of readdirSync(fullDir)) {
					if (!name.endsWith(".jsonl")) continue;
					const fp = join(fullDir, name);
					try {
						const fst = statSync(fp);
						if (!fst.isFile() || fst.size === 0) continue;
						found.push({
							rawId: basename(name, ".jsonl"),
							filePath: fp,
							mtimeMs: fst.mtimeMs,
							dirName: projDir
						});
					} catch {}
				}
			}
		} catch {
			return [];
		}
		found.sort((a, b) => b.mtimeMs - a.mtimeMs);
		return found;
	}
	locateSessionFile(rawId) {
		const cached = this.runtime.get(rawId);
		if (cached?.filePath && existsSync(cached.filePath)) return cached.filePath;
		return this.scanSessionFiles().find((f) => f.rawId === rawId)?.filePath ?? "";
	}
	async probe(force = false) {
		const cli = this.ensureCli(force);
		if (!cli) return {
			installed: false,
			version: "",
			binaryPath: "",
			error: "未检测到 claude 命令"
		};
		return {
			installed: true,
			version: await probeCliVersion(cli, force) || "installed",
			binaryPath: cli.displayPath
		};
	}
	async listSessions(limit = 40) {
		const files = this.scanSessionFiles().slice(0, Math.max(limit, 50));
		const rows = [];
		const seen = /* @__PURE__ */ new Set();
		for (const f of files) {
			seen.add(f.rawId);
			const parsed = parseClaudeJsonl(f.filePath, false);
			const fallbackCwd = decodeProjectDirName(f.dirName);
			const cwd = parsed.cwd || (existsSync(fallbackCwd) ? fallbackCwd : homedir());
			let rt = this.runtime.get(f.rawId);
			if (!rt) {
				rt = {
					rawId: f.rawId,
					filePath: f.filePath,
					cwd,
					title: parsed.title,
					model: parsed.model,
					updatedAt: Math.round(f.mtimeMs),
					isNew: false,
					running: false,
					activeChild: null,
					localMessages: []
				};
				this.runtime.set(f.rawId, rt);
			} else {
				rt.filePath = f.filePath;
				rt.isNew = false;
				if (parsed.title && parsed.title !== "Claude 会话") rt.title = parsed.title;
				if (parsed.model) rt.model = parsed.model;
				if (cwd) rt.cwd = cwd;
				if (f.mtimeMs > rt.updatedAt) rt.updatedAt = Math.round(f.mtimeMs);
			}
			rows.push({
				id: formatSessionId("claude", f.rawId),
				rawId: f.rawId,
				backend: "claude",
				title: rt.title,
				cwd: rt.cwd,
				updatedAt: rt.updatedAt,
				running: rt.running,
				asking: false,
				preview: parsed.preview,
				model: rt.model ? {
					provider: "claude",
					model: rt.model,
					reasoningEffort: ""
				} : null
			});
		}
		for (const rt of this.runtime.values()) {
			if (seen.has(rt.rawId)) continue;
			rows.push({
				id: formatSessionId("claude", rt.rawId),
				rawId: rt.rawId,
				backend: "claude",
				title: rt.title,
				cwd: rt.cwd,
				updatedAt: rt.updatedAt,
				running: rt.running,
				asking: false,
				model: rt.model ? {
					provider: "claude",
					model: rt.model,
					reasoningEffort: ""
				} : null
			});
		}
		rows.sort((a, b) => b.updatedAt - a.updatedAt);
		return rows.slice(0, limit);
	}
	async getMessages(rawId, opts) {
		const rt = this.runtime.get(rawId);
		const fp = this.locateSessionFile(rawId);
		let all = [];
		let model = rt?.model ?? "";
		let cwd = rt?.cwd ?? homedir();
		if (fp) {
			const parsed = parseClaudeJsonl(fp, true);
			all = parsed.messages;
			if (parsed.model) model = parsed.model;
			if (parsed.cwd) cwd = parsed.cwd;
			if (rt) {
				rt.filePath = fp;
				rt.isNew = false;
				if (model) rt.model = model;
				if (cwd) rt.cwd = cwd;
			}
		} else if (rt && rt.localMessages.length > 0) all = [...rt.localMessages];
		const lim = opts?.limit && opts.limit > 0 ? opts.limit : all.length;
		const start = Math.max(0, all.length - lim);
		return {
			messages: all.slice(start),
			total: all.length,
			hasMore: start > 0,
			model: model || void 0,
			cwd,
			running: rt?.running === true,
			asking: false
		};
	}
	async createSession(cwd, opts) {
		const safeCwd = validateWorkingDir(cwd, true);
		const rawId = randomUUID();
		const rt = {
			rawId,
			filePath: "",
			cwd: safeCwd,
			title: opts?.title?.trim() || "Claude 新会话",
			model: opts?.model?.trim() || "",
			updatedAt: Date.now(),
			isNew: true,
			running: false,
			activeChild: null,
			localMessages: []
		};
		this.runtime.set(rawId, rt);
		return {
			id: formatSessionId("claude", rawId),
			rawId,
			backend: "claude",
			title: rt.title,
			cwd: rt.cwd,
			updatedAt: rt.updatedAt,
			running: false,
			asking: false,
			model: rt.model ? {
				provider: "claude",
				model: rt.model,
				reasoningEffort: ""
			} : null
		};
	}
	async sendMessage(rawId, text, opts) {
		const cli = this.ensureCli();
		if (!cli) throw new Error("本机未检测到 claude 命令");
		const trimmed = text.trim();
		if (!trimmed) throw new Error("消息内容不能为空");
		let rt = this.runtime.get(rawId);
		if (!rt) {
			const fp = this.locateSessionFile(rawId);
			const parsed = fp ? parseClaudeJsonl(fp, false) : null;
			rt = {
				rawId,
				filePath: fp,
				cwd: opts?.cwd || parsed?.cwd || homedir(),
				title: parsed?.title || trimmed.slice(0, 36),
				model: opts?.model || parsed?.model || "",
				updatedAt: Date.now(),
				isNew: !fp,
				running: false,
				activeChild: null,
				localMessages: []
			};
			this.runtime.set(rawId, rt);
		}
		if (rt.running) throw new Error("Claude Code 当前会话正在运行，请等待完成或先中断");
		const safeCwd = validateWorkingDir(opts?.cwd || rt.cwd, true);
		rt.cwd = safeCwd;
		if (opts?.model && opts.model.trim() !== "") rt.model = opts.model.trim();
		if (rt.title === "Claude 新会话" || rt.title === "Claude 会话") rt.title = trimmed.slice(0, 36);
		const args = [
			"-p",
			"--output-format",
			"stream-json",
			"--verbose",
			"--include-partial-messages"
		];
		if (rt.isNew) args.push("--session-id", rawId);
		else args.push("--resume", rawId);
		if (rt.model) args.push("--model", rt.model);
		args.push(trimmed);
		rt.localMessages.push({
			seq: rt.localMessages.length + 1,
			role: "user",
			text: trimmed,
			time: Date.now()
		});
		const child = spawnCli(cli, args, { cwd: safeCwd });
		rt.activeChild = child;
		rt.running = true;
		rt.updatedAt = Date.now();
		this.emit(rawId, {
			type: "status",
			running: true
		});
		let stdoutBuf = "";
		let stderrText = "";
		let accText = "";
		let accThinking = "";
		let sawStreamDeltas = false;
		const handleJsonLine = (line) => {
			let ev;
			try {
				const p = JSON.parse(line);
				if (!p || typeof p !== "object") return;
				ev = p;
			} catch {
				return;
			}
			if (ev.type === "stream_event" && ev.event && typeof ev.event === "object") {
				const inner = ev.event;
				if (inner.type === "content_block_delta" && inner.delta && typeof inner.delta === "object") {
					const d = inner.delta;
					if (d.type === "text_delta" && typeof d.text === "string" && d.text !== "") {
						sawStreamDeltas = true;
						accText += d.text;
						rt.updatedAt = Date.now();
						this.emit(rawId, {
							type: "delta",
							text: d.text,
							running: true
						});
					} else if (d.type === "thinking_delta" && typeof d.thinking === "string" && d.thinking !== "") {
						sawStreamDeltas = true;
						accThinking += d.thinking;
						rt.updatedAt = Date.now();
						this.emit(rawId, {
							type: "thinking",
							thinking: d.thinking,
							running: true
						});
					}
				}
				return;
			}
			if (ev.type === "assistant" && ev.message && typeof ev.message === "object") {
				const m = ev.message;
				if (typeof m.model === "string" && m.model) rt.model = m.model;
				const content = Array.isArray(m.content) ? m.content : [];
				for (const block of content) {
					if (!block || typeof block !== "object") continue;
					const b = block;
					if (b.type === "text" && typeof b.text === "string" && b.text && !sawStreamDeltas) {
						const diff = b.text.startsWith(accText) ? b.text.slice(accText.length) : b.text;
						if (diff) {
							accText += diff;
							this.emit(rawId, {
								type: "delta",
								text: diff,
								running: true
							});
						}
					} else if (b.type === "thinking" && typeof b.thinking === "string" && b.thinking && !sawStreamDeltas) {
						const diff = b.thinking.startsWith(accThinking) ? b.thinking.slice(accThinking.length) : b.thinking;
						if (diff) {
							accThinking += diff;
							this.emit(rawId, {
								type: "thinking",
								thinking: diff,
								running: true
							});
						}
					} else if (b.type === "tool_use") this.emit(rawId, {
						type: "tool",
						toolId: typeof b.id === "string" ? b.id : void 0,
						toolName: typeof b.name === "string" ? b.name : "tool",
						toolInput: b.input !== void 0 ? JSON.stringify(b.input).slice(0, 500) : "",
						toolStatus: "running",
						running: true
					});
				}
				return;
			}
			if (ev.type === "result") {
				if (ev.is_error === true) {
					const errStr = typeof ev.result === "string" ? ev.result : "Claude Code 执行失败";
					this.emit(rawId, {
						type: "error",
						error: errStr,
						running: false
					});
				} else if (typeof ev.result === "string" && ev.result !== "" && accText === "") {
					accText = ev.result;
					this.emit(rawId, {
						type: "delta",
						text: ev.result,
						running: true
					});
				}
			}
		};
		child.stdout?.on("data", (chunk) => {
			stdoutBuf += chunk.toString("utf8");
			let nl;
			while ((nl = stdoutBuf.indexOf("\n")) >= 0) {
				const line = stdoutBuf.slice(0, nl).trim();
				stdoutBuf = stdoutBuf.slice(nl + 1);
				if (line) handleJsonLine(line);
			}
		});
		child.stderr?.on("data", (chunk) => {
			stderrText += chunk.toString("utf8");
			if (stderrText.length > 2e3) stderrText = stderrText.slice(-2e3);
		});
		child.on("exit", (code) => {
			if (stdoutBuf.trim()) handleJsonLine(stdoutBuf.trim());
			if (accText || accThinking) rt.localMessages.push({
				seq: rt.localMessages.length + 1,
				role: "assistant",
				text: accText,
				thinking: accThinking,
				time: Date.now()
			});
			rt.isNew = false;
			rt.running = false;
			rt.activeChild = null;
			rt.updatedAt = Date.now();
			const fp = this.locateSessionFile(rawId);
			if (fp) rt.filePath = fp;
			if (code !== 0 && code !== null && !accText) {
				const hint = stderrText.trim().slice(0, 260) || `Claude Code 退出码 ${String(code)}`;
				this.emit(rawId, {
					type: "error",
					error: hint,
					running: false
				});
			}
			this.emit(rawId, {
				type: "done",
				running: false
			});
		});
		child.on("error", (err) => {
			rt.running = false;
			rt.activeChild = null;
			this.emit(rawId, {
				type: "error",
				error: err.message,
				running: false
			});
			this.emit(rawId, {
				type: "done",
				running: false
			});
		});
		return {
			ok: true,
			runId: `cl-${Date.now()}`,
			status: "started"
		};
	}
	async abort(rawId) {
		const rt = this.runtime.get(rawId);
		if (rt?.activeChild) {
			killProcessTree$1(rt.activeChild);
			rt.activeChild = null;
		}
		if (rt) {
			rt.running = false;
			this.emit(rawId, {
				type: "done",
				running: false
			});
		}
		return true;
	}
	subscribe(rawId, listener) {
		let set = this.listeners.get(rawId);
		if (!set) {
			set = /* @__PURE__ */ new Set();
			this.listeners.set(rawId, set);
		}
		set.add(listener);
		return () => {
			const s = this.listeners.get(rawId);
			if (!s) return;
			s.delete(listener);
			if (s.size === 0) this.listeners.delete(rawId);
		};
	}
	getAsk(_rawId) {
		return { pending: null };
	}
	async answerAsk(_rawId, _askId, _answers) {
		return false;
	}
	async listModels() {
		return DEFAULT_CLAUDE_MODELS;
	}
	async setModel(rawId, model) {
		const rt = this.runtime.get(rawId);
		if (rt) rt.model = model.trim();
		return true;
	}
	isRunning(rawId) {
		return this.runtime.get(rawId)?.running === true;
	}
	dispose() {
		for (const rt of this.runtime.values()) if (rt.activeChild) {
			killProcessTree$1(rt.activeChild);
			rt.activeChild = null;
		}
		this.runtime.clear();
		this.listeners.clear();
	}
};
//#endregion
//#region src/backends/codex-backend.ts
const CODEX_CAPABILITIES = {
	listExistingSessions: true,
	historyReplay: true,
	streamDelta: true,
	approval: true,
	abort: true,
	images: true,
	files: false,
	modelSwitch: true,
	reasoningEffort: true,
	planMode: false,
	goalMode: false,
	compact: false,
	fork: false,
	archivePin: false,
	webConsole: false
};
const IDLE_TTL_MS$1 = 900 * 1e3;
function tsMs(raw) {
	if (typeof raw !== "number" || !Number.isFinite(raw)) return Date.now();
	return raw > 0xe8d4a51000 ? raw : Math.round(raw * 1e3);
}
function extractTextFromContent(content) {
	if (typeof content === "string") return content;
	if (!Array.isArray(content)) return "";
	const parts = [];
	for (const item of content) if (typeof item === "string") parts.push(item);
	else if (item && typeof item === "object") {
		const o = item;
		if (typeof o.text === "string") parts.push(o.text);
	}
	return parts.join("\n");
}
function mapTurnsToMessages(turns, fallbackTime) {
	if (!Array.isArray(turns)) return [];
	const out = [];
	let seq = 0;
	for (const t of turns) {
		if (!t || typeof t !== "object") continue;
		const turnObj = t;
		const items = Array.isArray(turnObj.items) ? turnObj.items : [];
		let curAssistant = null;
		const ensureA = () => {
			if (!curAssistant) {
				curAssistant = {
					seq: ++seq,
					role: "assistant",
					text: "",
					thinking: "",
					tools: [],
					time: fallbackTime
				};
				out.push(curAssistant);
			}
			return curAssistant;
		};
		for (const rawItem of items) {
			if (!rawItem || typeof rawItem !== "object") continue;
			const item = rawItem;
			const typ = typeof item.type === "string" ? item.type : "";
			if (typ === "userMessage") {
				curAssistant = null;
				const txt = extractTextFromContent(item.content) || (typeof item.text === "string" ? item.text : "");
				if (txt.trim() !== "") out.push({
					seq: ++seq,
					role: "user",
					text: txt,
					time: fallbackTime
				});
				continue;
			}
			if (typ === "agentMessage") {
				const a = ensureA();
				const txt = typeof item.text === "string" ? item.text : extractTextFromContent(item.content);
				if (txt) a.text = a.text ? `${a.text}\n${txt}` : txt;
				continue;
			}
			if (typ === "reasoning") {
				const a = ensureA();
				const combined = [Array.isArray(item.summary) ? item.summary.map((x) => typeof x === "string" ? x : extractTextFromContent(x)).filter(Boolean).join("\n") : typeof item.summary === "string" ? item.summary : "", extractTextFromContent(item.content)].filter(Boolean).join("\n");
				if (combined) a.thinking = a.thinking ? `${a.thinking}\n${combined}` : combined;
				continue;
			}
			if (typ === "commandExecution") {
				const a = ensureA();
				if (!a.tools) a.tools = [];
				const cmd = typeof item.command === "string" ? item.command : "shell";
				const status = typeof item.status === "string" ? item.status : "";
				const done = status !== "inProgress" && status !== "running";
				const ok = status !== "failed" && status !== "declined" && (item.exitCode === void 0 || item.exitCode === 0);
				const tc = {
					id: typeof item.id === "string" ? item.id : `cx-cmd-${seq}`,
					name: "command",
					summary: cmd.slice(0, 200),
					status: !done ? "run" : ok ? "ok" : "err"
				};
				a.tools.push(tc);
				continue;
			}
			if (typ === "fileChange" || typ === "mcpToolCall" || typ === "toolCall" || typ === "webSearch") {
				const a = ensureA();
				if (!a.tools) a.tools = [];
				const name = typeof item.tool === "string" ? item.tool : typeof item.name === "string" ? item.name : typ;
				const input = item.arguments !== void 0 ? JSON.stringify(item.arguments).slice(0, 200) : item.changes !== void 0 ? JSON.stringify(item.changes).slice(0, 200) : typeof item.query === "string" ? item.query.slice(0, 200) : name;
				const status = typeof item.status === "string" ? item.status : "";
				const done = status !== "inProgress" && status !== "running";
				const ok = status !== "failed" && status !== "declined";
				a.tools.push({
					id: typeof item.id === "string" ? item.id : `cx-t-${seq}`,
					name,
					summary: input,
					status: !done ? "run" : ok ? "ok" : "err"
				});
			}
		}
	}
	return out;
}
var CodexBackend = class {
	id = "codex";
	label = "Codex";
	capabilities = CODEX_CAPABILITIES;
	cli = null;
	child = null;
	stdoutBuf = "";
	nextId = 1;
	pending = /* @__PURE__ */ new Map();
	initPromise = null;
	initialized = false;
	lastActivity = Date.now();
	idleTimer = null;
	runtime = /* @__PURE__ */ new Map();
	listeners = /* @__PURE__ */ new Map();
	modelsCache = null;
	ensureCli(force = false) {
		if (!force && this.cli) return this.cli;
		this.cli = resolveCliCommand("codex", force);
		return this.cli;
	}
	getOrCreateRuntime(rawId) {
		let s = this.runtime.get(rawId);
		if (!s) {
			s = {
				rawId,
				cwd: homedir(),
				model: "",
				title: "Codex 会话",
				updatedAt: Date.now(),
				loaded: false,
				running: false,
				activeTurnId: "",
				liveAssistant: null,
				pendingAsk: null
			};
			this.runtime.set(rawId, s);
		}
		return s;
	}
	emit(rawId, ev) {
		const set = this.listeners.get(rawId);
		if (!set) return;
		for (const fn of set) try {
			fn(ev);
		} catch {}
	}
	ensureProcess() {
		if (this.child && !this.child.killed && this.child.exitCode === null) return;
		const cli = this.ensureCli();
		if (!cli) throw new Error("本机未检测到 codex 命令");
		this.stdoutBuf = "";
		this.initialized = false;
		const child = spawnCli(cli, ["app-server"], { cwd: homedir() });
		this.child = child;
		this.lastActivity = Date.now();
		child.stdout?.on("data", (chunk) => {
			this.lastActivity = Date.now();
			this.stdoutBuf += chunk.toString("utf8");
			let nl;
			while ((nl = this.stdoutBuf.indexOf("\n")) >= 0) {
				const line = this.stdoutBuf.slice(0, nl).trim();
				this.stdoutBuf = this.stdoutBuf.slice(nl + 1);
				if (!line) continue;
				this.handleLine(line);
			}
		});
		child.stderr?.on("data", () => {});
		child.on("exit", (code, signal) => {
			this.failAllPending(`codex app-server exited (code=${String(code)}, signal=${String(signal)})`);
			this.child = null;
			this.initialized = false;
			this.initPromise = null;
			for (const s of this.runtime.values()) {
				s.loaded = false;
				if (s.running) {
					s.running = false;
					s.activeTurnId = "";
					this.emit(s.rawId, {
						type: "done",
						running: false
					});
				}
				if (s.pendingAsk) {
					s.pendingAsk = null;
					this.emit(s.rawId, {
						type: "ask",
						asking: false,
						ask: null
					});
				}
			}
		});
		child.on("error", (err) => {
			this.failAllPending(err.message);
			this.child = null;
			this.initialized = false;
			this.initPromise = null;
		});
		if (!this.idleTimer) {
			this.idleTimer = setInterval(() => {
				if (!Array.from(this.runtime.values()).some((s) => s.running) && this.child && Date.now() - this.lastActivity > IDLE_TTL_MS$1) this.stopProcess();
			}, 6e4);
			this.idleTimer.unref?.();
		}
	}
	stopProcess() {
		this.failAllPending("codex app-server stopped");
		killProcessTree$1(this.child);
		this.child = null;
		this.initialized = false;
		this.initPromise = null;
	}
	failAllPending(reason) {
		for (const [, p] of this.pending) {
			clearTimeout(p.timer);
			p.reject(new Error(reason));
		}
		this.pending.clear();
	}
	writeFrame(frame) {
		this.ensureProcess();
		if (!this.child?.stdin || this.child.stdin.destroyed) throw new Error("codex app-server stdin 不可写");
		this.lastActivity = Date.now();
		this.child.stdin.write(JSON.stringify(frame) + "\n");
	}
	async ensureInitialized() {
		if (this.initialized && this.child && this.child.exitCode === null) return;
		if (this.initPromise) return this.initPromise;
		this.initPromise = this.rawRequest("initialize", { clientInfo: {
			name: "dsh-mobile",
			version: "3.0.0"
		} }, 15e3).then(() => {
			this.initialized = true;
		}).catch((err) => {
			this.initPromise = null;
			throw err;
		});
		return this.initPromise;
	}
	async rawRequest(method, params, timeoutMs = 25e3) {
		this.ensureProcess();
		const id = this.nextId++;
		return await new Promise((resolveReq, rejectReq) => {
			const timer = setTimeout(() => {
				this.pending.delete(id);
				rejectReq(/* @__PURE__ */ new Error(`codex RPC timeout: ${method}`));
			}, timeoutMs);
			this.pending.set(id, {
				resolve: resolveReq,
				reject: rejectReq,
				timer
			});
			try {
				this.writeFrame({
					jsonrpc: "2.0",
					id,
					method,
					params
				});
			} catch (err) {
				clearTimeout(timer);
				this.pending.delete(id);
				rejectReq(err instanceof Error ? err : new Error(String(err)));
			}
		});
	}
	async request(method, params, timeoutMs = 25e3) {
		await this.ensureInitialized();
		return await this.rawRequest(method, params, timeoutMs);
	}
	handleLine(line) {
		let msg;
		try {
			const parsed = JSON.parse(line);
			if (!parsed || typeof parsed !== "object") return;
			msg = parsed;
		} catch {
			return;
		}
		if (msg.id !== void 0 && msg.method === void 0) {
			const id = Number(msg.id);
			const p = this.pending.get(id);
			if (!p) return;
			this.pending.delete(id);
			clearTimeout(p.timer);
			if (msg.error !== void 0 && msg.error !== null) {
				const errObj = msg.error;
				p.reject(new Error(typeof errObj.message === "string" ? errObj.message : JSON.stringify(errObj)));
			} else p.resolve(msg.result);
			return;
		}
		if (msg.id !== void 0 && typeof msg.method === "string") {
			const rpcId = msg.id;
			const params = msg.params && typeof msg.params === "object" ? msg.params : {};
			const threadId = typeof params.threadId === "string" ? params.threadId : "";
			if (msg.method === "item/commandExecution/requestApproval" || msg.method === "item/fileChange/requestApproval" || msg.method.endsWith("/requestApproval")) {
				if (!threadId) {
					this.replyApproval(rpcId, "decline");
					return;
				}
				const s = this.getOrCreateRuntime(threadId);
				const askId = `cx-ask-${randomUUID().slice(0, 8)}`;
				const isCmd = msg.method.includes("commandExecution");
				const detail = typeof params.command === "string" ? params.command : typeof params.reason === "string" ? params.reason : JSON.stringify(params).slice(0, 260);
				const ask = {
					askId,
					sessionId: formatSessionId("codex", threadId),
					createdAt: Date.now(),
					questions: [{
						header: isCmd ? "Codex 命令审批" : "Codex 文件修改审批",
						question: detail,
						multiSelect: false,
						options: [
							{
								label: "允许本次",
								description: "仅允许这一次操作",
								value: "accept"
							},
							{
								label: "本会话始终允许",
								description: "当前会话内同类操作自动放行",
								value: "acceptForSession"
							},
							{
								label: "拒绝",
								description: "拒绝此操作",
								value: "decline"
							}
						]
					}]
				};
				s.pendingAsk = {
					ask,
					rpcId,
					method: msg.method
				};
				this.emit(threadId, {
					type: "ask",
					asking: true,
					ask
				});
				return;
			}
			try {
				this.writeFrame({
					jsonrpc: "2.0",
					id: rpcId,
					error: {
						code: -32601,
						message: `Unsupported method: ${msg.method}`
					}
				});
			} catch {}
			return;
		}
		if (typeof msg.method !== "string") return;
		const params = msg.params && typeof msg.params === "object" ? msg.params : {};
		const threadId = typeof params.threadId === "string" ? params.threadId : params.thread && typeof params.thread.id === "string" ? String(params.thread.id) : "";
		if (!threadId) return;
		const s = this.getOrCreateRuntime(threadId);
		if (msg.method === "turn/started") {
			const turn = params.turn;
			s.running = true;
			s.activeTurnId = typeof turn?.id === "string" ? turn.id : typeof params.turnId === "string" ? params.turnId : "";
			s.updatedAt = Date.now();
			this.emit(threadId, {
				type: "status",
				running: true
			});
			return;
		}
		if (msg.method === "item/agentMessage/delta") {
			const delta = typeof params.delta === "string" ? params.delta : "";
			if (delta) {
				s.updatedAt = Date.now();
				this.emit(threadId, {
					type: "delta",
					text: delta,
					running: true
				});
			}
			return;
		}
		if (msg.method === "item/reasoning/summaryTextDelta" || msg.method === "item/reasoning/textDelta") {
			const delta = typeof params.delta === "string" ? params.delta : "";
			if (delta) {
				s.updatedAt = Date.now();
				this.emit(threadId, {
					type: "thinking",
					thinking: delta,
					running: true
				});
			}
			return;
		}
		if (msg.method === "item/started" || msg.method === "item/completed") {
			const item = params.item;
			if (!item) return;
			const typ = typeof item.type === "string" ? item.type : "";
			if (typ === "commandExecution" || typ === "fileChange" || typ === "mcpToolCall" || typ === "toolCall") {
				const done = msg.method === "item/completed";
				const statusRaw = typeof item.status === "string" ? item.status : "";
				const toolStatus = !done ? "running" : statusRaw === "failed" || statusRaw === "declined" ? "error" : "done";
				const toolName = typ === "commandExecution" ? "command" : typeof item.tool === "string" ? item.tool : typeof item.name === "string" ? item.name : typ;
				const toolInput = typeof item.command === "string" ? item.command.slice(0, 400) : item.arguments !== void 0 ? JSON.stringify(item.arguments).slice(0, 400) : "";
				const toolOutput = typeof item.aggregatedOutput === "string" ? item.aggregatedOutput.slice(0, 1200) : typeof item.output === "string" ? item.output.slice(0, 1200) : "";
				this.emit(threadId, {
					type: "tool",
					toolId: typeof item.id === "string" ? item.id : void 0,
					toolName,
					toolInput,
					toolOutput,
					toolStatus,
					running: true
				});
			}
			return;
		}
		if (msg.method === "turn/completed") {
			s.running = false;
			s.activeTurnId = "";
			s.updatedAt = Date.now();
			const errObj = params.turn?.error;
			if (errObj && typeof errObj.message === "string" && errObj.message.trim() !== "") this.emit(threadId, {
				type: "error",
				error: errObj.message,
				running: false
			});
			this.emit(threadId, {
				type: "done",
				running: false
			});
			return;
		}
		if (msg.method === "error") {
			const errMsg = typeof params.message === "string" ? params.message : params.error && typeof params.error.message === "string" ? String(params.error.message) : "Codex 运行出错";
			this.emit(threadId, {
				type: "error",
				error: errMsg,
				running: s.running
			});
		}
	}
	replyApproval(rpcId, decision) {
		try {
			this.writeFrame({
				jsonrpc: "2.0",
				id: rpcId,
				result: { decision }
			});
		} catch {}
	}
	async probe(force = false) {
		const cli = this.ensureCli(force);
		if (!cli) return {
			installed: false,
			version: "",
			binaryPath: "",
			error: "未检测到 codex 命令"
		};
		return {
			installed: true,
			version: await probeCliVersion(cli, force) || "installed",
			binaryPath: cli.displayPath
		};
	}
	async listSessions(limit = 40) {
		const res = await this.request("thread/list", { limit }, 15e3);
		const data = res && Array.isArray(res.data) ? res.data : [];
		const rows = [];
		for (const item of data) {
			if (!item || typeof item !== "object") continue;
			const o = item;
			const rawId = typeof o.id === "string" ? o.id : "";
			if (!rawId) continue;
			const rt = this.getOrCreateRuntime(rawId);
			const nameStr = typeof o.name === "string" && o.name.trim() !== "" ? o.name.trim() : "";
			const preview = typeof o.preview === "string" ? o.preview.trim() : "";
			const title = nameStr || preview.slice(0, 48) || "Codex 会话";
			const cwd = typeof o.cwd === "string" && o.cwd.trim() !== "" ? o.cwd : homedir();
			const updatedAt = tsMs(o.updatedAt ?? o.createdAt);
			const model = typeof o.model === "string" ? o.model : "";
			const provider = typeof o.modelProvider === "string" ? o.modelProvider : "codex";
			const stObj = o.status;
			const running = rt.running || stObj?.type === "active";
			rt.cwd = cwd;
			rt.title = title;
			if (model) rt.model = model;
			if (updatedAt > rt.updatedAt) rt.updatedAt = updatedAt;
			rows.push({
				id: formatSessionId("codex", rawId),
				rawId,
				backend: "codex",
				title,
				cwd,
				updatedAt: rt.updatedAt,
				running,
				asking: rt.pendingAsk !== null,
				preview: preview.slice(0, 120),
				model: model ? {
					provider,
					model,
					reasoningEffort: typeof o.reasoningEffort === "string" ? o.reasoningEffort : ""
				} : null
			});
		}
		rows.sort((a, b) => b.updatedAt - a.updatedAt);
		return rows.slice(0, limit);
	}
	async getMessages(rawId, opts) {
		const rt = this.getOrCreateRuntime(rawId);
		const res = await this.request("thread/read", {
			threadId: rawId,
			includeTurns: true
		}, 2e4);
		const thread = res?.thread && typeof res.thread === "object" ? res.thread : {};
		if (typeof thread.cwd === "string" && thread.cwd) rt.cwd = thread.cwd;
		if (typeof thread.model === "string" && thread.model) rt.model = thread.model;
		const updatedAt = tsMs(thread.updatedAt ?? thread.createdAt);
		const all = mapTurnsToMessages(thread.turns, updatedAt);
		const lim = opts?.limit && opts.limit > 0 ? opts.limit : all.length;
		const start = Math.max(0, all.length - lim);
		return {
			messages: all.slice(start),
			total: all.length,
			hasMore: start > 0,
			model: rt.model || void 0,
			cwd: rt.cwd,
			running: rt.running,
			asking: rt.pendingAsk !== null
		};
	}
	async createSession(cwd, opts) {
		const safeCwd = validateWorkingDir(cwd, true);
		const params = { cwd: safeCwd };
		if (opts?.model && opts.model.trim() !== "") params.model = opts.model.trim();
		const res = await this.request("thread/start", params, 2e4);
		const thread = res?.thread && typeof res.thread === "object" ? res.thread : res;
		const rawId = typeof thread?.id === "string" ? thread.id : "";
		if (!rawId) throw new Error("Codex thread/start 未返回线程 ID");
		const rt = this.getOrCreateRuntime(rawId);
		rt.cwd = safeCwd;
		rt.loaded = true;
		rt.title = opts?.title?.trim() || "Codex 新会话";
		rt.model = typeof thread.model === "string" ? thread.model : opts?.model ?? "";
		rt.updatedAt = Date.now();
		return {
			id: formatSessionId("codex", rawId),
			rawId,
			backend: "codex",
			title: rt.title,
			cwd: rt.cwd,
			updatedAt: rt.updatedAt,
			running: false,
			asking: false,
			model: rt.model ? {
				provider: "codex",
				model: rt.model,
				reasoningEffort: ""
			} : null
		};
	}
	async sendMessage(rawId, text, opts) {
		const rt = this.getOrCreateRuntime(rawId);
		if (opts?.cwd) rt.cwd = opts.cwd;
		if (rt.running) throw new Error("Codex 当前会话正在运行，请等待完成或先中断");
		if (!rt.loaded) try {
			await this.request("thread/resume", { threadId: rawId }, 2e4);
			rt.loaded = true;
		} catch {
			rt.loaded = true;
		}
		const input = [];
		if (text.trim() !== "") input.push({
			type: "text",
			text
		});
		if (opts?.images && opts.images.length > 0) for (const img of opts.images) {
			const url = img.data.startsWith("data:") ? img.data : `data:${img.mime || "image/jpeg"};base64,${img.data}`;
			input.push({
				type: "image",
				url
			});
		}
		if (input.length === 0) throw new Error("消息内容不能为空");
		const params = {
			threadId: rawId,
			input
		};
		const wantModel = opts?.model?.trim() || rt.model;
		if (wantModel) params.model = wantModel;
		rt.running = true;
		rt.updatedAt = Date.now();
		if (rt.title === "Codex 新会话" || rt.title === "Codex 会话") rt.title = text.trim().slice(0, 36) || rt.title;
		this.emit(rawId, {
			type: "status",
			running: true
		});
		const res = await this.request("turn/start", params, 3e4);
		const turn = res?.turn && typeof res.turn === "object" ? res.turn : {};
		if (typeof turn.id === "string") rt.activeTurnId = turn.id;
		return {
			ok: true,
			runId: rt.activeTurnId || `cx-${Date.now()}`,
			status: "started"
		};
	}
	async abort(rawId) {
		const rt = this.runtime.get(rawId);
		if (rt?.pendingAsk) {
			this.replyApproval(rt.pendingAsk.rpcId, "cancel");
			rt.pendingAsk = null;
			this.emit(rawId, {
				type: "ask",
				asking: false,
				ask: null
			});
		}
		try {
			const params = { threadId: rawId };
			if (rt?.activeTurnId) params.turnId = rt.activeTurnId;
			await this.request("turn/interrupt", params, 8e3);
		} catch {}
		if (rt) {
			rt.running = false;
			rt.activeTurnId = "";
			this.emit(rawId, {
				type: "done",
				running: false
			});
		}
		return true;
	}
	subscribe(rawId, listener) {
		let set = this.listeners.get(rawId);
		if (!set) {
			set = /* @__PURE__ */ new Set();
			this.listeners.set(rawId, set);
		}
		set.add(listener);
		return () => {
			const s = this.listeners.get(rawId);
			if (!s) return;
			s.delete(listener);
			if (s.size === 0) this.listeners.delete(rawId);
		};
	}
	getAsk(rawId) {
		return { pending: this.runtime.get(rawId)?.pendingAsk?.ask ?? null };
	}
	async answerAsk(rawId, askId, answers) {
		const rt = this.runtime.get(rawId);
		if (!rt?.pendingAsk) return false;
		if (askId && rt.pendingAsk.ask.askId !== askId) return false;
		const pending = rt.pendingAsk;
		rt.pendingAsk = null;
		const chosen = Object.values(answers)[0] ?? "";
		const decision = (pending.ask.questions[0]?.options.find((o) => o.label === chosen || o.value === chosen))?.value || "decline";
		this.replyApproval(pending.rpcId, decision);
		this.emit(rawId, {
			type: "ask",
			asking: false,
			ask: null
		});
		return true;
	}
	async listModels() {
		if (this.modelsCache && Date.now() - this.modelsCache.at < 300 * 1e3) return this.modelsCache.items;
		try {
			const res = await this.request("model/list", {}, 12e3);
			const data = res && Array.isArray(res.data) ? res.data : [];
			const items = [];
			for (const item of data) {
				if (!item || typeof item !== "object") continue;
				const o = item;
				if (o.hidden === true) continue;
				const id = typeof o.model === "string" ? o.model : typeof o.id === "string" ? o.id : "";
				if (!id) continue;
				items.push({
					id,
					name: typeof o.displayName === "string" && o.displayName ? o.displayName : id,
					provider: "codex",
					description: typeof o.description === "string" ? o.description : void 0
				});
			}
			this.modelsCache = {
				at: Date.now(),
				items
			};
			return items;
		} catch {
			return this.modelsCache?.items ?? [];
		}
	}
	async setModel(rawId, model) {
		const rt = this.getOrCreateRuntime(rawId);
		rt.model = model.trim();
		return true;
	}
	isRunning(rawId) {
		return this.runtime.get(rawId)?.running === true;
	}
	dispose() {
		if (this.idleTimer) {
			clearInterval(this.idleTimer);
			this.idleTimer = null;
		}
		this.stopProcess();
		this.runtime.clear();
		this.listeners.clear();
	}
};
//#endregion
//#region src/backends/opencode-backend.ts
/**
* OpenCode 后端适配器（基于通用 ACP 引擎驱动 `opencode acp --pure`）：
* - 发现本机已有 OpenCode 会话（ACP `session/list` + `opencode session list --format json` 兜底）；
* - 通过 ACP `session/load` 重放历史消息到标准 `ChatMessage[]`；
* - 通过 ACP `session/prompt` / `session/update` / `session/request_permission` 实现流式输出、审批弹窗与安全中断。
*/
const OPENCODE_CAPABILITIES = {
	listExistingSessions: true,
	historyReplay: true,
	streamDelta: true,
	approval: true,
	abort: true,
	images: true,
	files: false,
	modelSwitch: false,
	reasoningEffort: false,
	planMode: false,
	goalMode: false,
	compact: false,
	fork: false,
	archivePin: false,
	webConsole: false
};
var OpenCodeBackend = class extends AcpSessionBackend {
	id = "opencode";
	label = "OpenCode";
	capabilities = OPENCODE_CAPABILITIES;
	resolveSpec(force = false) {
		const cli = resolveCliCommand("opencode", force);
		if (!cli) return null;
		return {
			cli,
			args: [
				"acp",
				"--pure",
				"--cwd",
				homedir()
			]
		};
	}
	missingCliMessage() {
		return "本机未检测到 opencode 命令";
	}
	/** 快速通过 CLI 列出本机历史会话（避免首次列举必须等整个 ACP 进程初始化）。 */
	async listViaCliFallback(limit) {
		const spec = this.ensureSpec();
		if (!spec) return [];
		return await new Promise((resolveList) => {
			let out = "";
			let done = false;
			const finish = (rows) => {
				if (done) return;
				done = true;
				clearTimeout(timer);
				resolveList(rows);
			};
			const child = spawnCli(spec.cli, [
				"session",
				"list",
				"--format",
				"json",
				"-n",
				String(limit)
			]);
			const timer = setTimeout(() => {
				killProcessTree$1(child);
				finish([]);
			}, 1e4);
			child.stdout?.on("data", (d) => {
				out += d.toString("utf8");
			});
			child.on("error", () => finish([]));
			child.on("exit", () => {
				try {
					const parsed = JSON.parse(out.trim());
					if (Array.isArray(parsed)) {
						finish(parsed.filter((x) => x !== null && typeof x === "object"));
						return;
					}
				} catch {}
				finish([]);
			});
		});
	}
};
//#endregion
//#region src/backends/registry.ts
/**
* 多 Agent 后端注册表与调度中心（完全独立于 Cordis `ctx`）：
* - 统一管理外部后端（Codex / Claude Code / OpenCode / Antigravity）的探测、开关、会话聚合与按 ID 前缀分发；
* - 默认所有外部后端关闭（可通过持久化开关按需开启），确保安全边界与零破坏兼容。
*/
var BackendRegistry = class {
	deps;
	backends = /* @__PURE__ */ new Map();
	probeCache = /* @__PURE__ */ new Map();
	countCache = /* @__PURE__ */ new Map();
	constructor(deps) {
		this.deps = deps;
		const codex = new CodexBackend();
		const claude = new ClaudeBackend();
		const opencode = new OpenCodeBackend();
		const antigravity = new AntigravityBackend();
		this.backends.set(codex.id, codex);
		this.backends.set(claude.id, claude);
		this.backends.set(opencode.id, opencode);
		this.backends.set(antigravity.id, antigravity);
	}
	getExternal(id) {
		if (id === "dsh") return null;
		return this.backends.get(id) ?? null;
	}
	resolveBySessionId(sid) {
		const parsed = parseSessionId(sid);
		return {
			backend: parsed.backend,
			rawId: parsed.rawId,
			driver: this.getExternal(parsed.backend)
		};
	}
	isEnabled(id) {
		if (id === "dsh") return true;
		return this.deps.getEnabledMap()[id] === true;
	}
	async toggle(id, enabled) {
		if (id === "dsh") throw new Error("DSH 为默认内置后端，不可关闭");
		const driver = this.backends.get(id);
		if (!driver) throw new Error(`未知后端: ${id}`);
		const probe = await driver.probe(false);
		if (enabled && !probe.installed) throw new Error(`${driver.label} 未安装或不在 PATH 中`);
		this.deps.setEnabled(id, enabled);
		if (!enabled) driver.dispose();
		return await this.infoOf(id, false);
	}
	async infoOf(id, forceProbe = false) {
		if (id === "dsh") return {
			id: "dsh",
			label: "DSH",
			installed: true,
			enabled: true,
			version: this.deps.dshVersion || "builtin",
			status: "ready",
			sessionCount: this.deps.dshSessionCount ? this.deps.dshSessionCount() : 0,
			capabilities: DSH_CAPABILITIES
		};
		const driver = this.backends.get(id);
		if (!driver) return {
			id,
			label: id,
			installed: false,
			enabled: false,
			version: "",
			status: "unavailable",
			sessionCount: 0,
			capabilities: DSH_CAPABILITIES
		};
		let probe = this.probeCache.get(id);
		if (forceProbe || !probe) {
			probe = await driver.probe(forceProbe);
			this.probeCache.set(id, probe);
		}
		const enabled = this.isEnabled(id);
		const status = !probe.installed ? "unavailable" : enabled ? "ready" : "disabled";
		return {
			id: driver.id,
			label: driver.label,
			installed: probe.installed,
			enabled: probe.installed && enabled,
			version: probe.version,
			status,
			sessionCount: this.countCache.get(id) ?? 0,
			error: probe.error,
			capabilities: driver.capabilities
		};
	}
	async listBackendInfos(forceProbe = false) {
		const ids = ["dsh", ...EXTERNAL_BACKEND_IDS];
		return await Promise.all(ids.map((id) => this.infoOf(id, forceProbe)));
	}
	/** 拉取已启用外部后端的会话（支持单个指定或全部聚合，单后端失败不拖垮整体列表）。 */
	async listExternalSessions(filter = "all", limitPerBackend = 30) {
		const activeTargets = (filter === "all" ? [...EXTERNAL_BACKEND_IDS] : filter === "dsh" ? [] : [filter]).filter((id) => this.isEnabled(id));
		if (activeTargets.length === 0) return [];
		return (await Promise.all(activeTargets.map(async (id) => {
			const driver = this.backends.get(id);
			if (!driver) return [];
			try {
				const rows = await driver.listSessions(limitPerBackend);
				this.countCache.set(id, rows.length);
				return rows;
			} catch {
				return [];
			}
		}))).flat();
	}
	dispose() {
		for (const driver of this.backends.values()) driver.dispose();
	}
};
//#endregion
//#region src/panel.ts
/**
* DSH 设置面板同源路由：配对状态、二维码、连接与安全权限开关，以及本机管理员可见的反馈工单。
*/
const PANEL_PREFIX = "/api/dsh-mobile/panel";
const panelJson = (status, payload) => new Response(JSON.stringify(payload), {
	status,
	headers: {
		"content-type": "application/json; charset=utf-8",
		"cache-control": "no-store"
	}
});
const qrSvg = async (text) => {
	try {
		const mod = await import("qrcode");
		const svg = await (mod?.default ?? mod).toString(text, {
			type: "svg",
			margin: 1,
			width: 240,
			errorCorrectionLevel: "M"
		});
		return typeof svg === "string" ? svg : null;
	} catch {
		return null;
	}
};
const panelBody = async (request) => {
	try {
		const text = await request.text();
		if (text.trim().length === 0) return {
			ok: true,
			data: {}
		};
		const parsed = JSON.parse(text);
		if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) return {
			ok: true,
			data: parsed
		};
		return {
			ok: false,
			error: "请求体必须是 JSON 对象"
		};
	} catch {
		return {
			ok: false,
			error: "请求体 JSON 格式不合法"
		};
	}
};
const FEEDBACK_BASE = (process.env.AGENT_MOBILE_FEEDBACK_URL ?? "https://feedback.juo.de5.net").trim();
const feedbackKey = () => {
	if (FEEDBACK_BASE === "") return "";
	try {
		const file = join(dshHome(), "feedback-admin.key");
		if (!existsSync(file)) return "";
		return readFileSync(file, "utf8").trim();
	} catch {
		return "";
	}
};
const feedbackCall = async (method, path, body) => {
	if (FEEDBACK_BASE === "") return {
		code: 503,
		data: { error: "未配置反馈服务地址" }
	};
	const key = feedbackKey();
	try {
		const headers = { authorization: `Bearer ${key}` };
		if (body !== void 0) headers["content-type"] = "application/json; charset=utf-8";
		const res = await fetch(FEEDBACK_BASE + path, {
			method,
			headers,
			body: body === void 0 ? void 0 : JSON.stringify(body)
		});
		const text = await res.text();
		let data = {};
		try {
			const parsed = JSON.parse(text);
			if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) data = parsed;
		} catch {
			data = { error: text.slice(0, 300) || `HTTP ${String(res.status)}` };
		}
		return {
			code: res.status,
			data
		};
	} catch (error) {
		return {
			code: 0,
			data: { error: error instanceof Error ? error.message : String(error) }
		};
	}
};
const createPanel = (ctx) => {
	const panelSnapshot = () => {
		const snapshot = ctx.pairState();
		const base = String(snapshot.base ?? "");
		const alts = Array.isArray(snapshot.alts) ? snapshot.alts : [];
		const payload = base.length > 0 ? ctx.pairPayload(base, String(snapshot.code ?? ""), alts) : "";
		return {
			...snapshot,
			payload
		};
	};
	const panelConfig = async (request) => {
		const parsedBody = await panelBody(request);
		if (!parsedBody.ok) return panelJson(400, { error: parsedBody.error });
		const body = parsedBody.data;
		const current = ctx.pairState();
		let publicUrl = String(current.publicUrl ?? "");
		if (body.publicUrl !== void 0) {
			if (typeof body.publicUrl !== "string") return panelJson(400, { error: "公网地址必须是字符串" });
			const checked = validatePublicUrl(body.publicUrl);
			if (!checked.ok) return panelJson(400, { error: checked.error });
			publicUrl = checked.url;
		}
		let nextAnswerMode = current.answerMode === "desktop" ? "desktop" : "phone";
		if (body.answerMode !== void 0) {
			if (body.answerMode !== "phone" && body.answerMode !== "desktop") return panelJson(400, { error: "回答模式只能是 phone 或 desktop" });
			nextAnswerMode = body.answerMode;
		}
		let nextAllowTerminal = current.allowTerminal !== false;
		if (body.allowTerminal !== void 0) {
			if (typeof body.allowTerminal !== "boolean") return panelJson(400, { error: "允许远程终端开关必须是布尔值" });
			nextAllowTerminal = body.allowTerminal;
		}
		let nextPreviewPorts = Array.isArray(current.previewPorts) ? current.previewPorts : [];
		if (body.previewPorts !== void 0) {
			const checkedPorts = parsePreviewPorts(body.previewPorts);
			if (!checkedPorts.ok) return panelJson(400, { error: checkedPorts.error });
			nextPreviewPorts = checkedPorts.ports;
		}
		const next = {
			allowLan: typeof body.allowLan === "boolean" ? body.allowLan : Boolean(current.allowLan),
			allowRemote: typeof body.allowRemote === "boolean" ? body.allowRemote : Boolean(current.allowRemote),
			publicUrl,
			answerMode: nextAnswerMode,
			allowTerminal: nextAllowTerminal,
			previewPorts: nextPreviewPorts
		};
		ctx.writePrefs(next);
		await ctx.record(`200 PANEL config lan=${String(next.allowLan)} remote=${String(next.allowRemote)} answer=${next.answerMode} term=${String(next.allowTerminal)} ports=${next.previewPorts.join(",")}`);
		return panelJson(200, panelSnapshot());
	};
	const panelQr = async (request) => {
		const asked = new URL(request.url).searchParams.get("payload");
		const snapshot = ctx.pairState();
		const base = String(snapshot.base ?? "");
		const alts = Array.isArray(snapshot.alts) ? snapshot.alts : [];
		const text = asked !== null && asked.length > 0 ? asked : base.length > 0 ? ctx.pairPayload(base, String(snapshot.code ?? ""), alts) : "";
		if (text.length === 0) return panelJson(409, { error: "当前没有可用的连接地址，请开启「局域网直连」或填写公网地址" });
		const svg = await qrSvg(text);
		if (svg === null) return panelJson(503, { error: "二维码组件未就绪，请使用下方 6 位配对码连接" });
		return new Response(svg, {
			status: 200,
			headers: {
				"content-type": "image/svg+xml; charset=utf-8",
				"cache-control": "no-store"
			}
		});
	};
	const feedbackState = async () => {
		if (FEEDBACK_BASE === "" || feedbackKey() === "") return panelJson(200, { configured: false });
		const list = await feedbackCall("GET", "/v1/admin/tickets?limit=60");
		if (list.code !== 200) return panelJson(list.code === 0 ? 502 : list.code, {
			configured: true,
			error: String(list.data.error ?? "获取反馈列表失败")
		});
		const sum = await feedbackCall("GET", "/v1/admin/summary");
		const tickets = Array.isArray(list.data.tickets) ? list.data.tickets : [];
		return panelJson(200, {
			configured: true,
			tickets,
			summary: sum.data
		});
	};
	const feedbackReply = async (request) => {
		const parsedBody = await panelBody(request);
		if (!parsedBody.ok) return panelJson(400, { error: parsedBody.error });
		const body = parsedBody.data;
		const id = typeof body.id === "string" ? body.id : "";
		const text = typeof body.text === "string" ? body.text.trim() : "";
		if (id === "" || text === "") return panelJson(400, { error: "工单 ID 和回复内容不能为空" });
		const status = typeof body.status === "string" ? body.status : "";
		const payload = { text };
		if (status !== "") payload.status = status;
		const r = await feedbackCall("POST", `/v1/admin/tickets/${encodeURIComponent(id)}/reply`, payload);
		return panelJson(r.code === 0 ? 502 : r.code, r.data);
	};
	const feedbackStatus = async (request) => {
		const parsedBody = await panelBody(request);
		if (!parsedBody.ok) return panelJson(400, { error: parsedBody.error });
		const body = parsedBody.data;
		const id = typeof body.id === "string" ? body.id : "";
		const status = typeof body.status === "string" ? body.status : "";
		if (id === "" || status === "") return panelJson(400, { error: "工单 ID 和目标状态不能为空" });
		const r = await feedbackCall("POST", `/v1/admin/tickets/${encodeURIComponent(id)}/status`, { status });
		return panelJson(r.code === 0 ? 502 : r.code, r.data);
	};
	const feedbackFile = async (request) => {
		if (FEEDBACK_BASE === "") return panelJson(503, { error: "未配置反馈服务地址" });
		const key = feedbackKey();
		if (key === "") return panelJson(503, { error: "未配置管理员密钥" });
		const url = new URL(request.url);
		const id = url.searchParams.get("id") ?? "";
		const name = url.searchParams.get("name") ?? "";
		if (id === "" || name === "") return panelJson(400, { error: "缺少附件参数 id 或 name" });
		try {
			const res = await fetch(`${FEEDBACK_BASE}/v1/admin/files/${encodeURIComponent(id)}/${encodeURIComponent(name)}`, { headers: { authorization: `Bearer ${key}` } });
			if (!res.ok) return panelJson(res.status, { error: `上游返回 HTTP ${String(res.status)}` });
			const bytes = Buffer.from(await res.arrayBuffer());
			return new Response(bytes, {
				status: 200,
				headers: {
					"content-type": res.headers.get("content-type") ?? "application/octet-stream",
					"content-disposition": `attachment; filename*=UTF-8''${encodeURIComponent(name)}`,
					"cache-control": "no-store"
				}
			});
		} catch (error) {
			const message = error instanceof Error ? error.message : String(error);
			return panelJson(502, { error: message });
		}
	};
	const panelDeviceRevoke = async (request) => {
		const parsedBody = await panelBody(request);
		if (!parsedBody.ok) return panelJson(400, { error: parsedBody.error });
		const body = parsedBody.data;
		const deviceId = typeof body.deviceId === "string" ? body.deviceId.trim() : "";
		if (deviceId === "" || typeof body.revoked !== "boolean") return panelJson(400, { error: "deviceId 不能为空且 revoked 必须为布尔值" });
		const result = ctx.revokeDevice(deviceId, body.revoked);
		if (!result.ok) return panelJson(404, { error: result.error });
		await ctx.record(`200 PANEL device-revoke device=${deviceId} revoked=${String(body.revoked)}`);
		return panelJson(200, panelSnapshot());
	};
	return { routes: [
		{
			path: `${PANEL_PREFIX}/state`,
			methods: ["GET"],
			requestBody: "buffered",
			fetch: async () => panelJson(200, panelSnapshot())
		},
		{
			path: `${PANEL_PREFIX}/newcode`,
			methods: ["POST"],
			requestBody: "buffered",
			fetch: async () => {
				ctx.rotatePair();
				return panelJson(200, panelSnapshot());
			}
		},
		{
			path: `${PANEL_PREFIX}/config`,
			methods: ["POST"],
			requestBody: "buffered",
			fetch: async (request) => panelConfig(request)
		},
		{
			path: `${PANEL_PREFIX}/devices/revoke`,
			methods: ["POST"],
			requestBody: "buffered",
			fetch: async (request) => panelDeviceRevoke(request)
		},
		{
			path: `${PANEL_PREFIX}/qr.svg`,
			methods: ["GET"],
			requestBody: "buffered",
			fetch: async (request) => panelQr(request)
		},
		{
			path: `${PANEL_PREFIX}/feedback/state`,
			methods: ["GET"],
			requestBody: "buffered",
			fetch: async () => feedbackState()
		},
		{
			path: `${PANEL_PREFIX}/feedback/reply`,
			methods: ["POST"],
			requestBody: "buffered",
			fetch: async (request) => feedbackReply(request)
		},
		{
			path: `${PANEL_PREFIX}/feedback/status`,
			methods: ["POST"],
			requestBody: "buffered",
			fetch: async (request) => feedbackStatus(request)
		},
		{
			path: `${PANEL_PREFIX}/feedback/file`,
			methods: ["GET"],
			requestBody: "buffered",
			fetch: async (request) => feedbackFile(request)
		}
	] };
};
//#endregion
//#region src/routes/e2ee.ts
/**
* L6 端到端加密信封（`Noise_IK_25519_ChaChaPoly_SHA256`）与已配对设备管理路由：
* - `POST /api/e2ee/handshake`：核验设备撤销与公钥绑定，执行 Noise_IK 握手并建立加密会话 `sid`；
* - `POST /api/e2ee/rpc`：按单会话串行互斥锁解密 RPC 信封、经内部分发器执行并加密返回；
* - `GET /api/e2ee/devices`、`POST /api/e2ee/devices/revoke`：查看已配对设备与立即撤销/恢复授权。
*/
const SESSION_CAP$1 = 32;
const SESSION_IDLE_MS = 1800 * 1e3;
const LAST_SEEN_THROTTLE_MS = 60 * 1e3;
const MAX_RPC_BODY_BYTES = 24 * 1024 * 1024;
const ALLOWED_INNER_METHODS = /* @__PURE__ */ new Set([
	"GET",
	"HEAD",
	"POST",
	"PATCH",
	"PUT",
	"DELETE"
]);
function createE2eeRoutes(deps) {
	const sessions = /* @__PURE__ */ new Map();
	const evictSession = (sid) => {
		const existing = sessions.get(sid);
		if (existing !== void 0) {
			sessions.delete(sid);
			existing.recvCipher.destroy();
			existing.sendCipher.destroy();
		}
	};
	const pruneSessions = (now) => {
		for (const [sid, entry] of sessions) if (now - entry.updatedAt > SESSION_IDLE_MS) evictSession(sid);
		while (sessions.size > SESSION_CAP$1) {
			const oldest = sessions.keys().next().value;
			if (oldest === void 0) break;
			evictSession(oldest);
		}
	};
	const evictDeviceSessions = (deviceId) => {
		let removed = 0;
		for (const [sid, entry] of [...sessions]) if (entry.deviceId === deviceId) {
			evictSession(sid);
			removed += 1;
		}
		return removed;
	};
	const isDeviceRevoked = (deviceId) => {
		return pairedDevices().find((d) => d.deviceId === deviceId)?.revoked === true;
	};
	const revokeDevice = (deviceId, revoked) => {
		const cleanId = deviceId.trim();
		if (cleanId === "") return {
			ok: false,
			error: "deviceId 不能为空"
		};
		const updated = setDeviceRevoked(cleanId, revoked);
		if (!updated.ok) return {
			ok: false,
			error: "未找到指定设备"
		};
		if (revoked) evictDeviceSessions(cleanId);
		return {
			ok: true,
			devices: updated.devices
		};
	};
	/** 单会话串行互斥锁：防止并发 RPC 乱序导致 Noise Nonce 失步。 */
	const withSessionMutex = async (entry, fn) => {
		let release;
		const prev = entry.chain;
		entry.chain = new Promise((resolve) => {
			release = resolve;
		});
		await prev;
		try {
			return await fn();
		} finally {
			release();
		}
	};
	const tryHandle = async (req, res, _url, path, method) => {
		if (path === "/api/e2ee/handshake" && method === "POST") {
			const body = await readJson(req, 64 * 1024);
			const deviceId = typeof body.deviceId === "string" ? body.deviceId.trim() : "";
			const deviceName = typeof body.deviceName === "string" ? body.deviceName.trim().slice(0, 64) : "";
			const pubKeyStr = typeof body.pubKey === "string" ? body.pubKey.trim() : "";
			const msg1Str = typeof body.msg1 === "string" ? body.msg1.trim() : "";
			if (deviceId === "" || deviceId.length > 128) {
				send(res, 400, { error: "deviceId 不合法" });
				return true;
			}
			let pubKeyBuf;
			let msg1Buf;
			try {
				pubKeyBuf = decodeBase64Flexible(pubKeyStr);
				msg1Buf = decodeBase64Flexible(msg1Str);
			} catch {
				send(res, 400, { error: "pubKey 或 msg1 不是有效的 Base64 编码" });
				return true;
			}
			if (pubKeyBuf.length !== 32 || msg1Buf.length < 96) {
				send(res, 400, { error: "pubKey 必须为 32 字节且 msg1 长度合法" });
				return true;
			}
			const canonicalPub = pubKeyBuf.toString("base64");
			const existing = pairedDevices().find((d) => d.deviceId === deviceId);
			if (existing !== void 0) {
				if (existing.revoked === true) {
					await record(deps.logFile, `403 E2EE handshake revoked device=${deviceId}`);
					send(res, 403, {
						error: "此设备已被电脑端撤销授权",
						code: "DEVICE_REVOKED"
					});
					return true;
				}
				let existingPubBuf = null;
				try {
					existingPubBuf = decodeBase64Flexible(existing.pubKey);
				} catch {
					existingPubBuf = null;
				}
				if (existingPubBuf === null || !keysEqual(existingPubBuf, pubKeyBuf)) {
					await record(deps.logFile, `403 E2EE handshake key-mismatch device=${deviceId}`);
					send(res, 403, {
						error: "设备公钥变更，请重新配对或先在电脑端移除旧设备",
						code: "DEVICE_KEY_MISMATCH"
					});
					return true;
				}
			}
			const hostId = resolveHostId();
			const { priv, pub } = resolveE2eeKeypair();
			const prologue = Buffer.from(`dsh-mobile-e2ee-v1:${hostId}:${deviceId}`, "utf8");
			let accepted;
			try {
				accepted = new NoiseResponder({
					localStaticPriv: priv,
					localStaticPub: pub,
					prologue
				}).accept(msg1Buf);
			} catch (err) {
				await record(deps.logFile, `401 E2EE handshake failed device=${deviceId}: ${err instanceof Error ? err.message : String(err)}`);
				send(res, 401, {
					error: "端到端加密握手失败",
					code: "E2EE_HANDSHAKE_FAILED"
				});
				return true;
			}
			if (!keysEqual(accepted.remoteStatic, pubKeyBuf)) {
				accepted.recvCipher.destroy();
				accepted.sendCipher.destroy();
				await record(deps.logFile, `403 E2EE handshake static-key-mismatch device=${deviceId}`);
				send(res, 403, {
					error: "设备公钥变更，请重新配对或先在电脑端移除旧设备",
					code: "DEVICE_KEY_MISMATCH"
				});
				return true;
			}
			const now = Date.now();
			upsertPairedDevice({
				deviceId,
				pubKey: canonicalPub,
				name: deviceName !== "" ? deviceName : existing?.name ?? "未命名设备",
				createdAt: existing?.createdAt ?? now,
				lastSeenAt: now,
				revoked: false
			});
			pruneSessions(now);
			while (sessions.size >= SESSION_CAP$1) {
				const oldest = sessions.keys().next().value;
				if (oldest === void 0) break;
				evictSession(oldest);
			}
			const sid = randomBytes(18).toString("base64url");
			sessions.set(sid, {
				sid,
				deviceId,
				recvCipher: accepted.recvCipher,
				sendCipher: accepted.sendCipher,
				updatedAt: now,
				lastPersistedSeenAt: now,
				chain: Promise.resolve()
			});
			await record(deps.logFile, `200 E2EE handshake device=${deviceId}`);
			send(res, 200, {
				ok: true,
				sid,
				hostId,
				msg2: accepted.msg2.toString("base64")
			});
			return true;
		}
		if (path === "/api/e2ee/rpc" && method === "POST") {
			const body = await readJson(req, MAX_RPC_BODY_BYTES);
			const sid = typeof body.sid === "string" ? body.sid.trim() : "";
			const ctStr = typeof body.ct === "string" ? body.ct.trim() : "";
			if (sid === "" || ctStr === "") {
				send(res, 400, { error: "sid 与 ct 不能为空" });
				return true;
			}
			pruneSessions(Date.now());
			const session = sessions.get(sid);
			if (session === void 0 || isDeviceRevoked(session.deviceId)) {
				if (session !== void 0) evictSession(sid);
				send(res, 401, {
					error: "加密会话已过期",
					code: "E2EE_SESSION_EXPIRED"
				});
				return true;
			}
			let ctBuf;
			try {
				ctBuf = decodeBase64Flexible(ctStr);
			} catch {
				send(res, 400, { error: "ct 不是有效的 Base64 编码" });
				return true;
			}
			await withSessionMutex(session, async () => {
				if (!sessions.has(sid) || isDeviceRevoked(session.deviceId)) {
					evictSession(sid);
					send(res, 401, {
						error: "加密会话已过期",
						code: "E2EE_SESSION_EXPIRED"
					});
					return;
				}
				let plainBuf;
				try {
					plainBuf = session.recvCipher.decrypt(ctBuf);
				} catch {
					evictSession(sid);
					await record(deps.logFile, `401 E2EE rpc decrypt failed device=${session.deviceId}`);
					send(res, 401, {
						error: "加密会话校验失败，请重新握手",
						code: "E2EE_SESSION_EXPIRED"
					});
					return;
				}
				let inner;
				try {
					const parsed = JSON.parse(plainBuf.toString("utf8"));
					if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("not an object");
					inner = parsed;
				} catch {
					send(res, 200, {
						ok: true,
						ct: session.sendCipher.encrypt(Buffer.from(JSON.stringify({
							status: 400,
							body: { error: "内部 RPC 负载必须是 JSON 对象" }
						}), "utf8")).toString("base64")
					});
					return;
				}
				const innerMethod = typeof inner.method === "string" ? inner.method.trim().toUpperCase() : "GET";
				const innerPath = typeof inner.path === "string" ? inner.path.trim() : "";
				const innerIdem = typeof inner.idem === "string" ? inner.idem.trim() : void 0;
				let result;
				if (!ALLOWED_INNER_METHODS.has(innerMethod) || !innerPath.startsWith("/")) result = {
					status: 400,
					body: { error: "内部请求 method 或 path 不合法" }
				};
				else if (innerPath === "/api/e2ee" || innerPath.startsWith("/api/e2ee/")) result = {
					status: 403,
					body: { error: "禁止递归调用 /api/e2ee/* 接口" }
				};
				else try {
					result = await deps.dispatchInternal({
						method: innerMethod,
						path: innerPath,
						body: inner.body,
						idem: innerIdem,
						outerReq: req
					});
				} catch (err) {
					result = {
						status: 500,
						body: { error: err instanceof Error ? err.message : String(err) }
					};
				}
				const doneNow = Date.now();
				session.updatedAt = doneNow;
				sessions.delete(sid);
				sessions.set(sid, session);
				if (doneNow - session.lastPersistedSeenAt >= LAST_SEEN_THROTTLE_MS) {
					session.lastPersistedSeenAt = doneNow;
					const currentDev = pairedDevices().find((d) => d.deviceId === session.deviceId);
					if (currentDev !== void 0 && currentDev.revoked !== true) upsertPairedDevice({
						...currentDev,
						lastSeenAt: doneNow
					});
				}
				const outPlain = Buffer.from(JSON.stringify({
					status: result.status,
					body: result.body
				}), "utf8");
				send(res, 200, {
					ok: true,
					ct: session.sendCipher.encrypt(outPlain).toString("base64")
				});
			});
			return true;
		}
		if (path === "/api/e2ee/devices" && method === "GET") {
			send(res, 200, {
				ok: true,
				hostId: resolveHostId(),
				e2eePub: resolveE2eeKeypair().pub,
				devices: pairedDevices()
			});
			return true;
		}
		if (path === "/api/e2ee/devices/revoke" && method === "POST") {
			const body = await readJson(req);
			const deviceId = typeof body.deviceId === "string" ? body.deviceId.trim() : "";
			if (deviceId === "" || typeof body.revoked !== "boolean") {
				send(res, 400, { error: "deviceId 必须非空且 revoked 必须为布尔值" });
				return true;
			}
			const resRevoke = revokeDevice(deviceId, body.revoked);
			if (!resRevoke.ok) {
				send(res, 404, { error: resRevoke.error });
				return true;
			}
			await record(deps.logFile, `200 E2EE device revoke device=${deviceId} revoked=${String(body.revoked)}`);
			send(res, 200, {
				ok: true,
				deviceId,
				revoked: body.revoked,
				devices: resRevoke.devices
			});
			return true;
		}
		return false;
	};
	const dispose = () => {
		for (const sid of [...sessions.keys()]) evictSession(sid);
	};
	return {
		tryHandle,
		revokeDevice,
		dispose
	};
}
//#endregion
//#region src/routes/backends.ts
function parseImagesFromBody(body) {
	const raw = Array.isArray(body.images) ? body.images : [];
	const out = [];
	for (const item of raw) {
		if (!item || typeof item !== "object") continue;
		const o = item;
		const data = typeof o.data === "string" ? o.data : typeof o.base64 === "string" ? o.base64 : "";
		const mime = typeof o.mime === "string" ? o.mime : typeof o.mediaType === "string" ? o.mediaType : "image/jpeg";
		if (data.length > 0) out.push({
			mime,
			data,
			name: typeof o.name === "string" ? o.name : void 0
		});
	}
	return out;
}
function buildAskPayload(driver, rawId) {
	const ask = driver.getAsk(rawId).pending;
	if (!ask) return {
		active: [],
		mode: "phone"
	};
	return {
		mode: "phone",
		active: [{
			callId: ask.askId,
			id: ask.askId,
			state: "pending",
			synthetic: true,
			sessionId: ask.sessionId,
			createdAt: ask.createdAt,
			questions: ask.questions.map((q, idx) => ({
				id: `q${String(idx)}`,
				header: q.header,
				prompt: q.question,
				question: q.question,
				multiSelect: q.multiSelect === true,
				options: q.options.map((o) => ({
					label: o.label,
					description: o.description ?? ""
				}))
			}))
		}]
	};
}
function createBackendRoutes(deps) {
	const activeStreamClosers = /* @__PURE__ */ new Set();
	const streamExternalSession = async (res, sessionId, rawId, driver, limit) => {
		res.writeHead(200, {
			"content-type": "text/event-stream; charset=utf-8",
			"cache-control": "no-cache, no-transform",
			connection: "keep-alive",
			"x-accel-buffering": "no"
		});
		let closed = false;
		const writeSse = (chunk) => {
			if (closed || res.writableEnded || res.destroyed) return;
			try {
				res.write(chunk);
			} catch {
				cleanup();
			}
		};
		let baseMessages = [];
		let liveAssistant = null;
		let running = driver.isRunning(rawId);
		let lastErr = null;
		const loadBase = async () => {
			try {
				const resMsg = await driver.getMessages(rawId, { limit });
				baseMessages = resMsg.messages.map((m, idx) => ({
					...m,
					seq: m.seq || idx + 1
				}));
				running = resMsg.running;
			} catch {}
		};
		const pushSnapshot = () => {
			const merged = liveAssistant ? [...baseMessages, liveAssistant] : [...baseMessages];
			const total = merged.length;
			const payload = {
				ok: true,
				sessionId,
				total,
				firstSeq: total > 0 ? merged[0]?.seq ?? 1 : 1,
				messages: merged.slice(-40),
				lastTurn: null,
				lastErr,
				running,
				context: null,
				plan: {
					active: false,
					pending: false
				},
				queue: [],
				questions: buildAskPayload(driver, rawId)
			};
			writeSse(`event: update\ndata: ${JSON.stringify(payload)}\n\n`);
		};
		const ensureLive = () => {
			if (!liveAssistant) liveAssistant = {
				seq: (baseMessages.length > 0 ? baseMessages[baseMessages.length - 1].seq : 0) + 1,
				role: "assistant",
				text: "",
				thinking: "",
				tools: [],
				time: Date.now()
			};
			return liveAssistant;
		};
		let flushTimer = null;
		const scheduleFlush = () => {
			if (flushTimer || closed) return;
			flushTimer = setTimeout(() => {
				flushTimer = null;
				pushSnapshot();
			}, 120);
		};
		const onEvent = (ev) => {
			if (closed) return;
			if (ev.type === "status") {
				running = ev.running === true;
				if (running) {
					lastErr = null;
					loadBase().then(() => pushSnapshot());
				} else pushSnapshot();
				return;
			}
			if (ev.type === "delta" && ev.text) {
				running = true;
				const a = ensureLive();
				a.text += ev.text;
				scheduleFlush();
				return;
			}
			if (ev.type === "thinking" && ev.thinking) {
				running = true;
				const a = ensureLive();
				a.thinking = (a.thinking ?? "") + ev.thinking;
				scheduleFlush();
				return;
			}
			if (ev.type === "tool") {
				running = true;
				const a = ensureLive();
				if (!a.tools) a.tools = [];
				const tid = ev.toolId || `t-${a.tools.length}`;
				const st = ev.toolStatus === "error" ? "err" : ev.toolStatus === "done" ? "ok" : "run";
				const summary = (ev.toolInput || ev.toolOutput || ev.toolName || "tool").slice(0, 200);
				const existing = a.tools.find((t) => t.id === tid);
				if (existing) {
					if (ev.toolName) existing.name = ev.toolName;
					if (summary) existing.summary = summary;
					existing.status = st;
				} else a.tools.push({
					id: tid,
					name: ev.toolName || "tool",
					summary,
					status: st
				});
				scheduleFlush();
				return;
			}
			if (ev.type === "ask") {
				pushSnapshot();
				return;
			}
			if (ev.type === "error" && ev.error) {
				lastErr = {
					code: "backend_error",
					text: ev.error,
					time: Date.now()
				};
				pushSnapshot();
				return;
			}
			if (ev.type === "done") {
				running = false;
				const finalLive = liveAssistant;
				liveAssistant = null;
				loadBase().then(() => {
					if (finalLive && finalLive.text.trim() !== "" && (baseMessages.length === 0 || baseMessages[baseMessages.length - 1]?.role !== "assistant")) baseMessages = [...baseMessages, {
						...finalLive,
						seq: baseMessages.length + 1
					}];
					pushSnapshot();
				});
			}
		};
		const unsubscribe = driver.subscribe(rawId, onEvent);
		const pingTimer = setInterval(() => {
			writeSse(": ping\n\n");
		}, 15e3);
		const cleanup = () => {
			if (closed) return;
			closed = true;
			if (flushTimer) {
				clearTimeout(flushTimer);
				flushTimer = null;
			}
			clearInterval(pingTimer);
			unsubscribe();
			activeStreamClosers.delete(cleanup);
			try {
				if (!res.writableEnded) res.end();
			} catch {}
		};
		activeStreamClosers.add(cleanup);
		res.on("close", cleanup);
		res.on("error", cleanup);
		await loadBase();
		pushSnapshot();
	};
	const tryHandle = async (req, res, url, path, method) => {
		if (path === "/api/backends" && method === "GET") {
			const refresh = url.searchParams.get("refresh") === "1";
			send(res, 200, {
				ok: true,
				backends: await deps.registry.listBackendInfos(refresh)
			});
			return true;
		}
		const toggleMatch = /^\/api\/backends\/(codex|claude|opencode|antigravity)\/toggle$/.exec(path);
		if (toggleMatch && method === "POST") {
			const id = toggleMatch[1];
			const want = (await readJson(req)).enabled === true;
			const backend = await deps.registry.toggle(id, want);
			await record(deps.logFile, `200 BACKEND toggle ${id}=${String(want)}`);
			send(res, 200, {
				ok: true,
				backend
			});
			return true;
		}
		if (path === "/api/sessions" && method === "POST") {
			const body = await readJson(req);
			const backendRaw = typeof body.backend === "string" ? body.backend.trim().toLowerCase() : "dsh";
			if (backendRaw === "" || backendRaw === "dsh") {
				req.__parsedBody = body;
				return false;
			}
			const id = backendRaw;
			const driver = deps.registry.getExternal(id);
			if (!driver) {
				send(res, 400, { error: `不支持的后端类型: ${backendRaw}` });
				return true;
			}
			if (!deps.registry.isEnabled(id)) {
				send(res, 403, { error: `${driver.label} 后端尚未开启，请先在「设置 -> Agent 引擎与协作」中开启` });
				return true;
			}
			const cwd = typeof body.cwd === "string" ? body.cwd.trim() : "";
			const title = typeof body.title === "string" ? body.title.trim() : void 0;
			const model = typeof body.model === "string" ? body.model.trim() : void 0;
			const created = await driver.createSession(cwd, {
				title,
				model
			});
			await record(deps.logFile, `200 POST create external session=${created.id}`);
			send(res, 200, {
				ok: true,
				sessionId: created.id,
				backend: id,
				session: created
			});
			return true;
		}
		if (path === "/api/models" && method === "GET") {
			const sidParam = (url.searchParams.get("sessionId") ?? "").trim();
			if (sidParam !== "") {
				const resolvedM = deps.registry.resolveBySessionId(sidParam);
				if (resolvedM.backend !== "dsh" && resolvedM.driver) {
					const msgInfo = await resolvedM.driver.getMessages(resolvedM.rawId, { limit: 1 }).catch(() => null);
					const list = await resolvedM.driver.listModels();
					const curModel = msgInfo?.model ?? "";
					send(res, 200, {
						ok: true,
						sessionId: sidParam,
						catalog: {
							current: curModel ? {
								provider: resolvedM.backend,
								model: curModel,
								reasoningEffort: ""
							} : null,
							routable: true,
							groups: list.length > 0 ? [{
								id: resolvedM.backend,
								name: resolvedM.driver.label,
								models: list.map((m) => ({
									id: m.id,
									name: m.name,
									description: m.description ?? "",
									efforts: [],
									defaultEffort: ""
								}))
							}] : [],
							failures: []
						}
					});
					return true;
				}
			}
			return false;
		}
		if (path === "/api/permissions" && method === "GET") {
			const sidParam = (url.searchParams.get("sessionId") ?? "").trim();
			if (sidParam !== "") {
				const resolvedP = deps.registry.resolveBySessionId(sidParam);
				if (resolvedP.backend !== "dsh" && resolvedP.driver) {
					send(res, 200, {
						ok: true,
						current: "",
						presets: []
					});
					return true;
				}
			}
			return false;
		}
		const sessMatch = /^\/api\/sessions\/([^/]+)(?:\/(.+))?$/.exec(path);
		if (!sessMatch) return false;
		const sessionId = decodeURIComponent(sessMatch[1]);
		const sub = sessMatch[2] ?? "";
		const resolved = deps.registry.resolveBySessionId(sessionId);
		if (resolved.backend === "dsh" || !resolved.driver) return false;
		const driver = resolved.driver;
		const rawId = resolved.rawId;
		if (!deps.registry.isEnabled(resolved.backend)) {
			send(res, 403, { error: `${driver.label} 后端已关闭` });
			return true;
		}
		if (sub === "messages" && method === "GET") {
			const limit = Number(url.searchParams.get("limit") ?? "50");
			const sinceRaw = url.searchParams.get("since");
			const since = sinceRaw !== null && sinceRaw !== "" ? Number(sinceRaw) : NaN;
			const compact = url.searchParams.get("compact") === "1";
			const data = await driver.getMessages(rawId, {
				limit: Number.isFinite(limit) && limit > 0 ? limit : 50,
				compact
			});
			const allMsgs = data.messages.map((m, idx) => ({
				...m,
				seq: m.seq || idx + 1
			}));
			const msgs = Number.isFinite(since) && since >= 0 ? allMsgs.filter((m) => m.seq > since) : allMsgs;
			const firstSeq = allMsgs.length > 0 ? allMsgs[0]?.seq ?? 1 : 1;
			send(res, 200, {
				ok: true,
				sessionId,
				backend: resolved.backend,
				capabilities: driver.capabilities,
				total: data.total,
				firstSeq,
				hasMore: data.hasMore,
				messages: msgs,
				running: data.running,
				model: data.model ? {
					provider: resolved.backend,
					model: data.model
				} : null,
				cwd: data.cwd ?? "",
				context: null,
				plan: {
					active: false,
					pending: false
				},
				queue: [],
				questions: buildAskPayload(driver, rawId),
				lastTurn: null,
				lastErr: null
			});
			return true;
		}
		if ((sub === "messages" || sub === "send" || sub === "outbox") && method === "POST") {
			const body = await readJson(req);
			const text = typeof body.text === "string" ? body.text : typeof body.content === "string" ? body.content : "";
			const images = parseImagesFromBody(body);
			const model = typeof body.model === "string" ? body.model.trim() : void 0;
			const cwd = typeof body.cwd === "string" ? body.cwd.trim() : void 0;
			const result = await driver.sendMessage(rawId, text, {
				images,
				model,
				cwd
			});
			await record(deps.logFile, `200 POST send external session=${sessionId}`);
			send(res, 200, {
				...result,
				parts: (text.trim() !== "" ? 1 : 0) + images.length
			});
			return true;
		}
		if (sub === "stream/sign" && method === "POST") {
			const exp = String(Math.floor(Date.now() / 1e3) + deps.sigTtlSec);
			send(res, 200, {
				ok: true,
				e: exp,
				sig: deps.sigOf("stream", sessionId, exp)
			});
			return true;
		}
		if (sub === "stream" && method === "GET") {
			const limit = Number(url.searchParams.get("limit") ?? "50");
			await streamExternalSession(res, sessionId, rawId, driver, Number.isFinite(limit) && limit > 0 ? limit : 50);
			return true;
		}
		if ((sub === "abort" || sub === "stop") && method === "POST") {
			await driver.abort(rawId);
			send(res, 200, {
				ok: true,
				accepted: true
			});
			return true;
		}
		if (sub === "ask" && method === "GET") {
			send(res, 200, {
				ok: true,
				...buildAskPayload(driver, rawId)
			});
			return true;
		}
		if ((sub === "ask" || sub === "questions/answer") && method === "POST") {
			const body = await readJson(req);
			const askId = typeof body.callId === "string" ? body.callId : typeof body.askId === "string" ? body.askId : typeof body.id === "string" ? body.id : "";
			const answers = {};
			if (Array.isArray(body.answers)) for (const item of body.answers) {
				if (!item || typeof item !== "object") continue;
				const a = item;
				const qid = typeof a.id === "string" ? a.id : "q0";
				const sel = Array.isArray(a.selected) && a.selected.length > 0 ? String(a.selected[0]) : "";
				const txt = typeof a.text === "string" ? a.text : "";
				answers[qid] = sel || txt;
			}
			else if (body.answers && typeof body.answers === "object") for (const [k, v] of Object.entries(body.answers)) answers[k] = typeof v === "string" ? v : Array.isArray(v) ? String(v[0] ?? "") : String(v ?? "");
			const ok = await driver.answerAsk(rawId, askId, answers);
			send(res, ok ? 200 : 404, ok ? { ok: true } : { error: "未找到待处理的审批请求" });
			return true;
		}
		if (sub === "models" && method === "GET") {
			const msgInfo = await driver.getMessages(rawId, { limit: 1 }).catch(() => null);
			const list = await driver.listModels();
			const curModel = msgInfo?.model ?? "";
			send(res, 200, {
				ok: true,
				current: curModel ? {
					provider: resolved.backend,
					model: curModel
				} : null,
				catalog: list.length > 0 ? [{
					id: resolved.backend,
					name: driver.label,
					models: list.map((m) => ({
						id: m.id,
						name: m.name,
						provider: m.provider,
						description: m.description ?? ""
					}))
				}] : []
			});
			return true;
		}
		if (sub === "model" && method === "POST") {
			const body = await readJson(req);
			const model = typeof body.model === "string" ? body.model.trim() : "";
			if (!driver.setModel || !model) {
				send(res, 400, { error: `${driver.label} 暂不支持运行时切换模型` });
				return true;
			}
			if (!await driver.setModel(rawId, model)) {
				send(res, 400, { error: `${driver.label} 暂不支持运行时切换模型` });
				return true;
			}
			send(res, 200, {
				ok: true,
				model: {
					provider: resolved.backend,
					model
				}
			});
			return true;
		}
		if (sub === "commands" && method === "GET") {
			send(res, 200, {
				ok: true,
				commands: []
			});
			return true;
		}
		if (sub === "stats" && method === "GET") {
			const msgs = (await driver.getMessages(rawId, { limit: 200 }).catch(() => null))?.messages ?? [];
			let userMsgs = 0;
			let assistantMsgs = 0;
			let toolCalls = 0;
			for (const m of msgs) if (m.role === "user") userMsgs++;
			else {
				assistantMsgs++;
				toolCalls += m.tools?.length ?? 0;
			}
			send(res, 200, {
				ok: true,
				stats: {
					turns: assistantMsgs,
					userMsgs,
					assistantMsgs,
					toolCalls,
					tokens: {
						uncachedInputTokens: 0,
						outputTokens: 0,
						cacheReadTokens: 0,
						cacheWriteTokens: 0
					}
				}
			});
			return true;
		}
		if (sub === "team" && method === "GET") {
			send(res, 200, {
				ok: true,
				enabled: false,
				sawMode: false,
				members: [],
				tasks: []
			});
			return true;
		}
		if (sub === "goal" && method === "GET") {
			send(res, 200, {
				ok: true,
				goal: null
			});
			return true;
		}
		send(res, 400, { error: `${driver.label} 暂不支持该操作 (${sub || method})` });
		return true;
	};
	return {
		tryHandle,
		disposeStreams: () => {
			for (const close of Array.from(activeStreamClosers)) close();
		}
	};
}
//#endregion
//#region src/routes/git.ts
/**
* Git 状态与 Unified Diff 路由（G5）：
* - `GET /api/sessions/:id/git/status`
* - `GET /api/sessions/:id/git/diff?path=<rel>&staged=0|1`
* 所有子进程调用强制 `windowsHide: true`。
*/
const MAX_DIFF_BYTES = 200 * 1024;
function runGit(cwd, args, timeout = 5e3) {
	return new Promise((resolvePromise) => {
		execFile("git", args, {
			cwd,
			windowsHide: true,
			timeout,
			maxBuffer: 2 * 1024 * 1024,
			encoding: "utf8"
		}, (error, stdout, stderr) => {
			if (error !== null) {
				resolvePromise({
					code: typeof error.code === "number" ? error.code : 1,
					stdout: String(stdout ?? ""),
					stderr: String(stderr ?? error.message)
				});
				return;
			}
			resolvePromise({
				code: 0,
				stdout: String(stdout ?? ""),
				stderr: String(stderr ?? "")
			});
		});
	});
}
/** 解码 Git porcelain C 风格转义路径（如八进制 UTF-8 字节与引号）。 */
function unquoteGitPath(raw) {
	const s = raw.trim();
	if (!s.startsWith("\"") || !s.endsWith("\"") || s.length < 2) return s;
	const inner = s.slice(1, -1);
	const bytes = [];
	for (let i = 0; i < inner.length; i += 1) {
		const ch = inner[i];
		if (ch === "\\" && i + 1 < inner.length) {
			const next = inner[i + 1];
			if (next >= "0" && next <= "7" && i + 3 < inner.length) {
				const oct = inner.slice(i + 1, i + 4);
				if (/^[0-7]{3}$/.test(oct)) {
					bytes.push(Number.parseInt(oct, 8));
					i += 3;
					continue;
				}
			}
			i += 1;
			bytes.push({
				n: 10,
				r: 13,
				t: 9,
				"\\": 92,
				"\"": 34
			}[next] ?? next.charCodeAt(0));
			continue;
		}
		const encoded = Buffer.from(ch, "utf8");
		for (const b of encoded) bytes.push(b);
	}
	return Buffer.from(bytes).toString("utf8");
}
function parsePorcelainStatus(output) {
	let branch = "";
	let ahead = 0;
	let behind = 0;
	const files = [];
	for (const rawLine of output.split(/\r?\n/)) {
		if (rawLine.length === 0) continue;
		if (rawLine.startsWith("## ")) {
			let head = rawLine.slice(3).trim();
			const bracketMatch = /\[([^\]]+)\]$/.exec(head);
			if (bracketMatch !== null) {
				const meta = bracketMatch[1] ?? "";
				const aMatch = /ahead\s+(\d+)/.exec(meta);
				const bMatch = /behind\s+(\d+)/.exec(meta);
				if (aMatch !== null) ahead = Number.parseInt(aMatch[1] ?? "0", 10) || 0;
				if (bMatch !== null) behind = Number.parseInt(bMatch[1] ?? "0", 10) || 0;
				head = head.slice(0, bracketMatch.index).trim();
			}
			const initMatch = /^(?:No commits yet on|Initial commit on)\s+(.+)$/.exec(head);
			if (initMatch !== null) branch = (initMatch[1] ?? "").trim();
			else branch = (head.split("...")[0] ?? "").trim();
			continue;
		}
		if (rawLine.length < 4) continue;
		const x = rawLine[0] ?? " ";
		const y = rawLine[1] ?? " ";
		const xy = `${x}${y}`.trim() || "?";
		let targetPath = rawLine.slice(3);
		if ((x === "R" || x === "C" || y === "R" || y === "C") && targetPath.includes(" -> ")) {
			const parts = targetPath.split(" -> ");
			targetPath = parts[parts.length - 1] ?? targetPath;
		}
		const cleanPath = unquoteGitPath(targetPath);
		const staged = x !== " " && x !== "?" && x !== "!";
		files.push({
			path: cleanPath,
			status: xy,
			staged
		});
	}
	return {
		branch,
		ahead,
		behind,
		files
	};
}
/** 为未跟踪文本文件拼装标准新文件 Unified Diff。 */
function buildUntrackedDiff(filePath, displayRel) {
	const norm = displayRel.replace(/\\/g, "/");
	let size = 0;
	try {
		const st = statSync(filePath);
		if (!st.isFile()) return "";
		size = st.size;
	} catch {
		return "";
	}
	const readLen = Math.min(size, 208896);
	const buf = Buffer.allocUnsafe(readLen);
	let fd;
	let actual = 0;
	try {
		fd = openSync(filePath, "r");
		actual = readSync(fd, buf, 0, readLen, 0);
	} catch {
		return "";
	} finally {
		if (fd !== void 0) try {
			closeSync(fd);
		} catch {}
	}
	const slice = buf.subarray(0, actual);
	if (slice.indexOf(0) >= 0) return `diff --git a/${norm} b/${norm}\nnew file mode 100644\nBinary files /dev/null and b/${norm} differ\n`;
	const text = slice.toString("utf8");
	if (text.length === 0) return `diff --git a/${norm} b/${norm}\nnew file mode 100644\n--- /dev/null\n+++ b/${norm}\n`;
	const rawLines = text.replace(/\r\n/g, "\n").split("\n");
	if (rawLines.length > 0 && rawLines[rawLines.length - 1] === "") rawLines.pop();
	const added = rawLines.map((l) => `+${l}`).join("\n");
	return [
		`diff --git a/${norm} b/${norm}`,
		"new file mode 100644",
		"--- /dev/null",
		`+++ b/${norm}`,
		`@@ -0,0 +1,${String(rawLines.length)} @@`,
		added,
		""
	].join("\n");
}
/** 按 UTF-8 安全字节边界截断到最多 200 KB。 */
function truncateUtf8(text, maxBytes) {
	const buf = Buffer.from(text, "utf8");
	if (buf.length <= maxBytes) return {
		text,
		truncated: false
	};
	let sliced = buf.subarray(0, maxBytes).toString("utf8");
	if (sliced.endsWith("�")) sliced = sliced.slice(0, -1);
	return {
		text: sliced,
		truncated: true
	};
}
function createGitRoutes(fsHelper) {
	const tryHandle = async (_req, res, url, path, method) => {
		const statusMatch = /^\/api\/sessions\/([^/]+)\/git\/status$/.exec(path);
		if (statusMatch !== null && method === "GET") {
			const sid = decodeURIComponent(statusMatch[1]);
			const picked = await fsHelper.rootOf(sid);
			if (picked.root === "" || !existsSync(picked.root)) {
				send(res, 200, {
					ok: true,
					isRepo: false,
					branch: "",
					ahead: 0,
					behind: 0,
					files: []
				});
				return true;
			}
			const out = await runGit(picked.root, [
				"status",
				"--porcelain=v1",
				"-b"
			], 5e3);
			if (out.code !== 0) {
				send(res, 200, {
					ok: true,
					isRepo: false,
					branch: "",
					ahead: 0,
					behind: 0,
					files: []
				});
				return true;
			}
			const parsed = parsePorcelainStatus(out.stdout);
			send(res, 200, {
				ok: true,
				isRepo: true,
				branch: parsed.branch,
				ahead: parsed.ahead,
				behind: parsed.behind,
				files: parsed.files
			});
			return true;
		}
		const diffMatch = /^\/api\/sessions\/([^/]+)\/git\/diff$/.exec(path);
		if (diffMatch !== null && method === "GET") {
			const sid = decodeURIComponent(diffMatch[1]);
			const rel = String(url.searchParams.get("path") ?? "").trim();
			if (rel === "") {
				send(res, 400, { error: "path is required" });
				return true;
			}
			const staged = url.searchParams.get("staged") === "1" || url.searchParams.get("staged") === "true";
			const picked = await fsHelper.rootOf(sid);
			if (picked.root === "") {
				send(res, 404, { error: "session has no working directory" });
				return true;
			}
			const target = fsHelper.underRoot(picked.root, rel);
			if (target === null) {
				send(res, 400, { error: "path escapes the working directory" });
				return true;
			}
			const args = staged ? [
				"diff",
				"--cached",
				"--no-ext-diff",
				"--no-color",
				"--",
				rel
			] : [
				"diff",
				"--no-ext-diff",
				"--no-color",
				"--",
				rel
			];
			const resDiff = await runGit(picked.root, args, 5e3);
			let diffText = resDiff.code === 0 ? resDiff.stdout : "";
			if (!staged && diffText.length === 0 && existsSync(target)) {
				const stOut = await runGit(picked.root, [
					"status",
					"--porcelain=v1",
					"--",
					rel
				], 4e3);
				if (stOut.code === 0 && stOut.stdout.trimStart().startsWith("??")) diffText = buildUntrackedDiff(target, rel);
			}
			const capped = truncateUtf8(diffText, MAX_DIFF_BYTES);
			send(res, 200, {
				ok: true,
				path: rel,
				diff: capped.text,
				truncated: capped.truncated
			});
			return true;
		}
		return false;
	};
	return { tryHandle };
}
//#endregion
//#region src/routes/host-extras.ts
/**
* 宿主扩展能力路由：
* - `GET /api/host/plugins`、`POST /api/host/plugins/toggle`
* - `GET / POST /api/host/plugins/settings`（R5 插件配置读写，屏蔽 dsh-mobile 与敏感字段）
* - `GET /api/host/schedules`、`POST /api/host/schedules/:id/action`
* - `GET /api/loopback/ports`、`POST /api/loopback/sign`、`GET|HEAD /api/loopback/:port/...`（R9 本机开发服预览代理）
*/
const PROFILE_DIR_NAME = /^[A-Za-z0-9._-]{1,64}$/;
const BUNDLE_NAME = /^(@[A-Za-z0-9._-]{1,64}\/)?[A-Za-z0-9._-]{1,120}$/;
const CONFIG_KEY_RE = /^[A-Za-z0-9._-]{1,64}$/;
const SENSITIVE_KEY_RE = /token|key|secret|password/i;
function isSelfMobilePlugin(name, rowId = "") {
	const lower = name.toLowerCase();
	return lower === "@deepseek-ai/dsh-mobile" || lower === "dsh-mobile" || lower.endsWith("/dsh-mobile") || rowId.toLowerCase() === "mobile";
}
/** 解析单行 YAML 标量值（仅接受安全扁平 boolean / number / string，拒绝 `!!js` 与复杂容器）。 */
function parseYamlScalar(rawVal) {
	let v = rawVal.trim();
	if (v === "") return {
		kind: "string",
		value: ""
	};
	if (v.startsWith("!!") || v.startsWith("[") || v.startsWith("{") || v === "|" || v === ">" || v === ">-" || v === "|-") return null;
	if (!v.startsWith("\"") && !v.startsWith("'")) {
		const hashAt = v.indexOf(" #");
		if (hashAt >= 0) v = v.slice(0, hashAt).trim();
	}
	if (v === "true" || v === "false") return {
		kind: "boolean",
		value: v
	};
	if (/^-?(?:0|[1-9]\d*)(?:\.\d+)?$/.test(v)) {
		const n = Number(v);
		if (Number.isFinite(n)) return {
			kind: "number",
			value: String(n)
		};
	}
	if (v.startsWith("'") && v.endsWith("'") && v.length >= 2) return {
		kind: "string",
		value: v.slice(1, -1).replace(/''/g, "'")
	};
	if (v.startsWith("\"") && v.endsWith("\"") && v.length >= 2) try {
		const parsed = JSON.parse(v);
		if (typeof parsed === "string") return {
			kind: "string",
			value: parsed
		};
	} catch {
		return {
			kind: "string",
			value: v.slice(1, -1)
		};
	}
	return {
		kind: "string",
		value: v
	};
}
function formatYamlScalar(kind, rawValue) {
	if (kind === "boolean") {
		if (typeof rawValue === "boolean") return String(rawValue);
		const s = String(rawValue).trim().toLowerCase();
		if (s !== "true" && s !== "false") throw new Error("布尔配置项的值只能为 true 或 false");
		return s;
	}
	if (kind === "number") {
		const n = typeof rawValue === "number" ? rawValue : Number(String(rawValue).trim());
		if (!Number.isFinite(n)) throw new Error("数值配置项必须是有效数字");
		return String(n);
	}
	const str = String(rawValue ?? "");
	if (/[\r\n]/.test(str)) throw new Error("字符串配置项不支持多行换行");
	return `'${str.replace(/'/g, "''")}'`;
}
/**
* 解析 `cordis.patch.yml` 中的条目及其 `config:` 块（同时支持顶层 `- id: xxx` 与 `- insert:` 内嵌条目）。
*/
function parseCordisPatchRows(text) {
	const lines = text.replace(/\r\n/g, "\n").split("\n");
	const rows = [];
	const unquoteSimple = (s) => {
		const t = s.trim().replace(/\s+#.*$/, "");
		if (t.startsWith("'") && t.endsWith("'") || t.startsWith("\"") && t.endsWith("\"")) return t.slice(1, -1);
		return t;
	};
	let i = 0;
	while (i < lines.length) {
		const line = lines[i];
		const dashMatch = /^(\s*)-\s+(.*)$/.exec(line);
		if (dashMatch === null) {
			i += 1;
			continue;
		}
		const itemIndent = (dashMatch[1] ?? "").length;
		const firstRest = (dashMatch[2] ?? "").trim();
		if (/^insert\s*:\s*(?:#.*)?$/.test(firstRest)) {
			i += 1;
			continue;
		}
		let endLine = i + 1;
		while (endLine < lines.length) {
			const probe = lines[endLine];
			const trimmed = probe.trim();
			if (trimmed === "" || trimmed.startsWith("#")) {
				endLine += 1;
				continue;
			}
			if ((probe.match(/^\s*/)?.[0] ?? "").length <= itemIndent) break;
			endLine += 1;
		}
		let id = "";
		let name = "";
		let configLine = -1;
		let configIndent = itemIndent + 2;
		const scalars = /* @__PURE__ */ new Map();
		const rawKeys = /* @__PURE__ */ new Set();
		const firstKv = /^([A-Za-z0-9._-]+)\s*:\s*(.*)$/.exec(firstRest);
		if (firstKv !== null) {
			const k = firstKv[1] ?? "";
			const v = firstKv[2] ?? "";
			if (k === "id") id = unquoteSimple(v);
			else if (k === "name") name = unquoteSimple(v);
		}
		const propIndent = itemIndent + 2;
		for (let j = i + 1; j < endLine; j += 1) {
			const sub = lines[j];
			const trimmed = sub.trim();
			if (trimmed === "" || trimmed.startsWith("#")) continue;
			if ((sub.match(/^\s*/)?.[0] ?? "").length === propIndent) {
				const kv = /^([A-Za-z0-9._-]+)\s*:\s*(.*)$/.exec(trimmed);
				if (kv !== null) {
					const k = kv[1] ?? "";
					const v = kv[2] ?? "";
					if (k === "id") id = unquoteSimple(v);
					else if (k === "name") name = unquoteSimple(v);
					else if (k === "config" && (v.trim() === "" || v.trim().startsWith("#"))) configLine = j;
				}
			}
		}
		if (configLine >= 0) {
			let detectedIndent = -1;
			for (let j = configLine + 1; j < endLine; j += 1) {
				const sub = lines[j];
				const trimmed = sub.trim();
				if (trimmed === "" || trimmed.startsWith("#")) continue;
				const indent = (sub.match(/^\s*/)?.[0] ?? "").length;
				if (indent <= propIndent) break;
				if (detectedIndent < 0) detectedIndent = indent;
				if (indent !== detectedIndent) continue;
				const kv = /^([A-Za-z0-9._-]+)\s*:\s*(.*)$/.exec(trimmed);
				if (kv === null) continue;
				const key = kv[1] ?? "";
				const valText = kv[2] ?? "";
				rawKeys.add(key);
				const parsed = parseYamlScalar(valText);
				if (parsed !== null) scalars.set(key, {
					...parsed,
					lineIndex: j
				});
			}
			configIndent = detectedIndent > propIndent ? detectedIndent : propIndent + 2;
		}
		if (id !== "" || name !== "") rows.push({
			id,
			name,
			startLine: i,
			endLine,
			itemIndent,
			configLine,
			configIndent,
			scalars,
			rawKeys
		});
		i = endLine;
	}
	return {
		lines,
		rows
	};
}
/** 定位已安装插件包自身的 `cordis.patch.yml` 并提取其默认 row `id` 与初始标量配置。 */
function inspectInstalledPluginMeta(profileDir, pkgName, depSpec) {
	const defaults = /* @__PURE__ */ new Map();
	const candidates = [];
	if (depSpec.startsWith("link:")) candidates.push(resolve(profileDir, depSpec.slice(5)));
	candidates.push(join(profileDir, "node_modules", ...pkgName.split("/")));
	for (const dir of candidates) {
		const patchFile = join(dir, "cordis.patch.yml");
		if (!existsSync(patchFile)) continue;
		try {
			const { rows } = parseCordisPatchRows(readFileSync(patchFile, "utf8"));
			const matched = rows.find((r) => r.name === pkgName) ?? rows[0];
			if (matched !== void 0) {
				for (const [k, v] of matched.scalars) defaults.set(k, {
					kind: v.kind,
					value: v.value
				});
				return {
					rowId: matched.id,
					defaults
				};
			}
		} catch {}
	}
	const short = pkgName.includes("/") ? pkgName.split("/").pop() ?? pkgName : pkgName;
	return {
		rowId: short.startsWith("dsh-") ? short.slice(4) : short,
		defaults
	};
}
function createHostExtrasRoutes(deps) {
	/** 校验 `/api/loopback/:port/...` 是否携带有效的 5 分钟短签名（查询参数或同路径限定 Cookie）。 */
	const verifyLoopbackSig = (portStr, exp, sig) => {
		if (exp === "" || sig === "") return false;
		const expN = Number(exp);
		if (!Number.isFinite(expN) || expN < Math.floor(Date.now() / 1e3)) return false;
		return tokenMatches(deps.sigOf("loopback", portStr, exp), sig.toLowerCase());
	};
	const parseCookies = (cookieHeader) => {
		if (typeof cookieHeader !== "string" || cookieHeader === "") return {};
		const out = {};
		for (const seg of cookieHeader.split(";")) {
			const eq = seg.indexOf("=");
			if (eq <= 0) continue;
			const k = seg.slice(0, eq).trim();
			const v = seg.slice(eq + 1).trim();
			if (k !== "") out[k] = v;
		}
		return out;
	};
	const isLoopbackAuthorized = (req, url, path, method) => {
		if (method !== "GET" && method !== "HEAD") return false;
		const m = /^\/api\/loopback\/(\d+)(?:\/|$)/.exec(path);
		if (m === null) return false;
		const portStr = m[1];
		const portNum = Number.parseInt(portStr, 10);
		if (!previewPorts().includes(portNum)) return false;
		const qExp = url.searchParams.get("e") ?? "";
		const qSig = url.searchParams.get("sig") ?? "";
		if (verifyLoopbackSig(portStr, qExp, qSig)) return true;
		const tokenCookie = parseCookies(req.headers.cookie)[`dsh_lb_${portStr}`] ?? "";
		const dot = tokenCookie.indexOf(".");
		if (dot > 0) {
			const cExp = tokenCookie.slice(0, dot);
			const cSig = tokenCookie.slice(dot + 1);
			if (verifyLoopbackSig(portStr, cExp, cSig)) return true;
		}
		return false;
	};
	const setLoopbackCookieIfSigned = (res, url, path) => {
		const m = /^\/api\/loopback\/(\d+)(?:\/|$)/.exec(path);
		if (m === null) return;
		const portStr = m[1];
		const qExp = url.searchParams.get("e") ?? "";
		const qSig = (url.searchParams.get("sig") ?? "").toLowerCase();
		if (verifyLoopbackSig(portStr, qExp, qSig)) res.setHeader("set-cookie", `dsh_lb_${portStr}=${qExp}.${qSig}; Path=/api/loopback/${portStr}; Max-Age=${String(deps.sigTtlSec)}; HttpOnly; SameSite=Lax`);
	};
	const tryHandle = async (req, res, url, path, method) => {
		if (path === "/api/loopback/ports" && method === "GET") {
			send(res, 200, {
				ok: true,
				ports: previewPorts()
			});
			return true;
		}
		if (path === "/api/loopback/sign" && method === "POST") {
			const body = await readJson(req);
			const portNum = Number(body.port);
			if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) {
				send(res, 400, { error: "port 必须是 1..65535 的整数" });
				return true;
			}
			if (!previewPorts().includes(portNum)) {
				send(res, 403, { error: `端口 ${String(portNum)} 未在电脑端授权预览白名单中` });
				return true;
			}
			const exp = String(Math.floor(Date.now() / 1e3) + deps.sigTtlSec);
			send(res, 200, {
				ok: true,
				port: portNum,
				e: exp,
				sig: deps.sigOf("loopback", String(portNum), exp)
			});
			return true;
		}
		const loopbackMatch = /^\/api\/loopback\/(\d+)(\/.*)?$/.exec(path);
		if (loopbackMatch !== null) {
			if (method !== "GET" && method !== "HEAD") {
				send(res, 405, { error: "本机预览代理仅允许 GET 与 HEAD 请求" });
				return true;
			}
			const portNum = Number.parseInt(loopbackMatch[1], 10);
			if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535 || !previewPorts().includes(portNum)) {
				send(res, 403, { error: `端口 ${String(portNum)} 未在电脑端授权预览白名单中` });
				return true;
			}
			setLoopbackCookieIfSigned(res, url, path);
			const subPath = loopbackMatch[2] && loopbackMatch[2].length > 0 ? loopbackMatch[2] : "/";
			const cleanParams = new URLSearchParams(url.searchParams);
			cleanParams.delete("t");
			cleanParams.delete("e");
			cleanParams.delete("sig");
			const qs = cleanParams.toString();
			const upstreamPath = qs === "" ? subPath : `${subPath}?${qs}`;
			const forwardHeaders = {};
			for (const [k, v] of Object.entries(req.headers)) {
				if (v === void 0) continue;
				const lower = k.toLowerCase();
				if (lower === "host" || lower === "authorization" || lower === "connection" || lower === "cookie") continue;
				forwardHeaders[k] = v;
			}
			forwardHeaders.host = `127.0.0.1:${String(portNum)}`;
			await new Promise((resolveDone) => {
				const proxyReq = request({
					host: "127.0.0.1",
					port: portNum,
					method,
					path: upstreamPath,
					headers: forwardHeaders,
					timeout: 15e3
				}, (proxyRes) => {
					const status = proxyRes.statusCode ?? 502;
					const rawLoc = proxyRes.headers.location;
					const outHeaders = {};
					for (const [hk, hv] of Object.entries(proxyRes.headers)) {
						if (hv === void 0) continue;
						const lower = hk.toLowerCase();
						if (lower === "transfer-encoding" || lower === "connection" || lower === "location") continue;
						outHeaders[hk] = hv;
					}
					if (typeof rawLoc === "string" && rawLoc.length > 0 && status >= 300 && status < 400) try {
						const resolved = new URL(rawLoc, `http://127.0.0.1:${String(portNum)}${upstreamPath}`);
						const rHost = resolved.hostname.toLowerCase();
						const rPort = resolved.port === "" ? resolved.protocol === "https:" ? 443 : 80 : Number(resolved.port);
						if (resolved.protocol !== "http:" || rHost !== "127.0.0.1" && rHost !== "localhost" || rPort !== portNum) {
							proxyRes.resume();
							send(res, 502, { error: "已拦截本机开发服向外部主机或非授权端口的重定向" });
							resolveDone();
							return;
						}
						outHeaders.location = `/api/loopback/${String(portNum)}${resolved.pathname}${resolved.search}`;
					} catch {
						proxyRes.resume();
						send(res, 502, { error: "无效的上游重定向地址" });
						resolveDone();
						return;
					}
					res.writeHead(status, outHeaders);
					if (method === "HEAD") {
						proxyRes.resume();
						res.end();
						resolveDone();
						return;
					}
					proxyRes.on("error", () => {
						res.destroy();
						resolveDone();
					});
					res.on("close", () => {
						proxyRes.destroy();
						resolveDone();
					});
					proxyRes.pipe(res);
					proxyRes.on("end", () => resolveDone());
				});
				proxyReq.on("timeout", () => {
					proxyReq.destroy(/* @__PURE__ */ new Error("upstream timeout"));
				});
				proxyReq.on("error", (err) => {
					send(res, 502, { error: `无法连接本机端口 ${String(portNum)}：${err.message}` });
					resolveDone();
				});
				res.on("close", () => {
					if (!res.writableEnded) proxyReq.destroy();
				});
				proxyReq.end();
			});
			return true;
		}
		if (path === "/api/host/plugins" && method === "GET") {
			const profilesDir = join(dshHome(), "profiles");
			const groups = [];
			let profiles = [];
			try {
				profiles = readdirSync(profilesDir);
			} catch {
				profiles = [];
			}
			for (const profile of profiles) {
				let raw = "";
				try {
					raw = readFileSync(join(profilesDir, profile, "package.json"), "utf8");
				} catch {
					continue;
				}
				let bag;
				try {
					bag = JSON.parse(raw);
				} catch {
					continue;
				}
				const depsMap = typeof bag.dependencies === "object" && bag.dependencies !== null ? bag.dependencies : {};
				const dsh = typeof bag.dsh === "object" && bag.dsh !== null ? bag.dsh : {};
				const prof = typeof dsh.profile === "object" && dsh.profile !== null ? dsh.profile : {};
				const bundles = Array.isArray(prof.bundles) ? prof.bundles.map((x) => String(x)) : [];
				const items = Object.keys(depsMap).map((dep) => {
					const version = String(depsMap[dep] ?? "");
					return {
						name: dep,
						version,
						enabled: bundles.indexOf(dep) >= 0,
						local: version.startsWith("link:")
					};
				});
				items.sort((a, b) => a.enabled === b.enabled ? a.name.localeCompare(b.name) : a.enabled ? -1 : 1);
				groups.push({
					profile,
					items
				});
			}
			send(res, 200, {
				ok: true,
				groups
			});
			return true;
		}
		if (path === "/api/host/plugins/toggle" && method === "POST") {
			let body;
			try {
				body = await readJson(req);
			} catch (error) {
				send(res, typeof error.status === "number" ? error.status : 400, { error: `请求体不是合法 JSON：${error instanceof Error ? error.message : String(error)}` });
				return true;
			}
			const profile = String(body.profile ?? "").trim();
			const name = String(body.name ?? "").trim();
			if (!PROFILE_DIR_NAME.test(profile)) {
				send(res, 400, { error: "profile 名字不合法" });
				return true;
			}
			if (!BUNDLE_NAME.test(name)) {
				send(res, 400, { error: "插件名不合法" });
				return true;
			}
			if (typeof body.enabled !== "boolean") {
				send(res, 400, { error: "enabled 必须是布尔值" });
				return true;
			}
			const enabled = body.enabled;
			const file = join(dshHome(), "profiles", profile, "package.json");
			let raw = "";
			try {
				raw = readFileSync(file, "utf8");
			} catch {
				send(res, 404, { error: `找不到 profile ${profile} 的 package.json` });
				return true;
			}
			let bag;
			try {
				bag = JSON.parse(raw);
			} catch {
				send(res, 500, { error: `profile ${profile} 的 package.json 不是合法 JSON，先手动修好再开开关` });
				return true;
			}
			if (typeof (typeof bag.dependencies === "object" && bag.dependencies !== null ? bag.dependencies : {})[name] !== "string") {
				send(res, 400, { error: `${name} 不在 profile ${profile} 的依赖里，这里只能开关已安装的插件` });
				return true;
			}
			const dsh = typeof bag.dsh === "object" && bag.dsh !== null ? bag.dsh : {};
			const prof = typeof dsh.profile === "object" && dsh.profile !== null ? dsh.profile : {};
			const current = Array.isArray(prof.bundles) ? prof.bundles.map((x) => String(x)) : [];
			if (current.indexOf(name) >= 0 === enabled) {
				await record(deps.logFile, `200 POST plugin-toggle ${profile}/${name} enabled=${String(enabled)} changed=false`);
				send(res, 200, {
					ok: true,
					profile,
					name,
					enabled,
					changed: false,
					restartRequired: false
				});
				return true;
			}
			const nextBundles = enabled ? current.concat([name]) : current.filter((x) => x !== name);
			bag.dsh = {
				...dsh,
				profile: {
					...prof,
					bundles: nextBundles
				}
			};
			const text = `${JSON.stringify(bag, null, 2)}\n`;
			try {
				writeFileSync(`${file}.bak`, raw, "utf8");
				atomicWriteSync(file, text);
			} catch (error) {
				const message = error instanceof Error ? error.message : String(error);
				await record(deps.logFile, `500 POST plugin-toggle ${profile}/${name} write failed: ${message}`);
				send(res, 500, { error: `写 profile 清单失败：${message}` });
				return true;
			}
			await record(deps.logFile, `200 POST plugin-toggle ${profile}/${name} enabled=${String(enabled)} changed=true`);
			send(res, 200, {
				ok: true,
				profile,
				name,
				enabled,
				changed: true,
				restartRequired: true
			});
			return true;
		}
		if (path === "/api/host/plugins/settings" && (method === "GET" || method === "POST")) {
			const body = method === "POST" ? await readJson(req) : {};
			const profile = String(method === "GET" ? url.searchParams.get("profile") ?? "" : body.profile ?? "").trim();
			const pkgName = String(method === "GET" ? url.searchParams.get("name") ?? "" : body.name ?? "").trim();
			if (!PROFILE_DIR_NAME.test(profile)) {
				send(res, 400, { error: "profile 名字不合法" });
				return true;
			}
			if (!BUNDLE_NAME.test(pkgName)) {
				send(res, 400, { error: "插件包名不合法" });
				return true;
			}
			if (isSelfMobilePlugin(pkgName)) {
				if (method === "POST") {
					send(res, 403, { error: "禁止修改 dsh-mobile 自身配置" });
					return true;
				}
				send(res, 200, {
					ok: true,
					writable: false,
					fields: []
				});
				return true;
			}
			const profileDir = join(dshHome(), "profiles", profile);
			const pkgJsonFile = join(profileDir, "package.json");
			if (!existsSync(pkgJsonFile)) {
				send(res, 404, { error: `找不到 profile ${profile}` });
				return true;
			}
			let depSpec = "";
			try {
				const depsMap = JSON.parse(readFileSync(pkgJsonFile, "utf8")).dependencies ?? {};
				if (typeof depsMap[pkgName] === "string") depSpec = depsMap[pkgName];
			} catch {
				send(res, 500, { error: `读取 profile ${profile} 的 package.json 失败` });
				return true;
			}
			if (depSpec === "") {
				send(res, 404, { error: `插件 ${pkgName} 未安装在 profile ${profile} 中` });
				return true;
			}
			const meta = inspectInstalledPluginMeta(profileDir, pkgName, depSpec);
			if (isSelfMobilePlugin(pkgName, meta.rowId)) {
				if (method === "POST") {
					send(res, 403, { error: "禁止修改 dsh-mobile 自身配置" });
					return true;
				}
				send(res, 200, {
					ok: true,
					writable: false,
					fields: []
				});
				return true;
			}
			const patchFile = join(profileDir, "cordis.patch.yml");
			const patchRaw = existsSync(patchFile) ? readFileSync(patchFile, "utf8") : "";
			const parsedPatch = parseCordisPatchRows(patchRaw);
			const matchedRow = parsedPatch.rows.find((r) => r.name !== "" && r.name === pkgName || meta.rowId !== "" && r.id === meta.rowId);
			if (matchedRow !== void 0 && isSelfMobilePlugin(matchedRow.name, matchedRow.id)) {
				if (method === "POST") {
					send(res, 403, { error: "禁止修改 dsh-mobile 自身配置" });
					return true;
				}
				send(res, 200, {
					ok: true,
					writable: false,
					fields: []
				});
				return true;
			}
			const buildMergedFields = (row) => {
				const merged = /* @__PURE__ */ new Map();
				for (const [k, v] of meta.defaults) {
					if (SENSITIVE_KEY_RE.test(k)) continue;
					merged.set(k, {
						key: k,
						kind: v.kind,
						value: v.value
					});
				}
				if (row !== void 0) for (const [k, v] of row.scalars) {
					if (SENSITIVE_KEY_RE.test(k)) continue;
					merged.set(k, {
						key: k,
						kind: v.kind,
						value: v.value
					});
				}
				return Array.from(merged.values());
			};
			const writable = meta.rowId !== "" || matchedRow !== void 0;
			if (method === "GET") {
				send(res, 200, {
					ok: true,
					writable,
					fields: buildMergedFields(matchedRow)
				});
				return true;
			}
			if (!writable) {
				send(res, 400, { error: "无法确定该插件在 cordis.patch.yml 中的条目 id，暂不支持自动写入" });
				return true;
			}
			const incomingUpdates = [];
			if (Array.isArray(body.fields)) for (const item of body.fields) {
				if (item === null || typeof item !== "object") continue;
				const f = item;
				const k = String(f.key ?? "").trim();
				const kh = f.kind === "boolean" || f.kind === "number" || f.kind === "string" ? f.kind : void 0;
				incomingUpdates.push({
					key: k,
					kindHint: kh,
					rawValue: f.value
				});
			}
			else {
				const mapSource = body.values ?? body.config ?? body.patch;
				if (mapSource !== null && typeof mapSource === "object" && !Array.isArray(mapSource)) for (const [k, v] of Object.entries(mapSource)) incomingUpdates.push({
					key: k.trim(),
					rawValue: v
				});
			}
			const currentFields = buildMergedFields(matchedRow);
			const currentByKey = new Map(currentFields.map((f) => [f.key, f]));
			const formattedUpdates = /* @__PURE__ */ new Map();
			for (const up of incomingUpdates) {
				if (!CONFIG_KEY_RE.test(up.key)) {
					send(res, 400, { error: `配置键名不合法：${up.key}` });
					return true;
				}
				if (SENSITIVE_KEY_RE.test(up.key)) {
					send(res, 403, { error: `禁止读取或修改敏感密钥字段：${up.key}` });
					return true;
				}
				if (matchedRow !== void 0 && matchedRow.rawKeys.has(up.key) && !matchedRow.scalars.has(up.key)) {
					send(res, 400, { error: `字段 ${up.key} 为动态表达式或复杂结构，不支持扁平覆盖` });
					return true;
				}
				const inferredKind = up.kindHint ?? currentByKey.get(up.key)?.kind ?? (typeof up.rawValue === "boolean" ? "boolean" : typeof up.rawValue === "number" ? "number" : "string");
				try {
					formattedUpdates.set(up.key, formatYamlScalar(inferredKind, up.rawValue));
				} catch (err) {
					send(res, 400, { error: err instanceof Error ? err.message : String(err) });
					return true;
				}
			}
			if (formattedUpdates.size > 0) {
				let nextLines;
				if (matchedRow === void 0) {
					const baseLines = patchRaw.trim().length === 0 ? [] : parsedPatch.lines.slice();
					if (baseLines.length > 0 && baseLines[baseLines.length - 1] !== "") baseLines.push("");
					baseLines.push(`- id: ${meta.rowId}`);
					baseLines.push("  config:");
					for (const [dk, dv] of meta.defaults) if (!formattedUpdates.has(dk) && !SENSITIVE_KEY_RE.test(dk)) baseLines.push(`    ${dk}: ${formatYamlScalar(dv.kind, dv.value)}`);
					for (const [uk, uv] of formattedUpdates) baseLines.push(`    ${uk}: ${uv}`);
					nextLines = baseLines;
				} else if (matchedRow.configLine < 0) {
					nextLines = parsedPatch.lines.slice();
					const propPad = " ".repeat(matchedRow.itemIndent + 2);
					const cfgPad = " ".repeat(matchedRow.itemIndent + 4);
					const inserted = [`${propPad}config:`];
					for (const [dk, dv] of meta.defaults) if (!formattedUpdates.has(dk) && !SENSITIVE_KEY_RE.test(dk)) inserted.push(`${cfgPad}${dk}: ${formatYamlScalar(dv.kind, dv.value)}`);
					for (const [uk, uv] of formattedUpdates) inserted.push(`${cfgPad}${uk}: ${uv}`);
					nextLines.splice(matchedRow.endLine, 0, ...inserted);
				} else {
					nextLines = parsedPatch.lines.slice();
					const cfgPad = " ".repeat(matchedRow.configIndent);
					const toAppend = [];
					for (const [uk, uv] of formattedUpdates) {
						const existingScalar = matchedRow.scalars.get(uk);
						if (existingScalar !== void 0) nextLines[existingScalar.lineIndex] = `${cfgPad}${uk}: ${uv}`;
						else toAppend.push(`${cfgPad}${uk}: ${uv}`);
					}
					if (toAppend.length > 0) {
						let insertAt = matchedRow.configLine + 1;
						for (const s of matchedRow.scalars.values()) if (s.lineIndex + 1 > insertAt) insertAt = s.lineIndex + 1;
						nextLines.splice(insertAt, 0, ...toAppend);
					}
				}
				const outYaml = `${nextLines.join("\n").replace(/\n+$/, "")}\n`;
				try {
					if (existsSync(patchFile)) writeFileSync(`${patchFile}.bak`, patchRaw, "utf8");
					atomicWriteSync(patchFile, outYaml);
				} catch (err) {
					send(res, 500, { error: `写入 cordis.patch.yml 失败：${err instanceof Error ? err.message : String(err)}` });
					return true;
				}
			}
			const updatedRow = parseCordisPatchRows(existsSync(patchFile) ? readFileSync(patchFile, "utf8") : "").rows.find((r) => r.name !== "" && r.name === pkgName || meta.rowId !== "" && r.id === meta.rowId);
			await record(deps.logFile, `200 POST plugins/settings ${profile}/${pkgName} keys=${String(formattedUpdates.size)}`);
			send(res, 200, {
				ok: true,
				writable: true,
				restartRequired: formattedUpdates.size > 0,
				fields: buildMergedFields(updatedRow)
			});
			return true;
		}
		if (path === "/api/host/schedules" && method === "GET") {
			const svc = deps.service("schedule");
			if (svc !== null && typeof svc.list === "function") {
				const page = await Promise.resolve(svc.list({ limit: 100 }));
				const bag = page !== null && typeof page === "object" ? page : {};
				send(res, 200, {
					ok: true,
					source: "service",
					items: (Array.isArray(bag.items) ? bag.items : []).map(normalizeScheduleTask)
				});
				return true;
			}
			let raw = "";
			try {
				raw = readFileSync(join(dshHome(), "storages", "schedule.json"), "utf8");
			} catch (err) {
				send(res, 503, { error: `scheduled tasks unavailable: ${err instanceof Error ? err.message : String(err)}` });
				return true;
			}
			let items = [];
			try {
				const bag = JSON.parse(raw);
				const table = bag.tables !== void 0 && bag.tables.tasks !== void 0 ? bag.tables.tasks : {};
				items = Object.keys(table).map((key) => normalizeScheduleTask(table[key]));
			} catch (err) {
				send(res, 500, { error: `cannot read scheduled tasks: ${err instanceof Error ? err.message : String(err)}` });
				return true;
			}
			send(res, 200, {
				ok: true,
				source: "file",
				items
			});
			return true;
		}
		const scheduleActionMatch = /^\/api\/host\/schedules\/([^/]+)\/action$/.exec(path);
		if (scheduleActionMatch !== null && method === "POST") {
			let body;
			try {
				body = await readJson(req);
			} catch (error) {
				send(res, typeof error.status === "number" ? error.status : 400, { error: `请求体不是合法 JSON：${error instanceof Error ? error.message : String(error)}` });
				return true;
			}
			const action = String(body.action ?? "").trim();
			if (action !== "pause" && action !== "resume" && action !== "run" && action !== "delete") {
				send(res, 400, { error: "action 只能是 pause、resume、run 或 delete" });
				return true;
			}
			let id = "";
			try {
				id = decodeURIComponent(scheduleActionMatch[1]);
			} catch {
				send(res, 400, { error: "任务 id 编码不合法" });
				return true;
			}
			if (id === "") {
				send(res, 400, { error: "任务 id 不能为空" });
				return true;
			}
			const svc = deps.service("schedule");
			if (svc === null) {
				send(res, 503, { error: "这台电脑没有挂载自动化任务（schedule 服务不可用）" });
				return true;
			}
			const canEdit = typeof svc.edit === "function";
			const canRun = typeof svc.run === "function";
			const attempts = [];
			if (action === "run") {
				if (canRun) attempts.push({
					label: "run",
					call: () => Promise.resolve(svc.run({ id }))
				});
				if (canEdit) attempts.push({
					label: "edit.run",
					call: () => Promise.resolve(svc.edit({
						id,
						action: "run"
					}))
				});
			} else if (action === "delete") {
				if (canEdit) attempts.push({
					label: "edit.delete",
					call: () => Promise.resolve(svc.edit({
						id,
						action: "delete"
					}))
				});
			} else {
				const wantResume = action === "resume";
				if (canEdit) {
					attempts.push({
						label: "edit.update",
						call: () => Promise.resolve(svc.edit({
							id,
							action: "update",
							patch: { active: wantResume }
						}))
					});
					attempts.push({
						label: `edit.${action}`,
						call: () => Promise.resolve(svc.edit({
							id,
							action
						}))
					});
				}
			}
			if (attempts.length === 0) {
				await record(deps.logFile, `501 POST schedule-action id=${id} action=${action} unsupported`);
				send(res, 501, {
					error: "这台电脑的定时任务服务不支持这个操作（缺少 edit / run 方法），升级 DSH 后再试",
					action,
					unsupported: true
				});
				return true;
			}
			let result = void 0;
			let used = "";
			const failures = [];
			for (const attempt of attempts) try {
				result = await attempt.call();
				used = attempt.label;
				break;
			} catch (error) {
				const coded = typeof error.code === "string" ? String(error.code) : "";
				const message = error instanceof Error ? error.message : String(error);
				failures.push(`${attempt.label}: ${message}`);
				if (!(coded === "schedule/input-invalid" || /unknown action|invalid|not supported|unsupported/i.test(message))) {
					const archived = coded === "schedule/target-archived" || message.indexOf("schedule/target-archived") >= 0;
					const status = archived ? 409 : 500;
					const readable = archived ? "这个任务的目标会话已归档，先在电脑上恢复那个会话再试" : `电脑端拒绝了这个操作：${message}`;
					await record(deps.logFile, `${String(status)} POST schedule-action id=${id} action=${action} code=${coded} err=${message}`);
					send(res, status, {
						error: readable,
						action
					});
					return true;
				}
			}
			if (used === "") {
				const detail = failures.length > 0 ? failures[failures.length - 1] : "没有可用的方法";
				await record(deps.logFile, `501 POST schedule-action id=${id} action=${action} none-of: ${failures.join(" | ")}`);
				send(res, 501, {
					error: `这台电脑的定时任务服务没有接受这个操作，升级 DSH 后再试（${String(detail)}）`,
					action,
					unsupported: true,
					tried: failures
				});
				return true;
			}
			const bag = result !== null && typeof result === "object" ? result : {};
			const code = typeof bag.code === "string" ? bag.code : "";
			if (code === "schedule_not_found") {
				await record(deps.logFile, `404 POST schedule-action id=${id} action=${action} not-found`);
				send(res, 404, {
					error: "这个任务在电脑上已经不存在了，刷新列表看看",
					action
				});
				return true;
			}
			if (code === "schedule_conflict") {
				await record(deps.logFile, `409 POST schedule-action id=${id} action=${action} conflict`);
				send(res, 409, {
					error: "任务刚被别处改过，刷新列表再试一次",
					action
				});
				return true;
			}
			if (code === "schedule_execution_pending") {
				await record(deps.logFile, `409 POST schedule-action id=${id} action=${action} pending`);
				send(res, 409, {
					error: "这个任务正在执行，稍等一会儿再点「立即」",
					action,
					pending: true
				});
				return true;
			}
			if (bag.deleted === true) {
				await record(deps.logFile, `200 POST schedule-action id=${id} action=${action} via=${used} deleted`);
				send(res, 200, {
					ok: true,
					action,
					id,
					via: used,
					deleted: true
				});
				return true;
			}
			await record(deps.logFile, `200 POST schedule-action id=${id} action=${action} via=${used}`);
			send(res, 200, {
				ok: true,
				action,
				id,
				via: used,
				item: normalizeScheduleTask(result)
			});
			return true;
		}
		return false;
	};
	return {
		tryHandle,
		isLoopbackAuthorized,
		setLoopbackCookieIfSigned
	};
}
//#endregion
//#region src/export-zip.ts
/**
* 会话日志导出工具：生成完整 Markdown 与零外部依赖的标准 ZIP 压缩包（仅用 `node:zlib`）。
*/
function computeCrc32(buf) {
	return zlib.crc32(buf) >>> 0;
}
function dosDateTime(date) {
	const year = Math.max(1980, Math.min(2107, date.getFullYear()));
	const month = date.getMonth() + 1;
	const day = date.getDate();
	const hours = date.getHours();
	const minutes = date.getMinutes();
	const seconds = Math.floor(date.getSeconds() / 2);
	return {
		dosTime: hours << 11 | minutes << 5 | seconds,
		dosDate: year - 1980 << 9 | month << 5 | day
	};
}
/** 构造规范的 PKZIP 归档字节（DEFLATE 压缩，UTF-8 文件名标志位）。 */
function buildZipBuffer(entries, now = /* @__PURE__ */ new Date()) {
	const { dosTime, dosDate } = dosDateTime(now);
	const localParts = [];
	const centralParts = [];
	let offset = 0;
	for (const entry of entries) {
		const nameBuf = Buffer.from(entry.name.replace(/\\/g, "/"), "utf8");
		const rawBuf = Buffer.isBuffer(entry.data) ? entry.data : Buffer.from(entry.data, "utf8");
		const crc = computeCrc32(rawBuf);
		const deflated = zlib.deflateRawSync(rawBuf);
		const useDeflate = deflated.length < rawBuf.length;
		const method = useDeflate ? 8 : 0;
		const compBuf = useDeflate ? deflated : rawBuf;
		const localHeader = Buffer.alloc(30);
		localHeader.writeUInt32LE(67324752, 0);
		localHeader.writeUInt16LE(20, 4);
		localHeader.writeUInt16LE(2048, 6);
		localHeader.writeUInt16LE(method, 8);
		localHeader.writeUInt16LE(dosTime, 10);
		localHeader.writeUInt16LE(dosDate, 12);
		localHeader.writeUInt32LE(crc, 14);
		localHeader.writeUInt32LE(compBuf.length, 18);
		localHeader.writeUInt32LE(rawBuf.length, 22);
		localHeader.writeUInt16LE(nameBuf.length, 26);
		localHeader.writeUInt16LE(0, 28);
		localParts.push(localHeader, nameBuf, compBuf);
		const cdHeader = Buffer.alloc(46);
		cdHeader.writeUInt32LE(33639248, 0);
		cdHeader.writeUInt16LE(20, 4);
		cdHeader.writeUInt16LE(20, 6);
		cdHeader.writeUInt16LE(2048, 8);
		cdHeader.writeUInt16LE(method, 10);
		cdHeader.writeUInt16LE(dosTime, 12);
		cdHeader.writeUInt16LE(dosDate, 14);
		cdHeader.writeUInt32LE(crc, 16);
		cdHeader.writeUInt32LE(compBuf.length, 20);
		cdHeader.writeUInt32LE(rawBuf.length, 24);
		cdHeader.writeUInt16LE(nameBuf.length, 28);
		cdHeader.writeUInt16LE(0, 30);
		cdHeader.writeUInt16LE(0, 32);
		cdHeader.writeUInt16LE(0, 34);
		cdHeader.writeUInt16LE(0, 36);
		cdHeader.writeUInt32LE(0, 38);
		cdHeader.writeUInt32LE(offset, 42);
		centralParts.push(cdHeader, nameBuf);
		offset += localHeader.length + nameBuf.length + compBuf.length;
	}
	const centralDir = Buffer.concat(centralParts);
	const eocd = Buffer.alloc(22);
	eocd.writeUInt32LE(101010256, 0);
	eocd.writeUInt16LE(0, 4);
	eocd.writeUInt16LE(0, 6);
	eocd.writeUInt16LE(entries.length, 8);
	eocd.writeUInt16LE(entries.length, 10);
	eocd.writeUInt32LE(centralDir.length, 12);
	eocd.writeUInt32LE(offset, 16);
	eocd.writeUInt16LE(0, 20);
	return Buffer.concat([
		...localParts,
		centralDir,
		eocd
	]);
}
/** 将会话消息轨迹渲染为清晰可读的 Markdown 导出文本。 */
function renderSessionMarkdown(options) {
	const exportedAt = options.exportedAt ?? (/* @__PURE__ */ new Date()).toISOString();
	const lines = [
		`# ${options.title || options.sessionId}`,
		"",
		`- 会话 ID: \`${options.sessionId}\``,
		...options.cwd !== "" ? [`- 工作目录: \`${options.cwd}\``] : [],
		`- 导出时间: ${exportedAt}`,
		`- 轮次 / 步骤 / 工具调用: ${String(options.stats.turns)} / ${String(options.stats.steps)} / ${String(options.stats.toolCalls)}`,
		`- Token 统计: 输入 ${String(options.stats.tokens.uncachedInputTokens)} · 输出 ${String(options.stats.tokens.outputTokens)} · 缓存命中 ${String(options.stats.tokens.cacheReadTokens)}`,
		"",
		"---",
		""
	];
	for (const msg of options.messages) {
		const roleLabel = msg.role === "user" ? "用户" : "助手";
		const ts = msg.time > 0 ? ` (${new Date(msg.time).toISOString()})` : "";
		lines.push(`## ${roleLabel}${ts}`);
		lines.push("");
		if (msg.thinking !== void 0 && msg.thinking.trim() !== "") {
			lines.push("<details>");
			lines.push("<summary>思考过程</summary>");
			lines.push("");
			lines.push(msg.thinking.trim());
			lines.push("");
			lines.push("</details>");
			lines.push("");
		}
		if (msg.tools !== void 0 && msg.tools.length > 0) {
			lines.push("**工具调用:**");
			for (const tool of msg.tools) {
				const summary = tool.summary !== "" ? ` — ${tool.summary}` : "";
				lines.push(`- \`${tool.name}\` [${tool.status}]${summary}`);
			}
			lines.push("");
		}
		if (msg.text.trim() !== "") {
			lines.push(msg.text.trim());
			lines.push("");
		}
		if (msg.images !== void 0 && msg.images.length > 0) {
			lines.push(`> 附带 ${String(msg.images.length)} 张图片附件`);
			lines.push("");
		}
	}
	return `${lines.join("\n").trimEnd()}\n`;
}
/** 构造导出元数据 JSON 字符串。 */
function buildExportMetaJson(options) {
	return `${JSON.stringify({
		sessionId: options.sessionId,
		title: options.title,
		cwd: options.cwd,
		exportedAt: options.exportedAt,
		host: hostname(),
		pluginVersion: VERSION,
		messageCount: options.messageCount,
		stats: options.stats
	}, null, 2)}\n`;
}
//#endregion
//#region src/outbox.ts
/**
* 统一发消息核心、per-session 异步互斥锁、宿主待发队列读写（含编辑保图）与幂等重放缓存。
*/
const MAX_UPLOAD_BYTES = 36 << 20;
const IMAGE_TYPES = /* @__PURE__ */ new Set([
	"image/png",
	"image/jpeg",
	"image/webp",
	"image/gif"
]);
/**
* Per-session 异步队列互斥锁：包裹同一会话的发送、入队、重排、编辑、删除与插队，
* 杜绝并发 `reorder` / `edit` / `send` 交叉读写宿主队列导致丢项或乱序。
*/
const sessionLocks = /* @__PURE__ */ new Map();
async function withSessionLock(sessionId, fn) {
	const prev = sessionLocks.get(sessionId) ?? Promise.resolve();
	let release;
	const gate = new Promise((resolve) => {
		release = resolve;
	});
	const chained = prev.then(() => gate, () => gate);
	sessionLocks.set(sessionId, chained);
	await prev.catch(() => void 0);
	try {
		return await fn();
	} finally {
		release();
		if (sessionLocks.get(sessionId) === chained) sessionLocks.delete(sessionId);
	}
}
/** 根据会话当前是否运行决定有效投递模式（空闲会话一律走 `steer` 启动新轮次）。 */
async function pickMode(ctl, sessionId, requested) {
	let known = false;
	let running = false;
	try {
		const listed = await Promise.resolve(ctl.list({}, AbortSignal.timeout(15e3)));
		for (const row of projectSessions(listed)) if (row.id === sessionId) {
			known = true;
			running = row.running === true;
			break;
		}
	} catch {}
	return {
		mode: running ? requested : "steer",
		running,
		known
	};
}
/** 读取宿主指定会话的状态快照。 */
async function hostState(ctl, sessionId) {
	if (!ctl || typeof ctl.state !== "function") return null;
	try {
		return await Promise.resolve(ctl.state({ sessionId }, AbortSignal.timeout(8e3)));
	} catch {
		return null;
	}
}
/** 读取宿主当前排队中的消息项列表。 */
async function hostQueued(ctl, sessionId) {
	const st = await hostState(ctl, sessionId);
	return (st && Array.isArray(st.queue) ? st.queue : []).filter((it) => it !== null && typeof it === "object" && it.placement === "queued");
}
function hostText(it) {
	return (it && Array.isArray(it.content) ? it.content : []).filter((p) => p !== null && typeof p === "object" && p.type === "text").map((p) => String(p.text ?? "")).join(" ").trim();
}
function hostImages(it) {
	const parts = it && Array.isArray(it.content) ? it.content : [];
	const out = [];
	for (const p of parts) {
		if (p === null || typeof p !== "object" || p.type !== "image") continue;
		const mediaType = String(p.mediaType ?? "image/png");
		const name = String(p.name ?? "");
		out.push(name === "" ? { mediaType } : {
			mediaType,
			name
		});
	}
	return out;
}
/** 构造返回给手机端的待发送队列视图。 */
async function hostQueueView(ctl, sessionId) {
	return (await hostQueued(ctl, sessionId)).map((it, i) => ({
		id: String(it.id),
		text: hostText(it),
		at: 0,
		index: i + 1,
		images: hostImages(it)
	}));
}
/** 向宿主排队区压入一条待发送消息并返回新生成的队列项 ID。 */
async function hostEnqueue(ctl, sessionId, content) {
	const before = new Set((await hostQueued(ctl, sessionId)).map((x) => String(x.id)));
	await Promise.resolve(ctl.prompt({
		requestId: randomBytes(16).toString("hex"),
		sessionId,
		mode: "queue",
		content
	}, AbortSignal.timeout(3e4)));
	const fresh = (await hostQueued(ctl, sessionId)).find((x) => !before.has(String(x.id)));
	return fresh === void 0 ? "" : String(fresh.id);
}
/** 调用宿主 `updateQueue` 修改、移除或插队执行一条排队项。 */
async function hostMutate(ctl, sessionId, itemId, action) {
	if (!ctl || typeof ctl.updateQueue !== "function") return false;
	try {
		await Promise.resolve(ctl.updateQueue({
			sessionId,
			itemId,
			action
		}, AbortSignal.timeout(2e4)));
		return true;
	} catch {
		return false;
	}
}
/**
* 构造排队项编辑后的 `content`：保留原排队项中所有非 `text` 内容块（如图片/文件 part），
* 仅替换文本块，避免编辑文字时丢失已附带的图片或附件。
*/
async function buildEditedQueueContent(ctl, sessionId, itemId, newText) {
	const existing = (await hostQueued(ctl, sessionId)).find((x) => String(x.id) === itemId);
	const oldParts = existing && Array.isArray(existing.content) ? existing.content : [];
	const nextContent = [];
	let placedText = false;
	for (const part of oldParts) {
		if (part === null || typeof part !== "object") continue;
		const p = part;
		if (p.type === "text") {
			if (!placedText) {
				nextContent.push({
					type: "text",
					text: newText
				});
				placedText = true;
			}
		} else nextContent.push(p);
	}
	if (!placedText) nextContent.unshift({
		type: "text",
		text: newText
	});
	return nextContent;
}
/** 校验并构造图片消息块列表。 */
function parseImageParts(raw, requireNonEmpty) {
	if (requireNonEmpty && raw.length === 0) throw new HttpError(400, "images is empty");
	if (raw.length > 9) throw new HttpError(400, `at most ${String(9)} images per request`);
	const parts = [];
	let bytes = 0;
	for (const item of raw) {
		if (item === null || typeof item !== "object") throw new HttpError(400, "each image must be an object");
		const img = item;
		const mediaType = String(img.mediaType ?? "").toLowerCase();
		if (!IMAGE_TYPES.has(mediaType)) throw new HttpError(400, `unsupported image type: ${mediaType}`);
		const data = String(img.data ?? "");
		if (data.length === 0) throw new HttpError(400, "image data is empty");
		bytes += Math.floor(data.length * 3 / 4);
		const part = {
			type: "image",
			mediaType,
			data
		};
		const name = String(img.name ?? "").trim().slice(0, 80);
		if (name !== "") part.name = name;
		parts.push(part);
	}
	return {
		parts,
		bytes
	};
}
/** 将手机上传的附件落盘到 `<dshHome>/mobile-uploads/<YYYYMMDD>/` 并返回说明文本。 */
async function saveMobileFiles(raw, requireNonEmpty = false) {
	if (requireNonEmpty && raw.length === 0) throw new HttpError(400, "files is empty");
	if (raw.length > 9) throw new HttpError(400, `at most ${String(9)} files per request`);
	const saved = [];
	if (raw.length === 0) return {
		saved,
		bytes: 0,
		text: ""
	};
	const stamp = /* @__PURE__ */ new Date();
	const day = `${String(stamp.getFullYear())}${String(stamp.getMonth() + 1).padStart(2, "0")}${String(stamp.getDate()).padStart(2, "0")}`;
	const dir = join(dshHome(), "mobile-uploads", day);
	await mkdir(dir, { recursive: true });
	let bytes = 0;
	for (const item of raw) {
		if (item === null || typeof item !== "object") throw new HttpError(400, "each file must be an object");
		const f = item;
		const data = String(f.data ?? "");
		if (data.length === 0) throw new HttpError(400, "file data is empty");
		const safe = String(f.name ?? "file").replace(/[\\/:*?"<>|\u0000-\u001f]/g, "_").trim().slice(0, 120) || "file";
		const target = join(dir, `${String(Date.now())}-${randomBytes(2).toString("hex")}-${safe}`);
		const buf = Buffer.from(data, "base64");
		await writeFile(target, buf);
		bytes += buf.length;
		saved.push({
			name: safe,
			path: target,
			bytes: buf.length
		});
	}
	const lines = saved.map((s) => `- ${String(s.path)}`);
	return {
		saved,
		bytes,
		text: `已保存到这台机器：\n${lines.join("\n")}`
	};
}
/**
* 统一发消息核心函数：供 `/send`、`/images`、`/files`、`/outbox` 共同复用，
* 内部加 `withSessionLock(sessionId)` 保证同一会话投递与队列读取的串行一致性。
*/
async function dispatchSessionMessage(ctl, sessionId, content, requestedMode, timeoutMs, logFile, logTag) {
	return withSessionLock(sessionId, async () => {
		const { mode, running, known } = await pickMode(ctl, sessionId, requestedMode);
		if (mode === "queue" && running) {
			const itemId = await hostEnqueue(ctl, sessionId, content);
			const queue = await hostQueueView(ctl, sessionId);
			await record(logFile, `200 POST ${logTag} session=${sessionId} mode=queue host=${itemId} parts=${String(content.length)}`);
			return {
				queued: true,
				mode: "queue",
				running: true,
				known,
				item: itemId,
				queue,
				result: null
			};
		}
		const result = await Promise.resolve(ctl.prompt({
			requestId: randomBytes(16).toString("hex"),
			sessionId,
			mode,
			content
		}, AbortSignal.timeout(timeoutMs)));
		await record(logFile, `200 POST ${logTag} session=${sessionId} mode=${mode} busy=${String(running)} known=${String(known)} parts=${String(content.length)}`);
		return {
			queued: false,
			mode,
			running,
			known,
			item: "",
			queue: [],
			result: result ?? null
		};
	});
}
function createIdempotencyStore() {
	const replay = /* @__PURE__ */ new Map();
	const inflight = /* @__PURE__ */ new Map();
	const inflightBusy = (key) => {
		const at = inflight.get(key);
		if (at === void 0) return false;
		if (Date.now() - at > 12e4) {
			inflight.delete(key);
			return false;
		}
		return true;
	};
	const inflightHold = (res, key) => {
		inflight.set(key, Date.now());
		res.on("finish", () => inflight.delete(key));
	};
	const replayGet = (key) => {
		const hit = replay.get(key);
		if (hit === void 0) return null;
		if (Date.now() - hit.at > 600 * 1e3) {
			replay.delete(key);
			return null;
		}
		return hit;
	};
	const replayPut = (key, status, body, route, hash) => {
		if (key === "" || status < 200 || status >= 300) return;
		const text = typeof body === "string" ? body : JSON.stringify(body);
		replay.delete(key);
		replay.set(key, {
			at: Date.now(),
			status,
			text,
			route,
			hash
		});
		while (replay.size > 200) {
			const first = replay.keys().next().value;
			if (first === void 0) break;
			replay.delete(first);
		}
	};
	const replayHit = (req, res, route, hash) => {
		const key = String(req.headers["idempotency-key"] ?? "");
		if (key === "") return false;
		const hit = replayGet(key);
		if (hit === null) return false;
		if (hit.route !== route || hit.hash !== hash) {
			send(res, 409, { error: "idempotency key reused with a different request" });
			return true;
		}
		res.writeHead(hit.status, {
			"content-type": "application/json; charset=utf-8",
			"content-length": String(Buffer.byteLength(hit.text)),
			"access-control-allow-origin": "*",
			"cache-control": "no-store",
			"x-idempotent-replay": "1"
		});
		res.end(hit.text);
		return true;
	};
	return {
		replayHit,
		inflightBusy,
		inflightHold,
		replayPut
	};
}
//#endregion
//#region src/transcript.ts
/**
* 会话 Zstd 事件日志解析、增量解压 + LRU 缓存（上限 16）、路径索引缓存、
* 思考链与工具调用轨迹提取、精简模式裁剪以及 AgentTeams 视图复用。
*/
const zstdDecompressSync = zlib.zstdDecompressSync;
const ZSTD_MAGIC = Buffer.from([
	40,
	181,
	47,
	253
]);
const MAX_SESSION_BYTES = 160 * 1024 * 1024;
const HISTORY_CACHE_CAP = 16;
const PATH_CACHE_CAP = 512;
const HEAD_HASH_BYTES = 4096;
const MAX_THINKING_CHARS = 4e3;
const COMPACT_THINKING_CHARS = 160;
/** `sessionId -> filePath` 映射缓存（LRU 上限 512），未命中或文件消失时才遍历磁盘目录。 */
const sessionFileCache = /* @__PURE__ */ new Map();
/** 定位某个会话的 `session.v4.jsonl.zstd` 文件。 */
function findSessionFile(id) {
	const home = dshHome();
	const hit = sessionFileCache.get(id);
	if (hit !== void 0 && hit.home === home) {
		if (existsSync(hit.file)) {
			sessionFileCache.delete(id);
			sessionFileCache.set(id, hit);
			return hit.file;
		}
		sessionFileCache.delete(id);
	}
	const root = join(home, "sessions");
	let projects;
	try {
		projects = readdirSync(root);
	} catch {
		return null;
	}
	const candidates = id.startsWith("session-") ? [id, id.slice(8)] : [id, `session-${id}`];
	for (const project of projects) for (const name of candidates) {
		const file = join(root, project, name, "session.v4.jsonl.zstd");
		try {
			if (statSync(file).isFile()) {
				sessionFileCache.delete(id);
				sessionFileCache.set(id, {
					home,
					file
				});
				while (sessionFileCache.size > PATH_CACHE_CAP) {
					const oldest = sessionFileCache.keys().next().value;
					if (oldest === void 0) break;
					sessionFileCache.delete(oldest);
				}
				return file;
			}
		} catch {}
	}
	return null;
}
/** 读取文件区间字节。 */
function readRange(fd, offset, length) {
	if (length <= 0) return Buffer.alloc(0);
	const buf = Buffer.allocUnsafe(length);
	let readTotal = 0;
	while (readTotal < length) {
		const n = readSync(fd, buf, readTotal, length - readTotal, offset + readTotal);
		if (n <= 0) break;
		readTotal += n;
	}
	return readTotal === length ? buf : buf.subarray(0, readTotal);
}
/** 计算头部块哈希，判断日志文件是否被截断重写。 */
function hashBuffer(buf) {
	return createHash("sha256").update(buf).digest("hex").slice(0, 32);
}
/**
* 解压一段字节中的完整 Zstd 帧序列。
* 返回成功解码的事件行列表，以及已消费的精确字节偏移 `consumedBytes`：
* 若末尾帧尚未写完（半帧），`consumedBytes` 停在该半帧起始位置，留待下次增量继续读取。
*/
function decodeZstdFrames(raw) {
	if (zstdDecompressSync === void 0) throw new Error("this Node build has no zstd support");
	if (raw.length === 0) return {
		lines: [],
		consumedBytes: 0
	};
	const starts = [];
	let cursor = 0;
	while ((cursor = raw.indexOf(ZSTD_MAGIC, cursor)) !== -1) {
		starts.push(cursor);
		cursor += 4;
	}
	if (starts.length === 0) return {
		lines: [],
		consumedBytes: 0
	};
	const parts = [];
	let consumedBytes = 0;
	let index = 0;
	while (index < starts.length) {
		const from = starts[index];
		let decoded = null;
		let nextIndex = index + 1;
		while (nextIndex <= starts.length) {
			const to = nextIndex < starts.length ? starts[nextIndex] : raw.length;
			try {
				decoded = zstdDecompressSync(raw.subarray(from, to));
				break;
			} catch {
				if (nextIndex === starts.length) break;
				nextIndex += 1;
			}
		}
		if (decoded !== null) {
			parts.push(decoded);
			consumedBytes = nextIndex < starts.length ? starts[nextIndex] : raw.length;
			index = nextIndex;
		} else {
			if (index === starts.length - 1) break;
			consumedBytes = starts[index + 1];
			index += 1;
		}
	}
	if (parts.length === 0) return {
		lines: [],
		consumedBytes
	};
	return {
		lines: Buffer.concat(parts).toString("utf8").split("\n").filter((line) => line.length > 0),
		consumedBytes
	};
}
/** 提取正文文本块。 */
function textOf(content) {
	if (!Array.isArray(content)) return "";
	const out = [];
	for (const part of content) {
		if (part === null || typeof part !== "object") continue;
		const p = part;
		if (p.type === "text" && typeof p.text === "string") out.push(p.text);
	}
	return out.join("").trim();
}
/** 提取 assistant 内容块中的 `reasoning` / `thinking` 思考链文本。 */
function thinkingOf(content) {
	if (!Array.isArray(content)) return "";
	const out = [];
	for (const part of content) {
		if (part === null || typeof part !== "object") continue;
		const p = part;
		if (p.type === "reasoning" || p.type === "thinking") {
			const trimmed = (typeof p.text === "string" ? p.text : typeof p.thinking === "string" ? p.thinking : typeof p.reasoning === "string" ? p.reasoning : "").trim();
			if (trimmed.length > 0) out.push(trimmed);
		}
	}
	return out.join("\n\n");
}
/** 裁剪思考链文本至最多 4000 字符。 */
function capThinking(raw) {
	if (raw.length <= MAX_THINKING_CHARS) return raw;
	return `${raw.slice(0, MAX_THINKING_CHARS - 1)}⋯`;
}
/** 从工具调用参数中提炼简明单行目标摘要（绝不混入大段文件内容或结果原文）。 */
function summarizeToolArgs(name, rawArgs) {
	let parsed = rawArgs;
	if (typeof rawArgs === "string") {
		const trimmed = rawArgs.trim();
		if (trimmed === "") return "";
		try {
			parsed = JSON.parse(trimmed);
		} catch {
			return trimmed.split(/\r?\n/)[0]?.replace(/\s+/g, " ").trim().slice(0, 100) ?? "";
		}
	}
	if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return "";
	const bag = parsed;
	const firstLine = (v, max = 100) => {
		if (typeof v !== "string") return "";
		const line = v.trim().split(/\r?\n/)[0]?.replace(/\s+/g, " ").trim() ?? "";
		return line.length > max ? `${line.slice(0, max - 1)}⋯` : line;
	};
	const lower = name.toLowerCase();
	if (lower === "pwsh" || lower === "bash" || lower === "shell" || lower.includes("terminal") || lower === "run_command") {
		const cmd = firstLine(bag.command ?? bag.cmd ?? bag.script ?? bag.CommandLine, 100);
		if (cmd !== "") return cmd;
	}
	if (lower === "grep" || lower === "glob") {
		const pat = firstLine(bag.pattern, 60);
		const scope = firstLine(bag.path ?? bag.include, 50);
		if (pat !== "") return scope !== "" ? `${pat} · ${scope}` : pat;
	}
	for (const key of [
		"file_path",
		"path",
		"filePath",
		"target_file",
		"command",
		"cmd",
		"pattern",
		"query",
		"url",
		"skill",
		"label",
		"subject",
		"objective",
		"task_id",
		"agent_id",
		"job_id",
		"to",
		"name",
		"action",
		"description",
		"prompt"
	]) {
		const val = bag[key];
		if (typeof val === "string" && val.trim() !== "") return firstLine(val, 100);
		if (typeof val === "number" || typeof val === "boolean") return `${key}=${String(val)}`;
	}
	for (const [k, v] of Object.entries(bag)) {
		if (k === "content" || k === "new_string" || k === "old_string" || k === "data") continue;
		if (typeof v === "string" && v.trim() !== "") return firstLine(v, 90);
		if (typeof v === "number" || typeof v === "boolean") return `${k}=${String(v)}`;
	}
	return "";
}
/** 提取 assistant 内容块中内嵌的 tool-call 列表。 */
function embeddedToolsOf(content) {
	if (!Array.isArray(content)) return [];
	const out = [];
	for (const part of content) {
		if (part === null || typeof part !== "object") continue;
		const p = part;
		if (p.type === "tool-call" || p.type === "tool_use") {
			const id = String(p.id ?? p.callId ?? "");
			const name = String(p.name ?? "");
			if (id !== "" && name !== "") out.push({
				id,
				name,
				args: p.arguments ?? p.input
			});
		}
	}
	return out;
}
/** 提取消息中的图片附件摘要。 */
function imagesOf(content) {
	if (!Array.isArray(content)) return [];
	const out = [];
	for (const part of content) {
		if (part === null || typeof part !== "object") continue;
		const p = part;
		if (p.type !== "image") continue;
		const a = p.attachment ?? {};
		const raw = String(a.attachmentId ?? "");
		const id = raw.startsWith("sha256:") ? raw.slice(7) : raw;
		if (!/^[0-9a-f]{8,128}$/i.test(id)) continue;
		const width = Number(a.width ?? 0);
		const height = Number(a.height ?? 0);
		out.push({
			id: id.toLowerCase(),
			mediaType: String(a.mediaType ?? "image/png"),
			width: Number.isFinite(width) && width > 0 ? width : 0,
			height: Number.isFinite(height) && height > 0 ? height : 0,
			name: String(a.name ?? "")
		});
	}
	return out;
}
/** 累加单次模型调用的 Token 计数。 */
function accumulateTokens(total, data) {
	if (data === null || typeof data !== "object") return;
	const usage = data.usage ?? data;
	const num = (v) => {
		const n = Number(v ?? 0);
		return Number.isFinite(n) && n > 0 ? n : 0;
	};
	total.uncachedInputTokens += num(usage.inputTokens ?? usage.uncachedInputTokens);
	total.outputTokens += num(usage.outputTokens);
	total.cacheReadTokens += num(usage.cacheReadTokens ?? usage.cachedInputTokens);
	total.cacheWriteTokens += num(usage.cacheWriteTokens);
}
/** 将 Markdown 文本压平为单行会话预览。 */
function plainPreview(text) {
	return text.replace(/```[\s\S]*?```/g, " ").replace(/`([^`]*)`/g, "$1").replace(/!\[[^\]]*\]\([^)]*\)/g, " ").replace(/\[([^\]]*)\]\([^)]*\)/g, "$1").replace(/^#{1,6}\s*/gm, "").replace(/^>\s?/gm, "").replace(/^\s*[-*+]\s+/gm, "").replace(/\*\*([^*]*)\*\*/g, "$1").replace(/\|/g, " ").replace(/\s+/g, " ").trim().slice(0, 90);
}
const historyCache = /* @__PURE__ */ new Map();
function createEmptyFoldEntry(size, mtimeMs, headLen, firstChunkHash) {
	return {
		size,
		mtimeMs,
		headLen,
		firstChunkHash,
		byteOffset: 0,
		messages: [],
		stats: {
			turns: 0,
			steps: 0,
			toolCalls: 0,
			tokens: {
				uncachedInputTokens: 0,
				outputTokens: 0,
				cacheReadTokens: 0,
				cacheWriteTokens: 0
			}
		},
		lastTurn: "",
		lastErr: null,
		stepAt: /* @__PURE__ */ new Map(),
		stepThinking: /* @__PURE__ */ new Map(),
		stepTools: /* @__PURE__ */ new Map(),
		turnStart: 0,
		turnIn: 0,
		turnOut: 0,
		turnReplyAt: -1,
		carryThinking: [],
		carryTools: [],
		currentStepKey: "",
		toolById: /* @__PURE__ */ new Map(),
		teamEnabled: false,
		teamSawMode: false,
		teamMembers: /* @__PURE__ */ new Map(),
		teamTasks: /* @__PURE__ */ new Map()
	};
}
/** 注册或更新一条工具调用轨迹，并挂到所属 step 或待合并队列上。 */
function registerToolTrace(entry, stepKey, callId, name, rawArgs) {
	const existing = entry.toolById.get(callId);
	if (existing !== void 0) {
		if (existing.summary === "" && rawArgs !== void 0) existing.summary = summarizeToolArgs(name, rawArgs);
		return existing;
	}
	const trace = {
		id: callId,
		name,
		summary: summarizeToolArgs(name, rawArgs),
		status: "run"
	};
	entry.toolById.set(callId, trace);
	const msgIdx = entry.stepAt.get(stepKey);
	if (msgIdx !== void 0) {
		const row = entry.messages[msgIdx];
		if (row !== void 0) {
			if (row.tools === void 0) row.tools = [];
			row.tools.push(trace);
			return trace;
		}
	}
	const list = entry.stepTools.get(stepKey) ?? [];
	list.push(trace);
	entry.stepTools.set(stepKey, list);
	return trace;
}
/** 将未发言 step 累积的思考与工具轨迹刷入指定回复气泡。 */
function flushCarryIntoRow(entry, row, stepKey) {
	const ownThinking = entry.stepThinking.get(stepKey) ?? "";
	const allThinking = [...entry.carryThinking, ...ownThinking !== "" ? [ownThinking] : []].join("\n\n").trim();
	entry.carryThinking = [];
	if (allThinking !== "") row.thinking = capThinking(allThinking);
	const ownTools = entry.stepTools.get(stepKey) ?? [];
	const mergedTools = [];
	const seen = /* @__PURE__ */ new Set();
	for (const t of [
		...entry.carryTools,
		...row.tools ?? [],
		...ownTools
	]) if (!seen.has(t.id)) {
		seen.add(t.id);
		mergedTools.push(t);
	}
	entry.carryTools = [];
	entry.stepTools.delete(stepKey);
	if (mergedTools.length > 0) row.tools = mergedTools;
}
/** 把上一个无文本 step 的思考与工具移入本轮 carry 池，等待本轮下一条有文本的回复承接。 */
function stashSilentStep(entry, stepKey) {
	if (stepKey === "" || entry.stepAt.has(stepKey)) return;
	const t = entry.stepThinking.get(stepKey);
	if (t !== void 0 && t !== "") {
		entry.carryThinking.push(t);
		entry.stepThinking.delete(stepKey);
	}
	const tools = entry.stepTools.get(stepKey);
	if (tools !== void 0 && tools.length > 0) {
		for (const item of tools) if (!entry.carryTools.some((x) => x.id === item.id)) entry.carryTools.push(item);
		entry.stepTools.delete(stepKey);
	}
}
/** 向增量状态喂入单行事件 JSON。 */
function foldEventLine(entry, line) {
	let event;
	try {
		event = JSON.parse(line);
	} catch {
		return;
	}
	if (event === null || typeof event !== "object") return;
	const ev = event;
	const type = String(ev.type ?? "");
	if (type === "team/mode") {
		entry.teamSawMode = true;
		entry.teamEnabled = ev.data?.enabled === true;
		return;
	}
	if (type === "team/member") {
		const member = ev.data?.member;
		if (member !== null && typeof member === "object") {
			const id = String(member.id ?? "");
			entry.teamMembers.set(id, {
				id,
				name: String(member.name ?? ""),
				description: String(member.description ?? ""),
				phase: String(member.phase ?? ""),
				error: String(member.error ?? "")
			});
		}
		return;
	}
	if (type === "team/task") {
		const task = ev.data?.task;
		if (task !== null && typeof task === "object") {
			const id = String(task.id ?? "");
			const seen = entry.teamTasks.get(id);
			const revision = Number(task.revision ?? 0);
			if (seen === void 0 || Number(seen.revision ?? -1) <= revision) entry.teamTasks.set(id, {
				id,
				revision,
				subject: String(task.subject ?? ""),
				description: String(task.description ?? ""),
				status: String(task.status ?? "pending"),
				ownerName: String(task.ownerName ?? ""),
				ownerId: String(task.ownerId ?? "")
			});
		}
		return;
	}
	if (type === "turn/start") {
		stashSilentStep(entry, entry.currentStepKey);
		entry.stats.turns += 1;
		entry.turnStart = Number(ev.time ?? 0);
		entry.turnIn = 0;
		entry.turnOut = 0;
		entry.turnReplyAt = -1;
		entry.carryThinking = [];
		entry.carryTools = [];
		entry.currentStepKey = "";
		entry.toolById.clear();
		return;
	}
	if (type === "step/start") {
		stashSilentStep(entry, entry.currentStepKey);
		entry.stats.steps += 1;
		entry.currentStepKey = `${String(ev.data?.turn ?? "")}:${String(ev.data?.step ?? "")}`;
		return;
	}
	if (type === "turn/end") {
		stashSilentStep(entry, entry.currentStepKey);
		entry.currentStepKey = "";
		entry.lastTurn = String(ev.data?.reason?.kind ?? "");
		const rawErr = ev.data?.reason?.error;
		let errCode = "";
		let errText = "";
		if (rawErr !== null && typeof rawErr === "object") {
			errCode = String(rawErr.code ?? "");
			errText = String(rawErr.message ?? "");
		} else if (typeof rawErr === "string") errText = rawErr;
		if (errText !== "") entry.lastErr = {
			code: errCode,
			text: errText,
			time: Number(ev.time ?? 0)
		};
		else entry.lastErr = null;
		const row = entry.turnReplyAt >= 0 ? entry.messages[entry.turnReplyAt] : void 0;
		if (row !== void 0) {
			if (entry.carryThinking.length > 0) {
				row.thinking = capThinking([row.thinking ?? "", ...entry.carryThinking].filter(Boolean).join("\n\n"));
				entry.carryThinking = [];
			}
			if (entry.carryTools.length > 0) {
				const existing = row.tools ?? [];
				const seen = new Set(existing.map((t) => t.id));
				for (const t of entry.carryTools) if (!seen.has(t.id)) {
					seen.add(t.id);
					existing.push(t);
				}
				row.tools = existing;
				entry.carryTools = [];
			}
			const endAt = Number(ev.time ?? 0);
			row.turn = {
				status: entry.lastTurn,
				ms: endAt > entry.turnStart && entry.turnStart > 0 ? endAt - entry.turnStart : 0,
				tokensIn: entry.turnIn,
				tokensOut: entry.turnOut,
				atSeq: Number(ev.seq ?? 0),
				finishedAt: endAt > 0 ? endAt : Date.now()
			};
			if (errText !== "") {
				row.turn.errCode = errCode;
				row.turn.errText = errText;
			}
		}
		return;
	}
	if (type === "tool/call") {
		entry.stats.toolCalls += 1;
		const callId = String(ev.data?.callId ?? ev.data?.id ?? "");
		const name = String(ev.data?.name ?? "");
		const stepKey = `${String(ev.data?.turn ?? "")}:${String(ev.data?.step ?? "")}`;
		if (callId !== "" && name !== "") registerToolTrace(entry, stepKey, callId, name, ev.data?.arguments ?? ev.data?.args ?? ev.data?.input);
		return;
	}
	if (type === "tool/result") {
		const msg = ev.data?.message;
		const parts = Array.isArray(msg?.content) ? msg.content : [];
		const callId = String(ev.data?.callId ?? ev.data?.toolCallId ?? msg?.source?.callId ?? parts[0]?.toolCallId ?? "");
		if (callId !== "") {
			const trace = entry.toolById.get(callId);
			if (trace !== void 0) trace.status = ev.data?.isError === true || parts.some((p) => p?.isError === true) ? "err" : "ok";
		}
		return;
	}
	if (type === "assistant/attempt") {
		accumulateTokens(entry.stats.tokens, ev.data);
		return;
	}
	if (type === "user/message") {
		const source = ev.data?.source;
		if (source !== void 0 && source !== null && String(source.kind ?? "user") !== "user") return;
		const text = textOf(ev.data?.content);
		if (text.length === 0 || text.startsWith("<system-reminder>")) return;
		const images = imagesOf(ev.data?.content);
		const row = {
			role: "user",
			text,
			time: Number(ev.time ?? 0),
			seq: Number(ev.seq ?? 0)
		};
		if (images.length > 0) row.images = images;
		entry.messages.push(row);
		return;
	}
	if (type === "assistant/message") {
		const content = ev.data?.message?.content;
		const text = textOf(content);
		const thinking = thinkingOf(content);
		const embedded = embeddedToolsOf(content);
		const stepKey = `${String(ev.data?.turn ?? "")}:${String(ev.data?.step ?? "")}`;
		if (entry.currentStepKey !== "" && entry.currentStepKey !== stepKey) stashSilentStep(entry, entry.currentStepKey);
		entry.currentStepKey = stepKey;
		const usage = ev.data?.usage;
		if (usage !== null && typeof usage === "object") {
			entry.turnIn = (Number(usage.inputTokens ?? 0) || 0) + (Number(usage.cacheReadTokens ?? usage.cachedInputTokens ?? 0) || 0);
			entry.turnOut += Number(usage.outputTokens ?? 0) || 0;
		}
		if (thinking !== "") entry.stepThinking.set(stepKey, thinking);
		for (const tool of embedded) registerToolTrace(entry, stepKey, tool.id, tool.name, tool.args);
		if (text.length === 0) return;
		const prevIdx = entry.stepAt.get(stepKey);
		const prevRow = prevIdx !== void 0 ? entry.messages[prevIdx] : void 0;
		const row = {
			role: "assistant",
			text,
			time: Number(ev.time ?? 0),
			seq: Number(ev.seq ?? 0)
		};
		if (prevRow?.thinking !== void 0) row.thinking = prevRow.thinking;
		if (prevRow?.tools !== void 0) row.tools = prevRow.tools;
		flushCarryIntoRow(entry, row, stepKey);
		if (thinking !== "" && row.thinking === void 0) row.thinking = capThinking(thinking);
		if (prevIdx !== void 0) {
			entry.messages[prevIdx] = row;
			entry.turnReplyAt = prevIdx;
		} else {
			const idx = entry.messages.length;
			entry.stepAt.set(stepKey, idx);
			entry.turnReplyAt = idx;
			entry.messages.push(row);
		}
	}
}
/** 维护 `historyCache` 的 LRU 顺序并裁剪到最多 16 个会话。 */
function touchHistoryCache(file, entry) {
	historyCache.delete(file);
	historyCache.set(file, entry);
	while (historyCache.size > HISTORY_CACHE_CAP) {
		const oldest = historyCache.keys().next().value;
		if (oldest === void 0) break;
		historyCache.delete(oldest);
	}
}
/**
* 确保指定会话日志文件在 `historyCache` 中已解码到最新字节：
* - 文件未变：直接命中返回；
* - 文件追加增长且头部块哈希未变：仅读取 `[cached.byteOffset, stat.size)` 增量解压合并；
* - 首次读取、文件缩小或头部重写：全量读取重算。
*/
function ensureDecoded(file) {
	if (zstdDecompressSync === void 0) throw new Error("this Node build has no zstd support");
	const st = statSync(file);
	if (st.size > MAX_SESSION_BYTES) throw new Error(`session log is ${String(st.size)} bytes, over the safety cap`);
	const cached = historyCache.get(file);
	if (cached !== void 0 && cached.size === st.size && cached.mtimeMs === st.mtimeMs) {
		touchHistoryCache(file, cached);
		return cached;
	}
	let fd;
	try {
		fd = openSync(file, "r");
		if (cached !== void 0 && st.size >= cached.byteOffset && cached.headLen > 0 && st.size >= cached.headLen) {
			if (hashBuffer(readRange(fd, 0, cached.headLen)) === cached.firstChunkHash) {
				if (st.size === cached.byteOffset) {
					cached.size = st.size;
					cached.mtimeMs = st.mtimeMs;
					touchHistoryCache(file, cached);
					return cached;
				}
				const { lines, consumedBytes } = decodeZstdFrames(readRange(fd, cached.byteOffset, st.size - cached.byteOffset));
				for (const line of lines) foldEventLine(cached, line);
				cached.byteOffset += consumedBytes;
				cached.size = st.size;
				cached.mtimeMs = st.mtimeMs;
				touchHistoryCache(file, cached);
				return cached;
			}
		}
		const raw = readRange(fd, 0, st.size);
		const headLen = Math.min(raw.length, HEAD_HASH_BYTES);
		const firstChunkHash = headLen > 0 ? hashBuffer(raw.subarray(0, headLen)) : "";
		const entry = createEmptyFoldEntry(st.size, st.mtimeMs, headLen, firstChunkHash);
		const { lines, consumedBytes } = decodeZstdFrames(raw);
		for (const line of lines) foldEventLine(entry, line);
		entry.byteOffset = consumedBytes;
		touchHistoryCache(file, entry);
		return entry;
	} finally {
		if (fd !== void 0) try {
			closeSync(fd);
		} catch {}
	}
}
/** 读取会话完整消息轨迹与统计（自动走增量 Zstd 缓存）。 */
function historyOf(file) {
	const entry = ensureDecoded(file);
	return {
		messages: entry.messages,
		stats: entry.stats,
		lastTurn: entry.lastTurn,
		lastErr: entry.lastErr,
		byteOffset: entry.byteOffset
	};
}
/** 复用 `historyCache` 增量解压结果构造 AgentTeams 团队状态快照。 */
function teamOf(file) {
	const entry = ensureDecoded(file);
	const taskRows = Array.from(entry.teamTasks.values()).filter((task) => task.status !== "deleted").sort((a, b) => {
		const rank = (s) => s === "in_progress" ? 0 : s === "pending" ? 1 : s === "completed" ? 2 : 3;
		const delta = rank(a.status) - rank(b.status);
		return delta !== 0 ? delta : String(a.subject).localeCompare(String(b.subject));
	});
	return {
		enabled: entry.teamEnabled,
		sawMode: entry.teamSawMode,
		members: Array.from(entry.teamMembers.values()),
		tasks: taskRows
	};
}
/** 折叠单条历史消息中的超长 Markdown 代码块（保持围栏闭合）。 */
function foldLongCodeBlocks(text) {
	return text.replace(/```([^\n`]*)\n([\s\S]*?)```/g, (full, lang, body) => {
		const lines = body.split("\n");
		if (lines.length <= 8 && body.length <= 360) return full;
		const head = lines.slice(0, 4).join("\n");
		const omitted = Math.max(1, lines.length - 4);
		return `\`\`\`${lang}\n${head}\n⋯ (已折叠 ${String(omitted)} 行代码)\n\`\`\``;
	});
}
/**
* R4 会话精简模式（`?compact=1`）：
* 对早于最后 6 条的历史消息裁剪 `thinking`（最多 160 字）并折叠超长代码块，不改动缓存原对象。
*/
function applyCompactMode(all, page) {
	const keepFullFromSeq = all.length > 6 ? all[all.length - 6]?.seq ?? 0 : 0;
	return page.map((msg) => {
		if (msg.seq >= keepFullFromSeq) return msg;
		const nextText = msg.text.includes("```") ? foldLongCodeBlocks(msg.text) : msg.text;
		const nextThinking = msg.thinking !== void 0 && msg.thinking.length > COMPACT_THINKING_CHARS ? `${msg.thinking.slice(0, COMPACT_THINKING_CHARS - 1)}⋯` : msg.thinking;
		if (nextText === msg.text && nextThinking === msg.thinking) return msg;
		const copy = {
			...msg,
			text: nextText
		};
		if (nextThinking !== void 0) copy.thinking = nextThinking;
		return copy;
	});
}
/** 读取日志尾部 96 KB 窗口提取最后一条消息单行预览（无需全量解压）。 */
function previewOf(file) {
	const cached = historyCache.get(file);
	if (cached !== void 0 && cached.messages.length > 0) {
		const last = cached.messages[cached.messages.length - 1];
		return {
			preview: plainPreview(last?.text ?? ""),
			count: cached.messages.length
		};
	}
	if (zstdDecompressSync === void 0) return {
		preview: "",
		count: 0
	};
	let size = 0;
	try {
		size = statSync(file).size;
	} catch {
		return {
			preview: "",
			count: 0
		};
	}
	const window = Math.min(size, 96 * 1024);
	if (window < 16) return {
		preview: "",
		count: 0
	};
	let fd;
	let buf;
	try {
		fd = openSync(file, "r");
		buf = readRange(fd, size - window, window);
	} catch {
		return {
			preview: "",
			count: 0
		};
	} finally {
		if (fd !== void 0) try {
			closeSync(fd);
		} catch {}
	}
	const starts = [];
	let cursor = 0;
	while ((cursor = buf.indexOf(ZSTD_MAGIC, cursor)) !== -1) {
		starts.push(cursor);
		cursor += 4;
	}
	const startIdx = size > window ? 1 : 0;
	if (starts.length <= startIdx) return {
		preview: "",
		count: 0
	};
	const texts = [];
	let count = 0;
	for (let index = startIdx; index < starts.length; index += 1) {
		const from = starts[index];
		const to = index + 1 < starts.length ? starts[index + 1] : buf.length;
		let decoded = "";
		try {
			decoded = zstdDecompressSync(buf.subarray(from, to)).toString("utf8");
		} catch {
			continue;
		}
		for (const raw of decoded.split("\n")) {
			if (raw.length === 0) continue;
			let ev;
			try {
				ev = JSON.parse(raw);
			} catch {
				continue;
			}
			const kind = String(ev.type ?? "");
			if (kind !== "user/message" && kind !== "assistant/message") continue;
			count += 1;
			const text = textOf(kind === "user/message" ? ev.data?.content : ev.data?.message?.content);
			if (text === "" || text.startsWith("<system-reminder>")) continue;
			texts.push(text);
		}
	}
	return {
		preview: plainPreview(texts.length > 0 ? texts[texts.length - 1] : ""),
		count
	};
}
/** 读取完整会话日志的原始 JSONL 文本（用于 ZIP 导出）。 */
function rawSessionJsonl(file) {
	if (zstdDecompressSync === void 0) throw new Error("this Node build has no zstd support");
	const st = statSync(file);
	if (st.size > MAX_SESSION_BYTES) throw new Error(`session log is ${String(st.size)} bytes, over the safety cap`);
	let fd;
	try {
		fd = openSync(file, "r");
		const { lines } = decodeZstdFrames(readRange(fd, 0, st.size));
		return lines.length > 0 ? `${lines.join("\n")}\n` : "";
	} finally {
		if (fd !== void 0) try {
			closeSync(fd);
		} catch {}
	}
}
//#endregion
//#region src/routes/sessions.ts
const ADD_SECTION_COMMANDS = /* @__PURE__ */ new Set([
	"file",
	"goal",
	"plan",
	"feedback"
]);
const FALLBACK_COMMANDS = [
	{
		name: "file",
		description: "添加文件到当前对话",
		section: "add"
	},
	{
		name: "goal",
		description: "设置或管理会话目标",
		hint: "<目标内容>",
		section: "add"
	},
	{
		name: "plan",
		description: "开启或关闭计划模式",
		section: "add"
	},
	{
		name: "feedback",
		description: "提交会话反馈",
		hint: "<反馈内容>",
		section: "add"
	},
	{
		name: "compact",
		description: "压缩当前对话上下文",
		section: "commands"
	},
	{
		name: "permission",
		description: "切换工具权限级别",
		section: "commands"
	},
	{
		name: "model",
		description: "切换当前会话模型",
		section: "commands"
	},
	{
		name: "export",
		description: "导出当前会话日志",
		section: "commands"
	},
	{
		name: "restart",
		description: "平滑重启电脑端服务",
		section: "commands"
	},
	{
		name: "restart-force",
		description: "强制重启电脑端服务",
		section: "commands"
	},
	{
		name: "web",
		description: "打开电脑端网页控制台",
		section: "commands"
	}
];
function normalizePlanValue(raw) {
	if (typeof raw === "boolean") return {
		active: raw,
		pending: false
	};
	if (raw !== null && typeof raw === "object") {
		const o = raw;
		return {
			active: o.active === true,
			pending: o.pending === true
		};
	}
	return {
		active: false,
		pending: false
	};
}
function createSessionRoutes(deps) {
	const idem = createIdempotencyStore();
	const activeStreamClosers = /* @__PURE__ */ new Set();
	/**
	* 优先读取内存中已存活的 agent；若是冷会话则自动调用 `sessionController.resolveAgent(sid)` 唤醒，
	* 彻底消除手机端操作冷会话时的 404/503 错误。
	*/
	const resolveLiveAgent = async (sid) => {
		const agents = deps.service("agents");
		if (agents !== null && typeof agents.get === "function") try {
			const live = agents.get(sid);
			if (live !== null && live !== void 0) return live;
		} catch {}
		const ctl = deps.controller();
		if (ctl && typeof ctl.resolveAgent === "function") try {
			const resolved = await Promise.resolve(ctl.resolveAgent(sid));
			if (resolved !== null && resolved !== void 0) return resolved;
		} catch {
			try {
				const resolved = await Promise.resolve(ctl.resolveAgent({ sessionId: sid }));
				if (resolved !== null && resolved !== void 0) return resolved;
			} catch {}
		}
		if (agents !== null && typeof agents.resolve === "function") try {
			const resolved = await Promise.resolve(agents.resolve(sid));
			if (resolved !== null && resolved !== void 0) return resolved;
		} catch {}
		if (agents !== null && typeof agents.get === "function") try {
			return agents.get(sid) ?? null;
		} catch {
			return null;
		}
		return null;
	};
	/** 读取会话计划模式状态（优先结合投影与 `planMode.get(agent)`）。 */
	const readPlanState = async (sid, projectedPlan, wakeCold = false) => {
		const planSvc = deps.service("planMode");
		if (planSvc !== null && typeof planSvc.get === "function") {
			const agents = deps.service("agents");
			const live = wakeCold ? await resolveLiveAgent(sid) : agents !== null && typeof agents.get === "function" ? agents.get(sid) : null;
			if (live !== null && live !== void 0) try {
				const val = await Promise.resolve(planSvc.get(live));
				if (val !== null && val !== void 0) return normalizePlanValue(val);
			} catch {}
		}
		if (projectedPlan !== void 0) return projectedPlan;
		try {
			const registry = deps.service("sessionProjections");
			const sessions = deps.service("sessions");
			const liveSession = sessions !== null && typeof sessions.get === "function" ? sessions.get(sid) : void 0;
			if (registry !== null && liveSession !== void 0 && typeof registry.snapshot === "function") return planOf(registry.snapshot(liveSession)?.values);
		} catch {}
		return {
			active: false,
			pending: false
		};
	};
	const disposeStreams = () => {
		for (const close of [...activeStreamClosers]) try {
			close();
		} catch {}
		activeStreamClosers.clear();
	};
	const serializeTailMsg = (msg) => {
		if (msg === void 0) return "";
		return JSON.stringify({
			seq: msg.seq,
			textLen: msg.text.length,
			thinkingLen: msg.thinking?.length ?? 0,
			tools: msg.tools ?? null,
			turn: msg.turn ?? null
		});
	};
	/** 启动指定会话的 SSE 实时流式推送（首帧立即推 `update`，450ms 检查增量，15s 心跳）。 */
	const serveSessionStream = async (req, res, url, sessionId) => {
		const sinceRaw = Number(url.searchParams.get("since") ?? "0");
		const initialSince = Number.isFinite(sinceRaw) ? Math.max(Math.trunc(sinceRaw), 0) : 0;
		const compact = url.searchParams.get("compact") === "1" || url.searchParams.get("compact") === "true";
		res.writeHead(200, {
			"content-type": "text/event-stream; charset=utf-8",
			"cache-control": "no-cache, no-store, no-transform",
			"connection": "keep-alive",
			"x-accel-buffering": "no",
			"access-control-allow-origin": "*"
		});
		let closed = false;
		let ticking = false;
		let lastSentSeq = initialSince;
		let lastTailSeq = 0;
		let lastTailSnap = "";
		let lastFingerprint = "";
		const writeSse = (chunk) => {
			if (closed || res.writableEnded || res.destroyed) return false;
			try {
				res.write(chunk);
				return true;
			} catch {
				cleanup();
				return false;
			}
		};
		const pushIfChanged = async (forceFirst) => {
			if (closed || ticking) return;
			ticking = true;
			try {
				let all = [];
				let lastTurn = "";
				let lastErr = null;
				let byteOffset = 0;
				let total = 0;
				let firstSeq = 0;
				if (zstdDecompressSync !== void 0) {
					const file = findSessionFile(sessionId);
					if (file !== null) try {
						const hist = historyOf(file);
						all = hist.messages;
						lastTurn = hist.lastTurn;
						lastErr = hist.lastErr;
						byteOffset = hist.byteOffset;
						total = all.length;
						firstSeq = all.length > 0 ? all[0]?.seq ?? 0 : 0;
					} catch {}
				}
				let running = false;
				let context = null;
				let projectedPlan;
				const ctl = deps.controller();
				let listed = [];
				if (ctl && typeof ctl.list === "function") try {
					listed = await Promise.resolve(ctl.list({}, AbortSignal.timeout(5e3)));
					const row = projectSessions(listed).find((r) => r.id === sessionId);
					if (row !== void 0) {
						running = row.running === true;
						context = row.context ?? deps.deepContext(sessionId);
						projectedPlan = row.plan;
					}
				} catch {}
				const plan = await readPlanState(sessionId, projectedPlan, false);
				const queue = await hostQueueView(ctl, sessionId);
				const questions = deps.askBridge.pendingAsks(listed, sessionId);
				const tailMsg = all.length > 0 ? all[all.length - 1] : void 0;
				const tailSnap = serializeTailMsg(tailMsg);
				const fp = JSON.stringify({
					byteOffset,
					total,
					tailSnap,
					running,
					lastTurn,
					lastErr,
					context,
					plan,
					queue,
					questions: questions.active
				});
				if (!forceFirst && fp === lastFingerprint) return;
				lastFingerprint = fp;
				let delta;
				if (forceFirst) delta = lastSentSeq > 0 ? all.filter((m) => m.seq > lastSentSeq).slice(-80) : all.slice(-30);
				else {
					delta = all.filter((m) => m.seq > lastSentSeq);
					if (tailMsg !== void 0 && tailMsg.seq === lastTailSeq && tailSnap !== lastTailSnap && !delta.some((m) => m.seq === tailMsg.seq)) delta = [...delta, tailMsg];
				}
				if (all.length > 0) {
					const newestSeq = all[all.length - 1]?.seq ?? lastSentSeq;
					if (newestSeq > lastSentSeq) lastSentSeq = newestSeq;
					lastTailSeq = tailMsg?.seq ?? 0;
					lastTailSnap = tailSnap;
				}
				const outMessages = compact ? applyCompactMode(all, delta) : delta;
				writeSse(`event: update\ndata: ${JSON.stringify({
					ok: true,
					sessionId,
					total,
					firstSeq,
					messages: outMessages,
					lastTurn,
					lastErr,
					running,
					context,
					plan,
					queue,
					questions
				})}\n\n`);
			} finally {
				ticking = false;
			}
		};
		const pollTimer = setInterval(() => {
			pushIfChanged(false);
		}, 450);
		const pingTimer = setInterval(() => {
			writeSse(": ping\n\n");
		}, 15e3);
		const cleanup = () => {
			if (closed) return;
			closed = true;
			clearInterval(pollTimer);
			clearInterval(pingTimer);
			activeStreamClosers.delete(cleanup);
			try {
				if (!res.writableEnded) res.end();
			} catch {}
		};
		activeStreamClosers.add(cleanup);
		res.on("close", cleanup);
		res.on("error", cleanup);
		await pushIfChanged(true);
	};
	const tryHandle = async (req, res, url, path, method) => {
		if (path === "/api/debug/raw" && method === "GET") {
			const ctl = deps.controller();
			if (!ctl || typeof ctl.list !== "function") {
				send(res, 503, { error: "sessionController unavailable" });
				return true;
			}
			const listed = await Promise.resolve(ctl.list({}, AbortSignal.timeout(15e3)));
			const rows = rowsOf(listed);
			const first = rows[0];
			send(res, 200, {
				ok: true,
				container: Array.isArray(listed) ? "array" : typeof listed,
				containerKeys: listed !== null && typeof listed === "object" && !Array.isArray(listed) ? Object.keys(listed) : [],
				count: rows.length,
				firstRowKeys: first !== null && typeof first === "object" ? Object.keys(first) : [],
				firstRow: first ?? null
			});
			return true;
		}
		if (path === "/api/sessions/previews" && method === "GET") {
			const ids = (url.searchParams.get("ids") ?? "").split(",").map((s) => s.trim()).filter((s) => s.length > 0).slice(0, 60);
			const previews = [];
			for (const id of ids) {
				const file = findSessionFile(id);
				if (file === null) continue;
				try {
					const one = previewOf(file);
					if (one.preview !== "") previews.push({
						id,
						preview: one.preview,
						count: one.count
					});
				} catch {}
			}
			send(res, 200, {
				ok: true,
				previews
			});
			return true;
		}
		if (path === "/api/sessions" && method === "GET") {
			const wantBackendRaw = (url.searchParams.get("backend") ?? "all").trim().toLowerCase();
			const wantBackend = wantBackendRaw === "dsh" || wantBackendRaw === "codex" || wantBackendRaw === "claude" || wantBackendRaw === "opencode" || wantBackendRaw === "antigravity" ? wantBackendRaw : "all";
			let dshSessions = [];
			if (wantBackend === "all" || wantBackend === "dsh") {
				const ctl = deps.controller();
				if (!ctl || typeof ctl.list !== "function") {
					if (wantBackend === "dsh") {
						send(res, 503, {
							error: "sessionController unavailable",
							hint: "is the DSH host fully started?"
						});
						return true;
					}
				} else {
					const listed = await Promise.resolve(ctl.list({}, AbortSignal.timeout(15e3)));
					dshSessions = deps.markPinned(deps.markArchived(projectSessions(listed, deps.askBridge.liveAsking()))).map((row) => ({
						...row,
						backend: "dsh"
					}));
				}
			}
			const extSessions = deps.backendRegistry ? await deps.backendRegistry.listExternalSessions(wantBackend, 30) : [];
			send(res, 200, {
				ok: true,
				sessions: [...dshSessions, ...extSessions].sort((a, b) => (b.updatedAt ?? 0) - (a.updatedAt ?? 0))
			});
			return true;
		}
		if (path === "/api/sessions" && method === "POST") {
			const ctl = deps.controller();
			if (!ctl || typeof ctl.create !== "function") {
				send(res, 503, { error: "sessionController.create unavailable" });
				return true;
			}
			const body = req.__parsedBody ?? await readJson(req);
			const cwd = String(body.cwd ?? "").trim();
			const args = {};
			if (cwd !== "") args.cwd = cwd;
			const created = await Promise.resolve(ctl.create(args));
			let raw = created;
			if (typeof raw === "string") try {
				raw = JSON.parse(raw);
			} catch {
				raw = null;
			}
			let sessionId = "";
			if (raw !== null && typeof raw === "object") {
				const row = raw;
				sessionId = String(row.sessionId ?? row.id ?? "");
			}
			await record(deps.logFile, `200 POST create session=${sessionId}`);
			send(res, 200, {
				ok: true,
				sessionId,
				result: created ?? null
			});
			return true;
		}
		const renameMatch = /^\/api\/sessions\/([^/]+)$/.exec(path);
		if (renameMatch !== null && method === "PATCH") {
			const ctl = deps.controller();
			if (!ctl || typeof ctl.rename !== "function") {
				send(res, 503, { error: "sessionController.rename unavailable" });
				return true;
			}
			const body = await readJson(req);
			const title = String(body.title ?? "").trim();
			if (title === "") {
				send(res, 400, { error: "title is empty" });
				return true;
			}
			const sessionId = decodeURIComponent(renameMatch[1]);
			await Promise.resolve(ctl.rename({
				sessionId,
				title
			}));
			await record(deps.logFile, `200 PATCH rename session=${sessionId} title=${title}`);
			send(res, 200, {
				ok: true,
				sessionId,
				title
			});
			return true;
		}
		const streamSignMatch = /^\/api\/sessions\/([^/]+)\/stream\/sign$/.exec(path);
		if (streamSignMatch !== null && method === "POST") {
			const sid = decodeURIComponent(streamSignMatch[1]);
			const exp = String(Math.floor(Date.now() / 1e3) + deps.sigTtlSec);
			send(res, 200, {
				ok: true,
				sessionId: sid,
				e: exp,
				sig: deps.sigOf("stream", sid, exp)
			});
			return true;
		}
		const streamMatch = /^\/api\/sessions\/([^/]+)\/stream$/.exec(path);
		if (streamMatch !== null && method === "GET") {
			const sid = decodeURIComponent(streamMatch[1]);
			await serveSessionStream(req, res, url, sid);
			return true;
		}
		const questionsMatch = /^\/api\/sessions\/([^/]+)\/questions$/.exec(path);
		if (questionsMatch !== null && method === "GET") {
			const sessionId = decodeURIComponent(questionsMatch[1]);
			const ctl = deps.controller();
			let listed = [];
			if (ctl && typeof ctl.list === "function") try {
				listed = await Promise.resolve(ctl.list({}, AbortSignal.timeout(8e3)));
			} catch {}
			send(res, 200, {
				ok: true,
				sessionId,
				...deps.askBridge.pendingAsks(listed, sessionId)
			});
			return true;
		}
		const answerMatch = /^\/api\/sessions\/([^/]+)\/questions\/answer$/.exec(path);
		if (answerMatch !== null && method === "POST") {
			const sessionId = decodeURIComponent(answerMatch[1]);
			const body = await readJson(req, 64 * 1024);
			const callId = String(body.callId ?? "");
			const answers = normalizeAskAnswers(body.answers);
			if (callId === "" || answers.length === 0) {
				send(res, 400, { error: "callId and answers are required" });
				return true;
			}
			const resolved = deps.askBridge.answer(sessionId, callId, { answers });
			if (!resolved.ok) {
				send(res, 409, {
					error: "this question is no longer waiting",
					callId
				});
				return true;
			}
			send(res, 200, {
				ok: true,
				callId,
				synthetic: resolved.synthetic,
				answered: answers.length
			});
			return true;
		}
		const historyMatch = /^\/api\/sessions\/([^/]+)\/messages$/.exec(path);
		if (historyMatch !== null && method === "GET") {
			const sessionId = decodeURIComponent(historyMatch[1]);
			if (zstdDecompressSync === void 0) {
				send(res, 501, { error: "this Node build has no zstd support" });
				return true;
			}
			const file = findSessionFile(sessionId);
			if (file === null) {
				send(res, 404, {
					error: "session log not found",
					sessionId
				});
				return true;
			}
			const raw = Number(url.searchParams.get("limit") ?? "30");
			const limit = Number.isFinite(raw) ? Math.min(Math.max(Math.trunc(raw), 1), 200) : 30;
			const sinceRaw = Number(url.searchParams.get("since") ?? "0");
			const since = Number.isFinite(sinceRaw) ? Math.max(Math.trunc(sinceRaw), 0) : 0;
			const beforeRaw = Number(url.searchParams.get("before") ?? "0");
			const before = Number.isFinite(beforeRaw) ? Math.max(Math.trunc(beforeRaw), 0) : 0;
			const compact = url.searchParams.get("compact") === "1" || url.searchParams.get("compact") === "true";
			const { messages: all, stats, lastTurn, lastErr } = historyOf(file);
			let tokens = stats.tokens;
			let running = false;
			let context = null;
			let projectedPlan;
			const ctl = deps.controller();
			let listed = [];
			if (ctl && typeof ctl.list === "function") try {
				listed = await Promise.resolve(ctl.list({}, AbortSignal.timeout(8e3)));
				const row = projectSessions(listed).find((r) => r.id === sessionId);
				if (row !== void 0) {
					tokens = row.tokens;
					running = row.running === true;
					context = row.context;
					projectedPlan = row.plan;
					if (context === null) context = deps.deepContext(sessionId);
				}
			} catch {}
			const plan = await readPlanState(sessionId, projectedPlan, false);
			const rawPage = since > 0 ? all.filter((m) => m.seq > since).slice(0, 200) : before > 0 ? all.filter((m) => m.seq < before).slice(-limit) : all.slice(-limit);
			const page = compact ? applyCompactMode(all, rawPage) : rawPage;
			send(res, 200, {
				ok: true,
				sessionId,
				total: all.length,
				firstSeq: all.length > 0 ? all[0]?.seq ?? 0 : 0,
				messages: page,
				stats: {
					...stats,
					tokens
				},
				lastTurn,
				lastErr,
				context,
				plan,
				running,
				queue: await hostQueueView(ctl, sessionId),
				questions: deps.askBridge.pendingAsks(listed, sessionId)
			});
			return true;
		}
		if (path === "/api/models" && method === "GET") {
			const ctl = deps.controller();
			if (!ctl || typeof ctl.modelCatalog !== "function") {
				send(res, 503, { error: "sessionController.modelCatalog unavailable" });
				return true;
			}
			const sessionId = url.searchParams.get("sessionId") ?? "";
			if (sessionId === "") {
				send(res, 400, { error: "sessionId is required" });
				return true;
			}
			send(res, 200, {
				ok: true,
				sessionId,
				catalog: normalizeCatalog(await Promise.resolve(ctl.modelCatalog({ sessionId }, AbortSignal.timeout(15e3))))
			});
			return true;
		}
		const modelMatch = /^\/api\/sessions\/([^/]+)\/model$/.exec(path);
		if (modelMatch !== null && method === "POST") {
			const ctl = deps.controller();
			if (!ctl || typeof ctl.selectModel !== "function") {
				send(res, 503, { error: "sessionController.selectModel unavailable" });
				return true;
			}
			const body = await readJson(req);
			const provider = String(body.provider ?? "").trim();
			const model = String(body.model ?? "").trim();
			if (provider === "" || model === "") {
				send(res, 400, { error: "provider and model are required" });
				return true;
			}
			const args = {
				sessionId: decodeURIComponent(modelMatch[1]),
				provider,
				model
			};
			const effort = String(body.reasoningEffort ?? "").trim();
			if (effort !== "") args.reasoningEffort = effort;
			const result = await Promise.resolve(ctl.selectModel(args, AbortSignal.timeout(2e4)));
			await record(deps.logFile, `200 POST model provider=${provider} model=${model} effort=${effort}`);
			send(res, 200, {
				ok: true,
				result: result ?? null
			});
			return true;
		}
		const stopMatch = /^\/api\/sessions\/([^/]+)\/stop$/.exec(path);
		if (stopMatch !== null && method === "POST") {
			const ctl = deps.controller();
			if (!ctl || typeof ctl.cancel !== "function") {
				send(res, 503, { error: "sessionController.cancel unavailable" });
				return true;
			}
			const sessionId = decodeURIComponent(stopMatch[1]);
			const result = await Promise.resolve(ctl.cancel({ sessionId }));
			let raw = result;
			if (typeof raw === "string") try {
				raw = JSON.parse(raw);
			} catch {
				raw = null;
			}
			let accepted = false;
			if (raw !== null && typeof raw === "object") accepted = raw.accepted === true;
			await record(deps.logFile, `200 POST stop session=${sessionId} accepted=${String(accepted)}`);
			send(res, 200, {
				ok: true,
				accepted,
				result: result ?? null
			});
			return true;
		}
		const archiveMatch = /^\/api\/sessions\/([^/]+)\/archive$/.exec(path);
		if (archiveMatch !== null && method === "POST") {
			const sessionId = decodeURIComponent(archiveMatch[1]);
			const ctl = deps.controller();
			const reg = deps.service("workspaceRegistry");
			if (!(ctl && typeof ctl.archive === "function") && !(reg && typeof reg.archiveSession === "function")) {
				send(res, 503, { error: "archiving is unavailable on this host" });
				return true;
			}
			const archiveCall = async (stopActivity) => {
				if (ctl && typeof ctl.archive === "function") {
					await Promise.resolve(ctl.archive({
						sessionId,
						stopActivity
					}));
					return;
				}
				await Promise.resolve(reg.archiveSession(sessionId, { stopActivity }));
			};
			let cancelledFirst = false;
			let stoppedFirst = false;
			try {
				await archiveCall(false);
			} catch (err) {
				const message = err instanceof Error ? err.message : String(err);
				if (/session-active|active|running|busy/i.test(message)) try {
					await archiveCall(true);
					stoppedFirst = true;
				} catch (err2) {
					if (ctl && typeof ctl.cancel === "function") {
						await Promise.resolve(ctl.cancel({ sessionId }));
						cancelledFirst = true;
						await archiveCall(false);
					} else throw err2;
				}
				else throw err;
			}
			await record(deps.logFile, `200 POST archive session=${sessionId} stoppedFirst=${String(stoppedFirst)} cancelledFirst=${String(cancelledFirst)}`);
			send(res, 200, {
				ok: true,
				sessionId,
				archived: true,
				stoppedFirst,
				cancelledFirst
			});
			return true;
		}
		const forkMatch = /^\/api\/sessions\/([^/]+)\/fork$/.exec(path);
		if (forkMatch !== null && method === "POST") {
			const sessionId = decodeURIComponent(forkMatch[1]);
			const ctl = deps.controller();
			if (!(ctl && typeof ctl.fork === "function")) {
				send(res, 503, { error: "forking is unavailable on this host" });
				return true;
			}
			const raw = (await readJson(req)).atSeq;
			const atSeq = typeof raw === "number" && Number.isFinite(raw) && raw >= 0 ? raw : void 0;
			try {
				const out = await Promise.resolve(ctl.fork(atSeq === void 0 ? { sessionId } : {
					sessionId,
					atSeq
				}));
				const child = typeof out === "string" ? out : String(out?.sessionId ?? "");
				if (child === "") {
					send(res, 500, { error: "host returned no session for the fork" });
					return true;
				}
				await record(deps.logFile, `200 POST fork session=${sessionId} at=${String(atSeq ?? "latest")} child=${child}`);
				send(res, 200, {
					ok: true,
					sessionId: child,
					atSeq: atSeq ?? null
				});
			} catch (err) {
				const message = err instanceof Error ? err.message : String(err);
				await record(deps.logFile, `500 POST fork session=${sessionId} at=${String(atSeq ?? "latest")} err=${message}`);
				send(res, 500, { error: message });
			}
			return true;
		}
		const unarchiveMatch = /^\/api\/sessions\/([^/]+)\/unarchive$/.exec(path);
		if (unarchiveMatch !== null && method === "POST") {
			const sessionId = decodeURIComponent(unarchiveMatch[1]);
			const ctl = deps.controller();
			const reg = deps.service("workspaceRegistry");
			const wc = deps.service("workspaceController");
			const attempts = [];
			if (ctl && typeof ctl.unarchive === "function") attempts.push({
				who: "sessionController.unarchive",
				run: () => Promise.resolve(ctl.unarchive({ sessionId }))
			});
			if (reg && typeof reg.unarchiveSession === "function") attempts.push({
				who: "workspaceRegistry.unarchiveSession",
				run: () => Promise.resolve(reg.unarchiveSession(sessionId))
			});
			if (wc && typeof wc.unarchiveSession === "function") attempts.push({
				who: "workspaceController.unarchiveSession",
				run: () => Promise.resolve(wc.unarchiveSession(sessionId))
			});
			if (attempts.length === 0) {
				send(res, 503, { error: "unarchiving is unavailable on this host" });
				return true;
			}
			let lastError = "";
			for (const attempt of attempts) try {
				await attempt.run();
				await record(deps.logFile, `200 POST unarchive session=${sessionId} via=${attempt.who}`);
				send(res, 200, {
					ok: true,
					sessionId,
					archived: false,
					via: attempt.who
				});
				return true;
			} catch (err) {
				lastError = err instanceof Error ? err.message : String(err);
			}
			send(res, 500, { error: `unarchive failed: ${lastError}` });
			return true;
		}
		const pinMatch = /^\/api\/sessions\/([^/]+)\/pin$/.exec(path);
		if (pinMatch !== null && method === "POST") {
			const sessionId = decodeURIComponent(pinMatch[1]);
			const body = await readJson(req);
			const want = body.pinned === void 0 ? true : body.pinned === true;
			const ctl = deps.controller();
			const reg = deps.service("workspaceRegistry");
			const anyCtl = ctl;
			const anyReg = reg;
			const attempts = [];
			const ctlFn = anyCtl === null ? void 0 : anyCtl[want ? "pin" : "unpin"];
			if (typeof ctlFn === "function") attempts.push({
				who: `sessionController.${want ? "pin" : "unpin"}`,
				run: () => Promise.resolve(ctlFn.call(ctl, { sessionId }))
			});
			const regFn = anyReg === null ? void 0 : anyReg[want ? "pinSession" : "unpinSession"];
			if (typeof regFn === "function") attempts.push({
				who: `workspaceRegistry.${want ? "pinSession" : "unpinSession"}`,
				run: () => Promise.resolve(regFn.call(reg, sessionId))
			});
			if (attempts.length === 0) {
				send(res, 503, { error: "pinning is unavailable on this host" });
				return true;
			}
			let lastError = "";
			for (const attempt of attempts) try {
				await attempt.run();
				await record(deps.logFile, `200 POST pin session=${sessionId} pinned=${String(want)} via=${attempt.who}`);
				send(res, 200, {
					ok: true,
					sessionId,
					pinned: want,
					via: attempt.who,
					ids: deps.pinnedIds() ?? []
				});
				return true;
			} catch (err) {
				lastError = err instanceof Error ? err.message : String(err);
			}
			send(res, 500, { error: `pin failed: ${lastError}` });
			return true;
		}
		const imagesMatch = /^\/api\/sessions\/([^/]+)\/images$/.exec(path);
		if (imagesMatch !== null && method === "POST") {
			const ctl = deps.controller();
			if (!ctl || typeof ctl.prompt !== "function") {
				send(res, 503, { error: "sessionController.prompt unavailable" });
				return true;
			}
			const body = await readJson(req, MAX_UPLOAD_BYTES);
			const { parts, bytes } = parseImageParts(Array.isArray(body.images) ? body.images : [], true);
			const sessionId = decodeURIComponent(imagesMatch[1]);
			const text = String(body.text ?? "").trim() || "（来自手机）";
			const requested = body.mode === "steer" ? "steer" : "queue";
			const outcome = await dispatchSessionMessage(ctl, sessionId, [{
				type: "text",
				text
			}, ...parts], requested, 6e4, deps.logFile, "images");
			if (outcome.queued) send(res, 200, {
				ok: true,
				sessionId,
				mode: "queue",
				queued: true,
				item: outcome.item,
				count: parts.length,
				queue: outcome.queue
			});
			else send(res, 200, {
				ok: true,
				sessionId,
				count: parts.length,
				bytes,
				mode: outcome.mode,
				running: outcome.running,
				result: outcome.result
			});
			return true;
		}
		const queueImgMatch = /^\/api\/sessions\/([^/]+)\/queue-image$/.exec(path);
		if (queueImgMatch !== null && method === "GET") {
			const sessionId = decodeURIComponent(queueImgMatch[1]);
			const itemId = String(url.searchParams.get("item") ?? "");
			const index = Number.parseInt(String(url.searchParams.get("i") ?? "0"), 10);
			const ctl = deps.controller();
			const item = (ctl === null ? [] : await hostQueued(ctl, sessionId)).find((x) => String(x.id) === itemId);
			const pick = (item && Array.isArray(item.content) ? item.content : []).filter((p) => p !== null && typeof p === "object" && p.type === "image")[Number.isFinite(index) ? index : 0];
			if (pick === void 0) {
				send(res, 404, { error: "queued image not found" });
				return true;
			}
			const mediaType = String(pick.mediaType ?? "image/png").toLowerCase();
			const buf = Buffer.from(String(pick.data ?? ""), "base64");
			res.writeHead(200, {
				"Content-Type": IMAGE_TYPES.has(mediaType) ? mediaType : "image/png",
				"Content-Length": String(buf.length),
				"Cache-Control": "no-store"
			});
			res.end(buf);
			return true;
		}
		const filesMatch = /^\/api\/sessions\/([^/]+)\/files$/.exec(path);
		if (filesMatch !== null && method === "POST") {
			const ctl = deps.controller();
			if (!ctl || typeof ctl.prompt !== "function") {
				send(res, 503, { error: "sessionController.prompt unavailable" });
				return true;
			}
			const body = await readJson(req, MAX_UPLOAD_BYTES);
			const { saved, bytes, text: savedNotice } = await saveMobileFiles(Array.isArray(body.files) ? body.files : [], true);
			const sessionId = decodeURIComponent(filesMatch[1]);
			const text = `${String(body.text ?? "").trim() || "（来自手机）"}\n\n${savedNotice}`;
			const requested = body.mode === "steer" ? "steer" : "queue";
			const outcome = await dispatchSessionMessage(ctl, sessionId, [{
				type: "text",
				text
			}], requested, 6e4, deps.logFile, "files");
			if (outcome.queued) send(res, 200, {
				ok: true,
				sessionId,
				mode: "queue",
				queued: true,
				item: outcome.item,
				count: saved.length,
				files: saved,
				queue: outcome.queue
			});
			else send(res, 200, {
				ok: true,
				sessionId,
				count: saved.length,
				bytes,
				files: saved,
				mode: outcome.mode,
				running: outcome.running,
				result: outcome.result
			});
			return true;
		}
		const queueMatch = /^\/api\/sessions\/([^/]+)\/queue$/.exec(path);
		if (queueMatch !== null) {
			const sessionId = decodeURIComponent(queueMatch[1]);
			if (method === "GET") {
				send(res, 200, {
					ok: true,
					sessionId,
					queue: await hostQueueView(deps.controller(), sessionId)
				});
				return true;
			}
			if (method === "POST") {
				const ctl = deps.controller();
				if (!ctl || typeof ctl.prompt !== "function") {
					send(res, 503, { error: "sessionController.prompt unavailable" });
					return true;
				}
				const body = await readJson(req);
				const text = String(body.text ?? "").trim();
				if (text.length === 0) {
					send(res, 400, { error: "text is empty" });
					return true;
				}
				const resultPayload = await withSessionLock(sessionId, async () => {
					return {
						itemId: await hostEnqueue(ctl, sessionId, [{
							type: "text",
							text
						}]),
						queue: await hostQueueView(ctl, sessionId)
					};
				});
				await record(deps.logFile, `200 QUEUE push session=${sessionId} host=${resultPayload.itemId}`);
				send(res, 200, {
					ok: true,
					sessionId,
					item: resultPayload.itemId,
					queue: resultPayload.queue
				});
				return true;
			}
		}
		const queueOrderMatch = /^\/api\/sessions\/([^/]+)\/queue\/reorder$/.exec(path);
		if (queueOrderMatch !== null && method === "POST") {
			const sessionId = decodeURIComponent(queueOrderMatch[1]);
			const ctl = deps.controller();
			if (!ctl || typeof ctl.prompt !== "function" || typeof ctl.updateQueue !== "function") {
				send(res, 503, { error: "sessionController queue API unavailable" });
				return true;
			}
			const body = await readJson(req);
			const wanted = Array.isArray(body.ids) ? body.ids.map((x) => String(x)) : [];
			await withSessionLock(sessionId, async () => {
				const listed = await hostQueued(ctl, sessionId);
				const byId = /* @__PURE__ */ new Map();
				for (const it of listed) byId.set(String(it.id), it);
				const unique = new Set(wanted);
				if (wanted.length !== listed.length || unique.size !== wanted.length || wanted.some((id) => !byId.has(id))) {
					send(res, 400, {
						error: "ids must cover every queued item exactly once",
						queue: await hostQueueView(ctl, sessionId)
					});
					return;
				}
				for (const it of listed) await hostMutate(ctl, sessionId, String(it.id), { kind: "remove" });
				let moved = 0;
				for (const id of wanted) {
					const it = byId.get(id);
					const content = it && Array.isArray(it.content) ? it.content : [];
					if (content.length === 0) continue;
					await hostEnqueue(ctl, sessionId, content);
					moved++;
				}
				await record(deps.logFile, `200 QUEUE reorder session=${sessionId} n=${String(moved)}`);
				send(res, 200, {
					ok: true,
					sessionId,
					moved,
					queue: await hostQueueView(ctl, sessionId)
				});
			});
			return true;
		}
		const queueItemMatch = /^\/api\/sessions\/([^/]+)\/queue\/([^/]+)\/(drop|fire|edit)$/.exec(path);
		if (queueItemMatch !== null && method === "POST") {
			const sessionId = decodeURIComponent(queueItemMatch[1]);
			const itemId = decodeURIComponent(queueItemMatch[2]);
			const action = queueItemMatch[3];
			const ctl = deps.controller();
			if (!ctl || typeof ctl.updateQueue !== "function") {
				send(res, 503, {
					error: "sessionController.updateQueue unavailable",
					hint: "restart the DSH host so the queue API is loaded"
				});
				return true;
			}
			let editText = "";
			if (action === "edit") {
				const body = await readJson(req);
				editText = String(body.text ?? "").trim();
				if (editText.length === 0) {
					send(res, 400, { error: "text is empty" });
					return true;
				}
			}
			await withSessionLock(sessionId, async () => {
				let mutation;
				if (action === "edit") mutation = {
					kind: "edit",
					content: await buildEditedQueueContent(ctl, sessionId, itemId, editText)
				};
				else if (action === "drop") mutation = { kind: "remove" };
				else mutation = { kind: "steer" };
				const mutated = await hostMutate(ctl, sessionId, itemId, mutation);
				await record(deps.logFile, `QUEUE ${action} session=${sessionId} id=${itemId} ok=${String(mutated)}`);
				if (!mutated) {
					send(res, 409, {
						error: "queue item is no longer pending",
						queue: await hostQueueView(ctl, sessionId)
					});
					return;
				}
				send(res, 200, {
					ok: true,
					sessionId,
					item: itemId,
					dropped: action === "drop",
					fired: action === "fire",
					queue: await hostQueueView(ctl, sessionId)
				});
			});
			return true;
		}
		const outboxMatch = /^\/api\/sessions\/([^/]+)\/outbox$/.exec(path);
		if (outboxMatch !== null && method === "POST") {
			const sessionId = decodeURIComponent(outboxMatch[1]);
			const body = await readJson(req, MAX_UPLOAD_BYTES);
			const route = `outbox:${sessionId}`;
			const reqHash = hashText(JSON.stringify(body));
			if (idem.replayHit(req, res, route, reqHash)) return true;
			const idemKey = String(req.headers["idempotency-key"] ?? "");
			if (idemKey !== "") {
				if (idem.inflightBusy(idemKey)) {
					send(res, 409, { error: "the same idempotency key is in flight" });
					return true;
				}
				idem.inflightHold(res, idemKey);
			}
			const reply = (status, payload) => {
				idem.replayPut(idemKey, status, payload, route, reqHash);
				send(res, status, payload);
			};
			const ctl = deps.controller();
			if (!ctl || typeof ctl.prompt !== "function") {
				reply(503, { error: "sessionController.prompt unavailable" });
				return true;
			}
			const rawImgs = Array.isArray(body.images) ? body.images : [];
			const rawFiles = Array.isArray(body.files) ? body.files : [];
			const { parts: imgParts } = parseImageParts(rawImgs, false);
			const savedFiles = await saveMobileFiles(rawFiles, false);
			const text = String(body.text ?? "").trim();
			const content = [];
			if (text !== "") content.push({
				type: "text",
				text
			});
			content.push(...imgParts);
			if (savedFiles.text !== "") content.push({
				type: "text",
				text: savedFiles.text
			});
			if (content.length === 0) {
				reply(400, { error: "nothing to send" });
				return true;
			}
			const outcome = await dispatchSessionMessage(ctl, sessionId, content, body.mode === "steer" ? "steer" : "queue", 12e4, deps.logFile, "outbox");
			if (outcome.queued) reply(200, {
				ok: true,
				sessionId,
				mode: "queue",
				queued: true,
				item: outcome.item,
				parts: content.length,
				queue: outcome.queue
			});
			else reply(200, {
				ok: true,
				sessionId,
				mode: outcome.mode,
				running: outcome.running,
				parts: content.length,
				result: outcome.result
			});
			return true;
		}
		const sendMatch = /^\/api\/sessions\/([^/]+)\/send$/.exec(path);
		if (sendMatch !== null && method === "POST") {
			const sessionId = decodeURIComponent(sendMatch[1]);
			const body = await readJson(req);
			const route = `send:${sessionId}`;
			const reqHash = hashText(JSON.stringify(body));
			if (idem.replayHit(req, res, route, reqHash)) return true;
			const idemKey = String(req.headers["idempotency-key"] ?? "");
			if (idemKey !== "") {
				if (idem.inflightBusy(idemKey)) {
					send(res, 409, { error: "the same idempotency key is in flight" });
					return true;
				}
				idem.inflightHold(res, idemKey);
			}
			const reply = (status, payload) => {
				idem.replayPut(idemKey, status, payload, route, reqHash);
				send(res, status, payload);
			};
			const ctl = deps.controller();
			if (!ctl || typeof ctl.prompt !== "function") {
				reply(503, {
					error: "sessionController.prompt unavailable",
					hint: "is the DSH host fully started?"
				});
				return true;
			}
			const text = String(body.text ?? "").trim();
			if (text.length === 0) {
				reply(400, { error: "text is empty" });
				return true;
			}
			const requested = body.mode === "steer" ? "steer" : "queue";
			const outcome = await dispatchSessionMessage(ctl, sessionId, [{
				type: "text",
				text
			}], requested, 2e4, deps.logFile, "send");
			if (outcome.queued) reply(200, {
				ok: true,
				sessionId,
				mode: "queue",
				queued: true,
				item: outcome.item,
				queue: outcome.queue
			});
			else reply(200, {
				ok: true,
				sessionId,
				mode: outcome.mode,
				running: outcome.running,
				result: outcome.result
			});
			return true;
		}
		if (path === "/api/presets" && method === "GET") {
			const svc = deps.service("agentPresets") ?? deps.service("agent-preset-registry");
			if (svc === null) {
				send(res, 200, {
					ok: true,
					presets: [],
					current: "",
					unavailable: true
				});
				return true;
			}
			const raw = typeof svc.remoteExportList === "function" ? await Promise.resolve(svc.remoteExportList()) : typeof svc.list === "function" ? await Promise.resolve(svc.list()) : null;
			const current = presetCurrent(svc);
			send(res, 200, {
				ok: true,
				presets: presetRows(raw, current),
				current,
				unavailable: false
			});
			return true;
		}
		const presetMatch = /^\/api\/sessions\/([^/]+)\/preset$/.exec(path);
		if (presetMatch !== null && method === "POST") {
			const body = await readJson(req);
			const presetId = String(body.presetId ?? "").trim();
			if (presetId === "") {
				send(res, 400, { error: "presetId is required" });
				return true;
			}
			const svc = deps.service("agentPresets") ?? deps.service("agent-preset-registry");
			if (svc === null) {
				send(res, 503, { error: "agentPresets service unavailable" });
				return true;
			}
			const sessionId = decodeURIComponent(presetMatch[1]);
			const agent = await resolveLiveAgent(sessionId);
			if (agent !== null && agent !== void 0 && typeof svc.select === "function") try {
				await Promise.resolve(svc.select(agent, presetId));
				await record(deps.logFile, `200 POST preset session=${sessionId} preset=${presetId} scope=session`);
				send(res, 200, {
					ok: true,
					selected: presetId,
					scope: "session"
				});
				return true;
			} catch (error) {
				const message = error instanceof Error ? error.message : String(error);
				if (!/already started|locked/.test(message)) throw error;
			}
			const settings = deps.service("settings");
			if (settings !== null && typeof settings.update === "function") {
				await Promise.resolve(settings.update("agent-preset-registry", { selectedDefault: presetId }, void 0));
				await record(deps.logFile, `200 POST preset session=${sessionId} preset=${presetId} scope=global`);
				send(res, 200, {
					ok: true,
					selected: presetId,
					scope: "global"
				});
				return true;
			}
			send(res, 409, { error: "this session already started a turn and no global default is available" });
			return true;
		}
		if (path === "/api/permissions" && method === "GET") {
			const svc = deps.service("permissionPresets");
			if (svc === null || typeof svc.catalog !== "function") {
				send(res, 200, {
					ok: true,
					presets: [],
					current: "",
					defaultPreset: "",
					unavailable: true
				});
				return true;
			}
			const cat = svc.catalog();
			const opts = cat !== null && Array.isArray(cat.options) ? cat.options : [];
			const presets = [];
			for (const item of opts) {
				if (item === null || typeof item !== "object") continue;
				const o = item;
				const value = String(o.value ?? "");
				if (value === "") continue;
				presets.push({
					value,
					name: String(o.name ?? value),
					description: String(o.description ?? "")
				});
			}
			let current = "";
			const sessionId = url.searchParams.get("sessionId") ?? "";
			if (sessionId !== "") {
				const agent = await resolveLiveAgent(sessionId);
				if (agent !== null && agent !== void 0) {
					const session = agent.session;
					if (session !== void 0 && typeof svc.current === "function") try {
						current = String(svc.current(session) ?? "");
					} catch {
						current = "";
					}
				}
			}
			send(res, 200, {
				ok: true,
				presets,
				current,
				defaultPreset: String(cat?.defaultPreset ?? ""),
				unavailable: false
			});
			return true;
		}
		const permMatch = /^\/api\/sessions\/([^/]+)\/permission$/.exec(path);
		if (permMatch !== null && method === "POST") {
			const body = await readJson(req);
			const preset = String(body.permission ?? "").trim();
			if (preset === "") {
				send(res, 400, { error: "permission is required" });
				return true;
			}
			const svc = deps.service("permissionPresets");
			if (svc === null || typeof svc.set !== "function") {
				send(res, 503, { error: "permissionPresets service unavailable" });
				return true;
			}
			const sessionId = decodeURIComponent(permMatch[1]);
			const agent = await resolveLiveAgent(sessionId);
			if (agent === null || agent === void 0) {
				send(res, 404, { error: `no agent for session ${sessionId}` });
				return true;
			}
			const session = agent.session;
			if (session === void 0) {
				send(res, 404, { error: `session ${sessionId} has no session object` });
				return true;
			}
			svc.set(session, preset);
			let current = preset;
			if (typeof svc.current === "function") try {
				current = String(svc.current(session) ?? preset);
			} catch {
				current = preset;
			}
			await record(deps.logFile, `200 POST permission session=${sessionId} preset=${preset} current=${current}`);
			send(res, 200, {
				ok: true,
				preset,
				current
			});
			return true;
		}
		const teamMatch = /^\/api\/sessions\/([^/]+)\/team$/.exec(path);
		if (teamMatch !== null && method === "GET") {
			const sessionId = decodeURIComponent(teamMatch[1]);
			const file = findSessionFile(sessionId);
			if (file === null) {
				send(res, 404, { error: "session log not found" });
				return true;
			}
			try {
				send(res, 200, {
					ok: true,
					sessionId,
					...teamOf(file)
				});
			} catch (error) {
				send(res, 500, { error: `cannot read session log: ${String(error)}` });
			}
			return true;
		}
		const teamModeMatch = /^\/api\/sessions\/([^/]+)\/team\/mode$/.exec(path);
		if (teamModeMatch !== null && method === "POST") {
			const body = await readJson(req);
			if (typeof body.enabled !== "boolean") {
				send(res, 400, { error: "enabled 必须是布尔值" });
				return true;
			}
			const enabled = body.enabled;
			const sessionId = decodeURIComponent(teamModeMatch[1]);
			const svc = deps.service("agentTeams");
			if (svc === null || typeof svc.setEnabled !== "function") {
				send(res, 503, { error: "这台电脑没有挂载智能体团队（agentTeams 服务不可用）" });
				return true;
			}
			const agent = await resolveLiveAgent(sessionId);
			if (agent === null || agent === void 0) {
				send(res, 404, { error: `找不到目标会话 ${sessionId}` });
				return true;
			}
			try {
				const change = svc.setEnabled;
				await Promise.resolve(change.call(svc, agent, enabled));
			} catch (error) {
				const code = typeof error.code === "string" ? String(error.code) : "";
				const message = error instanceof Error ? error.message : String(error);
				const status = code === "TEAM_LEAD_REQUIRED" ? 409 : 500;
				const readable = code === "TEAM_LEAD_REQUIRED" ? "这个会话是子智能体，请到它的根会话里切换智能体协作" : `电脑端拒绝了这个切换：${message}`;
				await record(deps.logFile, `${String(status)} POST team-mode session=${sessionId} enabled=${String(enabled)} code=${code} err=${message}`);
				send(res, status, { error: readable });
				return true;
			}
			await record(deps.logFile, `200 POST team-mode session=${sessionId} enabled=${String(enabled)}`);
			send(res, 200, {
				ok: true,
				enabled
			});
			return true;
		}
		const goalMatch = /^\/api\/sessions\/([^/]+)\/goal(?:\/(action))?$/.exec(path);
		if (goalMatch !== null) {
			const isAction = goalMatch[2] === "action";
			if (isAction && method !== "POST") {
				send(res, 405, { error: "method must be POST" });
				return true;
			}
			if (!isAction && method !== "GET") {
				send(res, 405, { error: "method must be GET" });
				return true;
			}
			const sid = decodeURIComponent(goalMatch[1]);
			const goalSvc = deps.service("goals");
			if (goalSvc === null) {
				send(res, 503, { error: "goals are unavailable on this host" });
				return true;
			}
			const agent = await resolveLiveAgent(sid);
			if (agent === void 0 || agent === null) {
				send(res, 404, { error: `找不到目标会话 ${sid}` });
				return true;
			}
			const viewOf = (v) => {
				if (v === void 0 || v === null || typeof v !== "object") return null;
				const o = v;
				return {
					id: o.id,
					objective: o.objective,
					phase: o.phase,
					revision: o.revision,
					roundsStarted: o.roundsStarted,
					maxGoalRounds: o.maxGoalRounds,
					activation: o.activation,
					updatedAt: o.updatedAt
				};
			};
			if (!isAction) {
				try {
					send(res, 200, {
						ok: true,
						sessionId: sid,
						goal: viewOf(goalSvc.get(agent))
					});
				} catch (ex) {
					send(res, 500, { error: String(ex) });
				}
				return true;
			}
			const body = await readJson(req);
			const action = typeof body.action === "string" ? body.action : "";
			if (action === "create") {
				if (typeof goalSvc.create !== "function") {
					send(res, 503, { error: "goals.create is unavailable on this host" });
					return true;
				}
				const objective = typeof body.objective === "string" ? body.objective.trim() : "";
				if (objective === "") {
					send(res, 400, { error: "objective 不能为空" });
					return true;
				}
				const rawRounds = body.maxGoalRounds;
				const maxGoalRounds = typeof rawRounds === "number" && Number.isFinite(rawRounds) && rawRounds > 0 ? Math.trunc(rawRounds) : void 0;
				try {
					const goalView = viewOf(await Promise.resolve(goalSvc.create(agent, {
						objective,
						...maxGoalRounds !== void 0 ? { maxGoalRounds } : {}
					}))) ?? viewOf(goalSvc.get(agent));
					await record(deps.logFile, `200 POST goal create session=${sid}`);
					send(res, 200, {
						ok: true,
						sessionId: sid,
						action: "create",
						goal: goalView
					});
				} catch (ex) {
					const err = ex;
					send(res, 409, {
						error: err.message ?? String(ex),
						code: err.code ?? ""
					});
				}
				return true;
			}
			let current = null;
			try {
				current = viewOf(goalSvc.get(agent));
			} catch (ex) {
				send(res, 500, { error: String(ex) });
				return true;
			}
			if (current === null) {
				send(res, 404, { error: "这个会话现在没有目标" });
				return true;
			}
			const ref = {
				id: current.id,
				revision: current.revision
			};
			try {
				if (action === "pause") await Promise.resolve(goalSvc.pause(agent, ref));
				else if (action === "resume") await Promise.resolve(goalSvc.resume(agent, ref));
				else if (action === "complete") await Promise.resolve(goalSvc.complete(agent, ref));
				else if (action === "clear") await Promise.resolve(goalSvc.clear(agent, ref));
				else if (action === "edit") {
					const patch = {};
					if (typeof body.objective === "string" && body.objective !== "") patch.objective = body.objective;
					if (typeof body.maxGoalRounds === "number" && body.maxGoalRounds > 0) patch.maxGoalRounds = body.maxGoalRounds;
					await Promise.resolve(goalSvc.edit(agent, ref, patch));
				} else {
					send(res, 400, { error: "action must be create, pause, resume, complete, clear or edit" });
					return true;
				}
				send(res, 200, {
					ok: true,
					sessionId: sid,
					action,
					goal: action === "clear" ? null : viewOf(goalSvc.get(agent))
				});
			} catch (ex) {
				const err = ex;
				send(res, 409, {
					error: err.message ?? String(ex),
					code: err.code ?? ""
				});
			}
			return true;
		}
		const planMatch = /^\/api\/sessions\/([^/]+)\/plan$/.exec(path);
		if (planMatch !== null) {
			const sid = decodeURIComponent(planMatch[1]);
			if (method === "GET") {
				let projectedPlan;
				const ctl = deps.controller();
				if (ctl && typeof ctl.list === "function") try {
					const row = projectSessions(await Promise.resolve(ctl.list({}, AbortSignal.timeout(5e3)))).find((r) => r.id === sid);
					if (row?.plan !== void 0) projectedPlan = row.plan;
				} catch {}
				const plan = await readPlanState(sid, projectedPlan, true);
				send(res, 200, {
					ok: true,
					active: plan.active,
					pending: plan.pending
				});
				return true;
			}
			if (method === "POST") {
				const body = await readJson(req);
				if (typeof body.active !== "boolean") {
					send(res, 400, { error: "active 必须是布尔值" });
					return true;
				}
				const planSvc = deps.service("planMode");
				if (planSvc === null || typeof planSvc.set !== "function") {
					send(res, 503, { error: "planMode 服务不可用" });
					return true;
				}
				const agent = await resolveLiveAgent(sid);
				if (agent === null || agent === void 0) {
					send(res, 404, { error: `找不到目标会话 ${sid}` });
					return true;
				}
				const rawRes = await Promise.resolve(planSvc.set(agent, body.active));
				let state = {
					active: body.active,
					pending: false
				};
				if (typeof planSvc.get === "function") try {
					const got = await Promise.resolve(planSvc.get(agent));
					if (got !== null && got !== void 0) state = normalizePlanValue(got);
				} catch {}
				else if (rawRes !== null && typeof rawRes === "object") state = normalizePlanValue(rawRes);
				const status = typeof rawRes === "string" ? rawRes : rawRes !== null && typeof rawRes === "object" && typeof rawRes.status === "string" ? String(rawRes.status) : state.active ? "active" : "inactive";
				await record(deps.logFile, `200 POST plan session=${sid} active=${String(state.active)}`);
				send(res, 200, {
					ok: true,
					active: state.active,
					pending: state.pending,
					status
				});
				return true;
			}
			send(res, 405, { error: "method must be GET or POST" });
			return true;
		}
		const cmdsMatch = /^\/api\/sessions\/([^/]+)\/commands$/.exec(path);
		if (cmdsMatch !== null && method === "GET") {
			const sid = decodeURIComponent(cmdsMatch[1]);
			const commandsSvc = deps.service("commands");
			let commands = [];
			if (commandsSvc !== null && typeof commandsSvc.list === "function") {
				const agent = await resolveLiveAgent(sid);
				if (agent !== null && agent !== void 0) try {
					const raw = await Promise.resolve(commandsSvc.list(agent));
					const list = Array.isArray(raw) ? raw : raw !== null && typeof raw === "object" && Array.isArray(raw.commands) ? raw.commands : raw !== null && typeof raw === "object" && Array.isArray(raw.items) ? raw.items : [];
					for (const item of list) {
						if (item === null || typeof item !== "object") continue;
						const c = item;
						const rawName = String(c.name ?? c.id ?? "").trim().replace(/^\/+/, "");
						if (rawName === "") continue;
						const hintRaw = typeof c.hint === "string" ? c.hint.trim() : typeof c.usage === "string" ? c.usage.trim() : "";
						const section = ADD_SECTION_COMMANDS.has(rawName.toLowerCase()) ? "add" : "commands";
						const entry = {
							name: rawName,
							description: String(c.description ?? ""),
							section
						};
						if (hintRaw !== "") entry.hint = hintRaw;
						commands.push(entry);
					}
				} catch {
					commands = [];
				}
			}
			if (commands.length === 0) commands = FALLBACK_COMMANDS.map((c) => ({ ...c }));
			send(res, 200, {
				ok: true,
				commands
			});
			return true;
		}
		const cmdExecMatch = /^\/api\/sessions\/([^/]+)\/commands\/execute$/.exec(path);
		if (cmdExecMatch !== null && method === "POST") {
			const sid = decodeURIComponent(cmdExecMatch[1]);
			const body = await readJson(req);
			const line = typeof body.line === "string" ? body.line.trim() : "";
			if (!line.startsWith("/") || line.length < 2) {
				send(res, 400, { error: "指令 line 必须以 / 开头且不能为空" });
				return true;
			}
			const spaceIdx = line.search(/\s/);
			const cmdName = (spaceIdx >= 0 ? line.slice(1, spaceIdx) : line.slice(1)).toLowerCase();
			const argText = spaceIdx >= 0 ? line.slice(spaceIdx + 1).trim() : "";
			const agent = await resolveLiveAgent(sid);
			if (agent === null || agent === void 0) {
				send(res, 404, { error: `找不到目标会话 ${sid}` });
				return true;
			}
			const trySessionFeedbackFallback = async () => {
				if (cmdName !== "feedback" || argText === "") return false;
				const fbSvc = deps.service("sessionFeedback");
				if (fbSvc === null) return false;
				try {
					if (typeof fbSvc.submit === "function") await Promise.resolve(fbSvc.submit(agent, argText));
					else if (typeof fbSvc.record === "function") await Promise.resolve(fbSvc.record(agent, argText));
					else if (typeof fbSvc.create === "function") await Promise.resolve(fbSvc.create({
						sessionId: sid,
						text: argText,
						agent
					}));
					else if (typeof fbSvc.add === "function") await Promise.resolve(fbSvc.add(agent, argText));
					else return false;
					await record(deps.logFile, `200 POST commands/execute session=${sid} cmd=feedback via=sessionFeedback`);
					send(res, 200, {
						ok: true,
						commandId: "feedback",
						kind: "info",
						text: "已记录反馈"
					});
					return true;
				} catch {
					return false;
				}
			};
			const commandsSvc = deps.service("commands");
			if (commandsSvc === null || typeof commandsSvc.execute !== "function") {
				if (await trySessionFeedbackFallback()) return true;
				send(res, 503, { error: "commands 服务不可用" });
				return true;
			}
			try {
				const execRes = await Promise.resolve(commandsSvc.execute(agent, line, [], AbortSignal.timeout(12e4)));
				const inner = execRes?.result !== null && typeof execRes?.result === "object" ? execRes.result : execRes ?? {};
				const commandId = String(execRes?.commandId ?? execRes?.id ?? cmdName);
				const kind = String(inner.kind ?? "info");
				const text = typeof inner.text === "string" ? inner.text : typeof inner.message === "string" ? inner.message : "";
				if (cmdName === "feedback" && argText !== "" && kind === "error") {
					if (await trySessionFeedbackFallback()) return true;
				}
				await record(deps.logFile, `200 POST commands/execute session=${sid} cmd=${commandId} kind=${kind}`);
				send(res, 200, {
					ok: true,
					commandId,
					kind,
					text
				});
				return true;
			} catch (ex) {
				if (await trySessionFeedbackFallback()) return true;
				const message = ex instanceof Error ? ex.message : String(ex);
				await record(deps.logFile, `500 POST commands/execute session=${sid} cmd=${cmdName} err=${message}`);
				send(res, 500, { error: `指令执行失败：${message}` });
				return true;
			}
		}
		const exportSignMatch = /^\/api\/sessions\/([^/]+)\/export\/sign$/.exec(path);
		if (exportSignMatch !== null && method === "POST") {
			const sid = decodeURIComponent(exportSignMatch[1]);
			const body = await readJson(req);
			const formatRaw = typeof body.format === "string" ? body.format.trim().toLowerCase() : "markdown";
			if (formatRaw !== "markdown" && formatRaw !== "zip") {
				send(res, 400, { error: "format 只能是 markdown 或 zip" });
				return true;
			}
			const exp = String(Math.floor(Date.now() / 1e3) + deps.sigTtlSec);
			send(res, 200, {
				ok: true,
				e: exp,
				sig: deps.sigOf("export", `${sid}|${formatRaw}`, exp),
				filename: `dsh-${sid.replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 64) || "session"}.${formatRaw === "zip" ? "zip" : "md"}`
			});
			return true;
		}
		const exportMatch = /^\/api\/sessions\/([^/]+)\/export$/.exec(path);
		if (exportMatch !== null && method === "GET") {
			const sid = decodeURIComponent(exportMatch[1]);
			const format = (url.searchParams.get("format") ?? "markdown").trim().toLowerCase();
			if (format !== "markdown" && format !== "zip") {
				send(res, 400, { error: "format 只能是 markdown 或 zip" });
				return true;
			}
			const sessionsSvc = deps.service("sessions");
			const liveSession = sessionsSvc !== null && typeof sessionsSvc.get === "function" ? sessionsSvc.get(sid) : void 0;
			if (liveSession !== void 0 && liveSession !== null && typeof sessionsSvc?.flush === "function") await Promise.resolve(sessionsSvc.flush(liveSession)).catch(() => void 0);
			const file = findSessionFile(sid);
			if (file === null) {
				send(res, 404, {
					error: "session log not found",
					sessionId: sid
				});
				return true;
			}
			let title = sid;
			let cwd = "";
			const ctl = deps.controller();
			if (ctl && typeof ctl.list === "function") try {
				const row = projectSessions(await Promise.resolve(ctl.list({}, AbortSignal.timeout(5e3)))).find((r) => r.id === sid);
				if (row !== void 0) {
					title = row.title;
					cwd = row.cwd;
				}
			} catch {}
			const exportedAt = (/* @__PURE__ */ new Date()).toISOString();
			const hist = historyOf(file);
			let markdown = "";
			try {
				const mod = await import(
					/* @vite-ignore */
					"@deepseek-ai/dsh-session-log-export"
);
				const fn = mod?.exportSessionMarkdown ?? mod?.renderMarkdown ?? mod?.default;
				if (typeof fn === "function") {
					const out = await Promise.resolve(fn({
						sessionId: sid,
						file,
						session: liveSession
					}));
					if (typeof out === "string" && out.trim().length > 0) markdown = out;
				}
			} catch {}
			if (markdown === "") markdown = renderSessionMarkdown({
				sessionId: sid,
				title,
				cwd,
				messages: hist.messages,
				stats: hist.stats,
				exportedAt
			});
			const safeId = sid.replace(/[^A-Za-z0-9._-]/g, "_").slice(0, 64) || "session";
			if (format === "markdown") {
				const filename = `dsh-${safeId}.md`;
				const bodyBuf = Buffer.from(markdown, "utf8");
				res.writeHead(200, {
					"content-type": "text/markdown; charset=utf-8",
					"content-length": String(bodyBuf.length),
					"content-disposition": `attachment; filename="${filename}"; filename*=UTF-8''${encodeURIComponent(filename)}`,
					"cache-control": "no-store"
				});
				res.end(bodyBuf);
				return true;
			}
			const jsonl = rawSessionJsonl(file);
			const metaJson = buildExportMetaJson({
				sessionId: sid,
				title,
				cwd,
				stats: hist.stats,
				messageCount: hist.messages.length,
				exportedAt
			});
			const zipBuf = buildZipBuffer([
				{
					name: "session.md",
					data: markdown
				},
				{
					name: "session.jsonl",
					data: jsonl
				},
				{
					name: "meta.json",
					data: metaJson
				}
			]);
			const filename = `dsh-${safeId}.zip`;
			res.writeHead(200, {
				"content-type": "application/zip",
				"content-length": String(zipBuf.length),
				"content-disposition": `attachment; filename="${filename}"; filename*=UTF-8''${encodeURIComponent(filename)}`,
				"cache-control": "no-store"
			});
			res.end(zipBuf);
			return true;
		}
		return false;
	};
	return {
		tryHandle,
		disposeStreams
	};
}
//#endregion
//#region src/routes/terminal.ts
/**
* 远程交互式终端路由（R6）：
* - 受 `allowTerminal` 开关控制（关闭返回 403）
* - `POST /api/sessions/:id/terminal/open`
* - `GET /api/sessions/:id/terminal/poll?since=<seq>`
* - `POST /api/sessions/:id/terminal/input`
* Windows 下使用 `powershell.exe -NoLogo -NoProfile` + UTF-8 (`chcp 65001`) + `windowsHide: true`。
*/
const MAX_TERM_BUFFER_BYTES = 64 * 1024;
const IDLE_TTL_MS = 1800 * 1e3;
const MAX_TERMINALS = 16;
function killProcessTree(proc) {
	if (proc === null) return;
	const pid = proc.pid;
	if (process.platform === "win32" && typeof pid === "number" && pid > 0) execFile("taskkill", [
		"/PID",
		String(pid),
		"/T",
		"/F"
	], { windowsHide: true }, () => {});
	try {
		proc.kill("SIGTERM");
	} catch {}
}
function createTerminalRoutes(fsHelper, logFile) {
	const terminals = /* @__PURE__ */ new Map();
	const pushChunk = (term, rawText) => {
		if (rawText.length === 0) return;
		let text = rawText;
		let bytes = Buffer.byteLength(text, "utf8");
		if (bytes > MAX_TERM_BUFFER_BYTES) {
			const buf = Buffer.from(text, "utf8");
			text = buf.subarray(buf.length - MAX_TERM_BUFFER_BYTES).toString("utf8");
			if (text.startsWith("�")) text = text.slice(1);
			bytes = Buffer.byteLength(text, "utf8");
		}
		term.seq += 1;
		term.chunks.push({
			seq: term.seq,
			text,
			bytes
		});
		term.totalBytes += bytes;
		term.lastActiveAt = Date.now();
		while (term.totalBytes > MAX_TERM_BUFFER_BYTES && term.chunks.length > 1) {
			const dropped = term.chunks.shift();
			if (dropped !== void 0) term.totalBytes -= dropped.bytes;
		}
	};
	const outputSince = (term, since) => term.chunks.filter((c) => c.seq > since).map((c) => c.text).join("");
	const spawnInto = (term) => {
		killProcessTree(term.proc);
		let proc;
		if (process.platform === "win32") proc = spawn("powershell.exe", [
			"-NoLogo",
			"-NoProfile",
			"-NoExit",
			"-Command",
			[
				"chcp 65001 > $null",
				"[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)",
				"[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)",
				"$OutputEncoding = [System.Text.UTF8Encoding]::new($false)"
			].join("; ")
		], {
			cwd: term.cwd,
			stdio: [
				"pipe",
				"pipe",
				"pipe"
			],
			windowsHide: true
		});
		else proc = spawn(process.env.SHELL && process.env.SHELL.length > 0 ? process.env.SHELL : "/bin/sh", ["-i"], {
			cwd: term.cwd,
			stdio: [
				"pipe",
				"pipe",
				"pipe"
			],
			windowsHide: true,
			env: {
				...process.env,
				TERM: "dumb"
			}
		});
		term.proc = proc;
		term.running = true;
		term.exitCode = null;
		term.lastActiveAt = Date.now();
		const outDecoder = new StringDecoder("utf8");
		const errDecoder = new StringDecoder("utf8");
		proc.stdout.on("data", (buf) => {
			pushChunk(term, outDecoder.write(buf));
		});
		proc.stderr.on("data", (buf) => {
			pushChunk(term, errDecoder.write(buf));
		});
		proc.on("error", (err) => {
			pushChunk(term, `\n[terminal error: ${err.message}]\n`);
			if (term.proc === proc) {
				term.running = false;
				term.exitCode = -1;
				term.proc = null;
			}
		});
		proc.on("close", (code) => {
			const tailOut = outDecoder.end();
			const tailErr = errDecoder.end();
			if (tailOut) pushChunk(term, tailOut);
			if (tailErr) pushChunk(term, tailErr);
			if (term.proc === proc) {
				term.running = false;
				term.exitCode = code ?? 0;
				term.proc = null;
			}
		});
	};
	const resolveSessionCwd = async (sid) => {
		const picked = await fsHelper.rootOf(sid);
		if (picked.root !== "") try {
			if (existsSync(picked.root) && statSync(picked.root).isDirectory()) return picked.root;
		} catch {}
		return homedir();
	};
	const openOrReuse = async (sid, forceRestart = false) => {
		const existing = terminals.get(sid);
		if (existing !== void 0 && existing.running && !forceRestart) {
			existing.lastActiveAt = Date.now();
			terminals.delete(sid);
			terminals.set(sid, existing);
			return existing;
		}
		if (existing !== void 0) {
			killProcessTree(existing.proc);
			terminals.delete(sid);
		}
		while (terminals.size >= MAX_TERMINALS) {
			const oldestKey = terminals.keys().next().value;
			if (oldestKey === void 0) break;
			const oldest = terminals.get(oldestKey);
			if (oldest !== void 0) killProcessTree(oldest.proc);
			terminals.delete(oldestKey);
		}
		const term = {
			sessionId: sid,
			cwd: await resolveSessionCwd(sid),
			proc: null,
			running: false,
			exitCode: null,
			seq: 0,
			totalBytes: 0,
			chunks: [],
			lastActiveAt: Date.now()
		};
		spawnInto(term);
		terminals.set(sid, term);
		await new Promise((r) => {
			setTimeout(r, 60);
		});
		return term;
	};
	const sweepTimer = setInterval(() => {
		const now = Date.now();
		for (const [sid, term] of terminals) if (now - term.lastActiveAt > IDLE_TTL_MS) {
			killProcessTree(term.proc);
			terminals.delete(sid);
			record(logFile, `terminal idle-reclaimed session=${sid}`);
		}
	}, 6e4);
	sweepTimer.unref?.();
	const disposeTerminals = () => {
		clearInterval(sweepTimer);
		for (const term of terminals.values()) {
			killProcessTree(term.proc);
			term.proc = null;
			term.running = false;
		}
		terminals.clear();
	};
	const tryHandle = async (req, res, url, path, method) => {
		const match = /^\/api\/sessions\/([^/]+)\/terminal\/(open|poll|input)$/.exec(path);
		if (match === null) return false;
		const sid = decodeURIComponent(match[1]);
		const op = match[2];
		if (!allowTerminal()) {
			send(res, 403, { error: "电脑端已关闭远程终端权限" });
			return true;
		}
		if (op === "open" && method === "POST") {
			const term = await openOrReuse(sid, false);
			await record(logFile, `200 POST terminal/open session=${sid} cwd=${term.cwd}`);
			send(res, 200, {
				ok: true,
				cwd: term.cwd,
				running: term.running,
				exitCode: term.exitCode,
				output: outputSince(term, 0),
				seq: term.seq
			});
			return true;
		}
		if (op === "poll" && method === "GET") {
			const sinceRaw = Number(url.searchParams.get("since") ?? "0");
			const since = Number.isFinite(sinceRaw) ? Math.max(Math.trunc(sinceRaw), 0) : 0;
			const term = terminals.get(sid);
			if (term === void 0) {
				send(res, 200, {
					ok: true,
					running: false,
					exitCode: null,
					output: "",
					seq: 0
				});
				return true;
			}
			term.lastActiveAt = Date.now();
			send(res, 200, {
				ok: true,
				running: term.running,
				exitCode: term.exitCode,
				output: outputSince(term, since),
				seq: term.seq
			});
			return true;
		}
		if (op === "input" && method === "POST") {
			const body = await readJson(req, 256 * 1024);
			const action = typeof body.action === "string" ? body.action.trim() : "";
			if (action === "close") {
				const existing = terminals.get(sid);
				if (existing !== void 0) {
					killProcessTree(existing.proc);
					existing.proc = null;
					existing.running = false;
					terminals.delete(sid);
				}
				await record(logFile, `200 POST terminal/input close session=${sid}`);
				send(res, 200, {
					ok: true,
					running: false,
					exitCode: existing?.exitCode ?? 0,
					output: "",
					seq: existing?.seq ?? 0
				});
				return true;
			}
			if (action === "restart") {
				const term = await openOrReuse(sid, true);
				await record(logFile, `200 POST terminal/input restart session=${sid}`);
				send(res, 200, {
					ok: true,
					cwd: term.cwd,
					running: term.running,
					exitCode: term.exitCode,
					output: outputSince(term, 0),
					seq: term.seq
				});
				return true;
			}
			if (action === "sigint") {
				const term = terminals.get(sid);
				if (term === void 0) {
					send(res, 200, {
						ok: true,
						running: false,
						exitCode: null,
						output: "",
						seq: 0
					});
					return true;
				}
				term.lastActiveAt = Date.now();
				if (process.platform === "win32") {
					pushChunk(term, "\n^C\n");
					spawnInto(term);
				} else if (term.proc !== null) try {
					term.proc.stdin.write("");
					term.proc.kill("SIGINT");
				} catch {}
				await record(logFile, `200 POST terminal/input sigint session=${sid}`);
				send(res, 200, {
					ok: true,
					running: term.running,
					exitCode: term.exitCode,
					seq: term.seq
				});
				return true;
			}
			if (action !== "") {
				send(res, 400, { error: "action must be sigint, close or restart" });
				return true;
			}
			const rawData = typeof body.data === "string" ? body.data : "";
			if (rawData === "") {
				send(res, 400, { error: "data or action is required" });
				return true;
			}
			const term = await openOrReuse(sid, false);
			if (term.proc === null || !term.running) {
				send(res, 500, { error: "终端进程未能启动" });
				return true;
			}
			const payload = body.raw === true || rawData.endsWith("\n") || rawData.endsWith("\r") ? rawData : `${rawData}\n`;
			const lineEndingNormalized = process.platform === "win32" ? payload.replace(/\r?\n/g, "\r\n") : payload;
			term.proc.stdin.write(lineEndingNormalized, "utf8");
			term.lastActiveAt = Date.now();
			send(res, 200, {
				ok: true,
				running: term.running,
				exitCode: term.exitCode,
				seq: term.seq
			});
			return true;
		}
		return false;
	};
	return {
		tryHandle,
		disposeTerminals
	};
}
//#endregion
//#region src/routes/web-console.ts
/**
* L5 一键免密打开电脑端完整网页控制台代理：
* - `POST /api/web-console/grant`（Bearer 鉴权）：签发 60 秒一次性随机票据（内存上限 16）；
* - `GET /api/web-console/enter?g=<grant>`（免 Bearer）：原子消费一次性票据并种下 30 分钟 HttpOnly Cookie，302 跳转至 `/api/web-console/proxy/`；
* - `ALL /api/web-console/proxy` 与 `/api/web-console/proxy/*`（校验 `dsh_wc` Cookie）：透明反向代理到本地 DSH Web GUI 并自动注入本地认证 Cookie；
* - `handleUpgrade`：支持 `/api/web-console/proxy/*` 的 WebSocket 双向隧道转发。
*/
const CORDIS_ORIGINAL = Symbol.for("cordis.original");
const GRANT_TTL_MS = 6e4;
const GRANT_CAP = 16;
const SESSION_TTL_MS = 1800 * 1e3;
const SESSION_CAP = 32;
const PROXY_PREFIX = "/api/web-console/proxy";
function getOptionalService(ctx, name) {
	if (!ctx || typeof ctx.get !== "function") return null;
	try {
		const val = ctx.get(name, false);
		if (val !== void 0 && val !== null) return val;
	} catch {}
	try {
		const val = ctx.get(name);
		return val === void 0 ? null : val;
	} catch {
		return null;
	}
}
function unwrapOriginal(obj) {
	if (obj === null || typeof obj !== "object") return obj;
	try {
		return Reflect.get(obj, CORDIS_ORIGINAL) ?? obj;
	} catch {
		return obj;
	}
}
function extractBrowserAuth(candidate) {
	if (candidate === null || candidate === void 0 || typeof candidate !== "object") return null;
	const targets = [
		candidate,
		candidate.auth,
		candidate.browserAuth
	];
	for (const t of targets) if (t !== null && t !== void 0 && typeof t === "object" && typeof t.authenticatedUrl === "function" && typeof t.authorizeIndex === "function") return t;
	return null;
}
/** 解析本地 DSH Web GUI 上游地址与认证实例。 */
function resolveDshWebRuntime(ctx) {
	const webServer = getOptionalService(ctx, "webServer");
	if (webServer === null || typeof webServer.getOrigin !== "function") return null;
	let rawOrigin;
	try {
		rawOrigin = webServer.getOrigin();
	} catch {
		return null;
	}
	if (rawOrigin === null || rawOrigin === void 0 || String(rawOrigin).trim() === "") return null;
	let origin;
	try {
		origin = rawOrigin instanceof URL ? new URL(rawOrigin.href) : new URL(String(rawOrigin));
	} catch {
		return null;
	}
	if (origin.protocol !== "http:" && origin.protocol !== "https:") return null;
	const auth = extractBrowserAuth(getOptionalService(ctx, "connection")) ?? extractBrowserAuth(webServer);
	return {
		origin,
		auth
	};
}
function exchangeLocalCookie(runtime) {
	const { origin, auth } = runtime;
	if (auth === null) return "";
	const bootstrap = new URL(auth.authenticatedUrl(origin.href));
	let cookie = "";
	auth.authorizeIndex({
		method: "GET",
		url: `/${bootstrap.search}`,
		headers: { host: origin.host }
	}, {
		writeHead(status, headers) {
			if (status >= 200 && status < 400 && headers !== void 0) {
				const raw = headers["set-cookie"] ?? headers["Set-Cookie"];
				const first = Array.isArray(raw) ? raw[0] : raw;
				if (typeof first === "string" && first.length > 0) cookie = first.split(";")[0] ?? "";
			}
		},
		end() {}
	});
	if (cookie === "") throw new Error("无法换取本地 DSH 网页控制台认证 Cookie");
	if (typeof auth.requestRejection === "function") {
		const rejected = auth.requestRejection({ headers: {
			host: origin.host,
			cookie
		} });
		if (rejected !== void 0) throw new Error(`本地 DSH 网页控制台认证被拒绝 (${String(rejected)})`);
	}
	return cookie;
}
function parseCookies(cookieHeader) {
	if (typeof cookieHeader !== "string" || cookieHeader === "") return {};
	const out = {};
	for (const seg of cookieHeader.split(";")) {
		const eq = seg.indexOf("=");
		if (eq <= 0) continue;
		const k = seg.slice(0, eq).trim();
		const v = seg.slice(eq + 1).trim();
		if (k !== "") out[k] = v;
	}
	return out;
}
function createWebConsoleRoutes(deps) {
	const grants = /* @__PURE__ */ new Map();
	const sessions = /* @__PURE__ */ new Map();
	const activeSockets = /* @__PURE__ */ new Set();
	let cachedAuth = null;
	const pruneGrants = (now) => {
		for (const [k, v] of grants) if (v.expiresAt <= now) grants.delete(k);
		while (grants.size > GRANT_CAP) {
			const oldest = grants.keys().next().value;
			if (oldest === void 0) break;
			grants.delete(oldest);
		}
	};
	const pruneSessions = (now) => {
		for (const [k, v] of sessions) if (v.expiresAt <= now) sessions.delete(k);
		while (sessions.size > SESSION_CAP) {
			const oldest = sessions.keys().next().value;
			if (oldest === void 0) break;
			sessions.delete(oldest);
		}
	};
	const hasValidSessionCookie = (req) => {
		const now = Date.now();
		pruneSessions(now);
		const sid = parseCookies(req.headers.cookie).dsh_wc ?? "";
		if (sid === "") return false;
		const hit = sessions.get(sid);
		if (hit === void 0 || hit.expiresAt <= now) {
			if (hit !== void 0) sessions.delete(sid);
			return false;
		}
		return true;
	};
	const resolveUpstream = () => {
		const runtime = resolveDshWebRuntime(deps.ctx);
		if (runtime === null) return null;
		const authRef = runtime.auth === null ? null : unwrapOriginal(runtime.auth);
		if (cachedAuth !== null && cachedAuth.originHref === runtime.origin.href && cachedAuth.authRef === authRef) {
			if (runtime.auth === null || typeof runtime.auth.requestRejection !== "function" || runtime.auth.requestRejection({ headers: {
				host: runtime.origin.host,
				cookie: cachedAuth.cookie
			} }) === void 0) return {
				origin: runtime.origin,
				cookie: cachedAuth.cookie
			};
		}
		try {
			const cookie = exchangeLocalCookie(runtime);
			cachedAuth = {
				originHref: runtime.origin.href,
				authRef,
				cookie
			};
			return {
				origin: runtime.origin,
				cookie
			};
		} catch {
			cachedAuth = null;
			return null;
		}
	};
	const isReady = () => resolveDshWebRuntime(deps.ctx) !== null;
	/** `/api/web-console/enter` 与 `/api/web-console/proxy*` 使用自有票据或 `dsh_wc` Cookie 鉴权，免 Bearer。 */
	const isBypassPath = (path, method) => {
		if (path === "/api/web-console/enter" && method === "GET") return true;
		if (path === PROXY_PREFIX || path.startsWith(`${PROXY_PREFIX}/`)) return true;
		return false;
	};
	const tryHandle = async (req, res, url, path, method) => {
		if (path === "/api/web-console/grant" && method === "POST") {
			if (!isReady()) {
				send(res, 503, { error: "电脑端网页控制台未就绪" });
				return true;
			}
			const now = Date.now();
			pruneGrants(now);
			while (grants.size >= GRANT_CAP) {
				const oldest = grants.keys().next().value;
				if (oldest === void 0) break;
				grants.delete(oldest);
			}
			const grant = randomBytes(24).toString("base64url");
			grants.set(grant, { expiresAt: now + GRANT_TTL_MS });
			await record(deps.logFile, "200 POST web-console/grant");
			send(res, 200, {
				ok: true,
				grant,
				path: `/api/web-console/enter?g=${grant}`,
				expiresIn: Math.floor(GRANT_TTL_MS / 1e3)
			});
			return true;
		}
		if (path === "/api/web-console/enter" && method === "GET") {
			const now = Date.now();
			pruneGrants(now);
			const g = (url.searchParams.get("g") ?? "").trim();
			const entry = g !== "" ? grants.get(g) : void 0;
			if (g !== "") grants.delete(g);
			if (entry === void 0 || entry.expiresAt <= now) {
				send(res, 401, { error: "网页控制台授权票据无效或已过期，请重新点击打开" });
				return true;
			}
			pruneSessions(now);
			while (sessions.size >= SESSION_CAP) {
				const oldest = sessions.keys().next().value;
				if (oldest === void 0) break;
				sessions.delete(oldest);
			}
			const sid = randomBytes(24).toString("base64url");
			sessions.set(sid, { expiresAt: now + SESSION_TTL_MS });
			await record(deps.logFile, "302 GET web-console/enter -> /api/web-console/proxy/");
			res.writeHead(302, {
				"set-cookie": `dsh_wc=${sid}; Path=${PROXY_PREFIX}; HttpOnly; SameSite=Lax; Max-Age=1800`,
				location: `${PROXY_PREFIX}/`,
				"cache-control": "no-store"
			});
			res.end();
			return true;
		}
		if (path === PROXY_PREFIX || path.startsWith(`${PROXY_PREFIX}/`)) {
			if (!hasValidSessionCookie(req)) {
				send(res, 401, { error: "网页控制台会话已过期，请重新从手机端打开" });
				return true;
			}
			if (path === PROXY_PREFIX && method === "GET") {
				res.writeHead(302, {
					location: `${PROXY_PREFIX}/${url.search}`,
					"cache-control": "no-store"
				});
				res.end();
				return true;
			}
			const upstream = resolveUpstream();
			if (upstream === null) {
				send(res, 503, { error: "电脑端网页控制台未就绪" });
				return true;
			}
			const { origin, cookie } = upstream;
			const upstreamPath = `${path.slice(22) || "/"}${url.search}`;
			const forwardHeaders = {};
			for (const [k, v] of Object.entries(req.headers)) {
				if (v === void 0) continue;
				const lower = k.toLowerCase();
				if (lower === "host" || lower === "authorization" || lower === "cookie" || lower === "connection" || lower === "forwarded" || lower.startsWith("x-forwarded-")) continue;
				if (lower === "origin") {
					forwardHeaders[k] = origin.origin;
					continue;
				}
				if (lower === "referer" && typeof v === "string") {
					try {
						const refUrl = new URL(v);
						if (refUrl.pathname.startsWith(PROXY_PREFIX)) {
							const refSub = refUrl.pathname.slice(22) || "/";
							forwardHeaders[k] = `${origin.origin}${refSub}${refUrl.search}`;
							continue;
						}
					} catch {}
					continue;
				}
				forwardHeaders[k] = v;
			}
			forwardHeaders.host = origin.host;
			if (cookie !== "") forwardHeaders.cookie = cookie;
			const reqFn = origin.protocol === "https:" ? request$1 : request;
			const portNum = origin.port !== "" ? Number(origin.port) : origin.protocol === "https:" ? 443 : 80;
			await new Promise((resolveDone) => {
				const proxyReq = reqFn({
					hostname: origin.hostname,
					port: portNum,
					method,
					path: upstreamPath,
					headers: forwardHeaders,
					timeout: 3e4
				}, (proxyRes) => {
					const status = proxyRes.statusCode ?? 502;
					const outHeaders = {};
					for (const [hk, hv] of Object.entries(proxyRes.headers)) {
						if (hv === void 0) continue;
						const lower = hk.toLowerCase();
						if (lower === "transfer-encoding" || lower === "connection" || lower === "set-cookie" || lower === "x-frame-options" || lower === "content-security-policy" || lower === "content-security-policy-report-only" || lower === "location") continue;
						outHeaders[hk] = hv;
					}
					const rawLoc = proxyRes.headers.location;
					if (typeof rawLoc === "string" && rawLoc.length > 0 && status >= 300 && status < 400) try {
						const resolved = new URL(rawLoc, `${origin.origin}${upstreamPath}`);
						if (resolved.origin === origin.origin) {
							resolved.searchParams.delete("token");
							const qs = resolved.searchParams.toString();
							outHeaders.location = `${PROXY_PREFIX}${resolved.pathname}${qs !== "" ? `?${qs}` : ""}`;
						} else outHeaders.location = rawLoc;
					} catch {}
					res.writeHead(status, outHeaders);
					if (method === "HEAD") {
						proxyRes.resume();
						res.end();
						resolveDone();
						return;
					}
					proxyRes.on("error", () => {
						res.destroy();
						resolveDone();
					});
					res.on("close", () => {
						proxyRes.destroy();
						resolveDone();
					});
					proxyRes.pipe(res);
					proxyRes.on("end", () => resolveDone());
				});
				proxyReq.on("timeout", () => {
					proxyReq.destroy(/* @__PURE__ */ new Error("upstream timeout"));
				});
				proxyReq.on("error", (err) => {
					send(res, 502, { error: `电脑端网页控制台代理连接失败：${err.message}` });
					resolveDone();
				});
				res.on("close", () => {
					if (!res.writableEnded) proxyReq.destroy();
				});
				if (method === "GET" || method === "HEAD") proxyReq.end();
				else req.pipe(proxyReq);
			});
			return true;
		}
		return false;
	};
	/** 支持 `/api/web-console/proxy/*` 的 WebSocket 透明代理升级。 */
	const handleUpgrade = (req, socket, head) => {
		let url;
		try {
			url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
		} catch {
			return false;
		}
		const path = url.pathname;
		if (!(path === PROXY_PREFIX || path.startsWith(`${PROXY_PREFIX}/`))) return false;
		const rejectSocket = (statusLine) => {
			try {
				socket.write(`HTTP/1.1 ${statusLine}\r\nConnection: close\r\n\r\n`);
			} catch {}
			socket.destroy();
		};
		if (!hasValidSessionCookie(req)) {
			rejectSocket("401 Unauthorized");
			return true;
		}
		const upstream = resolveUpstream();
		if (upstream === null) {
			rejectSocket("503 Service Unavailable");
			return true;
		}
		const { origin, cookie } = upstream;
		const upstreamPath = `${path.slice(22) || "/"}${url.search}`;
		const portNum = origin.port !== "" ? Number(origin.port) : origin.protocol === "https:" ? 443 : 80;
		const upstreamSocket = origin.protocol === "https:" ? connect$1({
			host: origin.hostname,
			port: portNum,
			servername: origin.hostname
		}) : connect({
			host: origin.hostname,
			port: portNum
		});
		activeSockets.add(socket);
		activeSockets.add(upstreamSocket);
		const cleanup = () => {
			activeSockets.delete(socket);
			activeSockets.delete(upstreamSocket);
			if (!socket.destroyed) socket.destroy();
			if (!upstreamSocket.destroyed) upstreamSocket.destroy();
		};
		upstreamSocket.on("connect", () => {
			const headerLines = [`${req.method ?? "GET"} ${upstreamPath} HTTP/1.1`, `Host: ${origin.host}`];
			for (let i = 0; i < req.rawHeaders.length; i += 2) {
				const name = req.rawHeaders[i];
				const value = req.rawHeaders[i + 1];
				if (name === void 0 || value === void 0) continue;
				const lower = name.toLowerCase();
				if (lower === "host" || lower === "cookie" || lower === "authorization" || lower === "forwarded" || lower.startsWith("x-forwarded-")) continue;
				if (lower === "origin") {
					headerLines.push(`Origin: ${origin.origin}`);
					continue;
				}
				headerLines.push(`${name}: ${value}`);
			}
			if (cookie !== "") headerLines.push(`Cookie: ${cookie}`);
			upstreamSocket.write(`${headerLines.join("\r\n")}\r\n\r\n`);
			if (head.length > 0) upstreamSocket.write(head);
			upstreamSocket.pipe(socket);
			socket.pipe(upstreamSocket);
		});
		upstreamSocket.on("error", () => {
			rejectSocket("502 Bad Gateway");
			cleanup();
		});
		socket.on("error", cleanup);
		upstreamSocket.on("close", cleanup);
		socket.on("close", cleanup);
		return true;
	};
	const dispose = () => {
		grants.clear();
		sessions.clear();
		for (const s of [...activeSockets]) try {
			s.destroy();
		} catch {}
		activeSockets.clear();
	};
	return {
		isReady,
		isBypassPath,
		tryHandle,
		handleUpgrade,
		dispose
	};
}
//#endregion
//#region src/routes/workspace-fs.ts
/**
* 工作区文件系统与本机目录浏览路由：
* - `GET /api/host/dirs`（本机常用根与盘符探测、会话近期工作区、逐级子目录浏览）
* - `GET /api/sessions/:id/fs`（支持 `offset` / `limit` 分页）
* - `POST /api/sessions/:id/fs/mkdir`（创建单层目录）
* - `POST /api/sessions/:id/fs/upload`（Base64 批量上传文件，防覆盖 409）
* - `/fs/file`、`/fs/rename`、`/fs/delete`、`/fs/sign`、`/fs/raw`、`/fs/download`
*/
const MAX_FS_UPLOAD_BYTES = 32 * 1024 * 1024;
const SYSTEM_SKIP_DIRS = /* @__PURE__ */ new Set([
	"$recycle.bin",
	"$winreagent",
	"system volume information",
	"recovery",
	"perflogs",
	"config.msi",
	"documents and settings",
	"node_modules",
	".git",
	".hvigor",
	"oh_modules"
]);
function createWorkspaceFsRoutes(deps) {
	const tidyCwd = (raw) => raw.replace(/\\\\/g, "\\");
	const cwdOf = async (sid) => {
		const sessions = deps.service("sessions");
		if (sessions !== null && typeof sessions.get === "function") {
			let live = null;
			try {
				live = sessions.get(sid);
			} catch {
				live = null;
			}
			if (live !== null && live !== void 0) {
				const cwd = live.cwd;
				if (typeof cwd === "string" && cwd.length > 0) return tidyCwd(cwd);
			}
		}
		const ctl = deps.controller();
		if (ctl && typeof ctl.list === "function") try {
			const row = projectSessions(await Promise.resolve(ctl.list({}, AbortSignal.timeout(1e4)))).find((r) => r.id === sid);
			if (row !== void 0 && row.cwd.length > 0) return tidyCwd(row.cwd);
		} catch {}
		return "";
	};
	const rootOf = async (sid) => {
		const cwd = await cwdOf(sid);
		if (cwd !== "") return {
			root: cwd,
			fallback: false
		};
		try {
			return {
				root: process.cwd(),
				fallback: true
			};
		} catch {
			return {
				root: "",
				fallback: false
			};
		}
	};
	const underRoot = (root, rel) => {
		const base = resolve(root);
		const target = resolve(base, rel.length === 0 ? "." : rel);
		if (!(target === base || target.startsWith(base + sep))) return null;
		try {
			const realBase = realpathSync(base);
			const realTarget = realpathSync(target);
			return realTarget === realBase || realTarget.startsWith(realBase + sep) ? realTarget : null;
		} catch {
			if (existsSync(target)) return null;
			try {
				const realBase = realpathSync(base);
				let probe = dirname(target);
				while (probe.length >= base.length && !existsSync(probe)) {
					const up = dirname(probe);
					if (up === probe) break;
					probe = up;
				}
				const realAncestor = realpathSync(probe);
				return realAncestor === realBase || realAncestor.startsWith(realBase + sep) ? target : null;
			} catch {
				return null;
			}
		}
	};
	const writeTarget = (root, rel, mustExist) => {
		if (rel === "") return null;
		const base = resolve(root);
		const lexical = resolve(base, rel);
		if (lexical === base || !lexical.startsWith(base + sep)) return null;
		let realBase = "";
		let realParent = "";
		try {
			realBase = realpathSync(base);
			realParent = realpathSync(dirname(lexical));
		} catch {
			return null;
		}
		if (!(realParent === realBase || realParent.startsWith(realBase + sep))) return null;
		const joined = join(realParent, basename(lexical));
		if (!mustExist) {
			try {
				if (lstatSync(joined).isSymbolicLink()) return null;
			} catch {}
			return joined;
		}
		try {
			if (lstatSync(joined).isSymbolicLink()) return null;
			return joined;
		} catch {
			return null;
		}
	};
	/** 收集已有会话中去重后的近期有效工作目录。 */
	const recentWorkspaces = async () => {
		const ctl = deps.controller();
		if (!ctl || typeof ctl.list !== "function") return [];
		try {
			const listed = await Promise.resolve(ctl.list({}, AbortSignal.timeout(8e3)));
			const seen = /* @__PURE__ */ new Set();
			const out = [];
			for (const row of projectSessions(listed)) {
				const clean = tidyCwd(row.cwd).trim();
				if (clean === "") continue;
				const key = process.platform === "win32" ? clean.toLowerCase() : clean;
				if (seen.has(key)) continue;
				try {
					if (statSync(clean).isDirectory()) {
						seen.add(key);
						out.push(clean);
						if (out.length >= 20) break;
					}
				} catch {}
			}
			return out;
		} catch {
			return [];
		}
	};
	/** 探测本机常用根目录与驱动器。 */
	const hostRootDirs = () => {
		const out = [];
		const seen = /* @__PURE__ */ new Set();
		const addIfExists = (name, p) => {
			const key = process.platform === "win32" ? p.toLowerCase() : p;
			if (seen.has(key)) return;
			try {
				if (statSync(p).isDirectory()) {
					seen.add(key);
					out.push({
						name,
						path: p
					});
				}
			} catch {}
		};
		const home = homedir();
		if (process.platform === "win32") {
			addIfExists("用户主目录", home);
			addIfExists("Documents", join(home, "Documents"));
			addIfExists("Desktop", join(home, "Desktop"));
			for (let code = 65; code <= 90; code += 1) {
				const drive = `${String.fromCharCode(code)}:\\`;
				addIfExists(drive, drive);
			}
		} else {
			addIfExists("用户主目录", home);
			addIfExists("Documents", join(home, "Documents"));
			addIfExists("/", "/");
		}
		return out;
	};
	const tryHandle = async (req, res, url, path, method) => {
		if (path === "/api/host/dirs" && method === "GET") {
			const rawPath = (url.searchParams.get("path") ?? "").trim();
			const recent = await recentWorkspaces();
			if (rawPath === "") {
				const roots = hostRootDirs();
				send(res, 200, {
					ok: true,
					path: "",
					parent: "",
					roots,
					dirs: roots,
					recent
				});
				return true;
			}
			const target = resolve(process.platform === "win32" && /^[A-Za-z]:$/.test(rawPath) ? `${rawPath}\\` : rawPath);
			try {
				if (!statSync(target).isDirectory()) {
					send(res, 400, { error: "指定路径不是文件夹" });
					return true;
				}
			} catch {
				send(res, 404, { error: "目录不存在或无权访问" });
				return true;
			}
			let entries = [];
			try {
				entries = readdirSync(target, { withFileTypes: true });
			} catch (err) {
				send(res, 403, { error: `无法读取目录：${err instanceof Error ? err.message : String(err)}` });
				return true;
			}
			const dirs = [];
			for (const item of entries) {
				const name = item.name;
				if (name.startsWith(".") || name.startsWith("$")) continue;
				if (SYSTEM_SKIP_DIRS.has(name.toLowerCase())) continue;
				let isDir = item.isDirectory();
				if (!isDir && item.isSymbolicLink()) try {
					isDir = statSync(join(target, name)).isDirectory();
				} catch {
					isDir = false;
				}
				if (!isDir) continue;
				dirs.push({
					name,
					path: join(target, name)
				});
			}
			dirs.sort((a, b) => a.name.localeCompare(b.name));
			const limited = dirs.slice(0, 200);
			const up = dirname(target);
			send(res, 200, {
				ok: true,
				path: target,
				parent: up !== target ? up : "",
				dirs: limited,
				recent
			});
			return true;
		}
		const fsMatch = /^\/api\/sessions\/([^/]+)\/fs$/.exec(path);
		if (fsMatch !== null && method === "GET") {
			const sid = decodeURIComponent(fsMatch[1]);
			const picked = await rootOf(sid);
			const root = picked.root;
			if (root === "") {
				send(res, 404, { error: `session ${sid} has no working directory` });
				return true;
			}
			const rel = String(url.searchParams.get("path") ?? "");
			const target = underRoot(root, rel);
			if (target === null) {
				send(res, 400, { error: "path escapes the working directory" });
				return true;
			}
			let names = [];
			try {
				names = readdirSync(target);
			} catch (err) {
				send(res, 404, { error: `cannot read folder: ${err instanceof Error ? err.message : String(err)}` });
				return true;
			}
			const entries = [];
			for (const name of names) {
				if (name === ".git" || name === "node_modules" || name === ".hvigor" || name === "oh_modules") continue;
				try {
					const st = statSync(join(target, name));
					entries.push({
						name,
						dir: st.isDirectory(),
						size: st.size,
						mtime: Math.round(st.mtimeMs)
					});
				} catch {}
			}
			entries.sort((a, b) => a.dir === b.dir ? a.name.localeCompare(b.name) : a.dir ? -1 : 1);
			const offsetRaw = Number(url.searchParams.get("offset") ?? "0");
			const offset = Number.isFinite(offsetRaw) ? Math.max(Math.trunc(offsetRaw), 0) : 0;
			const limitRaw = Number(url.searchParams.get("limit") ?? "400");
			const limit = Number.isFinite(limitRaw) ? Math.min(Math.max(Math.trunc(limitRaw), 1), 1e3) : 400;
			const total = entries.length;
			const page = entries.slice(offset, offset + limit);
			const nextOffset = offset + page.length;
			const more = nextOffset < total;
			await record(deps.logFile, `200 GET fs session=${sid} path=${rel} offset=${String(offset)} n=${String(page.length)}`);
			send(res, 200, {
				ok: true,
				root,
				path: rel,
				entries: page,
				total,
				offset,
				nextOffset,
				more,
				fallback: picked.fallback
			});
			return true;
		}
		const fsMkdirMatch = /^\/api\/sessions\/([^/]+)\/fs\/mkdir$/.exec(path);
		if (fsMkdirMatch !== null && method === "POST") {
			const sid = decodeURIComponent(fsMkdirMatch[1]);
			const picked = await rootOf(sid);
			const root = picked.root;
			if (root === "" || picked.fallback) {
				send(res, 400, { error: "session has no working directory" });
				return true;
			}
			const body = await readJson(req);
			const rel = String(body.path ?? "").trim();
			const target = writeTarget(root, rel, false);
			if (target === null) {
				send(res, 400, { error: "bad path" });
				return true;
			}
			if (existsSync(target)) {
				send(res, 409, { error: "同名文件或目录已存在" });
				return true;
			}
			try {
				mkdirSync(target);
				await record(deps.logFile, `200 POST fs/mkdir session=${sid} path=${rel}`);
				send(res, 200, {
					ok: true,
					path: rel
				});
			} catch (err) {
				send(res, 400, { error: `cannot create folder: ${err instanceof Error ? err.message : String(err)}` });
			}
			return true;
		}
		const fsUploadMatch = /^\/api\/sessions\/([^/]+)\/fs\/upload$/.exec(path);
		if (fsUploadMatch !== null && method === "POST") {
			const sid = decodeURIComponent(fsUploadMatch[1]);
			const picked = await rootOf(sid);
			const root = picked.root;
			if (root === "" || picked.fallback) {
				send(res, 400, { error: "session has no working directory" });
				return true;
			}
			const body = await readJson(req, MAX_FS_UPLOAD_BYTES);
			const dirRel = String(body.dir ?? "").trim();
			const dirTarget = underRoot(root, dirRel);
			if (dirTarget === null || !existsSync(dirTarget) || !statSync(dirTarget).isDirectory()) {
				send(res, 400, { error: "目标上传目录不存在或越界" });
				return true;
			}
			const rawFiles = Array.isArray(body.files) ? body.files : [];
			if (rawFiles.length === 0) {
				send(res, 400, { error: "files is empty" });
				return true;
			}
			if (rawFiles.length > 50) {
				send(res, 400, { error: "单次最多上传 50 个文件" });
				return true;
			}
			const planned = [];
			const seenNames = /* @__PURE__ */ new Set();
			for (const item of rawFiles) {
				if (item === null || typeof item !== "object") {
					send(res, 400, { error: "each file must be an object" });
					return true;
				}
				const f = item;
				const rawName = String(f.name ?? "").trim();
				if (rawName === "" || rawName === "." || rawName === ".." || rawName.length > 180 || /[\\/:*?"<>|\u0000-\u001f]/.test(rawName)) {
					send(res, 400, { error: `文件名不合法：${rawName || "(empty)"}` });
					return true;
				}
				const nameKey = process.platform === "win32" ? rawName.toLowerCase() : rawName;
				if (seenNames.has(nameKey)) {
					send(res, 409, { error: `上传列表中存在重名文件：${rawName}` });
					return true;
				}
				seenNames.add(nameKey);
				const data = String(f.data ?? "");
				if (data === "") {
					send(res, 400, { error: `文件数据为空：${rawName}` });
					return true;
				}
				const relFile = dirRel === "" ? rawName : `${dirRel.replace(/[\\/]+$/, "")}/${rawName}`;
				const dest = writeTarget(root, relFile, false);
				if (dest === null) {
					send(res, 400, { error: `非法的目标文件路径：${relFile}` });
					return true;
				}
				if (existsSync(dest)) {
					send(res, 409, { error: `目标文件已存在：${rawName}` });
					return true;
				}
				planned.push({
					relFile,
					dest,
					buf: Buffer.from(data, "base64")
				});
			}
			const saved = [];
			let bytes = 0;
			for (const one of planned) try {
				await writeFile(one.dest, one.buf, { flag: "wx" });
				saved.push(one.relFile);
				bytes += one.buf.length;
			} catch (err) {
				if (err.code === "EEXIST") {
					send(res, 409, { error: `目标文件已存在：${one.relFile}` });
					return true;
				}
				send(res, 500, { error: `写入文件失败：${err instanceof Error ? err.message : String(err)}` });
				return true;
			}
			await record(deps.logFile, `200 POST fs/upload session=${sid} dir=${dirRel} n=${String(saved.length)} bytes=${String(bytes)}`);
			send(res, 200, {
				ok: true,
				saved,
				bytes
			});
			return true;
		}
		const fsFileMatch = /^\/api\/sessions\/([^/]+)\/fs\/file$/.exec(path);
		if (fsFileMatch !== null && method === "GET") {
			const sid = decodeURIComponent(fsFileMatch[1]);
			const root = (await rootOf(sid)).root;
			const rel = String(url.searchParams.get("path") ?? "");
			const target = root === "" ? null : underRoot(root, rel);
			if (root === "" || target === null) {
				send(res, 400, { error: "bad path" });
				return true;
			}
			const LIMIT = 512 * 1024;
			let buf;
			try {
				const st = statSync(target);
				if (!st.isFile()) {
					send(res, 400, { error: "not a file" });
					return true;
				}
				if (st.size > LIMIT) {
					send(res, 413, { error: `file is too large to preview (${String(st.size)} bytes)` });
					return true;
				}
				buf = readFileSync(target);
			} catch (err) {
				send(res, 404, { error: `cannot read file: ${err instanceof Error ? err.message : String(err)}` });
				return true;
			}
			if (buf.indexOf(0) >= 0) {
				send(res, 415, { error: "binary file: no text preview" });
				return true;
			}
			send(res, 200, {
				ok: true,
				name: String(rel).split(/[\\/]/).pop() ?? rel,
				size: buf.length,
				text: buf.toString("utf8")
			});
			return true;
		}
		const fsRenameMatch = /^\/api\/sessions\/([^/]+)\/fs\/rename$/.exec(path);
		if (fsRenameMatch !== null && method === "POST") {
			const sid = decodeURIComponent(fsRenameMatch[1]);
			const picked = await rootOf(sid);
			const root = picked.root;
			if (root === "" || picked.fallback) {
				send(res, 400, { error: "session has no working directory" });
				return true;
			}
			const body = await readJson(req);
			const rel = String(body.path ?? "");
			const to = String(body.to ?? "");
			const from = writeTarget(root, rel, true);
			const dest = writeTarget(root, to, false);
			if (from === null || dest === null || from === dest) {
				send(res, 400, { error: "bad path" });
				return true;
			}
			if (existsSync(dest)) {
				send(res, 409, { error: "目标已存在" });
				return true;
			}
			try {
				renameSync(from, dest);
				await record(deps.logFile, `200 POST fs/rename session=${sid} from=${rel} to=${to}`);
				send(res, 200, { ok: true });
			} catch (err) {
				send(res, 400, { error: `cannot rename: ${err instanceof Error ? err.message : String(err)}` });
			}
			return true;
		}
		const fsDeleteMatch = /^\/api\/sessions\/([^/]+)\/fs\/delete$/.exec(path);
		if (fsDeleteMatch !== null && method === "POST") {
			const sid = decodeURIComponent(fsDeleteMatch[1]);
			const picked = await rootOf(sid);
			const root = picked.root;
			if (root === "" || picked.fallback) {
				send(res, 400, { error: "session has no working directory" });
				return true;
			}
			const body = await readJson(req);
			const rel = String(body.path ?? "");
			const target = writeTarget(root, rel, true);
			if (target === null) {
				send(res, 400, { error: "bad path" });
				return true;
			}
			try {
				if (statSync(target).isDirectory()) rmdirSync(target);
				else unlinkSync(target);
				await record(deps.logFile, `200 POST fs/delete session=${sid} path=${rel}`);
				send(res, 200, { ok: true });
			} catch (err) {
				send(res, 400, { error: `cannot delete: ${err instanceof Error ? err.message : String(err)}` });
			}
			return true;
		}
		const fsSignMatch = /^\/api\/sessions\/([^/]+)\/fs\/sign$/.exec(path);
		if (fsSignMatch !== null && method === "POST") {
			const sid = decodeURIComponent(fsSignMatch[1]);
			const body = await readJson(req);
			const rel = String(body.path ?? "");
			if (rel === "") {
				send(res, 400, { error: "path is required" });
				return true;
			}
			const exp = String(Math.floor(Date.now() / 1e3) + deps.sigTtlSec);
			send(res, 200, {
				ok: true,
				e: exp,
				sig: deps.sigOf("raw", `${sid}|${rel}`, exp)
			});
			return true;
		}
		const fsRawMatch = /^\/api\/sessions\/([^/]+)\/fs\/raw$/.exec(path);
		if (fsRawMatch !== null && method === "GET") {
			const sid = decodeURIComponent(fsRawMatch[1]);
			const root = (await rootOf(sid)).root;
			const rel = String(url.searchParams.get("path") ?? "");
			const target = root === "" ? null : underRoot(root, rel);
			if (root === "" || target === null) {
				send(res, 400, { error: "bad path" });
				return true;
			}
			const type = {
				".png": "image/png",
				".jpg": "image/jpeg",
				".jpeg": "image/jpeg",
				".webp": "image/webp",
				".gif": "image/gif",
				".bmp": "image/bmp",
				".svg": "image/svg+xml"
			}[extname(target).toLowerCase()];
			if (type === void 0) {
				send(res, 415, { error: "not an image" });
				return true;
			}
			const RAW_LIMIT = 16 * 1024 * 1024;
			let size = 0;
			try {
				const st = statSync(target);
				if (!st.isFile()) {
					send(res, 400, { error: "not a file" });
					return true;
				}
				if (st.size > RAW_LIMIT) {
					send(res, 413, { error: `image is too large (${String(st.size)} bytes)` });
					return true;
				}
				size = st.size;
			} catch (err) {
				send(res, 404, { error: `cannot read image: ${err instanceof Error ? err.message : String(err)}` });
				return true;
			}
			res.writeHead(200, {
				"content-type": type,
				"content-length": String(size),
				"cache-control": "private, max-age=60"
			});
			const imgStream = createReadStream(target);
			imgStream.on("error", () => {
				res.destroy();
			});
			res.on("close", () => {
				imgStream.destroy();
			});
			imgStream.pipe(res);
			return true;
		}
		const fsDownloadMatch = /^\/api\/sessions\/([^/]+)\/fs\/download$/.exec(path);
		if (fsDownloadMatch !== null && method === "GET") {
			const sid = decodeURIComponent(fsDownloadMatch[1]);
			const root = (await rootOf(sid)).root;
			const rel = String(url.searchParams.get("path") ?? "");
			const target = root === "" ? null : underRoot(root, rel);
			if (root === "" || target === null) {
				send(res, 400, { error: "bad path" });
				return true;
			}
			const LIMIT = 64 * 1024 * 1024;
			let size = 0;
			try {
				const st = statSync(target);
				if (!st.isFile()) {
					send(res, 400, { error: "not a file" });
					return true;
				}
				if (st.size > LIMIT) {
					send(res, 413, { error: `file is too large to download (${String(st.size)} bytes)` });
					return true;
				}
				size = st.size;
			} catch (err) {
				send(res, 404, { error: `cannot read file: ${err instanceof Error ? err.message : String(err)}` });
				return true;
			}
			const name = String(rel).split(/[\\/]/).pop() ?? rel;
			await record(deps.logFile, `200 GET fs/download session=${sid} path=${rel} n=${String(size)}`);
			res.writeHead(200, {
				"content-type": "application/octet-stream",
				"content-length": String(size),
				"content-disposition": `attachment; filename*=UTF-8''${encodeURIComponent(name)}`,
				"cache-control": "private, max-age=0"
			});
			const dlStream = createReadStream(target);
			dlStream.on("error", () => {
				res.destroy();
			});
			res.on("close", () => {
				dlStream.destroy();
			});
			dlStream.pipe(res);
			return true;
		}
		return false;
	};
	return {
		cwdOf,
		rootOf,
		underRoot,
		writeTarget,
		tryHandle
	};
}
//#endregion
//#region src/index.ts
/**
* agent-mobile-gateway 主入口：挂载独立手机网关 HTTP 服务与桌面设置面板路由，
* 协调配对鉴权、提问接管桥接、会话流、工作区文件/Git/终端及本机预览代理各子模块。
*
* @module agent-mobile-gateway
*/
const name = "mobile";
/** 导出给外部冒烟/纯函数测试使用的内部投影、日志读取与 Noise 加密工具。 */
const internals = {
	projectSessions,
	findSessionFile,
	historyOf,
	generateX25519Keypair,
	x25519PublicFromPrivate,
	NoiseCipherState,
	NoiseInitiator,
	NoiseResponder,
	BackendRegistry
};
const SIG_TTL_SEC = 300;
const MIME = {
	".html": "text/html; charset=utf-8",
	".js": "text/javascript; charset=utf-8",
	".css": "text/css; charset=utf-8",
	".svg": "image/svg+xml",
	".png": "image/png",
	".json": "application/json; charset=utf-8",
	".woff2": "font/woff2"
};
function apply(ctx, rawConfig) {
	const enabled = rawConfig?.enabled !== false;
	const port = rawConfig?.port ?? 8901;
	const host = rawConfig?.host ?? "::";
	const logFile = rawConfig?.logFile ?? join(dshHome(), "dsh-mobile.log");
	const token = enabled ? resolveToken(rawConfig?.token) : "";
	if (!enabled) return;
	const hostId = resolveHostId();
	const { pub: e2eePub } = resolveE2eeKeypair();
	const sigOf = (kind, value, exp) => createHmac("sha256", token).update(`${kind}\n${value}\n${exp}`).digest("hex");
	const signedOk = (kind, value, url) => {
		const exp = url.searchParams.get("e") ?? "";
		const sig = (url.searchParams.get("sig") ?? "").toLowerCase();
		if (exp === "" || sig === "") return false;
		const expN = Number(exp);
		if (!Number.isFinite(expN) || expN < Math.floor(Date.now() / 1e3)) return false;
		return tokenMatches(sigOf(kind, value, exp), sig);
	};
	const controller = () => {
		try {
			return ctx.get("sessionController");
		} catch {
			return;
		}
	};
	const service = (svcName) => {
		try {
			const found = ctx.get(svcName);
			return found === void 0 ? null : found;
		} catch {
			return null;
		}
	};
	const pairing = new PairingRuntime(port, logFile);
	const askBridge = createAskBridge(ctx, logFile);
	const deepContext = createDeepContextReader(service, logFile);
	const flags = createWorkspaceFlags(service);
	const fsRoutes = createWorkspaceFsRoutes({
		controller,
		service,
		sigOf,
		sigTtlSec: SIG_TTL_SEC,
		logFile
	});
	const gitRoutes = createGitRoutes(fsRoutes);
	const terminalRoutes = createTerminalRoutes(fsRoutes, logFile);
	const backendRegistry = new BackendRegistry({
		getEnabledMap: enabledBackends,
		setEnabled: (id, on) => setBackendEnabled(id, on),
		dshVersion: VERSION
	});
	const backendRoutes = createBackendRoutes({
		registry: backendRegistry,
		sigOf,
		sigTtlSec: SIG_TTL_SEC,
		logFile
	});
	const sessionRoutes = createSessionRoutes({
		controller,
		service,
		askBridge,
		deepContext,
		markArchived: flags.markArchived,
		markPinned: flags.markPinned,
		pinnedIds: flags.pinnedIds,
		sigOf,
		sigTtlSec: SIG_TTL_SEC,
		logFile,
		backendRegistry
	});
	const hostExtras = createHostExtrasRoutes({
		service,
		sigOf,
		sigTtlSec: SIG_TTL_SEC,
		logFile
	});
	const webConsoleRoutes = createWebConsoleRoutes({
		ctx,
		logFile
	});
	let handleRef;
	/** 轻量内存分发器：供 `/api/e2ee/rpc` 复用同一套 HTTP 路由处理逻辑，无需回环 TCP 连接。 */
	const dispatchInternal = async (inner) => {
		const bodyBuf = inner.body !== void 0 ? Buffer.from(typeof inner.body === "string" ? inner.body : JSON.stringify(inner.body), "utf8") : Buffer.alloc(0);
		const mockReq = Readable.from(bodyBuf.length > 0 ? [bodyBuf] : []);
		mockReq.method = inner.method;
		mockReq.url = inner.path;
		const headers = {
			host: String(inner.outerReq.headers.host ?? `127.0.0.1:${String(port)}`),
			authorization: `Bearer ${token}`
		};
		if (bodyBuf.length > 0) {
			headers["content-type"] = "application/json; charset=utf-8";
			headers["content-length"] = String(bodyBuf.length);
		}
		if (inner.idem !== void 0 && inner.idem !== "") headers["idempotency-key"] = inner.idem;
		mockReq.headers = headers;
		mockReq.socket = inner.outerReq.socket;
		return await new Promise((resolveDone, rejectDone) => {
			const emitter = new EventEmitter();
			const resHeaders = /* @__PURE__ */ new Map();
			const chunks = [];
			let settled = false;
			let statusCode = 200;
			let headersSent = false;
			let writableEnded = false;
			let destroyed = false;
			const finish = () => {
				if (settled) return;
				settled = true;
				const raw = Buffer.concat(chunks);
				const ctRaw = resHeaders.get("content-type");
				const ct = Array.isArray(ctRaw) ? ctRaw[0] ?? "" : ctRaw ?? "";
				let parsedBody;
				if (raw.length === 0) parsedBody = null;
				else if (ct.toLowerCase().includes("application/json")) try {
					parsedBody = JSON.parse(raw.toString("utf8"));
				} catch {
					parsedBody = raw.toString("utf8");
				}
				else if (ct === "" || ct.toLowerCase().startsWith("text/")) parsedBody = raw.toString("utf8");
				else parsedBody = raw.toString("base64");
				resolveDone({
					status: statusCode,
					body: parsedBody
				});
			};
			const mockRes = Object.assign(emitter, {
				get statusCode() {
					return statusCode;
				},
				set statusCode(code) {
					statusCode = code;
				},
				get headersSent() {
					return headersSent;
				},
				get writableEnded() {
					return writableEnded;
				},
				get destroyed() {
					return destroyed;
				},
				setHeader(name, value) {
					resHeaders.set(name.toLowerCase(), Array.isArray(value) ? value.map(String) : String(value));
				},
				getHeader(name) {
					return resHeaders.get(name.toLowerCase());
				},
				removeHeader(name) {
					resHeaders.delete(name.toLowerCase());
				},
				writeHead(code, hdrs) {
					statusCode = code;
					headersSent = true;
					if (hdrs !== void 0 && typeof hdrs === "object") for (const [k, v] of Object.entries(hdrs)) resHeaders.set(k.toLowerCase(), Array.isArray(v) ? v.map(String) : String(v));
					return mockRes;
				},
				write(chunk) {
					headersSent = true;
					chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
					return true;
				},
				end(chunk) {
					headersSent = true;
					if (chunk !== void 0) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
					writableEnded = true;
					emitter.emit("finish");
					emitter.emit("close");
					finish();
					return mockRes;
				},
				destroy() {
					destroyed = true;
					writableEnded = true;
					emitter.emit("close");
					finish();
					return mockRes;
				}
			});
			handleRef(mockReq, mockRes).then(() => {
				if (!settled) finish();
			}, (err) => {
				if (!settled) rejectDone(err);
			});
		});
	};
	const e2eeRoutes = createE2eeRoutes({
		dispatchInternal,
		logFile
	});
	const WEB_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "web");
	/** 安全提供 `web/` 下的静态资源，严格校验路径边界防前缀穿越。 */
	const serveStatic = (res, relative) => {
		const cleanRel = relative.replace(/^[/\\]+/, "");
		const target = resolve(WEB_ROOT, cleanRel === "" ? "." : cleanRel);
		if (!(target === WEB_ROOT || target.startsWith(WEB_ROOT + sep))) {
			send(res, 403, { error: "forbidden" });
			return;
		}
		let body;
		try {
			body = readFileSync(target);
		} catch {
			send(res, 404, {
				error: "not found",
				path: relative
			});
			return;
		}
		res.writeHead(200, {
			"content-type": MIME[extname(target)] ?? "application/octet-stream",
			"content-length": String(body.length),
			"cache-control": "no-store"
		});
		res.end(body);
	};
	const handle = async (req, res) => {
		const started = Date.now();
		const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
		const path = url.pathname;
		const method = req.method ?? "GET";
		if (method === "OPTIONS") {
			send(res, 204, "");
			return;
		}
		if (path === "/health") {
			send(res, 200, {
				ok: true,
				name: "dsh-mobile",
				version: VERSION,
				pid: process.pid,
				host: hostname(),
				hostId
			});
			return;
		}
		if (path === "/api/pair/info") {
			const prefs = pairPrefs();
			send(res, 200, {
				ok: true,
				name: "dsh-mobile",
				version: VERSION,
				host: hostname(),
				hostId,
				e2eePub,
				e2ee: true,
				port,
				lan: prefs.allowLan ? lanBases(port) : [],
				publicUrl: prefs.publicUrl,
				needCode: true
			});
			return;
		}
		if (path === "/api/pair/claim" && method === "POST") {
			const prefs = pairPrefs();
			if (!prefs.allowLan && !prefs.allowRemote) {
				send(res, 403, {
					error: "pairing is off",
					hint: "turn 允许连接 on in the DSH panel"
				});
				return;
			}
			const local = isLocalHostHeader(req.headers.host);
			if (local && !prefs.allowLan) {
				send(res, 403, {
					error: "lan pairing is off",
					hint: "turn 局域网直连 on in the DSH panel"
				});
				return;
			}
			if (!local && !prefs.allowRemote) {
				send(res, 403, {
					error: "remote pairing is off",
					hint: "turn 公网访问 on in the DSH panel"
				});
				return;
			}
			const now = Date.now();
			const peer = pairing.peerKey(req.socket.remoteAddress, local, req.headers);
			const until = pairing.lockedUntil(peer, now);
			if (until > now) {
				send(res, 429, {
					error: "too many wrong codes",
					retryAt: until
				});
				return;
			}
			const attempt = pairing.reserveAttempt(peer, now);
			let body;
			try {
				body = await readJson(req);
			} catch (err) {
				const status = typeof err?.status === "number" ? err.status : 400;
				send(res, status, { error: status === 413 ? "body too large" : "body must be a JSON object" });
				return;
			}
			const given = String(body.code ?? "").trim();
			const verify = pairing.verifyClaim(peer, attempt, given, peer.startsWith("tunnel:"));
			if (!verify.ok) {
				await record(logFile, `401 PAIR claim bad code from ${peer} left=${String(verify.left)} rotated=${String(verify.rotated)}`);
				send(res, 401, {
					error: "wrong code",
					code: "bad-code",
					left: verify.left,
					rotated: verify.rotated
				});
				return;
			}
			const headerHost = req.headers.host;
			const forwarded = req.headers["x-forwarded-proto"];
			const scheme = typeof forwarded === "string" && forwarded.toLowerCase() === "https" ? "https" : "http";
			const lan = lanBases(port);
			const base = typeof headerHost === "string" && headerHost.length > 0 ? `${scheme}://${headerHost}` : lan[0] ?? `http://127.0.0.1:${String(port)}`;
			await record(logFile, `200 PAIR claim base=${base} from ${peer} local=${String(local)}`);
			send(res, 200, {
				ok: true,
				token,
				base,
				host: hostname(),
				hostId,
				e2eePub,
				e2ee: true,
				version: VERSION,
				port,
				lan: prefs.allowLan ? lan : [],
				qr: pairPayload(base, pairing.ensurePair().code, lan.slice(1))
			});
			return;
		}
		const attSigned = path.startsWith("/api/attachments/") && method === "GET" ? signedOk("att", path.slice(17).toLowerCase(), url) : false;
		const rawMatch = /^\/api\/sessions\/([^/]+)\/fs\/raw$/.exec(path);
		const rawSigned = rawMatch !== null && method === "GET" && signedOk("raw", `${decodeURIComponent(rawMatch[1])}|${url.searchParams.get("path") ?? ""}`, url);
		const streamMatch = /^\/api\/sessions\/([^/]+)\/stream$/.exec(path);
		const streamSigned = streamMatch !== null && method === "GET" && signedOk("stream", decodeURIComponent(streamMatch[1]), url);
		const exportMatch = /^\/api\/sessions\/([^/]+)\/export$/.exec(path);
		const exportFormat = (url.searchParams.get("format") ?? "markdown").trim().toLowerCase();
		const exportSigned = exportMatch !== null && method === "GET" && (exportFormat === "markdown" || exportFormat === "zip") && signedOk("export", `${decodeURIComponent(exportMatch[1])}|${exportFormat}`, url);
		const loopbackSigned = hostExtras.isLoopbackAuthorized(req, url, path, method);
		const webConsoleBypass = webConsoleRoutes.isBypassPath(path, method);
		if (!attSigned && !rawSigned && !streamSigned && !exportSigned && !loopbackSigned && !webConsoleBypass && !tokenMatches(presentedToken(req, url), token)) {
			await record(logFile, `401 ${method} ${path} from ${req.socket.remoteAddress ?? "?"}`);
			send(res, 401, {
				error: "unauthorized",
				hint: "send Authorization: Bearer <token>, or ?t=<token>"
			});
			return;
		}
		pairing.phoneSeenAt = Date.now();
		{
			const prefs = pairPrefs();
			const local = isLocalHostHeader(req.headers.host);
			if (local && !prefs.allowLan) {
				send(res, 403, {
					error: "lan access is off",
					hint: "turn 局域网直连 on in the DSH panel"
				});
				return;
			}
			if (!local && !prefs.allowRemote) {
				send(res, 403, {
					error: "remote access is off",
					hint: "turn 公网访问 on in the DSH panel"
				});
				return;
			}
		}
		try {
			if (path === "/" || path === "/index.html") {
				serveStatic(res, "index.html");
				return;
			}
			if (path.startsWith("/app/")) {
				serveStatic(res, path.slice(5));
				return;
			}
			if (path === "/api/info") {
				send(res, 200, {
					ok: true,
					version: VERSION,
					host: hostname(),
					hostId,
					e2eePub,
					e2ee: true,
					addresses: lanAddresses(),
					port,
					sessions: true,
					messages: zstdDecompressSync !== void 0,
					send: true,
					stop: true,
					create: true,
					rename: true,
					pin: true,
					images: true,
					files: true,
					attachments: true,
					stream: true,
					git: true,
					terminal: allowTerminal(),
					plan: true,
					commands: true,
					webConsole: webConsoleRoutes.isReady(),
					loopback: previewPorts().length > 0
				});
				return;
			}
			if (path === "/api/presence") {
				let online = true;
				if (method === "POST") {
					const body = await readJson(req).catch(() => void 0);
					if (body !== void 0 && typeof body === "object" && body !== null) {
						if (body.online === false) online = false;
					}
				}
				pairing.phoneSeenAt = online ? Date.now() : 0;
				send(res, 200, {
					ok: true,
					online,
					ttlMs: PRESENCE_TTL_MS,
					sessionId: String(url.searchParams.get("sessionId") ?? "")
				});
				return;
			}
			if (path === "/api/answer-mode" && method === "GET") {
				send(res, 200, {
					ok: true,
					mode: answerMode()
				});
				return;
			}
			if (path === "/api/answer-mode" && method === "POST") {
				const wanted = (await readJson(req)).mode;
				if (wanted !== "phone" && wanted !== "desktop") {
					send(res, 400, { error: "mode must be \"phone\" or \"desktop\"" });
					return;
				}
				if (!writeState({ answerMode: wanted }, (error) => {
					record(logFile, `answer mode persist failed: ${String(error)}`);
				})) {
					await record(logFile, `500 ANSWER wanted=${wanted} persist failed`);
					send(res, 500, {
						ok: false,
						error: "answer mode not saved",
						mode: answerMode()
					});
					return;
				}
				if (wanted === "desktop") askBridge.delegateAll("api-answer-mode-desktop");
				await record(logFile, `200 ANSWER mode=${wanted}`);
				send(res, 200, {
					ok: true,
					mode: wanted
				});
				return;
			}
			if (path === "/api/pair/state" && method === "GET") {
				send(res, 200, pairing.snapshot());
				return;
			}
			if (path === "/api/pair/newcode" && method === "POST") {
				pairing.rotatePair(true);
				send(res, 200, pairing.snapshot());
				return;
			}
			if (path === "/api/pair/config" && method === "POST") {
				const body = await readJson(req);
				const current = pairPrefs();
				let publicUrl = current.publicUrl;
				if (body.publicUrl !== void 0) {
					if (typeof body.publicUrl !== "string") {
						send(res, 400, { error: "公网地址必须是字符串" });
						return;
					}
					const checked = validatePublicUrl(body.publicUrl);
					if (!checked.ok) {
						send(res, 400, { error: checked.error });
						return;
					}
					publicUrl = checked.url;
				}
				const nextPair = {
					allowLan: typeof body.allowLan === "boolean" ? body.allowLan : current.allowLan,
					allowRemote: typeof body.allowRemote === "boolean" ? body.allowRemote : current.allowRemote,
					publicUrl
				};
				const patch = { pair: nextPair };
				if (body.answerMode !== void 0) {
					if (body.answerMode !== "phone" && body.answerMode !== "desktop") {
						send(res, 400, { error: "回答模式只能是 phone 或 desktop" });
						return;
					}
					patch.answerMode = body.answerMode;
				}
				if (body.allowTerminal !== void 0) {
					if (typeof body.allowTerminal !== "boolean") {
						send(res, 400, { error: "allowTerminal 必须是布尔值" });
						return;
					}
					patch.allowTerminal = body.allowTerminal;
				}
				if (body.previewPorts !== void 0) {
					const checkedPorts = parsePreviewPorts(body.previewPorts);
					if (!checkedPorts.ok) {
						send(res, 400, { error: checkedPorts.error });
						return;
					}
					patch.previewPorts = checkedPorts.ports;
				}
				writeState(patch);
				if (patch.answerMode === "desktop") askBridge.delegateAll("pair-config-desktop");
				await record(logFile, `200 PAIR config lan=${String(nextPair.allowLan)} remote=${String(nextPair.allowRemote)}`);
				send(res, 200, pairing.snapshot());
				return;
			}
			if (path === "/api/attachments/sign" && method === "POST") {
				const body = await readJson(req);
				const ids = Array.isArray(body.ids) ? body.ids : [];
				if (ids.length > 64) {
					send(res, 400, { error: "at most 64 ids per request" });
					return;
				}
				const exp = String(Math.floor(Date.now() / 1e3) + SIG_TTL_SEC);
				send(res, 200, {
					ok: true,
					items: ids.map((raw) => String(raw).toLowerCase()).filter((id) => /^[0-9a-f]{8,128}$/.test(id)).map((id) => ({
						id,
						e: exp,
						sig: sigOf("att", id, exp)
					}))
				});
				return;
			}
			if (path.startsWith("/api/attachments/") && method === "GET") {
				const digest = path.slice(17).toLowerCase();
				if (!/^[0-9a-f]{8,128}$/.test(digest)) {
					send(res, 400, { error: "bad attachment id" });
					return;
				}
				const file = join(dshHome(), "attachments", "v1", "objects", digest.slice(0, 2), digest);
				let body;
				try {
					body = readFileSync(file);
				} catch {
					send(res, 404, {
						error: "attachment not found",
						id: digest
					});
					return;
				}
				const asked = String(url.searchParams.get("m") ?? "");
				const type = asked === "image/jpeg" || asked === "image/webp" || asked === "image/gif" || asked === "image/png" ? asked : "image/png";
				res.writeHead(200, {
					"content-type": type,
					"content-length": String(body.length),
					"cache-control": "private, max-age=86400"
				});
				res.end(body);
				return;
			}
			if (await webConsoleRoutes.tryHandle(req, res, url, path, method)) return;
			if (await e2eeRoutes.tryHandle(req, res, url, path, method)) return;
			if (await backendRoutes.tryHandle(req, res, url, path, method)) return;
			if (await fsRoutes.tryHandle(req, res, url, path, method)) return;
			if (await gitRoutes.tryHandle(req, res, url, path, method)) return;
			if (await terminalRoutes.tryHandle(req, res, url, path, method)) return;
			if (await hostExtras.tryHandle(req, res, url, path, method)) return;
			if (await sessionRoutes.tryHandle(req, res, url, path, method)) return;
			send(res, 404, {
				error: "not found",
				path
			});
		} catch (error) {
			const status = typeof error?.status === "number" ? error.status : 500;
			const message = error instanceof Error ? error.message : String(error);
			await record(logFile, `${String(status)} ${method} ${path} ${message}`);
			if (!res.headersSent) send(res, status, { error: message });
			else res.destroy();
		} finally {
			const qp = [];
			url.searchParams.forEach((v, k) => {
				qp.push(`${k}=${k === "t" || k === "payload" || k === "sig" || k === "g" ? "***" : v}`);
			});
			const q = qp.length === 0 ? "" : `?${qp.join("&").slice(0, 40)}`;
			record(logFile, `${String(res.statusCode)} ${method} ${path}${q} ${String(Date.now() - started)}ms`);
		}
	};
	handleRef = handle;
	const panel = createPanel({
		pairState: () => pairing.snapshot(),
		rotatePair: () => {
			pairing.rotatePair(true);
		},
		writePrefs: (next) => {
			writeState({
				pair: {
					allowLan: next.allowLan,
					allowRemote: next.allowRemote,
					publicUrl: next.publicUrl
				},
				answerMode: next.answerMode,
				allowTerminal: next.allowTerminal,
				previewPorts: next.previewPorts
			});
			if (next.answerMode === "desktop") askBridge.delegateAll("panel-answer-mode-desktop");
		},
		revokeDevice: (deviceId, revoked) => e2eeRoutes.revokeDevice(deviceId, revoked),
		pairPayload: (base, code, alts) => pairPayload(base, code, alts),
		record: (line) => record(logFile, line)
	});
	try {
		ctx.inject(["connection"], (connCtx) => {
			const registry = connCtx?.connection?.fetch;
			if (registry === void 0 || typeof registry.register !== "function") {
				record(logFile, "panel routes skipped: connection.fetch unavailable");
				return;
			}
			for (const route of panel.routes) try {
				const dispose = registry.register(route);
				connCtx.effect(() => dispose, `dsh-mobile: panel ${String(route.path)}`);
			} catch (error) {
				record(logFile, `panel route ${String(route.path)} not registered: ${error instanceof Error ? error.message : String(error)}`);
			}
			record(logFile, "panel routes registered on connection.fetch");
		});
	} catch (error) {
		record(logFile, `panel registration failed: ${error instanceof Error ? error.message : String(error)}`);
	}
	const server = createServer((req, res) => {
		handle(req, res).catch(() => {
			try {
				if (!res.headersSent) send(res, 500, { error: "internal gateway error" });
				else res.destroy();
			} catch {}
		});
	});
	server.on("upgrade", (req, socket, head) => {
		const prefs = pairPrefs();
		const local = isLocalHostHeader(req.headers.host);
		if (local && !prefs.allowLan || !local && !prefs.allowRemote) {
			socket.write("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
			socket.destroy();
			return;
		}
		if (!webConsoleRoutes.handleUpgrade(req, socket, head)) {
			socket.write("HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n");
			socket.destroy();
		}
	});
	ctx.effect(function* () {
		server.on("error", (error) => {
			record(logFile, `listen failed on ${host}:${String(port)} ${error.code ?? ""} ${error.message}`);
		});
		server.listen(port, host, () => {
			const urls = lanAddresses().map((a) => `http://${hostPort(a, port)}/?t=<token>`);
			record(logFile, `listening on ${host}:${String(port)}; urls ${urls.join(" ")}`);
			process.stdout.write(`[dsh-mobile] listening on ${host}:${String(port)} token file ${statePath()}\n`);
		});
		yield () => {
			record(logFile, "disposing; releasing live asks, streams, terminals, e2ee, web-console and listener");
			askBridge.delegateAll("plugin-dispose");
			backendRoutes.disposeStreams();
			backendRegistry.dispose();
			sessionRoutes.disposeStreams();
			terminalRoutes.disposeTerminals();
			webConsoleRoutes.dispose();
			e2eeRoutes.dispose();
			server.close();
			server.closeAllConnections?.();
		};
	}, "mobile listener");
}
//#endregion
export { apply, internals, name };

//# sourceMappingURL=index.js.map