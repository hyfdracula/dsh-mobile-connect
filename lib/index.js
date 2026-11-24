import { createHash, createHmac, randomBytes, randomInt, timingSafeEqual } from "node:crypto";
import { chmodSync, closeSync, createReadStream, existsSync, lstatSync, mkdirSync, openSync, readFileSync, readSync, readdirSync, realpathSync, renameSync, rmdirSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { appendFile, mkdir, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { homedir, hostname, networkInterfaces } from "node:os";
import { basename, dirname, extname, join, normalize, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import * as zlib from "node:zlib";
//#region src/http-util.ts
/** 普通请求体上限 1 MiB；上传走更大的显式限额。 */
const DEFAULT_BODY_BYTES = 1 << 20;
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
function tokenMatches(given, expected) {
	if (given.length === 0 || expected.length === 0) return false;
	const a = Buffer.from(given, "utf8");
	const b = Buffer.from(expected, "utf8");
	if (a.length !== b.length) return false;
	return timingSafeEqual(a, b);
}
function presentedToken(req, url) {
	const header = req.headers.authorization;
	if (typeof header === "string" && header.toLowerCase().startsWith("bearer ")) return header.slice(7).trim();
	const query = url.searchParams.get("t");
	return query === null ? "" : query.trim();
}
async function readJson(req, limit = DEFAULT_BODY_BYTES) {
	const chunks = [];
	let size = 0;
	for await (const chunk of req) {
		const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
		size += buf.length;
		if (size > limit) throw new Error("body too large");
		chunks.push(buf);
	}
	if (size === 0) return {};
	const text = Buffer.concat(chunks).toString("utf8");
	const parsed = JSON.parse(text);
	if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("body must be a JSON object");
	return parsed;
}
const send = (res, status, body) => {
	const text = typeof body === "string" ? body : JSON.stringify(body);
	res.writeHead(status, {
		"content-type": typeof body === "string" ? "text/plain; charset=utf-8" : "application/json; charset=utf-8",
		"content-length": String(Buffer.byteLength(text)),
		"access-control-allow-origin": "*",
		"access-control-allow-headers": "authorization,content-type",
		"access-control-allow-methods": "GET,POST,PATCH,OPTIONS",
		"cache-control": "no-store"
	});
	res.end(text);
};
//#endregion
//#region src/panel.ts
/**
* DSH 设置面板用的同源路由：配对状态、二维码、开关，以及本机管理员可见的反馈工单。
*
* 从 `index.ts` 拆出来：这些处理不碰手机端 HTTP 监听，只读写配对状态与偏好，
* 由宿主 web 服务器的 `connection.fetch` 注册。依赖通过 `PanelCtx` 传入，
* 模块本身不持有插件实例状态。
*/
const PANEL_PREFIX = "/api/dsh-mobile/panel";
/** JSON response for a panel route. */
const panelJson = (status, payload) => new Response(JSON.stringify(payload), {
	status,
	headers: {
		"content-type": "application/json; charset=utf-8",
		"cache-control": "no-store"
	}
});
/** Render the QR as SVG; a missing `qrcode` degrades to a caption, not a 500. */
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
/** Tolerant body reader: a panel POST without JSON is an empty patch. */
const panelBody = async (request) => {
	try {
		const text = await request.text();
		if (text.length === 0) return {};
		const parsed = JSON.parse(text);
		return parsed !== null && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
	} catch {
		return {};
	}
};
const FEEDBACK_BASE = "https://feedback.juo.de5.net";
const feedbackKey = () => {
	try {
		const file = join(homedir(), ".dsh", "feedback-admin.key");
		if (!existsSync(file)) return "";
		return readFileSync(file, "utf8").trim();
	} catch {
		return "";
	}
};
const feedbackCall = async (method, path, body) => {
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
			data = { raw: text.slice(0, 400) };
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
	/** The snapshot the panel renders, with the QR payload and its SVG data URL. */
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
	/** Merge one patch into the pairing preferences and answer with the new state. */
	const panelConfig = async (request) => {
		const body = await panelBody(request);
		const current = ctx.pairState();
		const next = {
			allowLan: typeof body.allowLan === "boolean" ? body.allowLan : Boolean(current.allowLan),
			allowRemote: typeof body.allowRemote === "boolean" ? body.allowRemote : Boolean(current.allowRemote),
			publicUrl: typeof body.publicUrl === "string" ? body.publicUrl.trim() : String(current.publicUrl ?? "")
		};
		ctx.writePair(next);
		await ctx.record(`200 PANEL config lan=${String(next.allowLan)} remote=${String(next.allowRemote)}`);
		return panelJson(200, panelSnapshot());
	};
	/** The QR itself, as an SVG the panel renders in an <img>. */
	const panelQr = async (request) => {
		const asked = new URL(request.url).searchParams.get("payload");
		const snapshot = ctx.pairState();
		const base = String(snapshot.base ?? "");
		const alts = Array.isArray(snapshot.alts) ? snapshot.alts : [];
		const text = asked !== null && asked.length > 0 ? asked : base.length > 0 ? ctx.pairPayload(base, String(snapshot.code ?? ""), alts) : "";
		if (text.length === 0) return panelJson(409, {
			error: "no base url yet",
			hint: "turn 局域网直连 on, or set a public url"
		});
		const svg = await qrSvg(text);
		if (svg === null) return panelJson(503, {
			error: "qrcode module missing",
			hint: "install qrcode in the plugin package"
		});
		return new Response(svg, {
			status: 200,
			headers: {
				"content-type": "image/svg+xml; charset=utf-8",
				"cache-control": "no-store"
			}
		});
	};
	const feedbackState = async () => {
		if (feedbackKey() === "") return panelJson(200, { configured: false });
		const list = await feedbackCall("GET", "/v1/admin/tickets?limit=60");
		if (list.code !== 200) return panelJson(list.code === 0 ? 502 : list.code, {
			configured: true,
			error: String(list.data.error ?? "upstream")
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
		const body = await panelBody(request);
		const id = typeof body.id === "string" ? body.id : "";
		const text = typeof body.text === "string" ? body.text.trim() : "";
		if (id === "" || text === "") return panelJson(400, { error: "id and text are required" });
		const status = typeof body.status === "string" ? body.status : "";
		const payload = { text };
		if (status !== "") payload.status = status;
		const r = await feedbackCall("POST", `/v1/admin/tickets/${encodeURIComponent(id)}/reply`, payload);
		return panelJson(r.code === 0 ? 502 : r.code, r.data);
	};
	const feedbackStatus = async (request) => {
		const body = await panelBody(request);
		const id = typeof body.id === "string" ? body.id : "";
		const status = typeof body.status === "string" ? body.status : "";
		if (id === "" || status === "") return panelJson(400, { error: "id and status are required" });
		const r = await feedbackCall("POST", `/v1/admin/tickets/${encodeURIComponent(id)}/status`, { status });
		return panelJson(r.code === 0 ? 502 : r.code, r.data);
	};
	const feedbackFile = async (request) => {
		const key = feedbackKey();
		if (key === "") return panelJson(503, { error: "no admin key" });
		const url = new URL(request.url);
		const id = url.searchParams.get("id") ?? "";
		const name = url.searchParams.get("name") ?? "";
		if (id === "" || name === "") return panelJson(400, { error: "id and name are required" });
		try {
			const res = await fetch(`${FEEDBACK_BASE}/v1/admin/files/${encodeURIComponent(id)}/${encodeURIComponent(name)}`, { headers: { authorization: `Bearer ${key}` } });
			if (!res.ok) return panelJson(res.status, { error: `upstream ${String(res.status)}` });
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
//#region src/index.ts
/**
* dsh-mobile: a standalone HTTP gateway that lets a phone (and its own app)
* read the session list and post messages into a DSH session.
*
* Why this exists: the shipped console plugin owns a paired-app protocol that
* is tied to its own tunnel and to an account entitlement, and it is a package
* we do not own. This row is deliberately *parallel* to it -- a second,
* independent listener on its own port, its own bearer token and no shared
* state -- so the console keeps working untouched while a phone client can be
* pointed at a server we control.
*
* What it is not: it does not proxy the web GUI, it does not sign anybody in,
* and it does not read the console's files. Everything goes through the same
* official plugin services the console uses, which is what makes it safe to
* run next to it:
*
*   ctl.list({}, signal)          -> { items: [...] }
*   ctl.prompt({ requestId, sessionId, mode, content }, signal)
*
* Both come from `ctx.get('sessionController')`. A missing controller turns
* every session route into a 503 with an explanation instead of a crash: the
* row stays mounted and `/health` keeps reporting the truth.
*
* Security posture: the listener binds 0.0.0.0 because a phone on the same
* Wi-Fi has to reach it, so *every* route except `/health` requires the bearer
* token. The token is generated once, persisted 0600 next to the rest of the
* DSH state, and compared in constant time.
*
* @module @deepseek-ai/dsh-mobile
*/
const name = "mobile";
const VERSION = "0.1.0";
/** Image bodies are base64 and several may arrive at once: 36 MB of JSON. */
const MAX_UPLOAD_BYTES = 36 << 20;
const MAX_IMAGES = 9;
/** 一次最多带几个附件文件过来（服务端会落到磁盘再给会话路径）。 */
const MAX_FILES = 9;
/** Media types the controller accepts on an image content part. */
const IMAGE_TYPES = /* @__PURE__ */ new Set([
	"image/png",
	"image/jpeg",
	"image/webp",
	"image/gif"
]);
const DEFAULT_PORT = 8901;
/** How long one pairing code stays valid. */
const PAIR_TTL_MS = 900 * 1e3;
/** Failed claims allowed per peer before the handshake is throttled. */
const PAIR_FAIL_LIMIT = 8;
/** Wrong codes that lock one peer out, and for how long. */
const PAIR_LOCK_MS = 300 * 1e3;
/** A phone counts as "connected" while it has been seen this recently. */
const PHONE_ONLINE_MS = 600 * 1e3;
/** Six digits, zero-padded; `randomInt` is the cryptographic RNG. */
function freshPairCode() {
	return String(randomInt(0, 1e6)).padStart(6, "0");
}
/** The deep link a QR code carries: base URL plus the live code. */
function pairPayload(base, code, alts = []) {
	const list = alts.filter((one) => one.length > 0 && one !== base);
	const tunnel = list.find((one) => /^https:\/\//i.test(one)) ?? "";
	const kept = list.filter((one) => one !== tunnel).slice(0, tunnel !== "" ? 3 : 4);
	const extra = (tunnel !== "" ? [tunnel, ...kept] : kept).map((one) => `&a=${encodeURIComponent(one)}`).join("");
	return `dshmobile://pair?b=${encodeURIComponent(base)}&c=${encodeURIComponent(code)}${extra}`;
}
/** Harness home, honouring the `DSH_HOME` override the launchers use. */
function dshHome() {
	const override = process.env.DSH_HOME;
	return override !== void 0 && override.length > 0 ? override : join(homedir(), ".dsh");
}
const statePath = () => join(dshHome(), "dsh-mobile.json");
/** Read the persisted state; a missing or corrupt file reads as an empty object. */
function readState() {
	try {
		const parsed = JSON.parse(readFileSync(statePath(), "utf8"));
		if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return {};
		return parsed;
	} catch {
		return {};
	}
}
/**
* Merge a patch into the persisted state, keeping the file 0600.
*
* Written to a sibling temp file and renamed into place: a failed write leaves
* the previous file (and the token in it) intact instead of truncated.
* @param patch - fields to merge over whatever is on disk (the token survives).
* @param onError - told about a failed write so the caller can log it.
* @returns false when the write failed; the process keeps serving either way.
*/
function writeState(patch, onError) {
	const file = statePath();
	const next = {
		...readState(),
		...patch
	};
	const temp = `${file}.${String(process.pid)}.tmp`;
	try {
		mkdirSync(dirname(file), { recursive: true });
		writeFileSync(temp, `${JSON.stringify(next, null, 2)}\n`, {
			encoding: "utf8",
			mode: 384
		});
		renameSync(temp, file);
		chmodSync(file, 384);
		return true;
	} catch (error) {
		try {
			unlinkSync(temp);
		} catch {}
		onError?.(error);
		return false;
	}
}
/** Pairing preferences with the defaults both the panel and the phone assume. */
function pairPrefs() {
	const raw = readState().pair;
	const envPublic = process.env.DSH_MOBILE_PUBLIC_URL;
	return {
		allowLan: raw?.allowLan !== false,
		allowRemote: raw?.allowRemote !== false,
		publicUrl: typeof raw?.publicUrl === "string" && raw.publicUrl.length > 0 ? raw.publicUrl : typeof envPublic === "string" ? envPublic : ""
	};
}
/**
* The answer-mode preference as it stands on disk right now.
*
* Read per question rather than cached: flipping the switch on the phone (or
* hand-editing the file) takes effect on the next card, without a restart.
*/
function answerMode() {
	return readState().answerMode === "desktop" ? "desktop" : "phone";
}
/**
* Read the persisted token, generating and saving one on first use.
* @param fromConfig - explicit token from the patch row, when present.
* @returns the token to enforce.
*/
function resolveToken(fromConfig) {
	if (fromConfig !== void 0 && fromConfig.length > 0) return fromConfig;
	const env = process.env.DSH_MOBILE_TOKEN;
	if (env !== void 0 && env.length > 0) return env;
	const file = statePath();
	try {
		const parsed = JSON.parse(readFileSync(file, "utf8"));
		if (typeof parsed.token === "string" && parsed.token.length >= 16) return parsed.token;
	} catch {}
	const token = randomBytes(24).toString("base64url");
	writeState({ token });
	return token;
}
/**
* Append one request line; never let diagnostics break the listener.
* @param file - absolute log path.
* @param line - message body.
*/
async function record(file, line) {
	if (file.length === 0) return;
	try {
		await mkdir(dirname(file), { recursive: true });
		await appendFile(file, `${(/* @__PURE__ */ new Date()).toISOString()} pid=${String(process.pid)} ${line}\n`, "utf8");
	} catch {}
}
/**
* 宿主的一条定时任务记录归一成手机端认识的形状。
*
* 两个来源字段名不同：活服务给的是 ScheduleCatalogEntry（`scheduledAt` 加
* `status`），磁盘上的 `tables.tasks` 行是旧格式。归一之后手机只渲染一种行，
* 列表和「暂停/恢复/删除」两处共用这里，免得各写一份再慢慢走样。
* @param raw - 宿主返回的一条任务记录。
* @returns 手机端的任务行。
*/
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
/** profile 目录名：只许一层普通名字，挡掉 `..` 之类穿越路径。 */
const PROFILE_DIR_NAME = /^[A-Za-z0-9._-]{1,64}$/;
/** 包名（可带 scope）：只用来在 dependencies 里查一项，不做版本解析。 */
const BUNDLE_NAME = /^(@[A-Za-z0-9._-]{1,64}\/)?[A-Za-z0-9._-]{1,120}$/;
/** Subagent catalog and shared-task board both sit under `projections.values`. */
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
/** Copy the phone's answers into the shape the host waterfall resolves with. */
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
/** Token counters live under `projections.values.tokenUsage`. */
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
function asksOf(values) {
	const raw = values?.userQuestions ?? {};
	const activeRaw = Array.isArray(raw.active) ? raw.active : [];
	const settledRaw = Array.isArray(raw.settled) ? raw.settled : [];
	const active = [];
	for (const entry of activeRaw) {
		const callId = String(entry.callId ?? "");
		const list = Array.isArray(entry.questions) ? entry.questions : [];
		if (callId === "" || list.length === 0) continue;
		const questions = list.map((q) => {
			const options = (Array.isArray(q.options) ? q.options : []).map((o) => ({
				label: String(o.label ?? ""),
				description: o.description === void 0 ? "" : String(o.description)
			})).filter((o) => o.label !== "");
			const one = {
				id: String(q.id ?? ""),
				prompt: String(q.prompt ?? q.question ?? ""),
				options,
				multiSelect: q.multiSelect === true
			};
			if (typeof q.header === "string" && q.header !== "") one.header = q.header;
			if (typeof q.detail === "string" && q.detail !== "") one.detail = q.detail;
			return one;
		});
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
/** The model a session would use next, under `projections.values.modelSelection`. */
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
/** Pull one raw list row's array container out of whatever shape arrived. */
function rowsOf(payload) {
	if (Array.isArray(payload)) return payload;
	if (payload !== null && typeof payload === "object") {
		const items = payload.items;
		if (Array.isArray(items)) return items;
	}
	return [];
}
/**
* Project whatever `sessionController.list` returned onto the phone's shape.
*
* The controller does not use `id`: a row carries `sessionId`, and the title
* lives under `projections.values.title` rather than on the row itself. Both
* facts are easy to miss and silently produce an empty list, which is exactly
* what the first version did.
*
* Rows are filtered the same way the console filters its own list: subagent
* shells are not something a phone should be offered.
* @param payload - raw list result.
* @returns the rows to expose.
*/
/**
* Decide which prompt mode to use for one session.
*
* `queue` is a no-op for an idle session — the controller parks the message in a
* mailbox nothing drains — while `steer` starts a turn but can interrupt one
* that is already running. So an idle session is always steered, and a running
* one keeps whatever the caller asked for.
*
* @param ctl - session controller obtained from the plugin context.
* @param sessionId - target session.
* @param requested - mode the caller asked for.
* @returns the effective mode plus what the list lookup established.
*/
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
/**
* Best-effort "which preset is selected", mirroring what the desktop console
* reads: the live reference first, then the registry config, then the settings
* document. Any of them may be lazy, so every step is guarded.
*/
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
/** Normalise the three shapes `agentPresets` may return into display rows. */
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
/**
* Sessions are addressed by id in the URL; the controller wants the row.
* @param liveAsking - 本插件自己按住、尚未作答的提问所在会话（宿主投影里没有）；省略即只看投影。
*/
function projectSessions(payload, liveAsking) {
	const rows = [];
	for (const item of rowsOf(payload)) {
		if (item === null || typeof item !== "object") continue;
		const s = item;
		if (s.__blank === true) continue;
		if (s.origin !== void 0 && s.origin !== null && String(s.origin) === "subagent") continue;
		const id = String(s.sessionId ?? s.id ?? "");
		if (id.length === 0) continue;
		const projections = s.projections;
		const projected = projections?.values?.title;
		const title = typeof projected === "string" && projected.length > 0 ? projected : typeof s.title === "string" && s.title.length > 0 ? s.title : "(untitled)";
		const updated = Number(s.updatedAt ?? 0);
		const projectedValues = projections?.values;
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
			agents: agentsOf(projectedValues)
		});
	}
	rows.sort((a, b) => b.updatedAt - a.updatedAt);
	return rows;
}
/**
* 控制器把模型目录包在 value / catalog 里，同一台机器上还见过字符串形态，
* 这里统一抹平成 UI 好渲染的形状。
*/
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
/**
* `zlib.zstdDecompressSync` landed in Node 22.15/23.8. Reading it through a
* narrow cast keeps the plugin loadable on an older host -- the history route
* then answers 501 instead of taking the whole row down at import time.
*/
const zstdDecompressSync = zlib.zstdDecompressSync;
/** zstd frame magic; a session log is one frame appended per event. */
const ZSTD_MAGIC = Buffer.from([
	40,
	181,
	47,
	253
]);
/** Refuse to walk a log past this size; the read is synchronous. */
const MAX_SESSION_BYTES = 160 * 1024 * 1024;
/** Decoded history keyed by path, invalidated by size+mtime. */
const historyCache = /* @__PURE__ */ new Map();
/**
* Locate one session's log on disk.
*
* Layout is `<dsh home>/sessions/<project slug>/<id>/session.v4.jsonl.zstd`,
* and the directory name is the session id exactly as the list reports it --
* with the historical `session-` prefix present or absent depending on when
* the session was created, so all spellings are tried.
* @param id - session id from the list.
* @returns absolute path, or null.
*/
function findSessionFile(id) {
	const root = join(dshHome(), "sessions");
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
			if (statSync(file).isFile()) return file;
		} catch {}
	}
	return null;
}
/**
* Decode a session log into its event lines.
*
* The log is not one compressed document: it is one zstd frame appended per
* event, and Node's decompressor stops at the first frame boundary. Splitting
* on the frame magic and decoding each slice is what makes the whole file
* readable -- a 39 MB log is 19k frames.
* @param file - absolute path.
* @returns one JSON string per event line.
*/
function readSessionLines(file) {
	if (zstdDecompressSync === void 0) throw new Error("this Node build has no zstd support");
	const size = statSync(file).size;
	if (size > MAX_SESSION_BYTES) throw new Error(`session log is ${String(size)} bytes, over the safety cap`);
	const raw = readFileSync(file);
	const starts = [];
	let cursor = 0;
	while ((cursor = raw.indexOf(ZSTD_MAGIC, cursor)) !== -1) {
		starts.push(cursor);
		cursor += 4;
	}
	if (starts.length === 0) return [];
	const parts = [];
	for (let index = 0; index < starts.length; index += 1) {
		const from = starts[index];
		const to = index + 1 < starts.length ? starts[index + 1] : raw.length;
		try {
			parts.push(zstdDecompressSync(raw.subarray(from, to)));
		} catch {}
	}
	return Buffer.concat(parts).toString("utf8").split("\n").filter((line) => line.length > 0);
}
/**
* Last readable line of a session, without decoding the whole log.
*
* The list wants a one-line preview per row; decoding a 39 MB log per row is
* not an option, so this reads only the tail window and decodes the frames that
* start inside it. The first frame is usually torn by the seek, hence skipping
* it.
* @param file - absolute path of the session log.
* @returns `{ preview, count }` where count covers the decoded tail only.
*/
function previewOf(file) {
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
	if (window < 512) return {
		preview: "",
		count: 0
	};
	const buf = Buffer.alloc(window);
	let fd;
	try {
		fd = openSync(file, "r");
		readSync(fd, buf, 0, window, size - window);
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
	if (starts.length < 2) return {
		preview: "",
		count: 0
	};
	const texts = [];
	let count = 0;
	for (let index = 1; index < starts.length; index += 1) {
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
/**
* Turn a message into one line of plain text for the session list.
*
* The list shows a summary, not rendered Markdown, so headings, bold markers,
* code fences, table pipes and link syntax would otherwise leak into the card.
* @param text - raw message text, Markdown included.
* @returns a single flattened line, at most 90 characters.
*/
function plainPreview(text) {
	return text.replace(/```[\s\S]*?```/g, " ").replace(/`([^`]*)`/g, "$1").replace(/!\[[^\]]*\]\([^)]*\)/g, " ").replace(/\[([^\]]*)\]\([^)]*\)/g, "$1").replace(/^#{1,6}\s*/gm, "").replace(/^>\s?/gm, "").replace(/^\s*[-*+]\s+/gm, "").replace(/\*\*([^*]*)\*\*/g, "$1").replace(/\|/g, " ").replace(/\s+/g, " ").trim().slice(0, 90);
}
/** Concatenate the `text` parts of a content array, skipping reasoning. */ function textOf(content) {
	if (!Array.isArray(content)) return "";
	const out = [];
	for (const part of content) {
		if (part === null || typeof part !== "object") continue;
		const p = part;
		if (p.type === "text" && typeof p.text === "string") out.push(p.text);
	}
	return out.join("").trim();
}
/**
* Pull the image parts out of a message.
*
* The host never inlines the bytes: a part carries
* `attachment: { attachmentId: 'sha256:<hex>', mediaType, width, height, name }`
* and the object lives under `<dsh home>/attachments/v1/objects/<ab>/<hex>`.
* Keeping only the digest here means the transcript stays small; the bytes come
* from the attachment route when the phone actually draws them.
* @param content - the message's content parts.
* @returns one ref per image part, in order.
*/
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
/**
* Build the chat transcript from a decoded session.
*
* Two facts drive the shaping: the assistant emits one `assistant/message` per
* streaming update, so only the last one per (turn, step) is the finished
* text; and `user/message` also carries injected system reminders, which are
* not something a phone should show back.
* @param file - absolute path.
* @returns the transcript in order.
*/
function historyOf(file) {
	const stat = statSync(file);
	const cached = historyCache.get(file);
	if (cached !== void 0 && cached.size === stat.size && cached.mtimeMs === stat.mtimeMs) return {
		messages: cached.messages,
		stats: cached.stats,
		lastTurn: cached.lastTurn,
		lastErr: cached.lastErr
	};
	const messages = [];
	const stepAt = /* @__PURE__ */ new Map();
	const stats = {
		turns: 0,
		steps: 0,
		toolCalls: 0,
		tokens: {
			uncachedInputTokens: 0,
			outputTokens: 0,
			cacheReadTokens: 0,
			cacheWriteTokens: 0
		}
	};
	let lastTurn = "";
	let lastErr = null;
	let turnStart = 0;
	let turnIn = 0;
	let turnOut = 0;
	let turnReplyAt = -1;
	for (const line of readSessionLines(file)) {
		let event;
		try {
			event = JSON.parse(line);
		} catch {
			continue;
		}
		if (event === null || typeof event !== "object") continue;
		const ev = event;
		if (ev.type === "turn/start") {
			stats.turns += 1;
			turnStart = Number(ev.time ?? 0);
			turnIn = 0;
			turnOut = 0;
			turnReplyAt = -1;
		} else if (ev.type === "turn/end") {
			lastTurn = String(ev.data?.reason?.kind ?? "");
			const rawErr = ev.data?.reason?.error;
			let errCode = "";
			let errText = "";
			if (rawErr !== null && typeof rawErr === "object") {
				errCode = String(rawErr.code ?? "");
				errText = String(rawErr.message ?? "");
			} else if (typeof rawErr === "string") errText = rawErr;
			if (errText !== "") lastErr = {
				code: errCode,
				text: errText,
				time: Number(ev.time ?? 0)
			};
			else lastErr = null;
			const row = turnReplyAt >= 0 ? messages[turnReplyAt] : void 0;
			if (row !== void 0) {
				const endAt = Number(ev.time ?? 0);
				row.turn = {
					status: lastTurn,
					ms: endAt > turnStart && turnStart > 0 ? endAt - turnStart : 0,
					tokensIn: turnIn,
					tokensOut: turnOut,
					atSeq: Number(ev.seq ?? 0),
					finishedAt: endAt > 0 ? endAt : Date.now()
				};
				if (errText !== "") {
					row.turn.errCode = errCode;
					row.turn.errText = errText;
				}
			}
		} else if (ev.type === "step/start") stats.steps += 1;
		else if (ev.type === "tool/call") stats.toolCalls += 1;
		else if (ev.type === "assistant/attempt") accumulateTokens(stats.tokens, ev.data);
		if (ev.type === "user/message") {
			const source = ev.data?.source;
			if (source !== void 0 && source !== null && String(source.kind ?? "user") !== "user") continue;
			const text = textOf(ev.data?.content);
			if (text.length === 0 || text.startsWith("<system-reminder>")) continue;
			const images = imagesOf(ev.data?.content);
			const row = {
				role: "user",
				text,
				time: Number(ev.time ?? 0),
				seq: Number(ev.seq ?? 0)
			};
			if (images.length > 0) row.images = images;
			messages.push(row);
			continue;
		}
		if (ev.type === "assistant/message") {
			const text = textOf(ev.data?.message?.content);
			const usage = ev.data?.usage;
			if (usage !== null && typeof usage === "object") {
				turnIn = (Number(usage.inputTokens ?? 0) || 0) + (Number(usage.cacheReadTokens ?? usage.cachedInputTokens ?? 0) || 0);
				turnOut += Number(usage.outputTokens ?? 0) || 0;
			}
			if (text.length === 0) continue;
			const row = {
				role: "assistant",
				text,
				time: Number(ev.time ?? 0),
				seq: Number(ev.seq ?? 0)
			};
			const key = `${String(ev.data?.turn ?? "")}:${String(ev.data?.step ?? "")}`;
			const at = stepAt.get(key);
			if (at !== void 0) {
				messages[at] = row;
				turnReplyAt = at;
			} else {
				stepAt.set(key, messages.length);
				turnReplyAt = messages.length;
				messages.push(row);
			}
		}
	}
	historyCache.set(file, {
		size: stat.size,
		mtimeMs: stat.mtimeMs,
		messages,
		stats,
		lastTurn,
		lastErr
	});
	return {
		messages,
		stats,
		lastTurn,
		lastErr
	};
}
/** Fold one attempt's usage counters into the running totals, if it carries any. */
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
/** Every non-internal IPv4 address plus global IPv6, so the operator can see the phone URL. */
/** Render a host:port pair with the brackets an IPv6 literal needs in a URL. */
function hostPort(address, port) {
	return address.includes(":") ? `[${address}]:${String(port)}` : `${address}:${String(port)}`;
}
/**
* Whether the caller reached us on a LAN-style address.
*
* Classification uses the Host header, not the socket peer: a Cloudflare tunnel
* forwards from 127.0.0.1, so every remote request would otherwise look local
* and the "allow remote" switch would gate nothing. A missing Host counts as
* local (curl on this machine, health checks).
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
* Order LAN candidates by how likely a phone on the same Wi-Fi can use them.
*
* A laptop typically has several adapters; Docker, WSL, VirtualBox and QEMU
* create host-only networks that no phone can reach. They still work as copyable
* text, but they must not become the address baked into the QR code.
*/
function lanRank(address) {
	if (address.includes(":")) return 9;
	if (address.startsWith("192.168.")) return address.startsWith("192.168.56.") ? 6 : 0;
	if (address.startsWith("10.")) return address.startsWith("10.0.2.") ? 7 : 1;
	if (address.startsWith("172.")) {
		const second = Number.parseInt(address.split(".")[1] ?? "", 10);
		return second >= 16 && second <= 31 ? 5 : 2;
	}
	return 3;
}
/** Constant-time comparison that tolerates a length mismatch. */
/**
* Files picked on the phone do not exist on this machine, so /outbox writes them
* to disk first and hands the paths to the session as one trailing text part.
* Returns the saved rows plus that text block (empty when nothing was saved).
*/
async function saveMobileFiles(raw) {
	const saved = [];
	if (raw.length === 0) return {
		saved,
		bytes: 0,
		text: ""
	};
	const stamp = /* @__PURE__ */ new Date();
	const day = `${String(stamp.getFullYear())}${String(stamp.getMonth() + 1).padStart(2, "0")}${String(stamp.getDate()).padStart(2, "0")}`;
	const dir = join(homedir(), ".dsh", "mobile-uploads", day);
	await mkdir(dir, { recursive: true });
	let bytes = 0;
	for (const item of raw) {
		if (item === null || typeof item !== "object") throw new Error("each file must be an object");
		const f = item;
		const data = String(f.data ?? "");
		if (data.length === 0) throw new Error("file data is empty");
		const safe = String(f.name ?? "file").replace(/[\\/:*?"<>|\u0000-\u001f]/g, "_").trim().slice(0, 120) || "file";
		const target = join(dir, `${String(Date.now())}-${safe}`);
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
/** Pull the caller's token out of the Authorization header or `?t=`. */
/** Read and JSON-parse a bounded request body. */
/**
* Internals exposed for out-of-process verification of the pure parts
* (projection and log decoding) against this machine's real files, without
* having to restart the host to exercise a route.
*/
const internals = {
	projectSessions,
	findSessionFile,
	historyOf
};
/**
* Mount the listener for as long as this row is mounted.
* @param ctx - plugin context, used for the service lookup and the lifecycle effect.
* @param rawConfig - deployment configuration from the profile patch row.
*/
function apply(ctx, rawConfig) {
	const enabled = rawConfig?.enabled !== false;
	const port = rawConfig?.port ?? DEFAULT_PORT;
	const host = rawConfig?.host ?? "::";
	const logFile = rawConfig?.logFile ?? join(dshHome(), "dsh-mobile.log");
	const token = enabled ? resolveToken(rawConfig?.token) : "";
	/**
	* 5 分钟短签名：图片直链不再带长期令牌，只带 exp 与 HMAC。
	* 签名覆盖「用途 + 对象 + 过期时间」，换用途或改对象都验不过。
	*/
	const SIG_TTL_SEC = 300;
	const sigOf = (kind, value, exp) => createHmac("sha256", token).update(`${kind}\n${value}\n${exp}`).digest("hex");
	const signedOk = (kind, value, url) => {
		const exp = url.searchParams.get("e") ?? "";
		const sig = (url.searchParams.get("sig") ?? "").toLowerCase();
		if (exp === "" || sig === "") return false;
		const expN = Number(exp);
		if (!Number.isFinite(expN) || expN < Math.floor(Date.now() / 1e3)) return false;
		return tokenMatches(sigOf(kind, value, exp), sig);
	};
	if (!enabled) return;
	/** Live pairing code: minted lazily, consumed on claim, rotated on demand. */
	let pairCode = null;
	/** Last authenticated request, which is how the panel knows the phone is there. */
	let phoneSeenAt = 0;
	/** Last phone poll per Session: only a chat somebody is watching holds a question. */
	const phoneSessionAt = /* @__PURE__ */ new Map();
	/** Wrong-claim counters per peer; a coarse throttle, not an account lock. */
	const pairFails = /* @__PURE__ */ new Map();
	/**
	* Live `ask_user_question` calls mirrored from the host waterfall.
	*
	* 宿主会依次询问每个答器；这里先把请求按住交给手机，等 ASK_HOLD_MS 到期或
	* signal 被 abort 才 next() 交还桌面答器。phone 模式不看手机在不在线：手机
	* 离线也照样等它（用户要求）。
	*
	* Blocking asks - the default `tool-ask-user` mode - carry no `wait.callId` at
	* all, so the card is only reachable if this listener (a) runs before the
	* desktop answerer, which never calls `next()` once it holds a request, and
	* (b) invents an id the phone can answer with.
	*/
	const liveAsks = /* @__PURE__ */ new Map();
	/**
	* 手机在最后一次认证请求之后算「在线」的时长，由 `POST /api/presence` 维持。
	* 现在只用于面板显示和 presence 回包，不再决定提问由谁回答。
	*/
	const PRESENCE_TTL_MS = 15 * 1e3;
	/**
	* 手机接管中的提问按会话归集，供会话列表的 asking 用：宿主投影只反映桌面答器，
	* 看不到 liveAsks。'*' 是宿主没给会话 id 的提问，归不到任何一行，跳过。
	*/
	const liveAsking = () => {
		const out = /* @__PURE__ */ new Set();
		for (const ask of liveAsks.values()) if (ask.sessionId !== "*") out.add(ask.sessionId);
		return out;
	};
	/** Bumped for every id minted here, so two asks in one millisecond stay apart. */
	let syntheticSeq = 0;
	try {
		ctx.on("user-questions/request", (request, next) => {
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
	/** The current code, extending it when it expired. */
	const ensurePair = () => {
		if (pairCode === null || pairCode.expiresAt <= Date.now()) {
			pairCode = {
				code: freshPairCode(),
				expiresAt: Date.now() + PAIR_TTL_MS
			};
			record(logFile, `pair code minted ttl=${String(PAIR_TTL_MS)}`);
		}
		return pairCode;
	};
	/** Throw the current code away and mint a fresh one. */
	const rotatePair = () => {
		pairCode = {
			code: freshPairCode(),
			expiresAt: Date.now() + PAIR_TTL_MS
		};
		record(logFile, "pair code rotated");
		return pairCode;
	};
	/**
	* LAN base URLs a phone on the same network can dial.
	*
	* IPv4 comes first on purpose: a phone gets an IPv4 address from the router,
	* and an IPv6 literal in a QR code is both fragile to type and often
	* unreachable from another device's stack even on the same Wi-Fi.
	*/
	const lanBases = () => {
		const all = lanAddresses();
		const v6 = all.filter((address) => address.includes(":") && !/^f[cd]/.test(address));
		return [...all.filter((address) => !address.includes(":")).sort((left, right) => lanRank(left) - lanRank(right)), ...v6].map((address) => `http://${hostPort(address, port)}`);
	};
	/** Everything the panel and the phone's setup screen show, minus the token. */
	const pairState = () => {
		const prefs = pairPrefs();
		const pending = ensurePair();
		const lan = lanBases();
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
			version: VERSION,
			port,
			code: pending.code,
			expiresAt: pending.expiresAt,
			allowLan: prefs.allowLan,
			allowRemote: prefs.allowRemote,
			publicUrl: prefs.publicUrl,
			lan,
			alts,
			/** Base URL a QR should carry right now: LAN first, then the tunnel. */
			base: primary,
			phoneSeenAt,
			phoneOnline: phoneSeenAt > 0 && Date.now() - phoneSeenAt < PHONE_ONLINE_MS,
			sessions: true
		};
	};
	const promptQueues = /* @__PURE__ */ new Map();
	const queueFile = () => join(dshHome(), "queue.json");
	let queueSaveTimer;
	const flushQueue = () => {
		try {
			const out = {};
			promptQueues.forEach((list, sid) => {
				if (list.length > 0) out[sid] = list;
			});
			writeFileSync(queueFile(), JSON.stringify(out), { mode: 384 });
		} catch {}
	};
	const saveQueue = () => {
		if (queueSaveTimer !== void 0) clearTimeout(queueSaveTimer);
		queueSaveTimer = setTimeout(() => {
			queueSaveTimer = void 0;
			flushQueue();
		}, 200);
	};
	const loadQueue = () => {
		try {
			const parsed = JSON.parse(readFileSync(queueFile(), "utf8"));
			for (const sid of Object.keys(parsed)) {
				const list = parsed[sid];
				if (Array.isArray(list) && list.length > 0) promptQueues.set(sid, list);
			}
		} catch {}
	};
	loadQueue();
	const queueList = (sessionId) => promptQueues.get(sessionId) ?? [];
	const dequeueById = (sessionId, id) => {
		const list = queueList(sessionId);
		const at = list.findIndex((q) => q.id === id);
		if (at < 0) return null;
		const [one] = list.splice(at, 1);
		if (list.length === 0) promptQueues.delete(sessionId);
		else promptQueues.set(sessionId, list);
		saveQueue();
		return one ?? null;
	};
	let drainingQueues = false;
	/** 每次拍子：把已经空闲的会话的队头送进去（steer，空会话用它才能起一轮）。 */
	const drainQueues = async () => {
		if (drainingQueues || promptQueues.size === 0) return;
		const ctl = controller();
		if (!ctl || typeof ctl.prompt !== "function") return;
		drainingQueues = true;
		try {
			for (const sessionId of [...promptQueues.keys()]) {
				const list = queueList(sessionId);
				if (list.length === 0) continue;
				const head = list[0];
				if (head === void 0) continue;
				const probe = await pickMode(ctl, sessionId, "queue");
				if (!probe.known || probe.running) continue;
				dequeueById(sessionId, head.id);
				try {
					await Promise.resolve(ctl.prompt({
						requestId: randomBytes(16).toString("hex"),
						sessionId,
						mode: "steer",
						content: head.content
					}, AbortSignal.timeout(6e4)));
					await record(logFile, `200 QUEUE flush session=${sessionId} id=${head.id}`);
				} catch (e) {
					const back = queueList(sessionId);
					back.unshift(head);
					promptQueues.set(sessionId, back);
					await record(logFile, `500 QUEUE flush session=${sessionId} id=${head.id} err=${e.message}`);
				}
			}
		} finally {
			drainingQueues = false;
		}
	};
	setInterval(() => {
		drainQueues();
	}, 2500);
	const hostState = async (ctl, sessionId) => {
		if (!ctl || typeof ctl.state !== "function") return null;
		try {
			return await Promise.resolve(ctl.state({ sessionId }, AbortSignal.timeout(8e3)));
		} catch {
			return null;
		}
	};
	const hostQueued = async (ctl, sessionId) => {
		const st = await hostState(ctl, sessionId);
		return (st && Array.isArray(st.queue) ? st.queue : []).filter((it) => it !== null && typeof it === "object" && it.placement === "queued");
	};
	const hostText = (it) => {
		return (it && Array.isArray(it.content) ? it.content : []).filter((p) => p !== null && typeof p === "object" && p.type === "text").map((p) => String(p.text ?? "")).join(" ").trim();
	};
	/** Image parts of one queued prompt, with metadata only: bytes go through /queue-image. */
	const hostImages = (it) => {
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
	};
	const hostQueueView = async (ctl, sessionId) => {
		return (await hostQueued(ctl, sessionId)).map((it, i) => ({
			id: String(it.id),
			text: hostText(it),
			at: 0,
			index: i + 1,
			images: hostImages(it)
		}));
	};
	const hostEnqueue = async (ctl, sessionId, content) => {
		const before = new Set((await hostQueued(ctl, sessionId)).map((x) => String(x.id)));
		await Promise.resolve(ctl.prompt({
			requestId: randomBytes(16).toString("hex"),
			sessionId,
			mode: "queue",
			content
		}, AbortSignal.timeout(3e4)));
		const fresh = (await hostQueued(ctl, sessionId)).find((x) => !before.has(String(x.id)));
		return fresh === void 0 ? "" : String(fresh.id);
	};
	const hostMutate = async (ctl, sessionId, itemId, action) => {
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
	};
	const controller = () => {
		try {
			return ctx.get("sessionController");
		} catch {
			return;
		}
	};
	/** Resolve an optional host service; a missing row is `null`, not an error. */
	const service = (name) => {
		try {
			const found = ctx.get(name);
			return found === void 0 ? null : found;
		} catch {
			return null;
		}
	};
	/**
	* Context pressure is a SessionProjectionSummaryExcluded value: `ctl.list()`
	* never carries it, so the Ring in the app would read 0% forever. The
	* projection registry keeps the full map, and its snapshot needs the live
	* Session object rather than the id — resolved here, cached briefly because
	* the phone polls this route every few seconds.
	*/
	const deepCache = /* @__PURE__ */ new Map();
	const DEEP_TTL_MS = 15e3;
	const deepContext = (sessionId) => {
		const hit = deepCache.get(sessionId);
		if (hit !== void 0 && Date.now() - hit.at < DEEP_TTL_MS) return hit.value;
		let value = null;
		try {
			const registry = service("sessionProjections");
			const sessions = service("sessions");
			const live = sessions !== null && typeof sessions.get === "function" ? sessions.get(sessionId) : void 0;
			if (registry !== null && live !== void 0 && typeof registry.snapshot === "function") value = contextOf(registry.snapshot(live)?.values ?? {});
		} catch (error) {
			record(logFile, `deep context failed: ${String(error)}`);
		}
		deepCache.set(sessionId, {
			at: Date.now(),
			value
		});
		return value;
	};
	/**
	* Sessions the host keeps in its archive. `ctl.list` does not carry that
	* flag, so the registry's set is the only place it lives; `null` means the
	* host has no such set and callers must not hide anything.
	*/
	const archivedIds = () => {
		const reg = service("workspaceRegistry");
		if (reg === null) return null;
		try {
			const raw = reg.archivedSessionIds;
			if (Array.isArray(raw)) return raw.map((x) => String(x)).filter(Boolean);
			if (raw && typeof raw.has === "function" && typeof raw.size === "number") return Array.from(raw, (x) => String(x)).filter(Boolean);
			return null;
		} catch {
			return null;
		}
	};
	/** Stamp the archive flag onto rows the controller handed us. */
	const markArchived = (rows) => {
		const set = archivedIds();
		if (set === null) return rows;
		const lookup = new Set(set);
		return rows.map((row) => ({
			...row,
			archived: lookup.has(row.id)
		}));
	};
	/** Sessions the host keeps pinned to the top of its own list. */
	const pinnedIds = () => {
		const reg = service("workspaceRegistry");
		if (reg === null) return null;
		try {
			const raw = reg.pinnedSessionIds;
			if (Array.isArray(raw)) return raw.map((x) => String(x)).filter(Boolean);
			if (raw && typeof raw.has === "function" && typeof raw.size === "number") return Array.from(raw, (x) => String(x)).filter(Boolean);
			return null;
		} catch {
			return null;
		}
	};
	/** Stamp the pin flag onto rows the controller handed us. */
	const markPinned = (rows) => {
		const set = pinnedIds();
		if (set === null) return rows;
		const lookup = new Set(set);
		return rows.map((row) => ({
			...row,
			pinned: lookup.has(row.id)
		}));
	};
	/**
	* 写请求幂等缓存：手机把同一条消息重试两次时，宿主只提交一次。
	* 只缓存成功响应（2xx），失败不缓存，方便客户端换 key 或人工重试。
	* 10 分钟、最多 200 条，够覆盖一次弱网重试，不会长期占内存。
	*/
	const replay = /* @__PURE__ */ new Map();
	/** 同一个 key 正在处理中：并发重放不能各提交一次。 */
	/** key → 开始处理的时刻。响应写完（finish）才释放；客户端断开（close）不提前释放。 */
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
	/** 请求相等性用 sha256 前 32 位，32 位 FNV 太短，不适合承担「同 key 同请求」的判断。 */
	const hashText = (t) => createHash("sha256").update(t).digest("hex").slice(0, 32);
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
	/** 命中缓存就直接回放，返回 true 表示这次请求已经处理完。 */
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
	/**
	* The phone UI lives in `web/` next to the built `lib/`, deliberately as
	* plain files: editing them takes effect on the next reload, without
	* rebuilding this row or restarting the host.
	*/
	const WEB_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "web");
	const MIME = {
		".html": "text/html; charset=utf-8",
		".js": "text/javascript; charset=utf-8",
		".css": "text/css; charset=utf-8",
		".svg": "image/svg+xml",
		".png": "image/png",
		".json": "application/json; charset=utf-8",
		".woff2": "font/woff2"
	};
	/** Serve one file under `web/`, refusing anything that escapes it. */
	const serveStatic = (res, relative) => {
		const target = normalize(join(WEB_ROOT, relative));
		if (!target.startsWith(WEB_ROOT)) {
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
				host: hostname()
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
				port,
				lan: prefs.allowLan ? lanBases() : [],
				publicUrl: prefs.publicUrl,
				needCode: true
			});
			return;
		}
		if (path === "/api/pair/claim" && method === "POST") {
			const peer = req.socket.remoteAddress ?? "?";
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
			const gate = pairFails.get(peer);
			if (gate !== void 0 && gate.until > now) {
				send(res, 429, {
					error: "too many wrong codes",
					retryAt: gate.until
				});
				return;
			}
			const expired = gate !== void 0 && gate.until !== 0 && gate.until <= now;
			const attempt = gate === void 0 || expired ? {
				n: 1,
				until: 0
			} : {
				n: gate.n + 1,
				until: 0
			};
			pairFails.set(peer, attempt);
			let body;
			try {
				body = await readJson(req);
			} catch {
				send(res, 400, { error: "body must be a JSON object" });
				return;
			}
			const given = String(body.code ?? "").trim();
			const pending = ensurePair();
			if (given.length !== 6 || !tokenMatches(given, pending.code)) {
				const next = {
					n: attempt.n,
					until: attempt.n >= PAIR_FAIL_LIMIT ? Date.now() + PAIR_LOCK_MS : 0
				};
				pairFails.set(peer, next);
				await record(logFile, `401 PAIR claim bad code from ${peer} n=${String(next.n)}`);
				send(res, 401, {
					error: "wrong code",
					code: "bad-code",
					left: Math.max(0, PAIR_FAIL_LIMIT - next.n)
				});
				return;
			}
			const headerHost = req.headers.host;
			const forwarded = req.headers["x-forwarded-proto"];
			const scheme = typeof forwarded === "string" && forwarded.toLowerCase() === "https" ? "https" : "http";
			const base = typeof headerHost === "string" && headerHost.length > 0 ? `${scheme}://${headerHost}` : lanBases()[0] ?? `http://127.0.0.1:${String(port)}`;
			rotatePair();
			pairFails.delete(peer);
			phoneSeenAt = Date.now();
			await record(logFile, `200 PAIR claim base=${base} from ${peer} local=${String(local)}`);
			send(res, 200, {
				ok: true,
				token,
				base,
				host: hostname(),
				version: VERSION,
				port,
				lan: prefs.allowLan ? lanBases() : [],
				qr: pairPayload(base, pairCode?.code ?? "", lanBases().slice(1))
			});
			return;
		}
		const attSigned = path.startsWith("/api/attachments/") ? signedOk("att", path.slice(17).toLowerCase(), url) : false;
		const rawMatch = /^\/api\/sessions\/([^/]+)\/fs\/raw$/.exec(path);
		const rawSigned = rawMatch !== null && method === "GET" && signedOk("raw", decodeURIComponent(rawMatch[1]) + "|" + (url.searchParams.get("path") ?? ""), url);
		if (!attSigned && !rawSigned && !tokenMatches(presentedToken(req, url), token)) {
			await record(logFile, `401 ${method} ${path} from ${req.socket.remoteAddress ?? "?"}`);
			send(res, 401, {
				error: "unauthorized",
				hint: "send Authorization: Bearer <token>, or ?t=<token>"
			});
			return;
		}
		phoneSeenAt = Date.now();
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
					attachments: true
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
				if (online) phoneSeenAt = Date.now();
				else phoneSeenAt = 0;
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
				await record(logFile, `200 ANSWER mode=${wanted}`);
				send(res, 200, {
					ok: true,
					mode: wanted
				});
				return;
			}
			if (path === "/api/pair/state" && method === "GET") {
				send(res, 200, pairState());
				return;
			}
			if (path === "/api/pair/newcode" && method === "POST") {
				rotatePair();
				send(res, 200, pairState());
				return;
			}
			if (path === "/api/pair/config" && method === "POST") {
				const body = await readJson(req);
				const current = pairPrefs();
				const next = {
					allowLan: typeof body.allowLan === "boolean" ? body.allowLan : current.allowLan,
					allowRemote: typeof body.allowRemote === "boolean" ? body.allowRemote : current.allowRemote,
					publicUrl: typeof body.publicUrl === "string" ? body.publicUrl.trim() : current.publicUrl
				};
				writeState({ pair: next });
				await record(logFile, `200 PAIR config lan=${String(next.allowLan)} remote=${String(next.allowRemote)}`);
				send(res, 200, pairState());
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
				const file = join(homedir(), ".dsh", "attachments", "v1", "objects", digest.slice(0, 2), digest);
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
			if (path === "/api/debug/raw" && method === "GET") {
				const ctl = controller();
				if (!ctl || typeof ctl.list !== "function") {
					send(res, 503, { error: "sessionController unavailable" });
					return;
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
				return;
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
				return;
			}
			if (path === "/api/sessions" && method === "GET") {
				const ctl = controller();
				if (!ctl || typeof ctl.list !== "function") {
					send(res, 503, {
						error: "sessionController unavailable",
						hint: "is the DSH host fully started?"
					});
					return;
				}
				const listed = await Promise.resolve(ctl.list({}, AbortSignal.timeout(15e3)));
				send(res, 200, {
					ok: true,
					sessions: markPinned(markArchived(projectSessions(listed, liveAsking())))
				});
				return;
			}
			/**
			* Open questions for one Session: the projection knows every recorded
			* ask, and `liveAsks` adds the ones currently blocking a turn.
			*/
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
			const questionsMatch = /^\/api\/sessions\/([^/]+)\/questions$/.exec(path);
			if (questionsMatch !== null && method === "GET") {
				const sessionId = decodeURIComponent(questionsMatch[1]);
				phoneSessionAt.set(sessionId, Date.now());
				const ctl = controller();
				let listed = [];
				if (ctl && typeof ctl.list === "function") try {
					listed = await Promise.resolve(ctl.list({}, AbortSignal.timeout(8e3)));
				} catch {}
				send(res, 200, {
					ok: true,
					sessionId,
					...pendingAsks(listed, sessionId)
				});
				return;
			}
			const answerMatch = /^\/api\/sessions\/([^/]+)\/questions\/answer$/.exec(path);
			if (answerMatch !== null && method === "POST") {
				const sessionId = decodeURIComponent(answerMatch[1]);
				const body = await readJson(req, 64 * 1024);
				const callId = String(body.callId ?? "");
				const answers = normalizeAskAnswers(body.answers);
				if (callId === "" || answers.length === 0) {
					send(res, 400, { error: "callId and answers are required" });
					return;
				}
				const live = liveAsks.get(callId);
				if (live === void 0 || live.sessionId !== sessionId && live.sessionId !== "*") {
					send(res, 409, {
						error: "this question is no longer waiting",
						callId
					});
					return;
				}
				const synthetic = live.synthetic;
				live.resolve({ answers });
				send(res, 200, {
					ok: true,
					callId,
					synthetic,
					answered: answers.length
				});
				return;
			}
			const historyMatch = /^\/api\/sessions\/([^/]+)\/messages$/.exec(path);
			if (historyMatch !== null && method === "GET") {
				const sessionId = decodeURIComponent(historyMatch[1]);
				phoneSessionAt.set(sessionId, Date.now());
				if (zstdDecompressSync === void 0) {
					send(res, 501, { error: "this Node build has no zstd support" });
					return;
				}
				const file = findSessionFile(sessionId);
				if (file === null) {
					send(res, 404, {
						error: "session log not found",
						sessionId
					});
					return;
				}
				const raw = Number(url.searchParams.get("limit") ?? "30");
				const limit = Number.isFinite(raw) ? Math.min(Math.max(Math.trunc(raw), 1), 200) : 30;
				const sinceRaw = Number(url.searchParams.get("since") ?? "0");
				const since = Number.isFinite(sinceRaw) ? Math.max(Math.trunc(sinceRaw), 0) : 0;
				const beforeRaw = Number(url.searchParams.get("before") ?? "0");
				const before = Number.isFinite(beforeRaw) ? Math.max(Math.trunc(beforeRaw), 0) : 0;
				const { messages: all, stats, lastTurn, lastErr } = historyOf(file);
				let tokens = stats.tokens;
				let running = false;
				let context = null;
				const ctl = controller();
				let listed = [];
				if (ctl && typeof ctl.list === "function") try {
					listed = await Promise.resolve(ctl.list({}, AbortSignal.timeout(8e3)));
					const row = projectSessions(listed).find((r) => r.id === sessionId);
					if (row !== void 0) {
						tokens = row.tokens;
						running = row.running === true;
						context = row.context;
						if (context === null) context = deepContext(sessionId);
					}
				} catch {}
				const page = since > 0 ? all.filter((m) => m.seq > since).slice(0, 200) : before > 0 ? all.filter((m) => m.seq < before).slice(-limit) : all.slice(-limit);
				send(res, 200, {
					ok: true,
					sessionId,
					total: all.length,
					firstSeq: all.length > 0 ? all[0].seq : 0,
					messages: page,
					stats: {
						...stats,
						tokens
					},
					lastTurn,
					lastErr,
					context,
					running,
					queue: await hostQueueView(ctl, sessionId),
					questions: pendingAsks(listed, sessionId)
				});
				return;
			}
			if (/^\/api\/models$/.exec(path) !== null && method === "GET") {
				const ctl = controller();
				if (!ctl || typeof ctl.modelCatalog !== "function") {
					send(res, 503, { error: "sessionController.modelCatalog unavailable" });
					return;
				}
				const sessionId = url.searchParams.get("sessionId") ?? "";
				if (sessionId === "") {
					send(res, 400, { error: "sessionId is required" });
					return;
				}
				send(res, 200, {
					ok: true,
					sessionId,
					catalog: normalizeCatalog(await Promise.resolve(ctl.modelCatalog({ sessionId }, AbortSignal.timeout(15e3))))
				});
				return;
			}
			const modelMatch = /^\/api\/sessions\/([^/]+)\/model$/.exec(path);
			if (modelMatch !== null && method === "POST") {
				const ctl = controller();
				if (!ctl || typeof ctl.selectModel !== "function") {
					send(res, 503, { error: "sessionController.selectModel unavailable" });
					return;
				}
				const body = await readJson(req);
				const provider = String(body.provider ?? "").trim();
				const model = String(body.model ?? "").trim();
				if (provider === "" || model === "") {
					send(res, 400, { error: "provider and model are required" });
					return;
				}
				const args = {
					sessionId: decodeURIComponent(modelMatch[1]),
					provider,
					model
				};
				const effort = String(body.reasoningEffort ?? "").trim();
				if (effort !== "") args.reasoningEffort = effort;
				const result = await Promise.resolve(ctl.selectModel(args, AbortSignal.timeout(2e4)));
				await record(logFile, `200 POST model provider=${provider} model=${model} effort=${effort}`);
				send(res, 200, {
					ok: true,
					result: result ?? null
				});
				return;
			}
			const stopMatch = /^\/api\/sessions\/([^/]+)\/stop$/.exec(path);
			if (stopMatch !== null && method === "POST") {
				const ctl = controller();
				if (!ctl || typeof ctl.cancel !== "function") {
					send(res, 503, { error: "sessionController.cancel unavailable" });
					return;
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
				await record(logFile, `200 POST stop session=${sessionId} accepted=${accepted}`);
				send(res, 200, {
					ok: true,
					accepted,
					result: result ?? null
				});
				return;
			}
			const archiveMatch = /^\/api\/sessions\/([^/]+)\/archive$/.exec(path);
			if (archiveMatch !== null && method === "POST") {
				const sessionId = decodeURIComponent(archiveMatch[1]);
				const ctl = controller();
				const reg = service("workspaceRegistry");
				if (!(ctl && typeof ctl.archive === "function") && !(reg && typeof reg.archiveSession === "function")) {
					send(res, 503, { error: "archiving is unavailable on this host" });
					return;
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
				await record(logFile, `200 POST archive session=${sessionId} stoppedFirst=${stoppedFirst} cancelledFirst=${cancelledFirst}`);
				send(res, 200, {
					ok: true,
					sessionId,
					archived: true,
					stoppedFirst,
					cancelledFirst
				});
				return;
			}
			const forkMatch = /^\/api\/sessions\/([^/]+)\/fork$/.exec(path);
			if (forkMatch !== null && method === "POST") {
				const sessionId = decodeURIComponent(forkMatch[1]);
				const ctl = controller();
				if (!(ctl && typeof ctl.fork === "function")) {
					send(res, 503, { error: "forking is unavailable on this host" });
					return;
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
						return;
					}
					await record(logFile, `200 POST fork session=${sessionId} at=${String(atSeq ?? "latest")} child=${child}`);
					send(res, 200, {
						ok: true,
						sessionId: child,
						atSeq: atSeq ?? null
					});
				} catch (err) {
					const message = err instanceof Error ? err.message : String(err);
					await record(logFile, `500 POST fork session=${sessionId} at=${String(atSeq ?? "latest")} err=${message}`);
					send(res, 500, { error: message });
				}
				return;
			}
			const unarchiveMatch = /^\/api\/sessions\/([^/]+)\/unarchive$/.exec(path);
			if (unarchiveMatch !== null && method === "POST") {
				const sessionId = decodeURIComponent(unarchiveMatch[1]);
				const ctl = controller();
				const reg = service("workspaceRegistry");
				const wc = service("workspaceController");
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
					return;
				}
				let lastError = "";
				for (const attempt of attempts) try {
					await attempt.run();
					await record(logFile, `200 POST unarchive session=${sessionId} via=${attempt.who}`);
					send(res, 200, {
						ok: true,
						sessionId,
						archived: false,
						via: attempt.who
					});
					return;
				} catch (err) {
					lastError = err instanceof Error ? err.message : String(err);
				}
				send(res, 500, { error: `unarchive failed: ${lastError}` });
				return;
			}
			const pinMatch = /^\/api\/sessions\/([^/]+)\/pin$/.exec(path);
			if (pinMatch !== null && method === "POST") {
				const sessionId = decodeURIComponent(pinMatch[1]);
				const body = await readJson(req);
				const want = body.pinned === void 0 ? true : body.pinned === true;
				const ctl = controller();
				const reg = service("workspaceRegistry");
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
					return;
				}
				let lastError = "";
				for (const attempt of attempts) try {
					await attempt.run();
					await record(logFile, `200 POST pin session=${sessionId} pinned=${String(want)} via=${attempt.who}`);
					send(res, 200, {
						ok: true,
						sessionId,
						pinned: want,
						via: attempt.who,
						ids: pinnedIds() ?? []
					});
					return;
				} catch (err) {
					lastError = err instanceof Error ? err.message : String(err);
				}
				send(res, 500, { error: `pin failed: ${lastError}` });
				return;
			}
			if (path === "/api/sessions" && method === "POST") {
				const ctl = controller();
				if (!ctl || typeof ctl.create !== "function") {
					send(res, 503, { error: "sessionController.create unavailable" });
					return;
				}
				const body = await readJson(req);
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
				await record(logFile, `200 POST create session=${sessionId}`);
				send(res, 200, {
					ok: true,
					sessionId,
					result: created ?? null
				});
				return;
			}
			const renameMatch = /^\/api\/sessions\/([^/]+)$/.exec(path);
			if (renameMatch !== null && method === "PATCH") {
				const ctl = controller();
				if (!ctl || typeof ctl.rename !== "function") {
					send(res, 503, { error: "sessionController.rename unavailable" });
					return;
				}
				const body = await readJson(req);
				const title = String(body.title ?? "").trim();
				if (title === "") {
					send(res, 400, { error: "title is empty" });
					return;
				}
				const sessionId = decodeURIComponent(renameMatch[1]);
				await Promise.resolve(ctl.rename({
					sessionId,
					title
				}));
				await record(logFile, `200 PATCH rename session=${sessionId} title=${title}`);
				send(res, 200, {
					ok: true,
					sessionId,
					title
				});
				return;
			}
			const imagesMatch = /^\/api\/sessions\/([^/]+)\/images$/.exec(path);
			if (imagesMatch !== null && method === "POST") {
				const ctl = controller();
				if (!ctl || typeof ctl.prompt !== "function") {
					send(res, 503, { error: "sessionController.prompt unavailable" });
					return;
				}
				const body = await readJson(req, MAX_UPLOAD_BYTES);
				const raw = Array.isArray(body.images) ? body.images : [];
				if (raw.length === 0) {
					send(res, 400, { error: "images is empty" });
					return;
				}
				if (raw.length > MAX_IMAGES) {
					send(res, 400, { error: `at most ${String(MAX_IMAGES)} images per request` });
					return;
				}
				const parts = [];
				let bytes = 0;
				for (const item of raw) {
					if (item === null || typeof item !== "object") {
						send(res, 400, { error: "each image must be an object" });
						return;
					}
					const img = item;
					const mediaType = String(img.mediaType ?? "").toLowerCase();
					if (!IMAGE_TYPES.has(mediaType)) {
						send(res, 400, {
							error: `unsupported image type: ${mediaType}`,
							allowed: [...IMAGE_TYPES]
						});
						return;
					}
					const data = String(img.data ?? "");
					if (data.length === 0) {
						send(res, 400, { error: "image data is empty" });
						return;
					}
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
				const sessionId = decodeURIComponent(imagesMatch[1]);
				const text = String(body.text ?? "").trim() || "（来自手机）";
				const { mode, running, known } = await pickMode(ctl, sessionId, body.mode === "steer" ? "steer" : "queue");
				if (mode === "queue" && running) {
					const itemId = await hostEnqueue(ctl, sessionId, [{
						type: "text",
						text
					}, ...parts]);
					await record(logFile, `200 POST images session=${sessionId} mode=queue host=${itemId} n=${String(parts.length)}`);
					send(res, 200, {
						ok: true,
						sessionId,
						mode: "queue",
						queued: true,
						item: itemId,
						count: parts.length,
						queue: await hostQueueView(ctl, sessionId)
					});
					return;
				}
				const result = await Promise.resolve(ctl.prompt({
					requestId: randomBytes(16).toString("hex"),
					sessionId,
					mode,
					content: [{
						type: "text",
						text
					}, ...parts]
				}, AbortSignal.timeout(6e4)));
				await record(logFile, `200 POST images session=${sessionId} n=${String(parts.length)} bytes=${String(bytes)} mode=${mode} busy=${String(running)} known=${String(known)}`);
				send(res, 200, {
					ok: true,
					sessionId,
					count: parts.length,
					bytes,
					mode,
					running,
					result: result ?? null
				});
				return;
			}
			const queueImgMatch = /^\/api\/sessions\/([^/]+)\/queue-image$/.exec(path);
			if (queueImgMatch !== null && method === "GET") {
				const sessionId = decodeURIComponent(queueImgMatch[1]);
				const itemId = String(url.searchParams.get("item") ?? "");
				const index = Number.parseInt(String(url.searchParams.get("i") ?? "0"), 10);
				const ctl = controller();
				const item = (ctl === null ? [] : await hostQueued(ctl, sessionId)).find((x) => String(x.id) === itemId);
				const pick = (item && Array.isArray(item.content) ? item.content : []).filter((p) => p !== null && typeof p === "object" && p.type === "image")[Number.isFinite(index) ? index : 0];
				if (pick === void 0) {
					send(res, 404, { error: "queued image not found" });
					return;
				}
				const mediaType = String(pick.mediaType ?? "image/png").toLowerCase();
				const buf = Buffer.from(String(pick.data ?? ""), "base64");
				res.writeHead(200, {
					"Content-Type": IMAGE_TYPES.has(mediaType) ? mediaType : "image/png",
					"Content-Length": String(buf.length),
					"Cache-Control": "no-store"
				});
				res.end(buf);
				return;
			}
			const filesMatch = /^\/api\/sessions\/([^/]+)\/files$/.exec(path);
			if (filesMatch !== null && method === "POST") {
				const ctl = controller();
				if (!ctl || typeof ctl.prompt !== "function") {
					send(res, 503, { error: "sessionController.prompt unavailable" });
					return;
				}
				const body = await readJson(req, MAX_UPLOAD_BYTES);
				const raw = Array.isArray(body.files) ? body.files : [];
				if (raw.length === 0) {
					send(res, 400, { error: "files is empty" });
					return;
				}
				if (raw.length > MAX_FILES) {
					send(res, 400, { error: `at most ${String(MAX_FILES)} files per request` });
					return;
				}
				const stamp = /* @__PURE__ */ new Date();
				const day = `${String(stamp.getFullYear())}${String(stamp.getMonth() + 1).padStart(2, "0")}${String(stamp.getDate()).padStart(2, "0")}`;
				const dir = join(homedir(), ".dsh", "mobile-uploads", day);
				await mkdir(dir, { recursive: true });
				const saved = [];
				let bytes = 0;
				for (const item of raw) {
					if (item === null || typeof item !== "object") {
						send(res, 400, { error: "each file must be an object" });
						return;
					}
					const f = item;
					const data = String(f.data ?? "");
					if (data.length === 0) {
						send(res, 400, { error: "file data is empty" });
						return;
					}
					const safe = String(f.name ?? "file").replace(/[\\/:*?"<>|\u0000-\u001f]/g, "_").trim().slice(0, 120) || "file";
					const target = join(dir, `${String(Date.now())}-${safe}`);
					const buf = Buffer.from(data, "base64");
					await writeFile(target, buf);
					bytes += buf.length;
					saved.push({
						name: safe,
						path: target,
						bytes: buf.length
					});
				}
				const sessionId = decodeURIComponent(filesMatch[1]);
				const head = String(body.text ?? "").trim();
				const lines = saved.map((s) => `- ${String(s.path)}`);
				const text = `${head === "" ? "（来自手机）" : head}\n\n已保存到这台机器：\n${lines.join("\n")}`;
				const { mode, running, known } = await pickMode(ctl, sessionId, body.mode === "steer" ? "steer" : "queue");
				if (mode === "queue" && running) {
					const itemId = await hostEnqueue(ctl, sessionId, [{
						type: "text",
						text
					}]);
					await record(logFile, `200 POST files session=${sessionId} mode=queue host=${itemId} n=${String(saved.length)}`);
					send(res, 200, {
						ok: true,
						sessionId,
						mode: "queue",
						queued: true,
						item: itemId,
						count: saved.length,
						files: saved,
						queue: await hostQueueView(ctl, sessionId)
					});
					return;
				}
				const result = await Promise.resolve(ctl.prompt({
					requestId: randomBytes(16).toString("hex"),
					sessionId,
					mode,
					content: [{
						type: "text",
						text
					}]
				}, AbortSignal.timeout(6e4)));
				await record(logFile, `200 POST files session=${sessionId} n=${String(saved.length)} bytes=${String(bytes)} mode=${mode} busy=${String(running)} known=${String(known)}`);
				send(res, 200, {
					ok: true,
					sessionId,
					count: saved.length,
					bytes,
					files: saved,
					mode,
					running,
					result: result ?? null
				});
				return;
			}
			const queueMatch = /^\/api\/sessions\/([^/]+)\/queue$/.exec(path);
			if (queueMatch !== null) {
				const sessionId = decodeURIComponent(queueMatch[1]);
				if (method === "GET") {
					const ctl = controller();
					send(res, 200, {
						ok: true,
						sessionId,
						queue: await hostQueueView(ctl, sessionId)
					});
					return;
				}
				if (method === "POST") {
					const ctl = controller();
					if (!ctl || typeof ctl.prompt !== "function") {
						send(res, 503, { error: "sessionController.prompt unavailable" });
						return;
					}
					const body = await readJson(req);
					const text = String(body.text ?? "").trim();
					if (text.length === 0) {
						send(res, 400, { error: "text is empty" });
						return;
					}
					const itemId = await hostEnqueue(ctl, sessionId, [{
						type: "text",
						text
					}]);
					await record(logFile, `200 QUEUE push session=${sessionId} host=${itemId}`);
					send(res, 200, {
						ok: true,
						sessionId,
						item: itemId,
						queue: await hostQueueView(ctl, sessionId)
					});
					return;
				}
			}
			const queueOrderMatch = /^\/api\/sessions\/([^/]+)\/queue\/reorder$/.exec(path);
			if (queueOrderMatch !== null && method === "POST") {
				const sessionId = decodeURIComponent(queueOrderMatch[1]);
				const ctl = controller();
				if (!ctl || typeof ctl.prompt !== "function" || typeof ctl.updateQueue !== "function") {
					send(res, 503, { error: "sessionController queue API unavailable" });
					return;
				}
				const body = await readJson(req);
				const wanted = Array.isArray(body.ids) ? body.ids.map((x) => String(x)) : [];
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
				await record(logFile, `200 QUEUE reorder session=${sessionId} n=${moved}`);
				send(res, 200, {
					ok: true,
					sessionId,
					moved,
					queue: await hostQueueView(ctl, sessionId)
				});
				return;
			}
			const queueItemMatch = /^\/api\/sessions\/([^/]+)\/queue\/([^/]+)\/(drop|fire|edit)$/.exec(path);
			if (queueItemMatch !== null && method === "POST") {
				const sessionId = decodeURIComponent(queueItemMatch[1]);
				const itemId = decodeURIComponent(queueItemMatch[2]);
				const action = queueItemMatch[3];
				const ctl = controller();
				if (!ctl || typeof ctl.updateQueue !== "function") {
					send(res, 503, {
						error: "sessionController.updateQueue unavailable",
						hint: "restart the DSH host so the queue API is loaded"
					});
					return;
				}
				let mutation;
				if (action === "edit") {
					const body = await readJson(req);
					const text = String(body.text ?? "").trim();
					if (text.length === 0) {
						send(res, 400, { error: "text is empty" });
						return;
					}
					mutation = {
						kind: "edit",
						content: [{
							type: "text",
							text
						}]
					};
				} else if (action === "drop") mutation = { kind: "remove" };
				else mutation = { kind: "steer" };
				const mutated = await hostMutate(ctl, sessionId, itemId, mutation);
				await record(logFile, `QUEUE ${action} session=${sessionId} id=${itemId} ok=${String(mutated)}`);
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
				return;
			}
			const outboxMatch = /^\/api\/sessions\/([^/]+)\/outbox$/.exec(path);
			if (outboxMatch !== null && method === "POST") {
				const outboxSid = decodeURIComponent(outboxMatch[1]);
				const body = await readJson(req, MAX_UPLOAD_BYTES);
				const route = "outbox:" + outboxSid;
				const reqHash = hashText(JSON.stringify(body));
				if (replayHit(req, res, route, reqHash)) return;
				const idemKey = String(req.headers["idempotency-key"] ?? "");
				if (idemKey !== "") {
					if (inflightBusy(idemKey)) {
						send(res, 409, { error: "the same idempotency key is in flight" });
						return;
					}
					inflightHold(res, idemKey);
				}
				const reply = (status, payload) => {
					replayPut(idemKey, status, payload, route, reqHash);
					send(res, status, payload);
				};
				const ctl = controller();
				if (!ctl || typeof ctl.prompt !== "function") {
					reply(503, { error: "sessionController.prompt unavailable" });
					return;
				}
				const rawImgs = Array.isArray(body.images) ? body.images : [];
				const rawFiles = Array.isArray(body.files) ? body.files : [];
				if (rawImgs.length > MAX_IMAGES) {
					reply(400, { error: `at most ${String(MAX_IMAGES)} images per request` });
					return;
				}
				if (rawFiles.length > MAX_FILES) {
					reply(400, { error: `at most ${String(MAX_FILES)} files per request` });
					return;
				}
				const text = String(body.text ?? "").trim();
				const content = [];
				if (text !== "") content.push({
					type: "text",
					text
				});
				for (const item of rawImgs) {
					const img = item;
					const mediaType = String(img.mediaType ?? "").toLowerCase();
					if (!IMAGE_TYPES.has(mediaType)) {
						reply(400, {
							error: `unsupported image type: ${mediaType}`,
							allowed: [...IMAGE_TYPES]
						});
						return;
					}
					const data = String(img.data ?? "");
					if (data.length === 0) {
						reply(400, { error: "image data is empty" });
						return;
					}
					const part = {
						type: "image",
						mediaType,
						data
					};
					const name = String(img.name ?? "").trim().slice(0, 80);
					if (name !== "") part.name = name;
					content.push(part);
				}
				const savedFiles = await saveMobileFiles(rawFiles);
				if (savedFiles.text !== "") content.push({
					type: "text",
					text: savedFiles.text
				});
				if (content.length === 0) {
					reply(400, { error: "nothing to send" });
					return;
				}
				const sessionId = decodeURIComponent(outboxMatch[1]);
				const { mode, running, known } = await pickMode(ctl, sessionId, body.mode === "steer" ? "steer" : "queue");
				if (mode === "queue" && running) {
					const itemId = await hostEnqueue(ctl, sessionId, content);
					await record(logFile, `200 POST outbox session=${sessionId} mode=queue host=${itemId} parts=${String(content.length)}`);
					reply(200, {
						ok: true,
						sessionId,
						mode: "queue",
						queued: true,
						item: itemId,
						parts: content.length,
						queue: await hostQueueView(ctl, sessionId)
					});
					return;
				}
				const result = await Promise.resolve(ctl.prompt({
					requestId: randomBytes(16).toString("hex"),
					sessionId,
					mode,
					content
				}, AbortSignal.timeout(12e4)));
				await record(logFile, `200 POST outbox session=${sessionId} mode=${mode} parts=${String(content.length)} known=${String(known)}`);
				reply(200, {
					ok: true,
					sessionId,
					mode,
					running,
					parts: content.length,
					result: result ?? null
				});
				return;
			}
			const sendMatch = /^\/api\/sessions\/([^/]+)\/send$/.exec(path);
			if (sendMatch !== null && method === "POST") {
				const sendSid = decodeURIComponent(sendMatch[1]);
				const body = await readJson(req);
				const route = "send:" + sendSid;
				const reqHash = hashText(JSON.stringify(body));
				if (replayHit(req, res, route, reqHash)) return;
				const idemKey = String(req.headers["idempotency-key"] ?? "");
				if (idemKey !== "") {
					if (inflightBusy(idemKey)) {
						send(res, 409, { error: "the same idempotency key is in flight" });
						return;
					}
					inflightHold(res, idemKey);
				}
				const reply = (status, payload) => {
					replayPut(idemKey, status, payload, route, reqHash);
					send(res, status, payload);
				};
				const ctl = controller();
				if (!ctl || typeof ctl.prompt !== "function") {
					reply(503, {
						error: "sessionController.prompt unavailable",
						hint: "is the DSH host fully started?"
					});
					return;
				}
				const text = String(body.text ?? "").trim();
				if (text.length === 0) {
					reply(400, { error: "text is empty" });
					return;
				}
				const requested = body.mode === "steer" ? "steer" : "queue";
				const sessionId = decodeURIComponent(sendMatch[1]);
				phoneSessionAt.set(sessionId, Date.now());
				const { mode: effective, running, known } = await pickMode(ctl, sessionId, requested);
				if (effective === "queue" && running) {
					const itemId = await hostEnqueue(ctl, sessionId, [{
						type: "text",
						text
					}]);
					await record(logFile, `200 POST send session=${sessionId} mode=queue host=${itemId}`);
					reply(200, {
						ok: true,
						sessionId,
						mode: "queue",
						queued: true,
						item: itemId,
						queue: await hostQueueView(ctl, sessionId)
					});
					return;
				}
				const result = await Promise.resolve(ctl.prompt({
					requestId: randomBytes(16).toString("hex"),
					sessionId,
					mode: effective,
					content: [{
						type: "text",
						text
					}]
				}, AbortSignal.timeout(2e4)));
				await record(logFile, `200 POST send session=${sessionId} mode=${effective} busy=${running} known=${known} bytes=${String(Buffer.byteLength(text))}`);
				reply(200, {
					ok: true,
					sessionId,
					mode: effective,
					running,
					result: result ?? null
				});
				return;
			}
			if (path === "/api/presets" && method === "GET") {
				const svc = service("agentPresets") ?? service("agent-preset-registry");
				if (svc === null) {
					send(res, 200, {
						ok: true,
						presets: [],
						current: "",
						unavailable: true
					});
					return;
				}
				const raw = typeof svc.remoteExportList === "function" ? await Promise.resolve(svc.remoteExportList()) : typeof svc.list === "function" ? await Promise.resolve(svc.list()) : null;
				const current = presetCurrent(svc);
				send(res, 200, {
					ok: true,
					presets: presetRows(raw, current),
					current,
					unavailable: false
				});
				return;
			}
			const presetMatch = /^\/api\/sessions\/([^/]+)\/preset$/.exec(path);
			if (presetMatch !== null && method === "POST") {
				const body = await readJson(req);
				const presetId = String(body.presetId ?? "").trim();
				if (presetId === "") {
					send(res, 400, { error: "presetId is required" });
					return;
				}
				const svc = service("agentPresets") ?? service("agent-preset-registry");
				if (svc === null) {
					send(res, 503, { error: "agentPresets service unavailable" });
					return;
				}
				const sessionId = decodeURIComponent(presetMatch[1]);
				const agents = service("agents");
				const agent = agents !== null && typeof agents.get === "function" ? agents.get(sessionId) : null;
				if (agent !== null && agent !== void 0 && typeof svc.select === "function") try {
					await Promise.resolve(svc.select(agent, presetId));
					await record(logFile, `200 POST preset session=${sessionId} preset=${presetId} scope=session`);
					send(res, 200, {
						ok: true,
						selected: presetId,
						scope: "session"
					});
					return;
				} catch (error) {
					const message = error instanceof Error ? error.message : String(error);
					if (!/already started|locked/.test(message)) throw error;
				}
				const settings = service("settings");
				if (settings !== null && typeof settings.update === "function") {
					await Promise.resolve(settings.update("agent-preset-registry", { selectedDefault: presetId }, void 0));
					await record(logFile, `200 POST preset session=${sessionId} preset=${presetId} scope=global`);
					send(res, 200, {
						ok: true,
						selected: presetId,
						scope: "global"
					});
					return;
				}
				send(res, 409, { error: "this session already started a turn and no global default is available" });
				return;
			}
			if (path === "/api/permissions" && method === "GET") {
				const svc = service("permissionPresets");
				if (svc === null || typeof svc.catalog !== "function") {
					send(res, 200, {
						ok: true,
						presets: [],
						current: "",
						defaultPreset: "",
						unavailable: true
					});
					return;
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
					const agents = service("agents");
					const agent = agents !== null && typeof agents.get === "function" ? agents.get(sessionId) : null;
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
				return;
			}
			const permMatch = /^\/api\/sessions\/([^/]+)\/permission$/.exec(path);
			if (permMatch !== null && method === "POST") {
				const body = await readJson(req);
				const preset = String(body.permission ?? "").trim();
				if (preset === "") {
					send(res, 400, { error: "permission is required" });
					return;
				}
				const svc = service("permissionPresets");
				if (svc === null || typeof svc.set !== "function") {
					send(res, 503, { error: "permissionPresets service unavailable" });
					return;
				}
				const sessionId = decodeURIComponent(permMatch[1]);
				const agents = service("agents");
				const agent = agents !== null && typeof agents.get === "function" ? agents.get(sessionId) : null;
				if (agent === null || agent === void 0) {
					send(res, 404, { error: `no agent for session ${sessionId}` });
					return;
				}
				const session = agent.session;
				if (session === void 0) {
					send(res, 404, { error: `session ${sessionId} has no session object` });
					return;
				}
				svc.set(session, preset);
				let current = preset;
				if (typeof svc.current === "function") try {
					current = String(svc.current(session) ?? preset);
				} catch {
					current = preset;
				}
				await record(logFile, `200 POST permission session=${sessionId} preset=${preset} current=${current}`);
				send(res, 200, {
					ok: true,
					preset,
					current
				});
				return;
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
					const deps = typeof bag.dependencies === "object" && bag.dependencies !== null ? bag.dependencies : {};
					const dsh = typeof bag.dsh === "object" && bag.dsh !== null ? bag.dsh : {};
					const prof = typeof dsh.profile === "object" && dsh.profile !== null ? dsh.profile : {};
					const bundles = Array.isArray(prof.bundles) ? prof.bundles.map((x) => String(x)) : [];
					const items = Object.keys(deps).map((dep) => {
						const version = String(deps[dep] ?? "");
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
				return;
			}
			if (path === "/api/host/plugins/toggle" && method === "POST") {
				let body = {};
				try {
					body = await readJson(req);
				} catch (error) {
					send(res, 400, { error: `请求体不是合法 JSON：${error instanceof Error ? error.message : String(error)}` });
					return;
				}
				const profile = String(body.profile ?? "").trim();
				const name = String(body.name ?? "").trim();
				if (!PROFILE_DIR_NAME.test(profile)) {
					send(res, 400, { error: "profile 名字不合法" });
					return;
				}
				if (!BUNDLE_NAME.test(name)) {
					send(res, 400, { error: "插件名不合法" });
					return;
				}
				if (typeof body.enabled !== "boolean") {
					send(res, 400, { error: "enabled 必须是布尔值" });
					return;
				}
				const enabled = body.enabled;
				const file = join(dshHome(), "profiles", profile, "package.json");
				let raw = "";
				try {
					raw = readFileSync(file, "utf8");
				} catch {
					send(res, 404, { error: `找不到 profile ${profile} 的 package.json` });
					return;
				}
				let bag;
				try {
					bag = JSON.parse(raw);
				} catch {
					send(res, 500, { error: `profile ${profile} 的 package.json 不是合法 JSON，先手动修好再开开关` });
					return;
				}
				if (typeof (typeof bag.dependencies === "object" && bag.dependencies !== null ? bag.dependencies : {})[name] !== "string") {
					send(res, 400, { error: `${name} 不在 profile ${profile} 的依赖里，这里只能开关已安装的插件` });
					return;
				}
				const dsh = typeof bag.dsh === "object" && bag.dsh !== null ? bag.dsh : {};
				const prof = typeof dsh.profile === "object" && dsh.profile !== null ? dsh.profile : {};
				const current = Array.isArray(prof.bundles) ? prof.bundles.map((x) => String(x)) : [];
				if (current.indexOf(name) >= 0 === enabled) {
					await record(logFile, `200 POST plugin-toggle ${profile}/${name} enabled=${String(enabled)} changed=false`);
					send(res, 200, {
						ok: true,
						profile,
						name,
						enabled,
						changed: false,
						restartRequired: false
					});
					return;
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
				const temp = `${file}.${String(process.pid)}.tmp`;
				try {
					writeFileSync(`${file}.bak`, raw, "utf8");
					writeFileSync(temp, text, "utf8");
					renameSync(temp, file);
				} catch (error) {
					try {
						unlinkSync(temp);
					} catch {}
					const message = error instanceof Error ? error.message : String(error);
					await record(logFile, `500 POST plugin-toggle ${profile}/${name} write failed: ${message}`);
					send(res, 500, { error: `写 profile 清单失败：${message}` });
					return;
				}
				await record(logFile, `200 POST plugin-toggle ${profile}/${name} enabled=${String(enabled)} changed=true`);
				send(res, 200, {
					ok: true,
					profile,
					name,
					enabled,
					changed: true,
					restartRequired: true
				});
				return;
			}
			const teamMatch = /^\/api\/sessions\/([^/]+)\/team$/.exec(path);
			if (teamMatch !== null && method === "GET") {
				const sessionId = decodeURIComponent(teamMatch[1]);
				const file = findSessionFile(sessionId);
				if (file === null) {
					send(res, 404, { error: "session log not found" });
					return;
				}
				let enabled = false;
				let sawMode = false;
				const members = /* @__PURE__ */ new Map();
				const tasks = /* @__PURE__ */ new Map();
				let lines = [];
				try {
					lines = readSessionLines(file);
				} catch (error) {
					send(res, 500, { error: `cannot read session log: ${String(error)}` });
					return;
				}
				for (const line of lines) {
					let ev;
					try {
						ev = JSON.parse(line);
					} catch {
						continue;
					}
					const type = String(ev?.type ?? "");
					if (type === "team/mode") {
						sawMode = true;
						enabled = ev?.data?.enabled === true;
						continue;
					}
					if (type === "team/member") {
						const member = ev?.data?.member;
						if (member !== null && typeof member === "object") members.set(String(member.id ?? ""), {
							id: String(member.id ?? ""),
							name: String(member.name ?? ""),
							description: String(member.description ?? ""),
							phase: String(member.phase ?? ""),
							error: String(member.error ?? "")
						});
						continue;
					}
					if (type === "team/task") {
						const task = ev?.data?.task;
						if (task !== null && typeof task === "object") {
							const id = String(task.id ?? "");
							const seen = tasks.get(id);
							const revision = Number(task.revision ?? 0);
							if (seen === void 0 || Number(seen.revision ?? -1) <= revision) tasks.set(id, {
								id,
								revision,
								subject: String(task.subject ?? ""),
								description: String(task.description ?? ""),
								status: String(task.status ?? "pending"),
								ownerName: String(task.ownerName ?? ""),
								ownerId: String(task.ownerId ?? "")
							});
						}
					}
				}
				const taskRows = Array.from(tasks.values()).filter((task) => task.status !== "deleted").sort((a, b) => {
					const rank = (s) => s === "in_progress" ? 0 : s === "pending" ? 1 : s === "completed" ? 2 : 3;
					const delta = rank(a.status) - rank(b.status);
					return delta !== 0 ? delta : String(a.subject).localeCompare(String(b.subject));
				});
				send(res, 200, {
					ok: true,
					sessionId,
					enabled,
					sawMode,
					members: Array.from(members.values()),
					tasks: taskRows
				});
				return;
			}
			const teamModeMatch = /^\/api\/sessions\/([^/]+)\/team\/mode$/.exec(path);
			if (teamModeMatch !== null && method === "POST") {
				let body = {};
				try {
					body = await readJson(req);
				} catch (error) {
					send(res, 400, { error: `请求体不是合法 JSON：${error instanceof Error ? error.message : String(error)}` });
					return;
				}
				const rawEnabled = body.enabled;
				if (typeof rawEnabled !== "boolean") {
					send(res, 400, { error: "enabled 必须是布尔值" });
					return;
				}
				const enabled = rawEnabled;
				const sessionId = decodeURIComponent(teamModeMatch[1]);
				const svc = service("agentTeams");
				if (svc === null || typeof svc.setEnabled !== "function") {
					send(res, 503, { error: "这台电脑没有挂载智能体团队（agentTeams 服务不可用）" });
					return;
				}
				const agents = service("agents");
				const agent = agents !== null && typeof agents.get === "function" ? agents.get(sessionId) : null;
				if (agent === null || agent === void 0) {
					send(res, 503, { error: "这个会话在电脑上没有打开：先在电脑端点开它一次，再回来切换" });
					return;
				}
				try {
					const change = svc.setEnabled;
					await Promise.resolve(change.call(svc, agent, enabled));
				} catch (error) {
					const code = typeof error.code === "string" ? String(error.code) : "";
					const message = error instanceof Error ? error.message : String(error);
					const status = code === "TEAM_LEAD_REQUIRED" ? 409 : 500;
					const readable = code === "TEAM_LEAD_REQUIRED" ? "这个会话是子智能体，请到它的根会话里切换智能体协作" : `电脑端拒绝了这个切换：${message}`;
					await record(logFile, `${String(status)} POST team-mode session=${sessionId} enabled=${String(enabled)} code=${code} err=${message}`);
					send(res, status, { error: readable });
					return;
				}
				await record(logFile, `200 POST team-mode session=${sessionId} enabled=${String(enabled)}`);
				send(res, 200, {
					ok: true,
					enabled
				});
				return;
			}
			if (path === "/api/host/schedules" && method === "GET") {
				const svc = service("schedule");
				if (svc !== null && typeof svc.list === "function") {
					const page = await Promise.resolve(svc.list({ limit: 100 }));
					const bag = page !== null && typeof page === "object" ? page : {};
					send(res, 200, {
						ok: true,
						source: "service",
						items: (Array.isArray(bag.items) ? bag.items : []).map(normalizeScheduleTask)
					});
					return;
				}
				let raw = "";
				try {
					raw = readFileSync(join(dshHome(), "storages", "schedule.json"), "utf8");
				} catch (err) {
					send(res, 503, { error: `scheduled tasks unavailable: ${err instanceof Error ? err.message : String(err)}` });
					return;
				}
				let items = [];
				try {
					const bag = JSON.parse(raw);
					const table = bag.tables !== void 0 && bag.tables.tasks !== void 0 ? bag.tables.tasks : {};
					items = Object.keys(table).map((key) => normalizeScheduleTask(table[key]));
				} catch (err) {
					send(res, 500, { error: `cannot read scheduled tasks: ${err instanceof Error ? err.message : String(err)}` });
					return;
				}
				send(res, 200, {
					ok: true,
					source: "file",
					items
				});
				return;
			}
			const scheduleActionMatch = /^\/api\/host\/schedules\/([^/]+)\/action$/.exec(path);
			if (scheduleActionMatch !== null && method === "POST") {
				let body = {};
				try {
					body = await readJson(req);
				} catch (error) {
					send(res, 400, { error: `请求体不是合法 JSON：${error instanceof Error ? error.message : String(error)}` });
					return;
				}
				const action = String(body.action ?? "").trim();
				if (action !== "pause" && action !== "resume" && action !== "run" && action !== "delete") {
					send(res, 400, { error: "action 只能是 pause、resume、run 或 delete" });
					return;
				}
				let id = "";
				try {
					id = decodeURIComponent(scheduleActionMatch[1]);
				} catch {
					send(res, 400, { error: "任务 id 编码不合法" });
					return;
				}
				if (id === "") {
					send(res, 400, { error: "任务 id 不能为空" });
					return;
				}
				const svc = service("schedule");
				if (svc === null) {
					send(res, 503, { error: "这台电脑没有挂载自动化任务（schedule 服务不可用）" });
					return;
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
					await record(logFile, `501 POST schedule-action id=${id} action=${action} unsupported`);
					send(res, 501, {
						error: "这台电脑的定时任务服务不支持这个操作（缺少 edit / run 方法），升级 DSH 后再试",
						action,
						unsupported: true
					});
					return;
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
						await record(logFile, `${String(status)} POST schedule-action id=${id} action=${action} code=${coded} err=${message}`);
						send(res, status, {
							error: readable,
							action
						});
						return;
					}
				}
				if (used === "") {
					const detail = failures.length > 0 ? failures[failures.length - 1] : "没有可用的方法";
					await record(logFile, `501 POST schedule-action id=${id} action=${action} none-of: ${failures.join(" | ")}`);
					send(res, 501, {
						error: `这台电脑的定时任务服务没有接受这个操作，升级 DSH 后再试（${detail}）`,
						action,
						unsupported: true,
						tried: failures
					});
					return;
				}
				const bag = result !== null && typeof result === "object" ? result : {};
				const code = typeof bag.code === "string" ? bag.code : "";
				if (code === "schedule_not_found") {
					await record(logFile, `404 POST schedule-action id=${id} action=${action} not-found`);
					send(res, 404, {
						error: "这个任务在电脑上已经不存在了，刷新列表看看",
						action
					});
					return;
				}
				if (code === "schedule_conflict") {
					await record(logFile, `409 POST schedule-action id=${id} action=${action} conflict`);
					send(res, 409, {
						error: "任务刚被别处改过，刷新列表再试一次",
						action
					});
					return;
				}
				if (code === "schedule_execution_pending") {
					await record(logFile, `409 POST schedule-action id=${id} action=${action} pending`);
					send(res, 409, {
						error: "这个任务正在执行，稍等一会儿再点「立即」",
						action,
						pending: true
					});
					return;
				}
				if (bag.deleted === true) {
					await record(logFile, `200 POST schedule-action id=${id} action=${action} via=${used} deleted`);
					send(res, 200, {
						ok: true,
						action,
						id,
						via: used,
						deleted: true
					});
					return;
				}
				await record(logFile, `200 POST schedule-action id=${id} action=${action} via=${used}`);
				send(res, 200, {
					ok: true,
					action,
					id,
					via: used,
					item: normalizeScheduleTask(result)
				});
				return;
			}
			const tidyCwd = (raw) => raw.replace(/\\\\/g, "\\");
			const cwdOf = async (sid) => {
				const sessions = service("sessions");
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
				const ctl = controller();
				if (ctl !== null && typeof ctl.list === "function") try {
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
					return existsSync(target) ? null : target;
				}
			};
			/**
			* 写操作专用校验：在 underRoot 之上再收紧三件事。
			* 1) 会话必须有真实工作目录，不能落到进程 cwd 的兜底；
			* 2) 目标父目录必须真实存在且解析后仍在根内（挡 symlink/junction 越界）；
			* 3) 目标本身如果是链接，一律拒绝，避免「操作的是链接还是链接指向」两可。
			* mustExist=false 用于重命名的目标：它还不存在，只校验父目录。
			*/
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
			const fsMatch = /^\/api\/sessions\/([^/]+)\/fs$/.exec(path);
			if (fsMatch !== null && method === "GET") {
				const sid = decodeURIComponent(fsMatch[1]);
				const picked = await rootOf(sid);
				const root = picked.root;
				if (root === "") {
					send(res, 404, { error: `session ${sid} has no working directory` });
					return;
				}
				const rel = String(url.searchParams.get("path") ?? "");
				const target = underRoot(root, rel);
				if (target === null) {
					send(res, 400, { error: "path escapes the working directory" });
					return;
				}
				let names = [];
				try {
					names = readdirSync(target);
				} catch (err) {
					send(res, 404, { error: `cannot read folder: ${err instanceof Error ? err.message : String(err)}` });
					return;
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
				const trimmed = entries.length > 400 ? entries.slice(0, 400) : entries;
				await record(logFile, `200 GET fs session=${sid} path=${rel} n=${trimmed.length}`);
				send(res, 200, {
					ok: true,
					root,
					path: rel,
					entries: trimmed,
					more: entries.length > trimmed.length,
					fallback: picked.fallback
				});
				return;
			}
			const fsFileMatch = /^\/api\/sessions\/([^/]+)\/fs\/file$/.exec(path);
			if (fsFileMatch !== null && method === "GET") {
				const root = (await rootOf(decodeURIComponent(fsFileMatch[1]))).root;
				const rel = String(url.searchParams.get("path") ?? "");
				const target = root === "" ? null : underRoot(root, rel);
				if (root === "" || target === null) {
					send(res, 400, { error: "bad path" });
					return;
				}
				const LIMIT = 512 * 1024;
				let buf;
				try {
					const st = statSync(target);
					if (!st.isFile()) {
						send(res, 400, { error: "not a file" });
						return;
					}
					if (st.size > LIMIT) {
						send(res, 413, { error: `file is too large to preview (${st.size} bytes)` });
						return;
					}
					buf = readFileSync(target);
				} catch (err) {
					send(res, 404, { error: `cannot read file: ${err instanceof Error ? err.message : String(err)}` });
					return;
				}
				if (buf.indexOf(0) >= 0) {
					send(res, 415, { error: "binary file: no text preview" });
					return;
				}
				send(res, 200, {
					ok: true,
					name: String(rel).split(/[\\/]/).pop() ?? rel,
					size: buf.length,
					text: buf.toString("utf8")
				});
				return;
			}
			const fsRenameMatch = /^\/api\/sessions\/([^/]+)\/fs\/rename$/.exec(path);
			if (fsRenameMatch !== null && method === "POST") {
				const sid = decodeURIComponent(fsRenameMatch[1]);
				const picked = await rootOf(sid);
				const root = picked.root;
				if (root === "" || picked.fallback) {
					send(res, 400, { error: "session has no working directory" });
					return;
				}
				const body = await readJson(req);
				const rel = String(body.path ?? "");
				const to = String(body.to ?? "");
				const from = writeTarget(root, rel, true);
				const dest = writeTarget(root, to, false);
				if (from === null || dest === null || from === dest) {
					send(res, 400, { error: "bad path" });
					return;
				}
				if (existsSync(dest)) {
					send(res, 409, { error: "目标已存在" });
					return;
				}
				try {
					renameSync(from, dest);
					await record(logFile, `200 POST fs/rename session=${sid} from=${rel} to=${to}`);
					send(res, 200, { ok: true });
				} catch (err) {
					send(res, 400, { error: `cannot rename: ${err instanceof Error ? err.message : String(err)}` });
				}
				return;
			}
			const fsDeleteMatch = /^\/api\/sessions\/([^/]+)\/fs\/delete$/.exec(path);
			if (fsDeleteMatch !== null && method === "POST") {
				const sid = decodeURIComponent(fsDeleteMatch[1]);
				const picked = await rootOf(sid);
				const root = picked.root;
				if (root === "" || picked.fallback) {
					send(res, 400, { error: "session has no working directory" });
					return;
				}
				const body = await readJson(req);
				const rel = String(body.path ?? "");
				const target = writeTarget(root, rel, true);
				if (target === null) {
					send(res, 400, { error: "bad path" });
					return;
				}
				try {
					if (statSync(target).isDirectory()) rmdirSync(target);
					else unlinkSync(target);
					await record(logFile, `200 POST fs/delete session=${sid} path=${rel}`);
					send(res, 200, { ok: true });
				} catch (err) {
					send(res, 400, { error: `cannot delete: ${err instanceof Error ? err.message : String(err)}` });
				}
				return;
			}
			const fsSignMatch = /^\/api\/sessions\/([^/]+)\/fs\/sign$/.exec(path);
			if (fsSignMatch !== null && method === "POST") {
				const sid = decodeURIComponent(fsSignMatch[1]);
				const body = await readJson(req);
				const rel = String(body.path ?? "");
				if (rel === "") {
					send(res, 400, { error: "path is required" });
					return;
				}
				const exp = String(Math.floor(Date.now() / 1e3) + SIG_TTL_SEC);
				send(res, 200, {
					ok: true,
					e: exp,
					sig: sigOf("raw", sid + "|" + rel, exp)
				});
				return;
			}
			const fsRawMatch = /^\/api\/sessions\/([^/]+)\/fs\/raw$/.exec(path);
			if (fsRawMatch !== null && method === "GET") {
				const root = (await rootOf(decodeURIComponent(fsRawMatch[1]))).root;
				const rel = String(url.searchParams.get("path") ?? "");
				const target = root === "" ? null : underRoot(root, rel);
				if (root === "" || target === null) {
					send(res, 400, { error: "bad path" });
					return;
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
					return;
				}
				const RAW_LIMIT = 16 * 1024 * 1024;
				let size = 0;
				try {
					const st = statSync(target);
					if (!st.isFile()) {
						send(res, 400, { error: "not a file" });
						return;
					}
					if (st.size > RAW_LIMIT) {
						send(res, 413, { error: `image is too large (${st.size} bytes)` });
						return;
					}
					size = st.size;
				} catch (err) {
					send(res, 404, { error: `cannot read image: ${err instanceof Error ? err.message : String(err)}` });
					return;
				}
				res.writeHead(200, {
					"content-type": type,
					"content-length": String(size),
					"cache-control": "private, max-age=60"
				});
				const imgStream = createReadStream(target);
				imgStream.on("error", (err) => {
					console.error(`fs/raw stream failed: ${err instanceof Error ? err.message : String(err)}`);
					res.destroy();
				});
				res.on("close", () => {
					imgStream.destroy();
				});
				imgStream.pipe(res);
				return;
			}
			const fsDownloadMatch = /^\/api\/sessions\/([^/]+)\/fs\/download$/.exec(path);
			if (fsDownloadMatch !== null && method === "GET") {
				const sid = decodeURIComponent(fsDownloadMatch[1]);
				const root = (await rootOf(sid)).root;
				const rel = String(url.searchParams.get("path") ?? "");
				const target = root === "" ? null : underRoot(root, rel);
				if (root === "" || target === null) {
					send(res, 400, { error: "bad path" });
					return;
				}
				const LIMIT = 64 * 1024 * 1024;
				let size = 0;
				try {
					const st = statSync(target);
					if (!st.isFile()) {
						send(res, 400, { error: "not a file" });
						return;
					}
					if (st.size > LIMIT) {
						send(res, 413, { error: `file is too large to download (${st.size} bytes)` });
						return;
					}
					size = st.size;
				} catch (err) {
					send(res, 404, { error: `cannot read file: ${err instanceof Error ? err.message : String(err)}` });
					return;
				}
				const name = String(rel).split(/[\\/]/).pop() ?? rel;
				await record(logFile, `200 GET fs/download session=${sid} path=${rel} n=${size}`);
				res.writeHead(200, {
					"content-type": "application/octet-stream",
					"content-length": String(size),
					"content-disposition": "attachment; filename*=UTF-8''" + encodeURIComponent(name),
					"cache-control": "private, max-age=0"
				});
				const dlStream = createReadStream(target);
				dlStream.on("error", (err) => {
					console.error(`fs/download stream failed: ${err instanceof Error ? err.message : String(err)}`);
					res.destroy();
				});
				res.on("close", () => {
					dlStream.destroy();
				});
				dlStream.pipe(res);
				return;
			}
			const goalMatch = /^\/api\/sessions\/([^/]+)\/goal(?:\/(action))?$/.exec(path);
			if (goalMatch) {
				const sid = goalMatch[1];
				const goalSvc = service("goals");
				if (goalSvc === null) {
					send(res, 503, { error: "goals are unavailable on this host" });
					return;
				}
				const agent = service("agents")?.get(sid);
				if (agent === void 0 || agent === null) {
					send(res, 503, { error: "这个会话在电脑上没有打开：先在电脑点开它一次，再回来看目标。" });
					return;
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
				if (goalMatch[2] === void 0) {
					try {
						send(res, 200, {
							ok: true,
							sessionId: sid,
							goal: viewOf(goalSvc.get(agent))
						});
					} catch (ex) {
						send(res, 500, { error: String(ex) });
					}
					return;
				}
				const body = await readJson(req);
				const action = typeof body.action === "string" ? body.action : "";
				let current = null;
				try {
					current = viewOf(goalSvc.get(agent));
				} catch (ex) {
					send(res, 500, { error: String(ex) });
					return;
				}
				if (current === null) {
					send(res, 404, { error: "这个会话现在没有目标" });
					return;
				}
				const ref = {
					id: current.id,
					revision: current.revision
				};
				try {
					if (action === "pause") goalSvc.pause(agent, ref);
					else if (action === "resume") goalSvc.resume(agent, ref);
					else if (action === "complete") goalSvc.complete(agent, ref);
					else if (action === "clear") goalSvc.clear(agent, ref);
					else if (action === "edit") {
						const patch = {};
						if (typeof body.objective === "string" && body.objective !== "") patch.objective = body.objective;
						if (typeof body.maxGoalRounds === "number" && body.maxGoalRounds > 0) patch.maxGoalRounds = body.maxGoalRounds;
						goalSvc.edit(agent, ref, patch);
					} else {
						send(res, 400, { error: "action must be pause, resume, complete, clear or edit" });
						return;
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
				return;
			}
			send(res, 404, {
				error: "not found",
				path
			});
		} catch (error) {
			const message = error instanceof Error ? error.message : String(error);
			await record(logFile, `500 ${method} ${path} ${message}`);
			send(res, 500, { error: message });
		} finally {
			const qp = [];
			url.searchParams.forEach((v, k) => {
				qp.push(k + "=" + (k === "t" || k === "payload" ? "***" : v));
			});
			const q = qp.length === 0 ? "" : "?" + qp.join("&").slice(0, 40);
			record(logFile, `${String(res.statusCode)} ${method} ${path}${q} ${String(Date.now() - started)}ms`);
		}
	};
	const panelRoutes = createPanel({
		pairState: () => pairState(),
		rotatePair: () => {
			rotatePair();
		},
		writePair: (next) => {
			writeState({ pair: next });
		},
		pairPayload: (base, code, alts) => pairPayload(base, code, alts),
		record: (line) => record(logFile, line)
	}).routes;
	try {
		ctx.inject(["connection"], (connCtx) => {
			const registry = connCtx?.connection?.fetch;
			if (registry === void 0 || typeof registry.register !== "function") {
				record(logFile, "panel routes skipped: connection.fetch unavailable");
				return;
			}
			for (const route of panelRoutes) try {
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
				res.destroy();
			} catch {}
		});
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
			record(logFile, "disposing; closing listener");
			server.close();
		};
	}, "mobile listener");
}
//#endregion
export { apply, internals, name };
