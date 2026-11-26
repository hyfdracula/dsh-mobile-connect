window.__ModuleLoader__.load({
	id: "agent-mobile-gateway",
	factory: (require) => {
		var module = { exports: {} };
		var exports = module.exports;
		Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });
		let react = require("react");
		let react_jsx_runtime = require("react/jsx-runtime");
		//#region src/client/MobileSection.tsx
		/**
		* Agent Mobile 桌面设置面板：
		* 首屏聚焦配对工作区（二维码 + 6 位一次性配对码 + 入口复制），
		* 下方分栏承接网络接入策略、端到端加密设备授权、协作权限与网关概览。
		* @module agent-mobile-gateway/client/MobileSection
		*/
		/** 适配深浅双色的宿主题回退变量，强调色对齐 #2F6BFF。 */
		const C$1 = {
			card: "var(--dsw-alias-surface-card, var(--dsw-alias-bg-layer-3, rgba(127,127,127,0.08)))",
			cardSoft: "var(--dsw-alias-bg-layer-2, var(--dsw-alias-bg-layer-1, rgba(127,127,127,0.06)))",
			border: "var(--dsw-alias-border-l2, rgba(127,127,127,0.22))",
			fg: "var(--dsw-alias-label-primary, currentColor)",
			fgDim: "var(--dsw-alias-label-secondary, rgba(127,127,127,0.85))",
			fgFaint: "var(--dsw-alias-label-tertiary, rgba(127,127,127,0.68))",
			accent: "var(--dsw-alias-state-business-primary, #2F6BFF)",
			accentSoft: "rgba(47,107,255,0.12)",
			accentBorder: "rgba(47,107,255,0.32)",
			onAccent: "var(--dsw-alias-label-on-color, #FFFFFF)",
			ok: "var(--dsw-alias-state-success-primary, #0F9D63)",
			okBg: "rgba(15,157,99,0.12)",
			bad: "var(--dsw-alias-state-error-primary, #DC3545)",
			badBg: "rgba(220,53,69,0.10)",
			qrPlate: "#FFFFFF",
			mono: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace"
		};
		const ROUTE$1 = "/api/dsh-mobile/panel";
		async function extractHttpError(res) {
			const text = await res.text();
			if (text.length > 0) {
				try {
					const parsed = JSON.parse(text);
					if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) {
						const msg = parsed.error;
						if (typeof msg === "string" && msg.trim().length > 0) return new Error(msg.trim());
					}
				} catch {}
				return new Error(text.slice(0, 200));
			}
			return /* @__PURE__ */ new Error(`HTTP ${String(res.status)}`);
		}
		async function getJson(path) {
			const res = await fetch(path, {
				credentials: "same-origin",
				cache: "no-store"
			});
			if (!res.ok) throw await extractHttpError(res);
			return await res.json();
		}
		async function postJson(path, body) {
			const res = await fetch(path, {
				method: "POST",
				credentials: "same-origin",
				cache: "no-store",
				headers: { "content-type": "application/json; charset=utf-8" },
				body: JSON.stringify(body)
			});
			if (!res.ok) throw await extractHttpError(res);
			return await res.json();
		}
		function validatePublicUrlInput(raw) {
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
				const u = new URL(trimmed);
				if (u.protocol !== "http:" && u.protocol !== "https:" || !u.hostname) return {
					ok: false,
					error: "公网地址格式不合法，请填写完整的 http:// 或 https:// 地址"
				};
				const cleanPath = u.pathname === "/" ? "" : u.pathname.replace(/\/+$/, "");
				return {
					ok: true,
					url: `${u.origin}${cleanPath}`
				};
			} catch {
				return {
					ok: false,
					error: "公网地址格式不合法，请填写完整的 http:// 或 https:// 地址"
				};
			}
		}
		function parsePortsInput(raw) {
			const parts = raw.split(/[,，\s]+/).map((s) => s.trim()).filter((s) => s.length > 0);
			const seen = /* @__PURE__ */ new Set();
			const ports = [];
			for (const part of parts) {
				if (!/^\d+$/.test(part)) return {
					ok: false,
					error: `端口号「${part}」不合法，请填写 1 到 65535 之间的整数`
				};
				const n = Number.parseInt(part, 10);
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
		function Card(props) {
			const hero = props.hero === true;
			return /* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
				style: {
					border: `1px solid ${hero ? C$1.accentBorder : C$1.border}`,
					background: C$1.card,
					borderRadius: 16,
					padding: hero ? "16px 18px" : "14px 16px",
					minWidth: 0
				},
				children: props.children
			});
		}
		function SectionHead(props) {
			return /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
				style: {
					display: "flex",
					alignItems: "center",
					justifyContent: "space-between",
					gap: 10,
					marginBottom: 10,
					minWidth: 0
				},
				children: [/* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
					style: { minWidth: 0 },
					children: [/* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
						style: {
							fontSize: 14,
							fontWeight: 600,
							color: C$1.fg,
							whiteSpace: "nowrap"
						},
						children: props.title
					}), props.subtitle ? /* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
						style: {
							fontSize: 12,
							color: C$1.fgFaint,
							marginTop: 2,
							overflowWrap: "anywhere"
						},
						children: props.subtitle
					}) : null]
				}), props.right]
			});
		}
		function Chip(props) {
			const color = props.tone === "ok" ? C$1.ok : props.tone === "bad" ? C$1.bad : props.tone === "accent" ? C$1.accent : C$1.fgFaint;
			return /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("span", {
				style: {
					display: "inline-flex",
					alignItems: "center",
					gap: 5,
					fontSize: 12,
					fontWeight: 500,
					color,
					background: props.tone === "ok" ? C$1.okBg : props.tone === "bad" ? C$1.badBg : props.tone === "accent" ? C$1.accentSoft : "rgba(127,127,127,0.12)",
					borderRadius: 999,
					padding: "3px 10px",
					flexShrink: 0,
					whiteSpace: "nowrap"
				},
				children: [/* @__PURE__ */ (0, react_jsx_runtime.jsx)("span", { style: {
					width: 6,
					height: 6,
					borderRadius: 3,
					background: color,
					flexShrink: 0
				} }), props.text]
			});
		}
		function Toggle(props) {
			const width = 42;
			const height = 24;
			const disabled = props.disabled === true;
			return /* @__PURE__ */ (0, react_jsx_runtime.jsx)("button", {
				type: "button",
				role: "switch",
				"aria-checked": props.on,
				disabled,
				onClick: () => {
					if (!disabled) props.onChange(!props.on);
				},
				style: {
					width,
					height,
					borderRadius: height / 2,
					border: "none",
					padding: 0,
					fontFamily: "inherit",
					cursor: disabled ? "default" : "pointer",
					opacity: disabled ? .5 : 1,
					background: props.on ? C$1.accent : "rgba(127,127,127,0.32)",
					position: "relative",
					transition: "background .18s ease",
					flexShrink: 0
				},
				children: /* @__PURE__ */ (0, react_jsx_runtime.jsx)("span", { style: {
					position: "absolute",
					top: 3,
					left: props.on ? 21 : 3,
					width: height - 6,
					height: height - 6,
					borderRadius: "50%",
					background: C$1.onAccent,
					boxShadow: "0 1px 2px rgba(0,0,0,0.22)",
					transition: "left .18s cubic-bezier(.34,1.4,.64,1)"
				} })
			});
		}
		function Btn(props) {
			const primary = props.primary === true;
			const disabled = props.disabled === true;
			return /* @__PURE__ */ (0, react_jsx_runtime.jsx)("button", {
				type: "button",
				disabled,
				onClick: props.onClick,
				style: {
					border: primary ? "none" : `1px solid ${C$1.border}`,
					background: primary ? C$1.accent : C$1.cardSoft,
					color: primary ? C$1.onAccent : C$1.fg,
					borderRadius: 10,
					padding: "6px 13px",
					fontSize: 13,
					fontWeight: primary ? 500 : 400,
					fontFamily: "inherit",
					lineHeight: 1.45,
					cursor: disabled ? "default" : "pointer",
					opacity: disabled ? .5 : 1,
					flexShrink: 0,
					whiteSpace: "nowrap"
				},
				children: props.text
			});
		}
		function MetaPill(props) {
			return /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
				style: {
					border: `1px solid ${C$1.border}`,
					background: C$1.cardSoft,
					borderRadius: 10,
					padding: "7px 10px",
					minWidth: 0,
					flex: "1 1 130px"
				},
				children: [/* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
					style: {
						fontSize: 11,
						color: C$1.fgFaint,
						marginBottom: 2
					},
					children: props.label
				}), /* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
					style: {
						fontSize: 12.5,
						color: C$1.fg,
						fontWeight: 500,
						fontFamily: C$1.mono,
						overflowWrap: "anywhere",
						wordBreak: "break-word"
					},
					children: props.value
				})]
			});
		}
		function countdown(secondsLeft) {
			const safe = Math.max(0, secondsLeft);
			const mm = Math.floor(safe / 60);
			const ss = safe % 60;
			return `${String(mm).padStart(2, "0")}:${String(ss).padStart(2, "0")}`;
		}
		function formatLastSeen(ts) {
			if (!Number.isFinite(ts) || ts <= 0) return "刚刚";
			const d = new Date(ts);
			const pad = (n) => String(n).padStart(2, "0");
			return `${String(d.getFullYear())}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
		}
		function MobileSection() {
			const [state, setState] = (0, react.useState)(null);
			const [error, setError] = (0, react.useState)("");
			const [busy, setBusy] = (0, react.useState)("");
			const [draftUrl, setDraftUrl] = (0, react.useState)("");
			const [urlDirty, setUrlDirty] = (0, react.useState)(false);
			const urlDirtyRef = (0, react.useRef)(false);
			const [draftPorts, setDraftPorts] = (0, react.useState)("");
			const [portsDirty, setPortsDirty] = (0, react.useState)(false);
			const portsDirtyRef = (0, react.useRef)(false);
			const [qrFailed, setQrFailed] = (0, react.useState)(false);
			const [copied, setCopied] = (0, react.useState)("");
			const [now, setNow] = (0, react.useState)(Date.now());
			const refreshedExpiredCodeRef = (0, react.useRef)("");
			const copyTimerRef = (0, react.useRef)(null);
			const syncDraftsFromState = (0, react.useCallback)((next) => {
				if (!urlDirtyRef.current) setDraftUrl(next.publicUrl ?? "");
				if (!portsDirtyRef.current) {
					const list = Array.isArray(next.previewPorts) ? next.previewPorts : [];
					setDraftPorts(list.join(", "));
				}
			}, []);
			const load = (0, react.useCallback)(async (clearErr = false) => {
				try {
					const next = await getJson(`${ROUTE$1}/state`);
					setState(next);
					if (clearErr) setError("");
					syncDraftsFromState(next);
				} catch (reason) {
					setError(reason instanceof Error ? reason.message : String(reason));
				}
			}, [syncDraftsFromState]);
			(0, react.useEffect)(() => {
				load(true);
				const poll = setInterval(() => {
					if (typeof document !== "undefined" && document.visibilityState === "hidden") return;
					load(false);
				}, 5e3);
				const clock = setInterval(() => {
					setNow(Date.now());
				}, 1e3);
				return () => {
					clearInterval(poll);
					clearInterval(clock);
					if (copyTimerRef.current !== null) {
						clearTimeout(copyTimerRef.current);
						copyTimerRef.current = null;
					}
				};
			}, [load]);
			const patch = (0, react.useCallback)(async (key, body, onSuccess) => {
				setBusy(key);
				try {
					const next = await postJson(`${ROUTE$1}/config`, body);
					setState(next);
					setError("");
					onSuccess?.(next);
				} catch (reason) {
					setError(reason instanceof Error ? reason.message : String(reason));
				} finally {
					setBusy("");
				}
			}, []);
			const savePublicUrl = (0, react.useCallback)(async () => {
				const checked = validatePublicUrlInput(draftUrl);
				if (!checked.ok) {
					setError(checked.error);
					return;
				}
				await patch("url", { publicUrl: checked.url }, (next) => {
					urlDirtyRef.current = false;
					setUrlDirty(false);
					setDraftUrl(next.publicUrl ?? "");
				});
			}, [draftUrl, patch]);
			const savePreviewPorts = (0, react.useCallback)(async () => {
				const checked = parsePortsInput(draftPorts);
				if (!checked.ok) {
					setError(checked.error);
					return;
				}
				await patch("ports", { previewPorts: checked.ports }, (next) => {
					portsDirtyRef.current = false;
					setPortsDirty(false);
					const list = Array.isArray(next.previewPorts) ? next.previewPorts : [];
					setDraftPorts(list.join(", "));
				});
			}, [draftPorts, patch]);
			const rotate = (0, react.useCallback)(async () => {
				setBusy("code");
				try {
					const next = await postJson(`${ROUTE$1}/newcode`, {});
					setState(next);
					setQrFailed(false);
					setError("");
				} catch (reason) {
					setError(reason instanceof Error ? reason.message : String(reason));
				} finally {
					setBusy("");
				}
			}, []);
			const toggleDeviceRevoke = (0, react.useCallback)(async (deviceId, revoked) => {
				setBusy(`dev:${deviceId}`);
				try {
					const next = await postJson(`${ROUTE$1}/devices/revoke`, {
						deviceId,
						revoked
					});
					setState(next);
					setError("");
				} catch (reason) {
					setError(reason instanceof Error ? reason.message : String(reason));
				} finally {
					setBusy("");
				}
			}, []);
			const copy = (0, react.useCallback)(async (text, label) => {
				try {
					await navigator.clipboard.writeText(text);
					setCopied(label);
					if (copyTimerRef.current !== null) clearTimeout(copyTimerRef.current);
					copyTimerRef.current = setTimeout(() => {
						setCopied("");
					}, 1800);
				} catch {
					setCopied("");
				}
			}, []);
			const online = state?.phoneOnline === true;
			const secondsLeft = state === null ? 0 : Math.floor((state.expiresAt - now) / 1e3);
			const qrSrc = state === null || state.payload.length === 0 ? "" : `${ROUTE$1}/qr.svg?payload=${encodeURIComponent(state.payload)}`;
			(0, react.useEffect)(() => {
				setQrFailed(false);
			}, [qrSrc]);
			(0, react.useEffect)(() => {
				if (state === null) return;
				if (secondsLeft <= 0 && refreshedExpiredCodeRef.current !== state.code) {
					refreshedExpiredCodeRef.current = state.code;
					load(false);
				}
			}, [
				state,
				secondsLeft,
				load
			]);
			const currentAnswerMode = state?.answerMode === "desktop" ? "desktop" : "phone";
			const codeChars = (state?.code && state.code.length === 6 ? state.code : "------").split("");
			const primaryAddress = state?.base && state.base.length > 0 ? state.base : state?.lan && state.lan.length > 0 ? String(state.lan[0]) : "";
			return /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
				style: {
					display: "flex",
					flexDirection: "column",
					gap: 14,
					minWidth: 0
				},
				children: [
					/* @__PURE__ */ (0, react_jsx_runtime.jsx)(Card, { children: /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
						style: {
							display: "flex",
							alignItems: "center",
							justifyContent: "space-between",
							gap: 12,
							flexWrap: "wrap",
							minWidth: 0
						},
						children: [/* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
							style: {
								display: "flex",
								alignItems: "center",
								gap: 12,
								minWidth: 0
							},
							children: [/* @__PURE__ */ (0, react_jsx_runtime.jsxs)("svg", {
								viewBox: "0 0 64 64",
								width: "40",
								height: "40",
								fill: "none",
								"aria-hidden": "true",
								style: {
									flexShrink: 0,
									display: "block",
									borderRadius: 11
								},
								children: [
									/* @__PURE__ */ (0, react_jsx_runtime.jsx)("defs", { children: /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("radialGradient", {
										id: "amGatewayIconBg",
										cx: "50%",
										cy: "28%",
										r: "72%",
										children: [
											/* @__PURE__ */ (0, react_jsx_runtime.jsx)("stop", {
												offset: "0%",
												stopColor: "#2A2E39"
											}),
											/* @__PURE__ */ (0, react_jsx_runtime.jsx)("stop", {
												offset: "55%",
												stopColor: "#151821"
											}),
											/* @__PURE__ */ (0, react_jsx_runtime.jsx)("stop", {
												offset: "100%",
												stopColor: "#0B0C10"
											})
										]
									}) }),
									/* @__PURE__ */ (0, react_jsx_runtime.jsx)("rect", {
										x: "1",
										y: "1",
										width: "62",
										height: "62",
										rx: "16",
										fill: "url(#amGatewayIconBg)",
										stroke: "#FFFFFF",
										strokeOpacity: "0.16",
										strokeWidth: "1.4"
									}),
									/* @__PURE__ */ (0, react_jsx_runtime.jsx)("path", {
										d: "M12.5 22.5 L20.5 30 L12.5 37.5",
										stroke: "#FFFFFF",
										strokeWidth: "5.2",
										strokeLinecap: "round",
										strokeLinejoin: "round"
									}),
									/* @__PURE__ */ (0, react_jsx_runtime.jsx)("path", {
										d: "M26 40 H38",
										stroke: "#FFFFFF",
										strokeWidth: "5.2",
										strokeLinecap: "round"
									}),
									/* @__PURE__ */ (0, react_jsx_runtime.jsx)("path", {
										d: "M51.5 22.5 L43.5 30 L51.5 37.5",
										stroke: "#FFFFFF",
										strokeWidth: "5.2",
										strokeLinecap: "round",
										strokeLinejoin: "round"
									})
								]
							}), /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
								style: { minWidth: 0 },
								children: [/* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
									style: {
										display: "flex",
										alignItems: "center",
										gap: 8,
										flexWrap: "wrap"
									},
									children: [/* @__PURE__ */ (0, react_jsx_runtime.jsx)("span", {
										style: {
											fontSize: 15,
											fontWeight: 700,
											color: C$1.fg
										},
										children: "Agent Mobile"
									}), state?.e2ee ? /* @__PURE__ */ (0, react_jsx_runtime.jsx)(Chip, {
										text: "Noise_IK 加密",
										tone: "accent"
									}) : null]
								}), /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
									style: {
										fontSize: 12,
										color: C$1.fgFaint,
										marginTop: 2,
										overflowWrap: "anywhere",
										wordBreak: "break-word"
									},
									children: [
										"本机：",
										state?.host ?? "-",
										" · 端口 ",
										state ? String(state.port) : "-"
									]
								})]
							})]
						}), /* @__PURE__ */ (0, react_jsx_runtime.jsx)(Chip, {
							text: online ? "手机在线" : "等待配对",
							tone: online ? "ok" : "idle"
						})]
					}) }),
					error.length > 0 ? /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
						role: "alert",
						style: {
							display: "flex",
							alignItems: "flex-start",
							justifyContent: "space-between",
							gap: 10,
							border: `1px solid ${C$1.bad}`,
							background: C$1.badBg,
							color: C$1.bad,
							borderRadius: 12,
							padding: "10px 12px",
							fontSize: 12.5,
							lineHeight: 1.45,
							minWidth: 0,
							overflowWrap: "anywhere"
						},
						children: [/* @__PURE__ */ (0, react_jsx_runtime.jsxs)("span", {
							style: {
								minWidth: 0,
								overflowWrap: "anywhere"
							},
							children: ["操作提示：", error]
						}), /* @__PURE__ */ (0, react_jsx_runtime.jsx)("button", {
							type: "button",
							onClick: () => {
								setError("");
							},
							style: {
								border: "none",
								background: "transparent",
								color: C$1.bad,
								fontSize: 15,
								fontFamily: "inherit",
								padding: "0 4px",
								cursor: "pointer",
								flexShrink: 0
							},
							"aria-label": "关闭错误提示",
							children: "×"
						})]
					}) : null,
					/* @__PURE__ */ (0, react_jsx_runtime.jsxs)(Card, {
						hero: true,
						children: [/* @__PURE__ */ (0, react_jsx_runtime.jsx)(SectionHead, {
							title: "连接手机 App",
							subtitle: "打开 Agent Mobile 扫码，或填入电脑地址与下方 6 位一次性配对码",
							right: /* @__PURE__ */ (0, react_jsx_runtime.jsx)(Btn, {
								text: busy === "code" ? "更新中..." : "换一个新码",
								primary: true,
								disabled: busy === "code",
								onClick: () => {
									rotate();
								}
							})
						}), /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
							style: {
								display: "flex",
								gap: 18,
								alignItems: "center",
								flexWrap: "wrap",
								minWidth: 0
							},
							children: [/* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
								style: {
									width: 196,
									minHeight: 196,
									borderRadius: 14,
									border: `1px solid ${C$1.border}`,
									background: qrSrc.length > 0 && !qrFailed ? C$1.qrPlate : C$1.cardSoft,
									display: "flex",
									alignItems: "center",
									justifyContent: "center",
									padding: 10,
									boxSizing: "border-box",
									flexShrink: 0
								},
								children: qrSrc.length > 0 && !qrFailed ? /* @__PURE__ */ (0, react_jsx_runtime.jsx)("img", {
									alt: "Agent Mobile 配对二维码",
									src: qrSrc,
									width: 176,
									height: 176,
									onError: () => {
										setQrFailed(true);
									},
									style: {
										display: "block",
										width: 176,
										height: 176
									}
								}) : /* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
									style: {
										fontSize: 12,
										color: C$1.fgFaint,
										textAlign: "center",
										lineHeight: 1.5,
										padding: 8
									},
									children: qrSrc.length === 0 ? "请先在下方开启「局域网直连」或填写公网地址以生成二维码" : "二维码生成失败，请使用右侧 6 位数字配对码"
								})
							}), /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
								style: {
									flex: "1 1 220px",
									minWidth: 0,
									display: "flex",
									flexDirection: "column",
									gap: 10
								},
								children: [
									/* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
										style: {
											display: "flex",
											alignItems: "center",
											justifyContent: "space-between",
											gap: 8
										},
										children: [/* @__PURE__ */ (0, react_jsx_runtime.jsx)("span", {
											style: {
												fontSize: 12.5,
												fontWeight: 500,
												color: C$1.fgDim
											},
											children: "6 位一次性配对码"
										}), /* @__PURE__ */ (0, react_jsx_runtime.jsx)("span", {
											style: {
												fontSize: 12,
												fontWeight: 500,
												color: copied === "code" ? C$1.ok : secondsLeft > 60 ? C$1.fgFaint : C$1.bad
											},
											children: copied === "code" ? "已复制配对码" : `有效期 ${countdown(secondsLeft)}`
										})]
									}),
									/* @__PURE__ */ (0, react_jsx_runtime.jsx)("button", {
										type: "button",
										disabled: !state?.code,
										onClick: () => {
											if (state?.code) copy(state.code, "code");
										},
										title: "点击复制 6 位配对码",
										style: {
											border: `1px solid ${C$1.border}`,
											background: C$1.cardSoft,
											borderRadius: 12,
											padding: "10px 8px",
											display: "flex",
											alignItems: "center",
											justifyContent: "center",
											gap: 6,
											cursor: state?.code ? "pointer" : "default",
											opacity: state?.code ? 1 : .5
										},
										children: codeChars.map((ch, idx) => /* @__PURE__ */ (0, react_jsx_runtime.jsx)("span", {
											style: {
												width: 28,
												height: 36,
												borderRadius: 8,
												background: C$1.card,
												border: `1px solid ${C$1.border}`,
												display: "inline-flex",
												alignItems: "center",
												justifyContent: "center",
												fontFamily: C$1.mono,
												fontSize: 20,
												fontWeight: 700,
												color: C$1.fg
											},
											children: ch
										}, idx))
									}),
									primaryAddress.length > 0 ? /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
										style: {
											display: "flex",
											flexDirection: "column",
											gap: 4
										},
										children: [/* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
											style: {
												fontSize: 11.5,
												color: C$1.fgFaint
											},
											children: "当前配对入口（点击复制）"
										}), /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("button", {
											type: "button",
											onClick: () => {
												copy(primaryAddress, "addr");
											},
											style: {
												border: `1px solid ${C$1.border}`,
												background: C$1.cardSoft,
												color: C$1.fg,
												borderRadius: 9,
												padding: "6px 10px",
												fontSize: 12,
												fontFamily: C$1.mono,
												textAlign: "left",
												cursor: "pointer",
												overflowWrap: "anywhere",
												wordBreak: "break-word"
											},
											children: [copied === "addr" ? "已复制：" : "", primaryAddress]
										})]
									}) : null,
									/* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
										style: {
											fontSize: 11.5,
											color: C$1.fgFaint,
											lineHeight: 1.45
										},
										children: "配对成功或连续输错 8 次将自动更换新码；多台手机可分别扫码各自持独立密钥对。"
									})
								]
							})]
						})]
					}),
					/* @__PURE__ */ (0, react_jsx_runtime.jsxs)(Card, { children: [
						/* @__PURE__ */ (0, react_jsx_runtime.jsx)(SectionHead, {
							title: "网络与接入策略",
							subtitle: "控制同 Wi-Fi 直连与公网隧道回连入口"
						}),
						/* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
							style: {
								display: "flex",
								alignItems: "center",
								justifyContent: "space-between",
								gap: 12,
								padding: "6px 0",
								minWidth: 0
							},
							children: [/* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
								style: { minWidth: 0 },
								children: [/* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
									style: {
										fontSize: 13,
										fontWeight: 500,
										color: C$1.fg
									},
									children: "局域网直连"
								}), /* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
									style: {
										fontSize: 12,
										color: C$1.fgFaint,
										overflowWrap: "anywhere"
									},
									children: "同一 Wi-Fi 下手机低延迟直连本机，自动附带全部本机局域网候选地址"
								})]
							}), /* @__PURE__ */ (0, react_jsx_runtime.jsx)(Toggle, {
								on: state?.allowLan === true,
								disabled: busy === "lan",
								onChange: (next) => {
									patch("lan", { allowLan: next });
								}
							})]
						}),
						/* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
							style: {
								display: "flex",
								alignItems: "center",
								justifyContent: "space-between",
								gap: 12,
								padding: "6px 0",
								minWidth: 0
							},
							children: [/* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
								style: { minWidth: 0 },
								children: [/* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
									style: {
										fontSize: 13,
										fontWeight: 500,
										color: C$1.fg
									},
									children: "公网访问"
								}), /* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
									style: {
										fontSize: 12,
										color: C$1.fgFaint,
										overflowWrap: "anywhere"
									},
									children: "外出切换蜂窝网络时经你的反向代理或隧道地址访问（建议 HTTPS + 端到端加密）"
								})]
							}), /* @__PURE__ */ (0, react_jsx_runtime.jsx)(Toggle, {
								on: state?.allowRemote === true,
								disabled: busy === "remote",
								onChange: (next) => {
									patch("remote", { allowRemote: next });
								}
							})]
						}),
						state !== null && state.allowLan && state.lan.length > 0 ? /* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
							style: {
								marginTop: 8,
								display: "flex",
								flexWrap: "wrap",
								gap: 6
							},
							children: state.lan.slice(0, 4).map((addr) => /* @__PURE__ */ (0, react_jsx_runtime.jsx)("button", {
								type: "button",
								onClick: () => {
									copy(addr, `lan:${addr}`);
								},
								style: {
									border: `1px solid ${C$1.border}`,
									background: C$1.cardSoft,
									color: C$1.fgDim,
									borderRadius: 8,
									padding: "4px 9px",
									fontSize: 11.5,
									fontFamily: C$1.mono,
									cursor: "pointer"
								},
								children: copied === `lan:${addr}` ? "已复制" : addr
							}, addr))
						}) : null,
						state !== null && state.allowRemote ? /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
							style: {
								marginTop: 10,
								minWidth: 0
							},
							children: [/* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
								style: {
									display: "flex",
									alignItems: "center",
									justifyContent: "space-between",
									gap: 8,
									marginBottom: 4
								},
								children: [/* @__PURE__ */ (0, react_jsx_runtime.jsx)("span", {
									style: {
										fontSize: 12,
										color: C$1.fgFaint
									},
									children: "公网隧道地址（需含 https:// 或 http://）"
								}), urlDirty ? /* @__PURE__ */ (0, react_jsx_runtime.jsx)("span", {
									style: {
										fontSize: 11,
										color: C$1.accent
									},
									children: "有未保存修改"
								}) : null]
							}), /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
								style: {
									display: "flex",
									gap: 8,
									minWidth: 0
								},
								children: [/* @__PURE__ */ (0, react_jsx_runtime.jsx)("input", {
									value: draftUrl,
									placeholder: "https://agent.example.com",
									onChange: (event) => {
										urlDirtyRef.current = true;
										setUrlDirty(true);
										setDraftUrl(event.target.value);
									},
									onKeyDown: (event) => {
										if (event.key === "Enter" && !event.nativeEvent.isComposing) {
											event.preventDefault();
											savePublicUrl();
										}
									},
									style: {
										flex: 1,
										minWidth: 0,
										border: `1px solid ${C$1.border}`,
										borderRadius: 9,
										background: C$1.cardSoft,
										color: C$1.fg,
										padding: "6px 10px",
										fontSize: 13,
										fontFamily: "inherit"
									}
								}), /* @__PURE__ */ (0, react_jsx_runtime.jsx)(Btn, {
									text: busy === "url" ? "保存中" : "保存",
									primary: urlDirty,
									disabled: busy === "url",
									onClick: () => {
										savePublicUrl();
									}
								})]
							})]
						}) : null
					] }),
					/* @__PURE__ */ (0, react_jsx_runtime.jsxs)(Card, { children: [
						/* @__PURE__ */ (0, react_jsx_runtime.jsx)(SectionHead, {
							title: "已配对设备与密钥指纹",
							subtitle: "基于 Noise_IK_25519_ChaChaPoly_SHA256 验证对端身份",
							right: /* @__PURE__ */ (0, react_jsx_runtime.jsx)(Chip, {
								text: state?.e2ee ? "E2EE 已就绪" : "标准鉴权",
								tone: state?.e2ee ? "ok" : "idle"
							})
						}),
						state?.e2eePub ? /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
							style: {
								display: "flex",
								alignItems: "center",
								justifyContent: "space-between",
								gap: 10,
								padding: "7px 10px",
								borderRadius: 10,
								background: C$1.cardSoft,
								border: `1px solid ${C$1.border}`,
								marginBottom: 8
							},
							children: [/* @__PURE__ */ (0, react_jsx_runtime.jsx)("span", {
								style: {
									fontSize: 12,
									color: C$1.fgDim
								},
								children: "电脑公钥指纹"
							}), /* @__PURE__ */ (0, react_jsx_runtime.jsx)("span", {
								style: {
									fontSize: 12,
									fontFamily: C$1.mono,
									color: C$1.fg,
									fontWeight: 600
								},
								children: state.e2eePub.slice(0, 12)
							})]
						}) : null,
						Array.isArray(state?.devices) && state.devices.length > 0 ? /* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
							style: {
								display: "flex",
								flexDirection: "column",
								gap: 8
							},
							children: state.devices.map((dev) => {
								const revoked = dev.revoked === true;
								const itemBusy = busy === `dev:${dev.deviceId}`;
								return /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
									style: {
										border: `1px solid ${C$1.border}`,
										background: C$1.cardSoft,
										borderRadius: 10,
										padding: "8px 10px",
										display: "flex",
										alignItems: "center",
										justifyContent: "space-between",
										gap: 10,
										minWidth: 0
									},
									children: [/* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
										style: {
											minWidth: 0,
											flex: 1
										},
										children: [/* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
											style: {
												display: "flex",
												alignItems: "center",
												gap: 6,
												flexWrap: "wrap"
											},
											children: [/* @__PURE__ */ (0, react_jsx_runtime.jsx)("span", {
												style: {
													fontSize: 13,
													fontWeight: 600,
													color: C$1.fg,
													overflowWrap: "anywhere"
												},
												children: dev.name || "未命名设备"
											}), /* @__PURE__ */ (0, react_jsx_runtime.jsx)(Chip, {
												text: revoked ? "已撤销" : "已授权",
												tone: revoked ? "bad" : "ok"
											})]
										}), /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
											style: {
												fontSize: 11.5,
												color: C$1.fgFaint,
												marginTop: 3,
												fontFamily: C$1.mono,
												overflowWrap: "anywhere"
											},
											children: [
												"指纹：",
												dev.pubKey.slice(0, 12),
												" · 最近活跃：",
												formatLastSeen(dev.lastSeenAt)
											]
										})]
									}), /* @__PURE__ */ (0, react_jsx_runtime.jsx)(Btn, {
										text: itemBusy ? "处理中" : revoked ? "恢复" : "撤销",
										disabled: itemBusy,
										onClick: () => {
											toggleDeviceRevoke(dev.deviceId, !revoked);
										}
									})]
								}, dev.deviceId);
							})
						}) : /* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
							style: {
								fontSize: 12,
								color: C$1.fgFaint,
								lineHeight: 1.5
							},
							children: "暂无已配对手机。完成首次扫码与加密握手后，设备名称与公钥指纹会自动登记于此。"
						})
					] }),
					/* @__PURE__ */ (0, react_jsx_runtime.jsxs)(Card, { children: [
						/* @__PURE__ */ (0, react_jsx_runtime.jsx)(SectionHead, {
							title: "协作与远程控制边界",
							subtitle: "统一调度提问答题归属、远程终端和本地预览代理"
						}),
						/* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
							style: {
								display: "flex",
								alignItems: "center",
								justifyContent: "space-between",
								gap: 12,
								padding: "6px 0",
								flexWrap: "wrap"
							},
							children: [/* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
								style: {
									minWidth: 0,
									flex: "1 1 200px"
								},
								children: [/* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
									style: {
										fontSize: 13,
										fontWeight: 500,
										color: C$1.fg
									},
									children: "谁来回答提问"
								}), /* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
									style: {
										fontSize: 12,
										color: C$1.fgFaint,
										overflowWrap: "anywhere"
									},
									children: "切回「电脑为主」时，等待手机审批的问题卡将立即交还桌面端"
								})]
							}), /* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
								style: {
									display: "inline-flex",
									border: `1px solid ${C$1.border}`,
									background: C$1.cardSoft,
									borderRadius: 999,
									padding: 2,
									gap: 2,
									flexShrink: 0
								},
								children: [{
									id: "phone",
									label: "手机为主"
								}, {
									id: "desktop",
									label: "电脑为主"
								}].map((opt) => {
									const active = currentAnswerMode === opt.id;
									const disabled = busy === "answerMode";
									return /* @__PURE__ */ (0, react_jsx_runtime.jsx)("button", {
										type: "button",
										disabled,
										onClick: () => {
											if (active) return;
											patch("answerMode", { answerMode: opt.id });
										},
										style: {
											border: "none",
											borderRadius: 999,
											padding: "4px 12px",
											fontSize: 12,
											fontFamily: "inherit",
											background: active ? C$1.accent : "transparent",
											color: active ? C$1.onAccent : C$1.fgDim,
											cursor: disabled ? "default" : "pointer",
											opacity: disabled ? .5 : 1,
											whiteSpace: "nowrap"
										},
										children: opt.label
									}, opt.id);
								})
							})]
						}),
						/* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
							style: {
								display: "flex",
								alignItems: "center",
								justifyContent: "space-between",
								gap: 12,
								padding: "6px 0"
							},
							children: [/* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
								style: { minWidth: 0 },
								children: [/* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
									style: {
										fontSize: 13,
										fontWeight: 500,
										color: C$1.fg
									},
									children: "允许远程终端"
								}), /* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
									style: {
										fontSize: 12,
										color: C$1.fgFaint,
										overflowWrap: "anywhere"
									},
									children: "允许已授权手机在会话工作目录打开交互终端"
								})]
							}), /* @__PURE__ */ (0, react_jsx_runtime.jsx)(Toggle, {
								on: state?.allowTerminal !== false,
								disabled: busy === "allowTerminal",
								onChange: (next) => {
									patch("allowTerminal", { allowTerminal: next });
								}
							})]
						}),
						/* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
							style: { marginTop: 8 },
							children: [
								/* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
									style: {
										display: "flex",
										alignItems: "center",
										justifyContent: "space-between",
										gap: 8,
										marginBottom: 4
									},
									children: [/* @__PURE__ */ (0, react_jsx_runtime.jsx)("span", {
										style: {
											fontSize: 13,
											fontWeight: 500,
											color: C$1.fg
										},
										children: "允许预览的本机开发端口"
									}), portsDirty ? /* @__PURE__ */ (0, react_jsx_runtime.jsx)("span", {
										style: {
											fontSize: 11,
											color: C$1.accent
										},
										children: "有未保存修改"
									}) : null]
								}),
								/* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
									style: {
										fontSize: 12,
										color: C$1.fgFaint,
										marginBottom: 6
									},
									children: "逗号分隔填写 1..65535 端口；留空则关闭本机开发服预览代理"
								}),
								/* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
									style: {
										display: "flex",
										gap: 8
									},
									children: [/* @__PURE__ */ (0, react_jsx_runtime.jsx)("input", {
										value: draftPorts,
										placeholder: "例如 3000, 5173",
										onChange: (event) => {
											portsDirtyRef.current = true;
											setPortsDirty(true);
											setDraftPorts(event.target.value);
										},
										onKeyDown: (event) => {
											if (event.key === "Enter" && !event.nativeEvent.isComposing) {
												event.preventDefault();
												savePreviewPorts();
											}
										},
										style: {
											flex: 1,
											minWidth: 0,
											border: `1px solid ${C$1.border}`,
											borderRadius: 9,
											background: C$1.cardSoft,
											color: C$1.fg,
											padding: "6px 10px",
											fontSize: 13,
											fontFamily: "inherit"
										}
									}), /* @__PURE__ */ (0, react_jsx_runtime.jsx)(Btn, {
										text: busy === "ports" ? "保存中" : "保存",
										primary: portsDirty,
										disabled: busy === "ports",
										onClick: () => {
											savePreviewPorts();
										}
									})]
								})
							]
						})
					] }),
					state !== null ? /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
						style: {
							display: "flex",
							flexWrap: "wrap",
							gap: 8
						},
						children: [
							/* @__PURE__ */ (0, react_jsx_runtime.jsx)(MetaPill, {
								label: "网关版本",
								value: `v${state.version}`
							}),
							/* @__PURE__ */ (0, react_jsx_runtime.jsx)(MetaPill, {
								label: "监听端口",
								value: String(state.port)
							}),
							state.hostId ? /* @__PURE__ */ (0, react_jsx_runtime.jsx)(MetaPill, {
								label: "主机标识",
								value: state.hostId
							}) : null
						]
					}) : null
				]
			});
		}
		//#endregion
		//#region src/client/FeedbackSection.tsx
		/**
		* DSH 设置对话框中的「用户反馈」管理面板（仅本机持有管理员密钥时注册显示）。
		* @module @deepseek-ai/dsh-mobile/client/FeedbackSection
		*/
		const C = {
			card: "var(--dsw-alias-surface-card, var(--dsw-alias-bg-layer-3, rgba(127,127,127,0.08)))",
			cardSoft: "var(--dsw-alias-bg-layer-2, var(--dsw-alias-bg-layer-1, rgba(127,127,127,0.06)))",
			border: "var(--dsw-alias-border-l2, rgba(127,127,127,0.24))",
			fg: "var(--dsw-alias-label-primary, currentColor)",
			fgDim: "var(--dsw-alias-label-secondary, rgba(127,127,127,0.85))",
			fgFaint: "var(--dsw-alias-label-tertiary, rgba(127,127,127,0.68))",
			accent: "var(--dsw-alias-state-business-primary, #1a6ef0)",
			onAccent: "var(--dsw-alias-label-on-color, #f8fafc)",
			ok: "var(--dsw-alias-state-success-primary, #1a9a5e)",
			bad: "var(--dsw-alias-state-error-primary, #d4380d)",
			badBg: "rgba(212,56,13,0.10)"
		};
		const ROUTE = "/api/dsh-mobile/panel/feedback";
		const STATUS = {
			open: {
				label: "待处理",
				color: C.accent
			},
			doing: {
				label: "处理中",
				color: C.accent
			},
			done: {
				label: "已完成",
				color: C.ok
			},
			wontfix: {
				label: "不处理",
				color: C.fgFaint
			}
		};
		const KIND = {
			bug: "问题反馈",
			feature: "功能建议",
			ux: "体验问题",
			other: "其他"
		};
		const stamp = (ms) => {
			const d = new Date(ms);
			const two = (n) => n < 10 ? `0${String(n)}` : String(n);
			return `${String(d.getMonth() + 1)}-${two(d.getDate())} ${two(d.getHours())}:${two(d.getMinutes())}`;
		};
		const formatIso = (ms) => {
			if (!Number.isFinite(ms) || ms <= 0) return "未知";
			try {
				return `${stamp(ms)} (${new Date(ms).toISOString()})`;
			} catch {
				return stamp(ms);
			}
		};
		const formatSize = (n) => n >= 1024 * 1024 ? `${(n / 1024 / 1024).toFixed(1)} MB` : `${String(Math.max(1, Math.round(n / 1024)))} KB`;
		const isInlineTextFile = (f) => f.size <= 65536 && (f.kind === "log" || /\.(?:txt|log|json|md|csv|yml|yaml)$/i.test(f.name));
		async function writeClipboard(text) {
			if (typeof navigator !== "undefined" && navigator.clipboard !== void 0) try {
				await navigator.clipboard.writeText(text);
				return true;
			} catch {}
			if (typeof document === "undefined") return false;
			const ta = document.createElement("textarea");
			ta.value = text;
			ta.setAttribute("readonly", "true");
			ta.style.position = "fixed";
			ta.style.left = "-9999px";
			ta.style.opacity = "0";
			document.body.appendChild(ta);
			ta.select();
			let copied = false;
			try {
				copied = document.execCommand("copy");
			} catch {
				copied = false;
			}
			document.body.removeChild(ta);
			return copied;
		}
		async function fetchInlineTextAttachment(ticketId, fileName) {
			try {
				const res = await fetch(`${ROUTE}/file?id=${encodeURIComponent(ticketId)}&name=${encodeURIComponent(fileName)}`, {
					credentials: "same-origin",
					cache: "no-store"
				});
				if (!res.ok) return `[读取失败 HTTP ${String(res.status)}]`;
				const text = await res.text();
				if (text.length > 16e3) return `${text.slice(0, 16e3)}\n... [已截断，总长度 ${String(text.length)} 字符]`;
				return text;
			} catch (e) {
				return `[读取失败: ${e instanceof Error ? e.message : String(e)}]`;
			}
		}
		async function buildAiTriageText(t) {
			const origin = typeof window !== "undefined" ? window.location.origin : "";
			const kindLabel = KIND[t.kind] ?? t.kind;
			const statusLabel = STATUS[t.status]?.label ?? t.status;
			const lines = [
				`# Agent Mobile 用户反馈工单 (${t.id})`,
				"",
				"## 工单元数据",
				`- 工单编号: ${t.id}`,
				`- 反馈分类: ${kindLabel} (${t.kind})`,
				`- 当前状态: ${statusLabel} (${t.status})`,
				`- 提交时间: ${formatIso(t.created_at)}`,
				`- 最后更新: ${formatIso(t.updated_at)}`,
				`- 运行环境: ${t.env !== "" ? t.env : "（未采集）"}`,
				`- 联系方式: ${t.contact !== "" ? t.contact : "（未填写）"}`,
				"",
				"## 问题标题",
				t.title,
				"",
				"## 详细描述",
				t.body !== "" ? t.body : "（无正文）",
				"",
				"## 附件清单与内容"
			];
			if (t.files.length === 0) lines.push("无附件");
			else for (const f of t.files) {
				const fileUrl = `${origin}${ROUTE}/file?id=${encodeURIComponent(t.id)}&name=${encodeURIComponent(f.name)}`;
				lines.push(`- ${f.name} [类型: ${f.kind} | 大小: ${formatSize(f.size)}] -> ${fileUrl}`);
				if (isInlineTextFile(f)) {
					const inlineContent = await fetchInlineTextAttachment(t.id, f.name);
					lines.push("```text");
					lines.push(inlineContent);
					lines.push("```");
				}
			}
			lines.push("");
			lines.push("## 处理与回复记录");
			if (t.replies.length === 0) lines.push("暂无历史回复");
			else for (const r of t.replies) {
				const role = r.author === "admin" ? "开发者" : "用户";
				lines.push(`- [${stamp(r.at)}] ${role}: ${r.text}`);
			}
			lines.push("");
			lines.push("## 工程上下文与排查要求");
			lines.push("- 项目仓库: Agent Mobile（app-shell/ 鸿蒙客户端 + gateway/ DSH 桌面端网关插件）");
			lines.push("- 请结合上述工单描述、运行环境、日志/附件与历史回复定位根因，列出涉及的文件路径与修改方案。");
			lines.push("- 如需补充给用户的中文回复或状态变更建议，请一并给出。");
			return lines.join("\n");
		}
		async function readErrorMessage(res) {
			const text = await res.text();
			if (text.length > 0) {
				try {
					const parsed = JSON.parse(text);
					if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) {
						const err = parsed.error;
						if (typeof err === "string" && err.trim().length > 0) return err.trim();
					}
				} catch {}
				return text.slice(0, 200);
			}
			return `HTTP ${String(res.status)}`;
		}
		async function post(path, body) {
			const res = await fetch(`${ROUTE}/${path}`, {
				method: "POST",
				credentials: "same-origin",
				cache: "no-store",
				headers: { "content-type": "application/json; charset=utf-8" },
				body: JSON.stringify(body)
			});
			if (!res.ok) throw new Error(await readErrorMessage(res));
		}
		function btn(primary, disabled) {
			return {
				fontSize: 12,
				fontFamily: "inherit",
				lineHeight: 1.45,
				padding: "5px 12px",
				borderRadius: 8,
				border: `1px solid ${primary ? C.accent : C.border}`,
				background: primary ? C.accent : "transparent",
				color: primary ? C.onAccent : C.fgDim,
				cursor: disabled ? "default" : "pointer",
				opacity: disabled ? .5 : 1,
				flexShrink: 0,
				whiteSpace: "nowrap"
			};
		}
		function FeedbackSection() {
			const [state, setState] = (0, react.useState)(null);
			const [seen, setSeen] = (0, react.useState)(false);
			const [loading, setLoading] = (0, react.useState)(false);
			const [busy, setBusy] = (0, react.useState)("");
			const [error, setError] = (0, react.useState)("");
			const [reply, setReply] = (0, react.useState)({});
			const [open, setOpen] = (0, react.useState)("");
			const [copyingId, setCopyingId] = (0, react.useState)("");
			const [copiedId, setCopiedId] = (0, react.useState)("");
			const copyTimerRef = (0, react.useRef)(null);
			const load = (0, react.useCallback)(async () => {
				setLoading(true);
				try {
					const res = await fetch(`${ROUTE}/state`, {
						credentials: "same-origin",
						cache: "no-store"
					});
					if (!res.ok) {
						const msg = await readErrorMessage(res);
						setError(msg);
						setState((prev) => prev ?? {
							configured: true,
							tickets: []
						});
						return;
					}
					const data = await res.json();
					setState(data);
					setError(data.error ?? "");
				} catch (e) {
					setError(e instanceof Error ? e.message : String(e));
				} finally {
					setLoading(false);
					setSeen(true);
				}
			}, []);
			(0, react.useEffect)(() => {
				load();
				const timer = setInterval(() => {
					if (typeof document !== "undefined" && document.visibilityState === "hidden") return;
					load();
				}, 3e4);
				return () => {
					clearInterval(timer);
					if (copyTimerRef.current !== null) clearTimeout(copyTimerRef.current);
				};
			}, [load]);
			if (!seen || state === null || state.configured !== true) return null;
			const handleCopyForAi = async (t) => {
				if (copyingId === t.id) return;
				setCopyingId(t.id);
				setError("");
				try {
					if (!await writeClipboard(await buildAiTriageText(t))) {
						setError("复制到剪贴板失败，请检查浏览器或系统剪贴板权限。");
						return;
					}
					setCopiedId(t.id);
					if (copyTimerRef.current !== null) clearTimeout(copyTimerRef.current);
					copyTimerRef.current = setTimeout(() => {
						setCopiedId("");
						copyTimerRef.current = null;
					}, 2e3);
				} catch (e) {
					setError(e instanceof Error ? e.message : String(e));
				} finally {
					setCopyingId("");
				}
			};
			const act = async (id, work) => {
				setBusy(id);
				setError("");
				try {
					await work();
					await load();
				} catch (e) {
					setError(e instanceof Error ? e.message : String(e));
				} finally {
					setBusy("");
				}
			};
			const tickets = state.tickets ?? [];
			const counts = state.summary?.counts ?? [];
			return /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
				style: {
					display: "flex",
					flexDirection: "column",
					gap: 12,
					minWidth: 0
				},
				children: [
					/* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
						style: {
							display: "flex",
							alignItems: "center",
							gap: 10,
							flexWrap: "wrap",
							minWidth: 0
						},
						children: [
							/* @__PURE__ */ (0, react_jsx_runtime.jsxs)("span", {
								style: {
									fontSize: 13,
									color: C.fgDim,
									flexShrink: 0,
									whiteSpace: "nowrap"
								},
								children: [
									"共 ",
									String(tickets.length),
									" 条"
								]
							}),
							counts.map((one) => /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("span", {
								style: {
									fontSize: 12,
									color: STATUS[one.status]?.color ?? C.fgFaint,
									flexShrink: 0,
									whiteSpace: "nowrap"
								},
								children: [
									STATUS[one.status]?.label ?? one.status,
									" ",
									String(one.n)
								]
							}, one.status)),
							/* @__PURE__ */ (0, react_jsx_runtime.jsx)("span", { style: { flex: 1 } }),
							/* @__PURE__ */ (0, react_jsx_runtime.jsx)("button", {
								type: "button",
								disabled: loading,
								onClick: () => {
									load();
								},
								style: {
									fontSize: 12,
									fontFamily: "inherit",
									lineHeight: 1.45,
									padding: "4px 10px",
									borderRadius: 8,
									border: `1px solid ${C.border}`,
									background: "transparent",
									color: C.fgDim,
									cursor: loading ? "default" : "pointer",
									opacity: loading ? .5 : 1,
									flexShrink: 0,
									whiteSpace: "nowrap"
								},
								children: "刷新"
							})
						]
					}),
					error.length > 0 ? /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
						role: "alert",
						style: {
							border: `1px solid ${C.bad}`,
							background: C.badBg,
							color: C.bad,
							borderRadius: 10,
							padding: "9px 12px",
							fontSize: 12.5,
							lineHeight: 1.45,
							minWidth: 0,
							overflowWrap: "anywhere",
							wordBreak: "break-word"
						},
						children: ["出错了：", error]
					}) : null,
					tickets.length === 0 ? /* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
						style: {
							fontSize: 12,
							color: C.fgFaint
						},
						children: "还没有人反馈。"
					}) : null,
					tickets.map((t) => {
						const st = STATUS[t.status] ?? {
							label: t.status,
							color: C.fgFaint
						};
						const expanded = open === t.id;
						const replyText = (reply[t.id] ?? "").trim();
						const replyDisabled = busy === t.id || replyText === "";
						const isCopying = copyingId === t.id;
						const isCopied = copiedId === t.id;
						const copyLabel = isCopying ? "整理中..." : isCopied ? "已复制给 AI" : "复制给 AI";
						return /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
							style: {
								border: `1px solid ${C.border}`,
								background: C.card,
								borderRadius: 12,
								padding: "12px 14px",
								display: "flex",
								flexDirection: "column",
								gap: 8,
								minWidth: 0
							},
							children: [/* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
								role: "button",
								tabIndex: 0,
								onClick: () => {
									setOpen(expanded ? "" : t.id);
								},
								onKeyDown: (e) => {
									if (e.key === "Enter" || e.key === " ") {
										e.preventDefault();
										setOpen(expanded ? "" : t.id);
									}
								},
								style: {
									display: "flex",
									flexDirection: "column",
									gap: 6,
									cursor: "pointer",
									minWidth: 0
								},
								children: [/* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
									style: {
										display: "flex",
										alignItems: "center",
										gap: 8,
										flexWrap: "wrap",
										minWidth: 0
									},
									children: [
										/* @__PURE__ */ (0, react_jsx_runtime.jsx)("span", {
											style: {
												fontSize: 12,
												color: C.fgDim,
												flexShrink: 0,
												whiteSpace: "nowrap"
											},
											children: expanded ? "▾" : "▸"
										}),
										/* @__PURE__ */ (0, react_jsx_runtime.jsx)("span", {
											style: {
												fontSize: 11,
												color: C.fgFaint,
												flexShrink: 0,
												whiteSpace: "nowrap"
											},
											children: t.id
										}),
										/* @__PURE__ */ (0, react_jsx_runtime.jsx)("span", {
											style: {
												fontSize: 11,
												color: C.fgDim,
												flexShrink: 0,
												whiteSpace: "nowrap"
											},
											children: KIND[t.kind] ?? t.kind
										}),
										/* @__PURE__ */ (0, react_jsx_runtime.jsx)("span", {
											style: {
												fontSize: 11,
												color: C.fgFaint,
												flexShrink: 0,
												whiteSpace: "nowrap"
											},
											children: stamp(t.created_at)
										}),
										/* @__PURE__ */ (0, react_jsx_runtime.jsx)("span", { style: { flex: 1 } }),
										/* @__PURE__ */ (0, react_jsx_runtime.jsx)("button", {
											type: "button",
											disabled: isCopying,
											onClick: (e) => {
												e.stopPropagation();
												handleCopyForAi(t);
											},
											style: {
												fontSize: 11,
												fontFamily: "inherit",
												lineHeight: 1.4,
												padding: "2px 9px",
												borderRadius: 999,
												border: `1px solid ${isCopied ? C.ok : C.border}`,
												background: isCopied ? "rgba(26,154,94,0.12)" : C.cardSoft,
												color: isCopied ? C.ok : C.accent,
												cursor: isCopying ? "default" : "pointer",
												opacity: isCopying ? .6 : 1,
												flexShrink: 0,
												whiteSpace: "nowrap"
											},
											children: copyLabel
										}),
										/* @__PURE__ */ (0, react_jsx_runtime.jsx)("span", {
											style: {
												fontSize: 11,
												color: st.color,
												background: "rgba(127,127,127,0.10)",
												borderRadius: 999,
												padding: "1px 8px",
												flexShrink: 0,
												whiteSpace: "nowrap"
											},
											children: st.label
										})
									]
								}), /* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
									style: {
										fontSize: 13,
										color: C.fg,
										fontWeight: 500,
										minWidth: 0,
										overflowWrap: "anywhere",
										wordBreak: "break-word"
									},
									children: t.title
								})]
							}), expanded ? /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
								style: {
									display: "flex",
									flexDirection: "column",
									gap: 8,
									minWidth: 0
								},
								children: [
									/* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
										style: {
											fontSize: 12.5,
											color: C.fg,
											whiteSpace: "pre-wrap",
											lineHeight: 1.65,
											minWidth: 0,
											overflowWrap: "anywhere",
											wordBreak: "break-word"
										},
										children: t.body
									}),
									/* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
										style: {
											fontSize: 11,
											color: C.fgFaint,
											minWidth: 0,
											overflowWrap: "anywhere",
											wordBreak: "break-word"
										},
										children: ["运行环境：", t.env === "" ? "（未采集）" : t.env]
									}),
									t.contact !== "" ? /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
										style: {
											fontSize: 11,
											color: C.fgFaint,
											minWidth: 0,
											overflowWrap: "anywhere",
											wordBreak: "break-word"
										},
										children: ["联系方式：", t.contact]
									}) : null,
									t.files.length > 0 ? /* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
										style: {
											display: "flex",
											flexWrap: "wrap",
											gap: 6,
											minWidth: 0
										},
										children: t.files.map((f) => /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("a", {
											href: `${ROUTE}/file?id=${encodeURIComponent(t.id)}&name=${encodeURIComponent(f.name)}`,
											style: {
												fontSize: 11,
												color: C.accent,
												border: `1px solid ${C.border}`,
												background: C.cardSoft,
												borderRadius: 8,
												padding: "2px 8px",
												textDecoration: "none",
												maxWidth: "100%",
												minWidth: 0,
												overflowWrap: "anywhere",
												wordBreak: "break-word"
											},
											children: [
												f.name,
												" · ",
												formatSize(f.size)
											]
										}, f.name))
									}) : null,
									t.replies.length > 0 ? /* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
										style: {
											display: "flex",
											flexDirection: "column",
											gap: 6,
											minWidth: 0
										},
										children: t.replies.map((r, i) => /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
											style: {
												fontSize: 12,
												color: C.fgDim,
												minWidth: 0,
												overflowWrap: "anywhere",
												wordBreak: "break-word"
											},
											children: [/* @__PURE__ */ (0, react_jsx_runtime.jsxs)("span", {
												style: { color: r.author === "admin" ? C.accent : C.fgFaint },
												children: [
													r.author === "admin" ? "我" : "用户",
													" · ",
													stamp(r.at),
													"："
												]
											}), r.text]
										}, `${t.id}-${String(i)}`))
									}) : null,
									/* @__PURE__ */ (0, react_jsx_runtime.jsx)("textarea", {
										value: reply[t.id] ?? "",
										onChange: (e) => {
											setReply({
												...reply,
												[t.id]: e.target.value
											});
										},
										placeholder: "回复内容（留空时仅可切换右侧状态）",
										rows: 2,
										style: {
											width: "100%",
											minWidth: 0,
											boxSizing: "border-box",
											fontSize: 12.5,
											fontFamily: "inherit",
											lineHeight: 1.45,
											padding: "8px 10px",
											borderRadius: 9,
											border: `1px solid ${C.border}`,
											background: C.cardSoft,
											color: C.fg,
											resize: "vertical"
										}
									}),
									/* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
										style: {
											display: "flex",
											gap: 8,
											flexWrap: "wrap"
										},
										children: [
											/* @__PURE__ */ (0, react_jsx_runtime.jsx)("button", {
												type: "button",
												disabled: isCopying,
												onClick: () => {
													handleCopyForAi(t);
												},
												style: {
													...btn(false, isCopying),
													borderColor: isCopied ? C.ok : C.border,
													color: isCopied ? C.ok : C.accent
												},
												children: copyLabel
											}),
											/* @__PURE__ */ (0, react_jsx_runtime.jsx)("button", {
												type: "button",
												disabled: replyDisabled,
												onClick: () => {
													if (replyDisabled) return;
													act(t.id, async () => {
														await post("reply", {
															id: t.id,
															text: replyText
														});
														setReply({
															...reply,
															[t.id]: ""
														});
													});
												},
												style: btn(true, replyDisabled),
												children: "回复"
											}),
											[
												"doing",
												"done",
												"wontfix",
												"open"
											].map((next) => {
												const stDisabled = busy === t.id || t.status === next;
												return /* @__PURE__ */ (0, react_jsx_runtime.jsx)("button", {
													type: "button",
													disabled: stDisabled,
													onClick: () => {
														if (stDisabled) return;
														act(t.id, async () => {
															await post("status", {
																id: t.id,
																status: next
															});
														});
													},
													style: btn(false, stDisabled),
													children: STATUS[next]?.label ?? next
												}, next);
											})
										]
									})
								]
							}) : null]
						}, t.id);
					})
				]
			});
		}
		//#endregion
		//#region src/client/index.ts
		/**
		* Agent Mobile 浏览器侧入口：注册设置面板「Agent Mobile」配对与权限控制页。
		* @module agent-mobile-gateway/client
		*/
		const inject = ["slots"];
		const FEEDBACK_STATE = "/api/dsh-mobile/panel/feedback/state";
		function apply(ctx) {
			ctx.slots.inject("settings.section", () => ctx.slots.register({
				name: "settings.section",
				id: "dsh-mobile",
				order: 36,
				label: () => "Agent Mobile"
			}, MobileSection));
			const registerFeedback = () => {
				ctx.slots.inject("settings.section", () => ctx.slots.register({
					name: "settings.section",
					id: "dsh-mobile-feedback",
					order: 37,
					label: () => "用户反馈"
				}, FeedbackSection));
			};
			fetch(FEEDBACK_STATE, {
				credentials: "same-origin",
				cache: "no-store"
			}).then(async (res) => {
				if (!res.ok) return null;
				return await res.json();
			}).then((state) => {
				if (state?.configured === true) registerFeedback();
			}).catch(() => void 0);
		}
		//#endregion
		exports.apply = apply;
		exports.inject = inject;
		return module.exports;
	}
});

//# sourceMappingURL=client.js.map