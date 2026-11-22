window.__ModuleLoader__.load({
	id: "@deepseek-ai/dsh-mobile",
	factory: (require) => {
		var module = { exports: {} };
		var exports = module.exports;
		Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });
		let react = require("react");
		let react_jsx_runtime = require("react/jsx-runtime");
		//#region src/client/MobileSection.tsx
		/**
		* The "手机连接" section of the DSH settings dialog.
		*
		* It is a thin view over the host half's pairing routes: show the live six
		* digit code, the QR a phone scans, which paths are offered, and whether a
		* phone has checked in recently. Nothing here is authoritative — every write
		* goes back to the host and the answer replaces the local copy.
		* @module @deepseek-ai/dsh-mobile/client/MobileSection
		*/
		/** The design tokens the DSH shell publishes, with light-theme fallbacks. */
		const C = {
			card: "var(--dsw-alias-bg-layer-3, #ffffff)",
			cardSoft: "var(--dsw-alias-bg-layer-1, #ffffff)",
			border: "var(--dsw-alias-border-l2, rgba(127,127,127,.24))",
			fg: "var(--dsw-alias-label-primary, #1b1d21)",
			fgDim: "var(--dsw-alias-label-secondary, #5c6270)",
			fgFaint: "var(--dsw-alias-label-tertiary, #8a90a0)",
			accent: "var(--dsw-alias-state-business-primary, #1a6ef0)",
			ok: "var(--dsw-alias-state-success-primary, #1a9a5e)",
			bad: "var(--dsw-alias-state-error-primary, #d4380d)"
		};
		const ROUTE = "api/dsh-mobile/panel";
		/** Read one JSON answer, turning a non-2xx into a readable error. */
		async function getJson(path) {
			const res = await fetch(path, {
				credentials: "same-origin",
				cache: "no-store"
			});
			if (!res.ok) throw new Error(`HTTP ${String(res.status)}`);
			return await res.json();
		}
		/** Post a JSON patch and read the resulting state back. */
		async function postJson(path, body) {
			const res = await fetch(path, {
				method: "POST",
				credentials: "same-origin",
				cache: "no-store",
				headers: { "content-type": "application/json" },
				body: JSON.stringify(body)
			});
			if (!res.ok) throw new Error(`HTTP ${String(res.status)}`);
			return await res.json();
		}
		/** One bordered card. */
		function Card(props) {
			return /* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
				style: {
					border: `1px solid ${C.border}`,
					background: C.card,
					borderRadius: 12,
					padding: "14px 16px"
				},
				children: props.children
			});
		}
		/** A card title row with an optional trailing chip. */
		function Title(props) {
			return /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
				style: {
					display: "flex",
					alignItems: "center",
					gap: 8,
					marginBottom: 6
				},
				children: [/* @__PURE__ */ (0, react_jsx_runtime.jsx)("span", {
					style: {
						fontSize: 14,
						fontWeight: 600,
						color: C.fg
					},
					children: props.text
				}), props.chip]
			});
		}
		/** A small status chip. */
		function Chip(props) {
			const color = props.tone === "ok" ? C.ok : props.tone === "bad" ? C.bad : C.fgFaint;
			return /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("span", {
				style: {
					display: "inline-flex",
					alignItems: "center",
					gap: 5,
					fontSize: 12,
					color,
					background: "rgba(127,127,127,.10)",
					borderRadius: 999,
					padding: "2px 9px"
				},
				children: [/* @__PURE__ */ (0, react_jsx_runtime.jsx)("span", { style: {
					width: 6,
					height: 6,
					borderRadius: 3,
					background: color
				} }), props.text]
			});
		}
		/** A labelled row. */
		function Row(props) {
			return /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
				style: {
					display: "flex",
					alignItems: "center",
					justifyContent: "space-between",
					gap: 12,
					padding: "6px 0"
				},
				children: [/* @__PURE__ */ (0, react_jsx_runtime.jsx)("span", {
					style: {
						fontSize: 13,
						color: C.fgDim
					},
					children: props.label
				}), /* @__PURE__ */ (0, react_jsx_runtime.jsx)("span", {
					style: {
						fontSize: 13,
						color: C.fg,
						textAlign: "right"
					},
					children: props.value
				})]
			});
		}
		/** A pill toggle. */
		function Toggle(props) {
			const width = 40;
			const height = 22;
			return /* @__PURE__ */ (0, react_jsx_runtime.jsx)("button", {
				type: "button",
				role: "switch",
				"aria-checked": props.on,
				disabled: props.disabled === true,
				onClick: () => {
					if (props.disabled !== true) props.onChange(!props.on);
				},
				style: {
					width,
					height,
					borderRadius: height / 2,
					border: "none",
					padding: 0,
					cursor: props.disabled === true ? "default" : "pointer",
					background: props.on ? C.accent : "rgba(127,127,127,.32)",
					position: "relative",
					transition: "background .18s ease",
					flex: "0 0 auto"
				},
				children: /* @__PURE__ */ (0, react_jsx_runtime.jsx)("span", { style: {
					position: "absolute",
					top: 2,
					left: props.on ? 20 : 2,
					width: height - 4,
					height: height - 4,
					borderRadius: "50%",
					background: "#ffffff",
					boxShadow: "0 1px 2px rgba(0,0,0,.25)",
					transition: "left .18s cubic-bezier(.34,1.4,.64,1)"
				} })
			});
		}
		/** A compact button. */
		function Btn(props) {
			const primary = props.primary === true;
			return /* @__PURE__ */ (0, react_jsx_runtime.jsx)("button", {
				type: "button",
				disabled: props.disabled === true,
				onClick: props.onClick,
				style: {
					border: primary ? "none" : `1px solid ${C.border}`,
					background: primary ? C.accent : "transparent",
					color: primary ? "#ffffff" : C.fg,
					borderRadius: 8,
					padding: "6px 12px",
					fontSize: 13,
					cursor: props.disabled === true ? "default" : "pointer",
					opacity: props.disabled === true ? .55 : 1,
					flex: "0 0 auto"
				},
				children: props.text
			});
		}
		/** Format the seconds a code still lives as `mm:ss`. */
		function countdown(secondsLeft) {
			const safe = Math.max(0, secondsLeft);
			const mm = Math.floor(safe / 60);
			const ss = safe % 60;
			return `${String(mm).padStart(2, "0")}:${String(ss).padStart(2, "0")}`;
		}
		/**
		* Render the pairing section.
		* @returns the section element.
		*/
		function MobileSection() {
			const [state, setState] = (0, react.useState)(null);
			const [error, setError] = (0, react.useState)("");
			const [busy, setBusy] = (0, react.useState)("");
			const [draftUrl, setDraftUrl] = (0, react.useState)("");
			const [copied, setCopied] = (0, react.useState)("");
			const [now, setNow] = (0, react.useState)(Date.now());
			/** Pull the live state; a failure keeps the last good copy on screen. */
			const load = (0, react.useCallback)(async () => {
				try {
					const next = await getJson(`${ROUTE}/state`);
					setState(next);
					setError("");
					setDraftUrl((current) => current.length > 0 ? current : next.publicUrl);
				} catch (reason) {
					setError(reason instanceof Error ? reason.message : String(reason));
				}
			}, []);
			(0, react.useEffect)(() => {
				load();
				const poll = setInterval(() => {
					if (typeof document !== "undefined" && document.visibilityState === "hidden") return;
					load();
				}, 5e3);
				const clock = setInterval(() => {
					setNow(Date.now());
				}, 1e3);
				return () => {
					clearInterval(poll);
					clearInterval(clock);
				};
			}, [load]);
			/** Apply one patch through the host and adopt its answer. */
			const patch = (0, react.useCallback)(async (key, body) => {
				setBusy(key);
				try {
					const next = await postJson(`${ROUTE}/config`, body);
					setState(next);
					setError("");
				} catch (reason) {
					setError(reason instanceof Error ? reason.message : String(reason));
				} finally {
					setBusy("");
				}
			}, []);
			/** Mint a fresh code. */
			const rotate = (0, react.useCallback)(async () => {
				setBusy("code");
				try {
					const next = await postJson(`${ROUTE}/newcode`, {});
					setState(next);
					setError("");
				} catch (reason) {
					setError(reason instanceof Error ? reason.message : String(reason));
				} finally {
					setBusy("");
				}
			}, []);
			/** Copy text to the clipboard and flash the source label. */
			const copy = (0, react.useCallback)(async (text, label) => {
				try {
					await navigator.clipboard.writeText(text);
					setCopied(label);
					setTimeout(() => {
						setCopied("");
					}, 1600);
				} catch {
					setCopied("");
				}
			}, []);
			const online = state?.phoneOnline === true;
			const secondsLeft = state === null ? 0 : Math.floor((state.expiresAt - now) / 1e3);
			const qrSrc = state === null || state.payload.length === 0 ? "" : `${ROUTE}/qr.svg?payload=${encodeURIComponent(state.payload)}`;
			return /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
				style: {
					display: "flex",
					flexDirection: "column",
					gap: 12
				},
				children: [
					/* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
						style: {
							fontSize: 13,
							color: C.fgDim
						},
						children: "手机扫码就能连上这台电脑的 DSH。配对码一次性，用过即换；手机和电脑要在同一个 WiFi。"
					}),
					/* @__PURE__ */ (0, react_jsx_runtime.jsx)(Card, { children: /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
						style: {
							display: "flex",
							alignItems: "center",
							justifyContent: "space-between",
							gap: 12
						},
						children: [/* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
							style: {
								display: "flex",
								alignItems: "center",
								gap: 10
							},
							children: [/* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
								style: {
									width: 34,
									height: 34,
									borderRadius: 9,
									background: "rgba(26,110,240,.12)",
									color: C.accent,
									display: "flex",
									alignItems: "center",
									justifyContent: "center",
									fontSize: 12,
									fontWeight: 700
								},
								children: "DSH"
							}), /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
								style: {
									fontSize: 14,
									fontWeight: 600,
									color: C.fg
								},
								children: "DSH 手机连接"
							}), /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
								style: {
									fontSize: 12,
									color: C.fgFaint
								},
								children: ["DeepSeek Harness · ", state?.host ?? "-"]
							})] })]
						}), /* @__PURE__ */ (0, react_jsx_runtime.jsx)(Chip, {
							text: online ? "手机已连接" : "等待手机连接",
							tone: online ? "ok" : "idle"
						})]
					}) }),
					/* @__PURE__ */ (0, react_jsx_runtime.jsxs)(Card, { children: [
						/* @__PURE__ */ (0, react_jsx_runtime.jsx)(Title, { text: "允许连接" }),
						/* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
							style: {
								display: "flex",
								alignItems: "center",
								justifyContent: "space-between",
								padding: "4px 0"
							},
							children: [/* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
								style: {
									fontSize: 13,
									color: C.fg
								},
								children: "局域网直连"
							}), /* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
								style: {
									fontSize: 12,
									color: C.fgFaint
								},
								children: "同一 WiFi 下 App 直接连这台电脑"
							})] }), /* @__PURE__ */ (0, react_jsx_runtime.jsx)(Toggle, {
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
								padding: "4px 0"
							},
							children: [/* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", { children: [/* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
								style: {
									fontSize: 13,
									color: C.fg
								},
								children: "公网访问"
							}), /* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
								style: {
									fontSize: 12,
									color: C.fgFaint
								},
								children: "手机在外网时连隧道地址，电脑需常驻"
							})] }), /* @__PURE__ */ (0, react_jsx_runtime.jsx)(Toggle, {
								on: state?.allowRemote === true,
								disabled: busy === "remote",
								onChange: (next) => {
									patch("remote", { allowRemote: next });
								}
							})]
						}),
						state !== null && state.allowLan && state.lan.length > 0 ? /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
							style: { marginTop: 8 },
							children: [/* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
								style: {
									fontSize: 12,
									color: C.fgFaint,
									marginBottom: 4
								},
								children: "本机地址（点一下复制）"
							}), /* @__PURE__ */ (0, react_jsx_runtime.jsx)("button", {
								type: "button",
								onClick: () => {
									copy(state.lan[0], "lan");
								},
								style: {
									border: `1px solid ${C.border}`,
									background: C.cardSoft,
									color: C.fg,
									borderRadius: 8,
									padding: "5px 10px",
									fontSize: 12,
									cursor: "pointer"
								},
								children: copied === "lan" ? "已复制" : String(state.lan[0])
							})]
						}) : null,
						state !== null && state.allowRemote ? /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
							style: { marginTop: 8 },
							children: [/* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
								style: {
									fontSize: 12,
									color: C.fgFaint,
									marginBottom: 4
								},
								children: "公网地址"
							}), /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
								style: {
									display: "flex",
									gap: 8
								},
								children: [/* @__PURE__ */ (0, react_jsx_runtime.jsx)("input", {
									value: draftUrl,
									placeholder: "https://dsh.example.net",
									onChange: (event) => {
										setDraftUrl(event.target.value);
									},
									style: {
										flex: 1,
										minWidth: 0,
										border: `1px solid ${C.border}`,
										borderRadius: 8,
										background: C.cardSoft,
										color: C.fg,
										padding: "6px 10px",
										fontSize: 13
									}
								}), /* @__PURE__ */ (0, react_jsx_runtime.jsx)(Btn, {
									text: busy === "url" ? "保存中" : "保存",
									disabled: busy === "url",
									onClick: () => {
										patch("url", { publicUrl: draftUrl });
									}
								})]
							})]
						}) : null
					] }),
					/* @__PURE__ */ (0, react_jsx_runtime.jsxs)(Card, { children: [/* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
						style: {
							display: "flex",
							alignItems: "center",
							justifyContent: "space-between",
							marginBottom: 10
						},
						children: [/* @__PURE__ */ (0, react_jsx_runtime.jsx)("span", {
							style: {
								fontSize: 14,
								fontWeight: 600,
								color: C.fg
							},
							children: "扫码连接"
						}), /* @__PURE__ */ (0, react_jsx_runtime.jsx)(Btn, {
							text: "换一个新码",
							disabled: busy === "code",
							onClick: () => {
								rotate();
							}
						})]
					}), qrSrc.length > 0 ? /* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
						style: {
							display: "flex",
							justifyContent: "center"
						},
						children: /* @__PURE__ */ (0, react_jsx_runtime.jsx)("img", {
							alt: "配对二维码",
							src: qrSrc,
							width: 200,
							height: 200,
							style: {
								background: "#ffffff",
								padding: 9,
								borderRadius: 12
							}
						})
					}) : /* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
						style: {
							fontSize: 12,
							color: C.fgFaint
						},
						children: "还没有可用地址：打开上面的「局域网直连」，或填一个公网地址。"
					})] }),
					/* @__PURE__ */ (0, react_jsx_runtime.jsxs)(Card, { children: [
						/* @__PURE__ */ (0, react_jsx_runtime.jsx)(Title, { text: "6 位配对码" }),
						/* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
							style: {
								display: "flex",
								alignItems: "center",
								gap: 10,
								marginTop: 4
							},
							children: [/* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
								style: {
									fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
									fontSize: 26,
									letterSpacing: 6,
									fontWeight: 600,
									color: C.fg
								},
								children: state?.code ?? "------"
							}), /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("span", {
								style: {
									fontSize: 12,
									color: secondsLeft > 60 ? C.fgFaint : C.bad
								},
								children: ["剩余 ", countdown(secondsLeft)]
							})]
						}),
						/* @__PURE__ */ (0, react_jsx_runtime.jsx)("div", {
							style: {
								fontSize: 12,
								color: C.fgFaint,
								marginTop: 6
							},
							children: "手机 App 里输入这 6 位数字即可配对；用过一次自动换新码。"
						})
					] }),
					state !== null ? /* @__PURE__ */ (0, react_jsx_runtime.jsxs)(Card, { children: [
						/* @__PURE__ */ (0, react_jsx_runtime.jsx)(Row, {
							label: "插件版本",
							value: `v${state.version}`
						}),
						/* @__PURE__ */ (0, react_jsx_runtime.jsx)(Row, {
							label: "网关端口",
							value: String(state.port)
						}),
						/* @__PURE__ */ (0, react_jsx_runtime.jsx)(Row, {
							label: "当前二维码地址",
							value: state.base.length > 0 ? state.base : "未配置"
						})
					] }) : null,
					error.length > 0 ? /* @__PURE__ */ (0, react_jsx_runtime.jsxs)("div", {
						style: {
							fontSize: 12,
							color: C.bad
						},
						children: ["状态读取失败：", error]
					}) : null
				]
			});
		}
		//#endregion
		//#region src/client/index.ts
		/**
		* dsh-mobile — browser half.
		*
		* Registers one section in the DSH settings dialog: the pairing panel a phone
		* scans. Everything it shows comes from the host half through same-origin
		* routes (`/api/dsh-mobile/panel/*`), so this bundle never holds the bearer
		* token and never talks to the phone gateway directly.
		* @module @deepseek-ai/dsh-mobile/client
		*/
		/** Services this half needs: the settings dialog exposes one slot per section. */
		const inject = ["slots"];
		/**
		* Register the pairing section.
		* @param ctx - client root context.
		*/
		function apply(ctx) {
			ctx.slots.inject("settings.section", () => ctx.slots.register({
				name: "settings.section",
				id: "dsh-mobile",
				order: 36,
				label: () => "手机连接"
			}, MobileSection));
		}
		//#endregion
		exports.apply = apply;
		exports.inject = inject;
		return module.exports;
	}
});

//# sourceMappingURL=client.js.map