"use strict";

(() => {
    const $ = (id) => document.getElementById(id);
    const numberFormat = new Intl.NumberFormat("en-US");
    const FILE_MODE_HINT =
        "This page needs its local server. Run python server.py --open in the project folder, then open http://127.0.0.1:8765/.";
    const isFileMode = () => window.location.protocol === "file:";

    const MODES = {
        hide: {
            note: "Encrypt a message, then copy the carrier.",
            title: "Carrier",
            emptySubtitle: "The visible text, with the message inside.",
            successSubtitle: "The visible text, with the message inside.",
            loadingSubtitle: "Working locally. The key comes first.",
            emptyTitle: "No carrier yet",
            emptyBody: "Hide a message and the visible carrier appears here.",
            emptyMeta: "0 hidden bytes",
            submit: "Hide message",
            busy: "Hiding…",
            loadingTitle: "Deriving the key",
            loadingBody: "bcrypt runs locally. Nothing leaves this machine.",
            copyLabel: "Copy carrier",
        },
        reveal: {
            note: "Paste a carrier, then check the tag.",
            title: "Revealed",
            emptySubtitle: "Paste a carrier to check its tag.",
            successSubtitle: "Decrypted locally. Poly1305 verified.",
            loadingSubtitle: "Working locally. The tag comes last.",
            emptyTitle: "Waiting for a message",
            emptyBody: "Paste text that contains the OSC magic, then reveal it.",
            emptyMeta: "OSC / 0 bytes",
            submit: "Reveal message",
            busy: "Revealing…",
            loadingTitle: "Deriving the key",
            loadingBody: "bcrypt runs locally, then the tag is checked.",
            copyLabel: "Copy message",
        },
    };

    const els = {
        tabs: Array.from(document.querySelectorAll(".mode-tab")),
        hidePanel: $("hide-panel"),
        revealPanel: $("reveal-panel"),
        hideForm: $("hide-form"),
        revealForm: $("reveal-form"),
        hideMessage: $("hide-message"),
        hideMessageCount: $("hide-message-count"),
        hidePassword: $("hide-password"),
        hidePasswordToggle: $("hide-password-toggle"),
        hideCarrier: $("hide-carrier"),
        hideCarrierCount: $("hide-carrier-count"),
        hideSpread: $("hide-spread"),
        hidePadding: $("hide-padding"),
        hideSubmit: $("hide-submit"),
        hideClear: $("hide-clear"),
        hideError: $("hide-error"),
        revealText: $("reveal-text"),
        revealTextCount: $("reveal-text-count"),
        revealPassword: $("reveal-password"),
        revealPasswordToggle: $("reveal-password-toggle"),
        revealSubmit: $("reveal-submit"),
        revealError: $("reveal-error"),
        sampleBtn: $("sample-btn"),
        trySample: $("try-sample"),
        sampleNote: $("sample-note"),
        modeNote: $("mode-note"),
        carrierPanel: $("carrier-panel"),
        carrierTitle: $("carrier-title"),
        carrierSubtitle: $("carrier-subtitle"),
        carrierBody: $("carrier-body"),
        carrierStates: Array.from(document.querySelectorAll(".carrier-state")),
        emptyTitle: $("empty-title"),
        emptyBody: $("empty-body"),
        emptyMeta: $("empty-meta"),
        loadingTitle: $("loading-title"),
        loadingBody: $("loading-body"),
        carrierErrorTitle: $("carrier-error-title"),
        carrierErrorMessage: $("carrier-error-message"),
        carrierErrorHint: $("carrier-error-hint"),
        copyBtn: $("copy-btn"),
        copyLabel: $("copy-label"),
        successHide: $("success-hide"),
        successReveal: $("success-reveal"),
        carrierText: $("carrier-text"),
        hiddenRibbon: $("hidden-ribbon"),
        hiddenFieldWrap: $("hidden-field-wrap"),
        byteField: $("byte-field"),
        revealedMessage: $("revealed-message"),
        revealedMeta: $("revealed-meta"),
        revealedNote: $("revealed-note"),
        carrierFoot: $("carrier-foot"),
        revealToggle: $("reveal-toggle"),
        carrierStat: $("carrier-stat"),
        traceGrid: $("trace-grid"),
        traceStatus: $("trace-status"),
        cipherBlockMeta: $("cipher-block-meta"),
        cipherHex: $("cipher-hex"),
        cipherLegend: $("cipher-legend"),
        liveStatus: $("live-status"),
        kdfNotice: $("kdf-notice"),
        fileNotice: $("file-notice"),
        dialogs: Array.from(document.querySelectorAll("dialog.dialog")),
        copyCommandButtons: Array.from(document.querySelectorAll("[data-copy-command]")),
        dialogOpenButtons: Array.from(document.querySelectorAll("[data-dialog-open]")),
        dialogCloseButtons: Array.from(document.querySelectorAll("[data-dialog-close]")),
    };

    const state = {
        mode: "hide",
        busy: false,
        result: null,
        sample: null,
        health: null,
        dialogTrigger: null,
    };

    const delay = (ms) => new Promise((resolve) => window.setTimeout(resolve, ms));

    function formatInt(value) {
        return numberFormat.format(Number(value) || 0);
    }

    function countChars(text) {
        let count = 0;
        for (const _char of text) {
            count += 1;
        }
        return count;
    }

    function announce(text) {
        els.liveStatus.textContent = "";
        window.setTimeout(() => {
            els.liveStatus.textContent = text;
        }, 30);
    }

    function updateCounts() {
        els.hideMessageCount.textContent = `${formatInt(countChars(els.hideMessage.value))} / 5,000`;
        els.hideCarrierCount.textContent = `${formatInt(countChars(els.hideCarrier.value))} / 5,000`;
        els.revealTextCount.textContent = `${formatInt(countChars(els.revealText.value))} characters`;
    }

    function showOnly(stateName) {
        for (const panel of els.carrierStates) {
            const active = panel.dataset.state === stateName;
            panel.classList.toggle("is-active", active);
            panel.setAttribute("aria-hidden", String(!active));
        }
        els.carrierBody.setAttribute("aria-busy", String(stateName === "loading"));
    }

    function resetCopyButton(mode) {
        if (els.copyBtn._copyTimer) {
            window.clearTimeout(els.copyBtn._copyTimer);
            els.copyBtn._copyTimer = null;
        }
        els.copyBtn.dataset.state = "";
        els.copyLabel.textContent = "Copy";
        els.copyBtn.setAttribute("aria-label", MODES[mode].copyLabel);
    }

    function resetPasswordVisibility() {
        for (const [input, button] of [
            [els.hidePassword, els.hidePasswordToggle],
            [els.revealPassword, els.revealPasswordToggle],
        ]) {
            input.type = "password";
            button.setAttribute("aria-pressed", "false");
            button.setAttribute("aria-label", "Show password");
        }
    }

    function clearAllErrors() {
        for (const errorEl of [els.hideError, els.revealError]) {
            errorEl.textContent = "";
        }
        for (const field of [
            els.hideMessage,
            els.hidePassword,
            els.hideCarrier,
            els.hideSpread,
            els.hidePadding,
            els.revealText,
            els.revealPassword,
        ]) {
            field.removeAttribute("aria-invalid");
            field.removeAttribute("aria-errormessage");
        }
    }

    function findField(name, errorEl) {
        const map = errorEl === els.hideError
            ? {
                message: els.hideMessage,
                password: els.hidePassword,
                carrier: els.hideCarrier,
                spread: els.hideSpread,
                padding: els.hidePadding,
            }
            : {
                text: els.revealText,
                password: els.revealPassword,
            };
        return map[name] || null;
    }

    function showFormError(errorEl, message, fieldName) {
        errorEl.textContent = message;
        const field = fieldName ? findField(fieldName, errorEl) : null;
        if (!field) {
            return;
        }
        field.setAttribute("aria-invalid", "true");
        field.setAttribute("aria-errormessage", errorEl.id);
        field.focus();
        if (field instanceof HTMLInputElement && (field.type === "password" || field.type === "text")) {
            field.select();
        }
    }

    function clearFieldError(field, errorEl) {
        if (field.getAttribute("aria-invalid") !== "true") {
            return;
        }
        field.removeAttribute("aria-invalid");
        field.removeAttribute("aria-errormessage");
        errorEl.textContent = "";
    }

    function bindFieldErrorClear(field, errorEl) {
        field.addEventListener("input", () => clearFieldError(field, errorEl));
        field.addEventListener("change", () => clearFieldError(field, errorEl));
    }

    function guardFileMode(errorEl) {
        if (!isFileMode()) {
            return false;
        }
        els.fileNotice.hidden = false;
        if (errorEl) {
            showFormError(errorEl, FILE_MODE_HINT);
        }
        announce(FILE_MODE_HINT);
        els.fileNotice.scrollIntoView({ block: "center" });
        return true;
    }

    function renderTraceSteps(steps) {
        els.traceGrid.replaceChildren();
        steps.forEach((step) => {
            const article = document.createElement("article");
            article.className = "trace-step";
            if (step.state) {
                article.dataset.state = step.state;
            }

            const head = document.createElement("div");
            head.className = "trace-step-head";
            const title = document.createElement("h3");
            title.textContent = step.label;
            head.append(title);

            const values = document.createElement("dl");
            values.className = "trace-values";
            for (const [label, value] of step.values) {
                const row = document.createElement("div");
                const term = document.createElement("dt");
                term.textContent = label;
                const detail = document.createElement("dd");
                if (value instanceof Node) {
                    detail.append(value);
                } else {
                    detail.textContent = value;
                }
                row.append(term, detail);
                values.append(row);
            }

            const note = document.createElement("p");
            note.className = "trace-note";
            note.textContent = step.note;

            article.append(head, values, note);
            els.traceGrid.append(article);
        });
    }

    function makeSkeleton(widthClass) {
        const span = document.createElement("span");
        span.className = `skeleton ${widthClass}`;
        span.setAttribute("aria-hidden", "true");
        return span;
    }

    function renderCipherEmpty(text, meta) {
        els.cipherBlockMeta.textContent = meta;
        els.cipherHex.replaceChildren(document.createTextNode(text));
        els.cipherHex.classList.add("cipher-hex--empty");
        els.cipherLegend.hidden = true;
    }

    function renderCipherFull(meta) {
        const hex = meta.ciphertext_hex || "";
        const tagLength = 32;
        const hasBody = hex.length > tagLength;
        const body = hasBody ? hex.slice(0, -tagLength) : "";
        const tag = hasBody ? hex.slice(-tagLength) : hex;
        const fragment = document.createDocumentFragment();
        if (body) {
            fragment.append(document.createTextNode(body));
        }
        const tagSpan = document.createElement("span");
        tagSpan.className = "cipher-tag";
        tagSpan.textContent = tag;
        fragment.append(tagSpan);
        els.cipherHex.replaceChildren(fragment);
        els.cipherHex.classList.remove("cipher-hex--empty");
        els.cipherBlockMeta.textContent = `${formatInt(meta.ciphertext_len)} bytes`;
        els.cipherLegend.hidden = false;
    }

    function renderTraceEmpty() {
        const labels = [
            ["Password key", "key id"],
            ["Session key", "keyhash"],
            ["ChaCha20 + Poly1305", "ciphertext"],
            ["Zero-width", "payload"],
        ];
        const steps = labels.map(([label, valueLabel]) => ({
            label,
            values: [[valueLabel, "—"]],
            note: "Waiting for an operation.",
        }));
        renderTraceSteps(steps);
        els.traceStatus.textContent = "Waiting";
        els.traceGrid.setAttribute("aria-busy", "false");
        renderCipherEmpty("Waiting for an operation.", "No ciphertext yet");
    }

    function renderTraceLoading() {
        const steps = [
            {
                label: "Password key",
                values: [["key id", makeSkeleton("skeleton--80")]],
                note: "Deriving the password key.",
                state: "loading",
            },
            {
                label: "Session key",
                values: [["keyhash", makeSkeleton("skeleton--70")]],
                note: "Waiting for the password key.",
                state: "loading",
            },
            {
                label: "ChaCha20 + Poly1305",
                values: [["ciphertext", makeSkeleton("skeleton--60")]],
                note: "Waiting for the session key.",
                state: "loading",
            },
            {
                label: "Zero-width",
                values: [["payload", makeSkeleton("skeleton--80")]],
                note: "Waiting for the ciphertext.",
                state: "loading",
            },
        ];
        renderTraceSteps(steps);
        els.traceStatus.textContent = "Working";
        els.traceGrid.setAttribute("aria-busy", "true");
        els.cipherBlockMeta.textContent = "Waiting for the result";
        const bar = makeSkeleton("skeleton--80");
        bar.classList.add("skeleton--dark");
        els.cipherHex.replaceChildren(bar);
        els.cipherHex.classList.remove("cipher-hex--empty");
        els.cipherLegend.hidden = true;
    }

    function renderTraceFull(meta, operation) {
        const zeroWidthValues = [
            ["payload", `${formatInt(meta.encoded_len)} bytes`],
            ["characters", formatInt(meta.hidden_len)],
            ["fillers", formatInt(meta.filler_count)],
        ];
        if (operation === "hide") {
            zeroWidthValues.push(["spread", meta.spread ? `every ${formatInt(meta.spread)}` : "off"]);
        } else {
            zeroWidthValues.push([
                "repaired",
                meta.repaired ? `offset ${meta.repaired.offset}, 0x${meta.repaired.byte}` : "none",
            ]);
        }

        const steps = [
            {
                label: "Password key",
                values: [
                    ["key id", meta.key_id],
                    ["bcrypt", `cost ${meta.bcrypt.password_cost}`],
                    ["key id cost", `cost ${meta.bcrypt.key_id_cost}`],
                    ["backend", meta.kdf_backend],
                ],
                note: "Fixed SIMPLESYM salt. The key ID is the bcrypt of SHA-384(raw)[32:48].",
            },
            {
                label: "Session key",
                values: [
                    ["keyhash", meta.keyhash],
                    ["salt", meta.salt],
                    ["iv", meta.iv],
                    ["bcrypt", `cost ${meta.bcrypt.keyhash_cost}`],
                ],
                note: "The keyhash selects the entry; the message key uses the same salt.",
            },
            {
                label: "ChaCha20 + Poly1305",
                values: [
                    ["ciphertext", `${formatInt(meta.ciphertext_len)} bytes`],
                    ["tag", meta.tag_hex],
                    ["message key", `cost ${meta.bcrypt.message_cost}`],
                ],
                note: operation === "reveal"
                    ? "The tag verifies the restored ciphertext."
                    : "The tag covers the ciphertext, zero padding, and the length.",
            },
            {
                label: "Zero-width",
                values: zeroWidthValues,
                note: operation === "reveal" && meta.repaired
                    ? "One missing byte recovered at the ciphertext offset shown."
                    : "OSC magic. 0x00–0x0F map to U+FE00–U+FE0F; the rest to U+E0100–U+E01EF.",
            },
        ];

        renderTraceSteps(steps);
        els.traceStatus.textContent = operation === "hide" ? "Encrypted" : "Verified";
        els.traceGrid.setAttribute("aria-busy", "false");
        renderCipherFull(meta);
    }

    function errorStep(code) {
        switch (code) {
            case "wrong_password":
                return 2;
            case "mac_mismatch":
            case "missing_bytes":
                return 3;
            case "no_payload":
            case "malformed":
                return 4;
            default:
                return 0;
        }
    }

    function errorHint(code) {
        switch (code) {
            case "wrong_password":
                return "The keyhash did not match. Check the password.";
            case "no_payload":
                return "The text does not contain the OSC magic.";
            case "mac_mismatch":
                return "The tag did not verify. The payload may be damaged.";
            case "missing_bytes":
                return "More than one byte is missing; only one can be recovered.";
            case "malformed":
                return "The envelope parsed, but the inner message did not.";
            case "too_large":
                return "The input is larger than this workbench accepts.";
            case "timeout":
                return "The operation took too long. The Python fallback may be in use.";
            case "offline":
                return "The local server is not responding. Restart it and try again.";
            case "bad_request":
                return "Check the highlighted field and try again.";
            default:
                return "Nothing was sent anywhere. Check the field and try again.";
        }
    }

    function renderTraceError(error) {
        const failed = errorStep(error.code);
        const beforeStart = error.code === "bad_request" || error.code === "too_large";
        const labels = [
            ["Password key", "key id"],
            ["Session key", "keyhash"],
            ["ChaCha20 + Poly1305", "ciphertext"],
            ["Zero-width", "payload"],
        ];

        const steps = labels.map(([label, valueLabel], index) => {
            const stepNumber = index + 1;
            let stepState;
            let value;
            let note;
            if (failed === 0) {
                value = beforeStart ? "Not run" : "No result";
                note = beforeStart
                    ? "The operation stopped before the first key step."
                    : "The local call did not return a result.";
            } else if (stepNumber < failed) {
                stepState = "done";
                value = "Complete";
                note = "Completed before the stop.";
            } else if (stepNumber === failed) {
                stepState = "error";
                value = "Stopped";
                note = error.message;
            } else {
                value = "Not reached";
                note = "Not reached.";
            }
            return { label, values: [[valueLabel, value]], note, state: stepState };
        });

        renderTraceSteps(steps);
        els.traceStatus.textContent = "Stopped";
        els.traceGrid.setAttribute("aria-busy", "false");
        renderCipherEmpty("No verified ciphertext was produced.", "Operation stopped");
    }

    function resetOutput() {
        state.result = null;
        els.carrierTitle.textContent = MODES[state.mode].title;
        els.carrierSubtitle.textContent = MODES[state.mode].emptySubtitle;
        els.emptyTitle.textContent = MODES[state.mode].emptyTitle;
        els.emptyBody.textContent = MODES[state.mode].emptyBody;
        els.emptyMeta.textContent = MODES[state.mode].emptyMeta;
        els.carrierStat.textContent = MODES[state.mode].emptyMeta;
        els.carrierFoot.classList.toggle("is-reveal", state.mode === "reveal");
        els.revealToggle.hidden = state.mode !== "hide";
        els.revealToggle.disabled = true;
        els.revealToggle.setAttribute("aria-checked", "false");
        els.revealToggle.querySelector(".switch-label").textContent = "Show hidden characters";
        els.copyBtn.disabled = true;
        resetCopyButton(state.mode);
        els.successHide.hidden = false;
        els.successReveal.hidden = true;
        els.carrierText.textContent = "";
        els.carrierText.classList.remove("is-empty");
        els.hiddenRibbon.hidden = false;
        els.hiddenFieldWrap.hidden = true;
        els.byteField.replaceChildren();
        els.revealedMessage.textContent = "";
        els.revealedMeta.replaceChildren();
        els.revealedNote.textContent = "";
        els.revealedNote.hidden = true;
        showOnly("empty");
        renderTraceEmpty();
    }

    function applyModeCopy() {
        const copy = MODES[state.mode];
        els.modeNote.textContent = copy.note;
        els.hideSubmit.querySelector(".key-label").textContent = MODES.hide.submit;
        els.revealSubmit.querySelector(".key-label").textContent = MODES.reveal.submit;
        els.copyBtn.setAttribute("aria-label", copy.copyLabel);
        els.copyLabel.textContent = "Copy";
    }

    function setMode(mode, options = {}) {
        const { focusTab = false, updateUrl = true } = options;
        if (!MODES[mode] || state.busy) {
            return;
        }
        state.mode = mode;
        for (const tab of els.tabs) {
            const active = tab.dataset.mode === mode;
            tab.setAttribute("aria-selected", String(active));
            tab.tabIndex = active ? 0 : -1;
        }
        els.hidePanel.hidden = mode !== "hide";
        els.revealPanel.hidden = mode !== "reveal";
        resetPasswordVisibility();
        clearAllErrors();
        resetOutput();
        applyModeCopy();

        if (updateUrl) {
            const url = new URL(window.location.href);
            if (mode === "hide") {
                url.searchParams.delete("mode");
            } else {
                url.searchParams.set("mode", mode);
            }
            window.history.replaceState(null, "", url.toString());
        }

        if (focusTab) {
            const activeTab = els.tabs.find((tab) => tab.dataset.mode === mode);
            if (activeTab) {
                activeTab.focus();
            }
        }
    }

    function beginOperation(mode) {
        state.busy = true;
        state.result = null;
        clearAllErrors();
        const copy = MODES[mode];
        els.carrierTitle.textContent = copy.title;
        els.carrierSubtitle.textContent = copy.loadingSubtitle;
        els.loadingTitle.textContent = copy.loadingTitle;
        els.loadingBody.textContent = copy.loadingBody;
        showOnly("loading");
        els.copyBtn.disabled = true;
        resetCopyButton(mode);
        els.revealToggle.hidden = mode !== "hide";
        els.revealToggle.disabled = true;
        els.revealToggle.setAttribute("aria-checked", "false");
        els.revealToggle.querySelector(".switch-label").textContent = "Show hidden characters";
        els.carrierFoot.classList.toggle("is-reveal", mode === "reveal");
        els.carrierStat.textContent = "Working";

        const submit = mode === "hide" ? els.hideSubmit : els.revealSubmit;
        submit.disabled = true;
        submit.setAttribute("aria-busy", "true");
        submit.querySelector(".key-label").textContent = copy.busy;

        els.hideClear.disabled = true;
        els.sampleBtn.disabled = true;
        els.trySample.disabled = true;
        for (const tab of els.tabs) {
            tab.setAttribute("aria-disabled", "true");
        }

        renderTraceLoading();
        announce(mode === "hide" ? "Hiding the message locally." : "Revealing the message locally.");
    }

    function endOperation() {
        state.busy = false;
        for (const [submit, mode] of [
            [els.hideSubmit, "hide"],
            [els.revealSubmit, "reveal"],
        ]) {
            submit.disabled = false;
            submit.setAttribute("aria-busy", "false");
            submit.querySelector(".key-label").textContent = MODES[mode].submit;
        }
        els.hideClear.disabled = false;
        els.sampleBtn.disabled = false;
        els.trySample.disabled = false;
        for (const tab of els.tabs) {
            tab.removeAttribute("aria-disabled");
        }
        els.traceGrid.setAttribute("aria-busy", "false");
    }

    function buildByteField(hex, expectedLength) {
        els.byteField.replaceChildren();
        if (typeof hex !== "string" || hex.length % 2 !== 0) {
            return;
        }
        const fragment = document.createDocumentFragment();
        const total = hex.length / 2;
        for (let index = 0; index < total; index += 1) {
            const byte = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
            if (!Number.isFinite(byte)) {
                continue;
            }
            const cell = document.createElement("span");
            cell.className = "byte-cell";
            cell.dataset.byte = byte.toString(16).padStart(2, "0");
            cell.dataset.tier = String(byteTier(byte));
            cell.title = `0x${byte.toString(16).padStart(2, "0")}`;
            cell.setAttribute("aria-hidden", "true");
            cell.textContent = byteGlyph(byte);
            if (index < 3) {
                cell.dataset.magic = "true";
            }
            fragment.append(cell);
        }
        els.byteField.append(fragment);
        els.byteField.setAttribute(
            "aria-label",
            `${formatInt(expectedLength)} hidden bytes. The first three bytes are the OSC magic.`,
        );
    }

    function byteTier(byte) {
        if (byte < 0x40) {
            return 1;
        }
        if (byte < 0x80) {
            return 2;
        }
        if (byte < 0xc0) {
            return 3;
        }
        return 4;
    }

    function byteGlyph(byte) {
        if (byte < 0x40) {
            return "·";
        }
        if (byte < 0x80) {
            return "░";
        }
        if (byte < 0xc0) {
            return "▒";
        }
        return "▓";
    }

    function showSuccessHide(result) {
        const meta = result.meta;
        state.result = {
            kind: "hide",
            output: result.output,
            carrier: result.carrier,
            meta,
        };
        els.carrierTitle.textContent = "Carrier";
        els.carrierSubtitle.textContent = MODES.hide.successSubtitle;
        const visible = (result.carrier || "").trimEnd();
        els.carrierText.textContent = visible || "No visible carrier.";
        els.carrierText.classList.toggle("is-empty", !visible);
        buildByteField(meta.encoded_hex, meta.encoded_len);
        els.successHide.hidden = false;
        els.successReveal.hidden = true;
        els.hiddenRibbon.hidden = false;
        els.hiddenFieldWrap.hidden = true;
        els.revealToggle.hidden = false;
        els.revealToggle.disabled = false;
        els.revealToggle.setAttribute("aria-checked", "false");
        els.revealToggle.querySelector(".switch-label").textContent = "Show hidden characters";
        els.carrierFoot.classList.remove("is-reveal");
        els.carrierStat.textContent = `${formatInt(meta.hidden_len)} hidden characters${meta.filler_count ? `, ${formatInt(meta.filler_count)} fillers` : ""}`;
        resetCopyButton("hide");
        els.copyBtn.disabled = false;
        showOnly("success");
        renderTraceFull(meta, "hide");
        announce(`Message hidden. ${formatInt(meta.hidden_len)} hidden characters.`);
        els.copyBtn.focus();
    }

    function checkIcon(size = 14) {
        const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
        svg.setAttribute("class", "icon");
        svg.setAttribute("width", String(size));
        svg.setAttribute("height", String(size));
        svg.setAttribute("viewBox", "0 0 24 24");
        svg.setAttribute("fill", "none");
        svg.setAttribute("stroke", "currentColor");
        svg.setAttribute("stroke-width", "1.8");
        svg.setAttribute("aria-hidden", "true");
        const path = document.createElementNS("http://www.w3.org/2000/svg", "path");
        path.setAttribute("d", "M5 12.5l4.5 4.5L19 7.5");
        svg.append(path);
        return svg;
    }

    function showSuccessReveal(result) {
        const meta = result.meta;
        state.result = {
            kind: "reveal",
            message: result.message,
            meta,
            repaired: result.repaired,
        };
        els.carrierTitle.textContent = "Revealed";
        els.carrierSubtitle.textContent = MODES.reveal.successSubtitle;
        els.revealedMessage.textContent = result.message || "Empty message.";

        const metaItems = [];
        const characters = document.createElement("span");
        characters.textContent = `${formatInt(meta.message_len)} characters`;
        metaItems.push(characters);

        const verified = document.createElement("span");
        verified.className = "meta-ok";
        verified.append(checkIcon(14), document.createTextNode("MAC verified"));
        metaItems.push(verified);

        if (result.repaired) {
            const repaired = document.createElement("span");
            repaired.textContent = "1 byte repaired";
            metaItems.push(repaired);
        }
        els.revealedMeta.replaceChildren(...metaItems);

        if (result.repaired) {
            els.revealedNote.textContent = `Offset ${result.repaired.offset}, byte 0x${result.repaired.byte} recovered.`;
            els.revealedNote.hidden = false;
        } else {
            els.revealedNote.textContent = "";
            els.revealedNote.hidden = true;
        }

        els.successHide.hidden = true;
        els.successReveal.hidden = false;
        els.revealToggle.hidden = true;
        els.revealToggle.disabled = true;
        els.revealToggle.setAttribute("aria-checked", "false");
        els.carrierFoot.classList.add("is-reveal");
        els.carrierStat.textContent = `key id ${meta.key_id}`;
        resetCopyButton("reveal");
        els.copyBtn.disabled = false;
        showOnly("success");
        renderTraceFull(meta, "reveal");
        announce(
            `Message revealed. ${formatInt(meta.message_len)} characters.${result.repaired ? " One missing byte recovered." : ""}`,
        );
        els.copyBtn.focus();
    }

    function showError(mode, error) {
        state.result = null;
        els.carrierTitle.textContent = MODES[mode].title;
        els.carrierSubtitle.textContent = "The operation did not finish.";
        els.carrierErrorTitle.textContent = mode === "hide" ? "Could not hide" : "Could not reveal";
        els.carrierErrorMessage.textContent = error.message;
        els.carrierErrorHint.textContent = errorHint(error.code);
        showOnly("error");
        els.copyBtn.disabled = true;
        resetCopyButton(mode);
        els.revealToggle.hidden = mode !== "hide";
        els.revealToggle.disabled = true;
        els.revealToggle.setAttribute("aria-checked", "false");
        els.revealToggle.querySelector(".switch-label").textContent = "Show hidden characters";
        els.carrierFoot.classList.toggle("is-reveal", mode === "reveal");
        els.carrierStat.textContent = "No result";
        renderTraceError(error);

        const formError = mode === "hide" ? els.hideError : els.revealError;
        showFormError(formError, error.message, error.field);
        if (!error.field) {
            const submit = mode === "hide" ? els.hideSubmit : els.revealSubmit;
            submit.focus();
        }
    }

    function normalizeError(error) {
        if (error && typeof error === "object") {
            const code = typeof error.code === "string" ? error.code : "internal";
            const message = typeof error.message === "string" && error.message
                ? error.message
                : "The local operation did not finish.";
            const field = typeof error.field === "string" ? error.field : null;
            return { code, message, field };
        }
        return { code: "internal", message: "The local operation did not finish.", field: null };
    }

    async function getJson(path) {
        const response = await fetch(path, {
            headers: { Accept: "application/json" },
        });
        const data = await response.json().catch(() => null);
        if (!response.ok || !data || data.ok === false) {
            const error = data && data.error
                ? data.error
                : { code: "internal", message: "The local server returned an unexpected response." };
            throw error;
        }
        return data;
    }

    async function apiPost(path, body) {
        const controller = new AbortController();
        const timeout = window.setTimeout(() => controller.abort(), 30000);
        try {
            const response = await fetch(path, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Accept: "application/json",
                },
                body: JSON.stringify(body),
                signal: controller.signal,
            });
            const data = await response.json().catch(() => null);
            if (!response.ok || !data || data.ok === false) {
                const error = data && data.error
                    ? data.error
                    : { code: "internal", message: "The local server returned an unexpected response." };
                throw error;
            }
            return data;
        } catch (error) {
            if (error && error.name === "AbortError") {
                throw {
                    code: "timeout",
                    message: "The operation took too long. The Python fallback may be in use.",
                };
            }
            if (error instanceof TypeError) {
                throw {
                    code: "offline",
                    message: "Could not reach the local server. Is it still running?",
                };
            }
            throw error;
        } finally {
            window.clearTimeout(timeout);
        }
    }

    async function atLeast(promise, milliseconds) {
        const started = performance.now();
        try {
            return await promise;
        } finally {
            const elapsed = performance.now() - started;
            if (elapsed < milliseconds) {
                await delay(milliseconds - elapsed);
            }
        }
    }

    function bytesToZeroWidth(hex) {
        let output = "";
        for (let index = 0; index < hex.length; index += 2) {
            const byte = Number.parseInt(hex.slice(index, index + 2), 16);
            if (!Number.isFinite(byte)) {
                continue;
            }
            output += byte < 0x10
                ? String.fromCodePoint(0xfe00 + byte)
                : String.fromCodePoint(0xe0100 + byte - 0x10);
        }
        return output;
    }

    async function loadSample() {
        if (state.busy) {
            return;
        }
        const activeError = state.mode === "hide" ? els.hideError : els.revealError;
        if (guardFileMode(activeError)) {
            return;
        }
        if (state.mode !== "reveal") {
            setMode("reveal");
        }

        els.sampleBtn.disabled = true;
        els.trySample.disabled = true;
        els.sampleBtn.setAttribute("aria-busy", "true");
        try {
            if (!state.sample) {
                state.sample = await getJson("/api/sample");
            }
            const sample = state.sample;
            els.revealText.value = `${sample.carrier} ${bytesToZeroWidth(sample.encoded_hex)}`;
            els.revealPassword.value = sample.password;
            resetPasswordVisibility();
            // els.sampleNote.textContent = sample.note;
            // els.sampleNote.hidden = false;
            clearAllErrors();
            resetOutput();
            applyModeCopy();
            updateCounts();
            announce("Sample loaded. Press Reveal message to decrypt it.");
            els.revealSubmit.focus();
        } catch (error) {
            const normalized = normalizeError(error);
            showFormError(els.revealError, normalized.message, normalized.field);
        } finally {
            els.sampleBtn.disabled = false;
            els.trySample.disabled = false;
            els.sampleBtn.removeAttribute("aria-busy");
        }
    }

    function hideSampleNote() {
        els.sampleNote.hidden = true;
    }

    async function copyText(text) {
        if (navigator.clipboard && window.isSecureContext) {
            await navigator.clipboard.writeText(text);
            return;
        }
        const textarea = document.createElement("textarea");
        textarea.value = text;
        textarea.setAttribute("readonly", "");
        textarea.style.position = "fixed";
        textarea.style.top = "-1000px";
        textarea.style.opacity = "0";
        document.body.append(textarea);
        textarea.select();
        const copied = document.execCommand("copy");
        textarea.remove();
        if (!copied) {
            throw new Error("Copy failed.");
        }
    }

    async function handleCopy(button, text, labelEl, defaultLabel) {
        if (!text) {
            return;
        }
        const originalAria = button.getAttribute("aria-label");
        window.clearTimeout(button._copyTimer);
        try {
            await copyText(text);
            button.dataset.state = "success";
            if (labelEl) {
                labelEl.textContent = "Copied";
            }
            button.setAttribute("aria-label", "Copied");
            announce("Copied to clipboard.");
            button._copyTimer = window.setTimeout(() => {
                button.dataset.state = "";
                if (labelEl) {
                    labelEl.textContent = defaultLabel;
                }
                if (originalAria) {
                    button.setAttribute("aria-label", originalAria);
                } else {
                    button.removeAttribute("aria-label");
                }
            }, 1800);
        } catch {
            button.dataset.state = "error";
            if (labelEl) {
                labelEl.textContent = "Copy failed";
            }
            button.setAttribute("aria-label", "Copy failed");
            announce("Copy failed. Select the text and copy it manually.");
            button._copyTimer = window.setTimeout(() => {
                button.dataset.state = "";
                if (labelEl) {
                    labelEl.textContent = defaultLabel;
                }
                if (originalAria) {
                    button.setAttribute("aria-label", originalAria);
                } else {
                    button.removeAttribute("aria-label");
                }
            }, 2400);
        }
    }

    function setupPasswordToggle(input, button) {
        button.addEventListener("click", () => {
            const show = input.type === "password";
            input.type = show ? "text" : "password";
            button.setAttribute("aria-pressed", String(show));
            button.setAttribute("aria-label", show ? "Hide password" : "Show password");
            input.focus();
        });
    }

    function openDialog(dialog, trigger) {
        state.dialogTrigger = trigger || document.activeElement;
        if (typeof dialog.showModal === "function") {
            dialog.showModal();
        } else {
            dialog.setAttribute("open", "");
        }
        const closeButton = dialog.querySelector("[data-dialog-close]");
        if (closeButton) {
            closeButton.focus();
        }
    }

    function closeDialog(dialog) {
        if (typeof dialog.close === "function") {
            dialog.close();
        } else {
            dialog.removeAttribute("open");
        }
        if (state.dialogTrigger) {
            state.dialogTrigger.focus();
            state.dialogTrigger = null;
        }
    }

    function setupEvents() {
        for (const [index, tab] of els.tabs.entries()) {
            tab.addEventListener("click", () => setMode(tab.dataset.mode));
            tab.addEventListener("keydown", (event) => {
                const keys = ["ArrowLeft", "ArrowRight", "Home", "End"];
                if (!keys.includes(event.key)) {
                    return;
                }
                event.preventDefault();
                let nextIndex = index;
                if (event.key === "ArrowLeft") {
                    nextIndex = (index - 1 + els.tabs.length) % els.tabs.length;
                } else if (event.key === "ArrowRight") {
                    nextIndex = (index + 1) % els.tabs.length;
                } else if (event.key === "Home") {
                    nextIndex = 0;
                } else if (event.key === "End") {
                    nextIndex = els.tabs.length - 1;
                }
                const next = els.tabs[nextIndex];
                setMode(next.dataset.mode, { focusTab: true });
            });
        }

        els.hideForm.addEventListener("submit", async (event) => {
            event.preventDefault();
            if (state.busy || guardFileMode(els.hideError)) {
                return;
            }
            const message = els.hideMessage.value;
            const password = els.hidePassword.value;
            const carrier = els.hideCarrier.value;
            const spread = els.hideSpread.checked ? 30 : 0;
            const padding = Number.parseInt(els.hidePadding.value, 10);

            if (!message) {
                showFormError(els.hideError, "Enter a message to hide.", "message");
                return;
            }
            if (!password) {
                showFormError(els.hideError, "Enter a password.", "password");
                return;
            }
            if (!Number.isInteger(padding) || padding < 0 || padding > 255) {
                showFormError(els.hideError, "Padding must be between 0 and 255 bytes.", "padding");
                return;
            }

            clearAllErrors();
            beginOperation("hide");
            try {
                const data = await atLeast(
                    apiPost("/api/encrypt", { message, password, carrier, spread, padding }),
                    280,
                );
                endOperation();
                showSuccessHide({ ...data, carrier });
            } catch (error) {
                endOperation();
                showError("hide", normalizeError(error));
            }
        });

        els.revealForm.addEventListener("submit", async (event) => {
            event.preventDefault();
            if (state.busy || guardFileMode(els.revealError)) {
                return;
            }
            const text = els.revealText.value;
            const password = els.revealPassword.value;

            if (!text) {
                showFormError(els.revealError, "Paste the text that contains the hidden payload.", "text");
                return;
            }
            if (!password) {
                showFormError(els.revealError, "Enter the password used to hide the message.", "password");
                return;
            }

            clearAllErrors();
            beginOperation("reveal");
            try {
                const data = await atLeast(
                    apiPost("/api/decrypt", { text, password }),
                    280,
                );
                endOperation();
                showSuccessReveal(data);
            } catch (error) {
                endOperation();
                showError("reveal", normalizeError(error));
            }
        });

        els.hideClear.addEventListener("click", () => {
            if (state.busy) {
                return;
            }
            els.hideMessage.value = "";
            els.hidePassword.value = "";
            els.hideCarrier.value = "This post is exactly what it looks like.";
            els.hideSpread.checked = false;
            els.hidePadding.value = "6";
            resetPasswordVisibility();
            clearAllErrors();
            updateCounts();
            resetOutput();
            applyModeCopy();
            els.hideMessage.focus();
            announce("Form cleared.");
        });

        els.sampleBtn.addEventListener("click", loadSample);
        els.trySample.addEventListener("click", loadSample);

        els.revealToggle.addEventListener("click", () => {
            if (!state.result || state.result.kind !== "hide") {
                return;
            }
            const show = els.revealToggle.getAttribute("aria-checked") !== "true";
            els.revealToggle.setAttribute("aria-checked", String(show));
            els.hiddenFieldWrap.hidden = !show;
            els.hiddenRibbon.hidden = show;
            els.revealToggle.querySelector(".switch-label").textContent = show
                ? "Hide hidden characters"
                : "Show hidden characters";
            announce(show ? "Hidden byte field shown." : "Hidden byte field hidden.");
        });

        els.copyBtn.addEventListener("click", () => {
            if (!state.result) {
                return;
            }
            const text = state.result.kind === "hide"
                ? state.result.output
                : state.result.message;
            handleCopy(els.copyBtn, text, els.copyLabel, "Copy");
        });

        for (const button of els.copyCommandButtons) {
            button.addEventListener("click", () => {
                const command = button.closest(".command");
                const code = command ? command.querySelector("code") : null;
                if (!code) {
                    return;
                }
                handleCopy(button, code.textContent, button.querySelector(".copy-label"), "Copy");
            });
        }

        for (const button of els.dialogOpenButtons) {
            button.addEventListener("click", () => {
                const dialog = document.getElementById(button.dataset.dialogOpen);
                if (dialog) {
                    openDialog(dialog, button);
                }
            });
        }

        for (const button of els.dialogCloseButtons) {
            button.addEventListener("click", () => {
                const dialog = button.closest("dialog");
                if (dialog) {
                    closeDialog(dialog);
                }
            });
        }

        for (const dialog of els.dialogs) {
            dialog.addEventListener("click", (event) => {
                if (event.target === dialog) {
                    closeDialog(dialog);
                }
            });
            dialog.addEventListener("close", () => {
                if (state.dialogTrigger) {
                    state.dialogTrigger.focus();
                    state.dialogTrigger = null;
                }
            });
        }

        els.hideMessage.addEventListener("input", updateCounts);
        els.hideCarrier.addEventListener("input", updateCounts);
        els.revealText.addEventListener("input", () => {
            updateCounts();
            hideSampleNote();
        });
        els.revealPassword.addEventListener("input", hideSampleNote);

        bindFieldErrorClear(els.hideMessage, els.hideError);
        bindFieldErrorClear(els.hidePassword, els.hideError);
        bindFieldErrorClear(els.hideCarrier, els.hideError);
        bindFieldErrorClear(els.hideSpread, els.hideError);
        bindFieldErrorClear(els.hidePadding, els.hideError);
        bindFieldErrorClear(els.revealText, els.revealError);
        bindFieldErrorClear(els.revealPassword, els.revealError);

        window.addEventListener("popstate", () => {
            const mode = new URLSearchParams(window.location.search).get("mode") === "reveal"
                ? "reveal"
                : "hide";
            setMode(mode, { updateUrl: false });
        });
    }

    async function loadHealth() {
        try {
            state.health = await getJson("/api/health");
            if (!state.health.native_bcrypt) {
                els.kdfNotice.hidden = false;
            }
        } catch {
            // The first operation will show a connection error if the server is gone.
        }
    }

    function init() {
        setupPasswordToggle(els.hidePassword, els.hidePasswordToggle);
        setupPasswordToggle(els.revealPassword, els.revealPasswordToggle);
        setupEvents();
        updateCounts();

        const mode = new URLSearchParams(window.location.search).get("mode") === "reveal"
            ? "reveal"
            : "hide";
        setMode(mode, { updateUrl: false });
        updateCounts();
        if (isFileMode()) {
            els.fileNotice.hidden = false;
        } else {
            loadHealth();
        }
    }

    init();
})();
