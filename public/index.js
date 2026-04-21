"use strict";

/* ---------- Login ---------- */
const REMEMBER_KEY = "sj_pw_hash_remember_v1";
const lockOverlay = document.getElementById("lock-overlay");
const lockTitle = document.getElementById("lock-title");
const lockSub = document.getElementById("lock-sub");
const lockForm = document.getElementById("lock-form");
const lockPassword = document.getElementById("lock-password");
const lockConfirm = document.getElementById("lock-confirm");
const lockSubmit = document.getElementById("lock-submit");
const lockError = document.getElementById("lock-error");
let isSetupMode = false;

async function sha256(text) {
        const buf = await crypto.subtle.digest(
                "SHA-256",
                new TextEncoder().encode(text)
        );
        return Array.from(new Uint8Array(buf))
                .map((b) => b.toString(16).padStart(2, "0"))
                .join("");
}

function renderLock(setupMode) {
        isSetupMode = setupMode;
        lockOverlay.classList.remove("hidden");
        lockError.textContent = "";
        lockPassword.value = "";
        lockConfirm.value = "";
        if (setupMode) {
                lockTitle.textContent = "Set a password";
                lockSub.textContent =
                        "This password is permanent. It cannot be changed or reset from here.";
                lockConfirm.classList.remove("hidden");
                lockSubmit.textContent = "Create";
        } else {
                lockTitle.textContent = "Enter password";
                lockSub.textContent = "Welcome back";
                lockConfirm.classList.add("hidden");
                lockSubmit.textContent = "Unlock";
        }
        setTimeout(() => lockPassword.focus(), 50);
}

function hideLock() {
        lockOverlay.classList.add("hidden");
}

async function tryRemembered() {
        const r = localStorage.getItem(REMEMBER_KEY);
        if (!r || !/^[a-f0-9]{64}$/.test(r)) return false;
        try {
                const res = await fetch("/api/auth/verify", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ hash: r }),
                });
                const d = await res.json().catch(() => ({}));
                if (res.ok && d.ok) return true;
                localStorage.removeItem(REMEMBER_KEY);
        } catch {}
        return false;
}

(async function initLock() {
        try {
                const res = await fetch("/api/auth/status", { cache: "no-store" });
                const data = await res.json();
                if (data.set && (await tryRemembered())) {
                        hideLock();
                        return;
                }
                renderLock(!data.set);
        } catch {
                renderLock(false);
                lockError.textContent = "Cannot reach server.";
        }
})();

lockForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        lockError.textContent = "";
        const pw = lockPassword.value;
        if (isSetupMode) {
                if (pw.length < 4) {
                        lockError.textContent = "Password must be at least 4 characters.";
                        return;
                }
                if (pw !== lockConfirm.value) {
                        lockError.textContent = "Passwords do not match.";
                        return;
                }
                const hash = await sha256(pw);
                const res = await fetch("/api/auth/setup", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ hash }),
                });
                if (res.ok) {
                        localStorage.setItem(REMEMBER_KEY, hash);
                        hideLock();
                } else {
                        const d = await res.json().catch(() => ({}));
                        lockError.textContent = d.error || "Could not save password.";
                        if (res.status === 409) renderLock(false);
                }
                return;
        }
        const hash = await sha256(pw);
        const res = await fetch("/api/auth/verify", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ hash }),
        });
        const d = await res.json().catch(() => ({}));
        if (res.ok && d.ok) {
                localStorage.setItem(REMEMBER_KEY, hash);
                hideLock();
        } else {
                lockError.textContent = "Incorrect password.";
                lockPassword.select();
        }
});

/* ---------- Original Scramjet code ---------- */
/**
 * @type {HTMLFormElement}
 */
const form = document.getElementById("sj-form");
/**
 * @type {HTMLInputElement}
 */
const address = document.getElementById("sj-address");
/**
 * @type {HTMLInputElement}
 */
const searchEngine = document.getElementById("sj-search-engine");
/**
 * @type {HTMLParagraphElement}
 */
const error = document.getElementById("sj-error");
/**
 * @type {HTMLPreElement}
 */
const errorCode = document.getElementById("sj-error-code");

const { ScramjetController } = $scramjetLoadController();

const scramjet = new ScramjetController({
        files: {
                wasm: "/scram/scramjet.wasm.wasm",
                all: "/scram/scramjet.all.js",
                sync: "/scram/scramjet.sync.js",
        },
});

scramjet.init();

const connection = new BareMux.BareMuxConnection("/baremux/worker.js");

form.addEventListener("submit", async (event) => {
        event.preventDefault();

        try {
                await registerSW();
        } catch (err) {
                error.textContent = "Failed to register service worker.";
                errorCode.textContent = err.toString();
                throw err;
        }

        const url = search(address.value, searchEngine.value);

        let wispUrl =
                (location.protocol === "https:" ? "wss" : "ws") +
                "://" +
                location.host +
                "/wisp/";
        if ((await connection.getTransport()) !== "/libcurl/index.mjs") {
                await connection.setTransport("/libcurl/index.mjs", [
                        { websocket: wispUrl },
                ]);
        }
        const frame = scramjet.createFrame();
        frame.frame.id = "sj-frame";
        document.body.appendChild(frame.frame);
        frame.go(url);
});
