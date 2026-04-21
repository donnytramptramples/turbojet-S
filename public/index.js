"use strict";

/* ---------------- Lock screen ---------------- */
//
// The password is set ONCE by the first visitor and stored as a SHA-256 hash
// on the server (in `.password-hash` next to the project). After that, it can
// never be changed or reset from the UI — the only way to change it is to
// edit/delete the `.password-hash` file on the server.

const lockOverlay = document.getElementById("lock-overlay");
const lockTitle = document.getElementById("lock-title");
const lockSub = document.getElementById("lock-sub");
const lockForm = document.getElementById("lock-form");
const lockPassword = document.getElementById("lock-password");
const lockConfirm = document.getElementById("lock-confirm");
const lockSubmit = document.getElementById("lock-submit");
const lockError = document.getElementById("lock-error");
const dockLock = document.getElementById("dock-lock");

let isSetupMode = false;

async function sha256(text) {
        const enc = new TextEncoder().encode(text);
        const buf = await crypto.subtle.digest("SHA-256", enc);
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
                lockPassword.setAttribute("autocomplete", "new-password");
        } else {
                lockTitle.textContent = "Enter password";
                lockSub.textContent = "Welcome back";
                lockConfirm.classList.add("hidden");
                lockSubmit.textContent = "Unlock";
                lockPassword.setAttribute("autocomplete", "current-password");
        }
        setTimeout(() => lockPassword.focus(), 50);
}

function hideLock() {
        lockOverlay.classList.add("hidden");
}

const REMEMBER_KEY = "sj_pw_hash_remember_v1";

async function tryRememberedUnlock() {
        const remembered = localStorage.getItem(REMEMBER_KEY);
        if (!remembered || !/^[a-f0-9]{64}$/.test(remembered)) return false;
        try {
                const res = await fetch("/api/auth/verify", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ hash: remembered }),
                });
                const data = await res.json().catch(() => ({}));
                if (res.ok && data.ok) return true;
                localStorage.removeItem(REMEMBER_KEY);
        } catch {
                // network error — fall through to lock screen
        }
        return false;
}

async function initLock() {
        try {
                const res = await fetch("/api/auth/status", { cache: "no-store" });
                const data = await res.json();
                if (data.set && (await tryRememberedUnlock())) {
                        hideLock();
                        return;
                }
                renderLock(!data.set);
        } catch {
                renderLock(false);
                lockError.textContent = "Cannot reach server.";
        }
}

initLock();

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
                        const data = await res.json().catch(() => ({}));
                        lockError.textContent = data.error || "Could not save password.";
                        if (res.status === 409) {
                                // Someone else set it first — switch to unlock mode
                                renderLock(false);
                        }
                }
                return;
        }

        const hash = await sha256(pw);
        const res = await fetch("/api/auth/verify", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ hash }),
        });
        const data = await res.json().catch(() => ({}));
        if (res.ok && data.ok) {
                localStorage.setItem(REMEMBER_KEY, hash);
                hideLock();
        } else {
                lockError.textContent = "Incorrect password.";
                lockPassword.select();
        }
});

if (dockLock) {
        dockLock.addEventListener("click", () => {
                localStorage.removeItem(REMEMBER_KEY);
                renderLock(false);
        });
}

/* ---------------- Panel clock ---------------- */
const clock = document.getElementById("panel-clock");
function tickClock() {
        const d = new Date();
        const days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
        const months = [
                "Jan",
                "Feb",
                "Mar",
                "Apr",
                "May",
                "Jun",
                "Jul",
                "Aug",
                "Sep",
                "Oct",
                "Nov",
                "Dec",
        ];
        const hh = String(d.getHours()).padStart(2, "0");
        const mm = String(d.getMinutes()).padStart(2, "0");
        clock.textContent = `${days[d.getDay()]} ${months[d.getMonth()]} ${d.getDate()}  ${hh}:${mm}`;
}
tickClock();
setInterval(tickClock, 1000 * 15);

/* ---------------- Scramjet search ---------------- */
const form = document.getElementById("sj-form");
const address = document.getElementById("sj-address");
const searchEngine = document.getElementById("sj-search-engine");
const error = document.getElementById("sj-error");
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
