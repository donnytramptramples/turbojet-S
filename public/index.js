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
const lockButton = document.getElementById("lock-button");

let isSetupMode = false;
const REMEMBER_KEY = "sj_pw_hash_remember_v1";

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
		// network error — fall through
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
	const data = await res.json().catch(() => ({}));
	if (res.ok && data.ok) {
		localStorage.setItem(REMEMBER_KEY, hash);
		hideLock();
	} else {
		lockError.textContent = "Incorrect password.";
		lockPassword.select();
	}
});

if (lockButton) {
	lockButton.addEventListener("click", () => {
		localStorage.removeItem(REMEMBER_KEY);
		renderLock(false);
	});
}

/* ---------------- Scramjet ---------------- */
const form = document.getElementById("sj-form");
const address = document.getElementById("sj-address");
const searchEngine = document.getElementById("sj-search-engine");
const error = document.getElementById("sj-error");
const errorCode = document.getElementById("sj-error-code");
const homeScreen = document.getElementById("home-screen");

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
let swReady = null;
async function ensureSW() {
	if (!swReady) swReady = registerSW();
	await swReady;
	const wispUrl =
		(location.protocol === "https:" ? "wss" : "ws") +
		"://" +
		location.host +
		"/wisp/";
	if ((await connection.getTransport()) !== "/libcurl/index.mjs") {
		await connection.setTransport("/libcurl/index.mjs", [
			{ websocket: wispUrl },
		]);
	}
}

/* ---------------- Tabs ---------------- */
const tabsEl = document.getElementById("tabs");
const framesEl = document.getElementById("frames");
const newTabBtn = document.getElementById("new-tab");

let nextTabId = 1;
const tabs = []; // { id, title, url, frame, tabEl }
let activeTabId = null;

function activateTab(id) {
	activeTabId = id;
	for (const t of tabs) {
		const isActive = t.id === id;
		t.tabEl.classList.toggle("active", isActive);
		if (t.frame) t.frame.classList.toggle("active", isActive);
	}
	const t = getTab(id);
	if (t) {
		address.value = t.url || "";
		homeScreen.classList.toggle("hidden", !!t.frame);
	} else {
		address.value = "";
		homeScreen.classList.remove("hidden");
	}
}

function getTab(id) {
	return tabs.find((t) => t.id === id);
}

function setTabTitle(t, title) {
	t.title = title || "New tab";
	t.tabEl.querySelector(".tab-title").textContent = t.title;
	t.tabEl.title = title || "New tab";
}

function createTab(focus = true) {
	const id = nextTabId++;
	const tabEl = document.createElement("div");
	tabEl.className = "tab";
	tabEl.innerHTML = `
		<span class="tab-title">New tab</span>
		<span class="tab-close" aria-label="Close" title="Close">
			<svg viewBox="0 0 24 24" width="12" height="12"><path fill="currentColor" d="M18.3 5.71 12 12.01l-6.3-6.3-1.4 1.41 6.29 6.3-6.3 6.3 1.42 1.41 6.29-6.3 6.3 6.3 1.4-1.41-6.29-6.3 6.3-6.3z"/></svg>
		</span>`;
	tabEl.addEventListener("click", (e) => {
		if (e.target.closest(".tab-close")) {
			closeTab(id);
		} else {
			activateTab(id);
		}
	});

	const t = { id, title: "New tab", url: "", frame: null, tabEl };
	tabs.push(t);
	tabsEl.appendChild(tabEl);
	if (focus) activateTab(id);
	return t;
}

function closeTab(id) {
	const idx = tabs.findIndex((t) => t.id === id);
	if (idx === -1) return;
	const [t] = tabs.splice(idx, 1);
	t.tabEl.remove();
	if (t.frame) t.frame.remove();
	if (activeTabId === id) {
		const next = tabs[idx] || tabs[idx - 1] || null;
		if (next) activateTab(next.id);
		else {
			activeTabId = null;
			activateTab(null);
		}
	}
	if (tabs.length === 0) createTab(true);
}

newTabBtn.addEventListener("click", () => createTab(true));

// initial tab
createTab(true);

/* ---------------- Navigation ---------------- */
form.addEventListener("submit", async (event) => {
	event.preventDefault();
	error.textContent = "";
	errorCode.textContent = "";

	let t = getTab(activeTabId);
	if (!t) t = createTab(true);

	try {
		await ensureSW();
	} catch (err) {
		error.textContent = "Failed to register service worker.";
		errorCode.textContent = err.toString();
		throw err;
	}

	const url = search(address.value, searchEngine.value);
	t.url = url;

	let title;
	try {
		title = new URL(url).hostname.replace(/^www\./, "");
	} catch {
		title = address.value;
	}
	setTabTitle(t, title);

	if (!t.frame) {
		const frame = scramjet.createFrame();
		frame.frame.classList.add("sj-frame");
		framesEl.appendChild(frame.frame);
		t.frame = frame.frame;
		t._sjframe = frame;
	}
	homeScreen.classList.add("hidden");
	for (const other of tabs) {
		if (other.frame) other.frame.classList.toggle("active", other.id === t.id);
	}
	t._sjframe.go(url);
});
