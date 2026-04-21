import { createServer } from "node:http";
import { fileURLToPath } from "url";
import { hostname } from "node:os";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { server as wisp, logging } from "@mercuryworkshop/wisp-js/server";
import Fastify from "fastify";
import fastifyStatic from "@fastify/static";

import { scramjetPath } from "@mercuryworkshop/scramjet/path";
import { libcurlPath } from "@mercuryworkshop/libcurl-transport";
import { baremuxPath } from "@mercuryworkshop/bare-mux/node";

const publicPath = fileURLToPath(new URL("../public/", import.meta.url));

// Wisp Configuration: Refer to the documentation at https://www.npmjs.com/package/@mercuryworkshop/wisp-js

logging.set_level(logging.NONE);
Object.assign(wisp.options, {
        allow_udp_streams: false,
        hostname_blacklist: [/example\.com/],
        dns_servers: ["1.1.1.3", "1.0.0.3"],
});

const fastify = Fastify({
        serverFactory: (handler) => {
                return createServer()
                        .on("request", (req, res) => {
                                res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
                                res.setHeader("Cross-Origin-Embedder-Policy", "require-corp");
                                handler(req, res);
                        })
                        .on("upgrade", (req, socket, head) => {
                                if (req.url.endsWith("/wisp/")) wisp.routeRequest(req, socket, head);
                                else socket.end();
                        });
        },
});

fastify.register(fastifyStatic, {
        root: publicPath,
        decorateReply: true,
});

// ---------- Permanent password storage ----------
const passwordFile = fileURLToPath(new URL("../.password-hash", import.meta.url));

function readStoredHash() {
        try {
                if (!existsSync(passwordFile)) return null;
                const v = readFileSync(passwordFile, "utf8").trim();
                return /^[a-f0-9]{64}$/i.test(v) ? v.toLowerCase() : null;
        } catch {
                return null;
        }
}

fastify.get("/api/auth/status", async () => {
        return { set: readStoredHash() !== null };
});

fastify.post("/api/auth/setup", async (req, reply) => {
        const existing = readStoredHash();
        if (existing) {
                return reply.code(409).send({ ok: false, error: "Password already set." });
        }
        const body = req.body || {};
        const hash = typeof body.hash === "string" ? body.hash.trim().toLowerCase() : "";
        if (!/^[a-f0-9]{64}$/.test(hash)) {
                return reply.code(400).send({ ok: false, error: "Invalid hash." });
        }
        writeFileSync(passwordFile, hash + "\n", { mode: 0o600 });
        return { ok: true };
});

fastify.post("/api/auth/verify", async (req, reply) => {
        const stored = readStoredHash();
        if (!stored) {
                return reply.code(409).send({ ok: false, error: "No password set." });
        }
        const body = req.body || {};
        const hash = typeof body.hash === "string" ? body.hash.trim().toLowerCase() : "";
        return { ok: hash === stored };
});

fastify.register(fastifyStatic, {
        root: scramjetPath,
        prefix: "/scram/",
        decorateReply: false,
});

fastify.register(fastifyStatic, {
        root: libcurlPath,
        prefix: "/libcurl/",
        decorateReply: false,
});

fastify.register(fastifyStatic, {
        root: baremuxPath,
        prefix: "/baremux/",
        decorateReply: false,
});

fastify.setNotFoundHandler((res, reply) => {
        return reply.code(404).type("text/html").sendFile("404.html");
});

fastify.server.on("listening", () => {
        const address = fastify.server.address();

        // by default we are listening on 0.0.0.0 (every interface)
        // we just need to list a few
        console.log("Listening on:");
        console.log(`\thttp://localhost:${address.port}`);
        console.log(`\thttp://${hostname()}:${address.port}`);
        console.log(
                `\thttp://${
                        address.family === "IPv6" ? `[${address.address}]` : address.address
                }:${address.port}`
        );
});

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

function shutdown() {
        console.log("SIGTERM signal received: closing HTTP server");
        fastify.close();
        process.exit(0);
}

let port = parseInt(process.env.PORT || "");

if (isNaN(port)) port = 8080;

fastify.listen({
        port: port,
        host: "0.0.0.0",
});
