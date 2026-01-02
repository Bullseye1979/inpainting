/********************************************************************
 * filename: server.js
 * version: 1.0
 * purpose: Image edit API with multi-engine support and whitelist
 *          validation; serves results and basic metadata. Includes
 *          /api/store and /api/publish, plus /results/* UI redirect
 *          when ?id=... is present, and allows /api/edit for self-
 *          hosted /results origins. Supports multi-user auth.
 ********************************************************************/

/********************************************************************
 * versioning:
 ********************************************************************/

import express from "express";
import multer from "multer";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import fetch from "node-fetch";
import FormData from "form-data";
import { PNG } from "pngjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const CONFIG_PATH = path.join(__dirname, "config.json");
const UPLOAD_DIR = path.join(__dirname, "uploads");
const PUBLIC_DIR = path.join(__dirname, "public");
const RESULTS_DIR = path.join(PUBLIC_DIR, "results");

/********************************************************************
 * functionSignature: getConfig(configPath)
 * purpose: Loads configuration with safe defaults and shallow merges
 *          across top-level config sections.
 ********************************************************************/
function getConfig(configPath) {
  const defaults = {
    server: { host: "0.0.0.0", port: 3300 },
    imageWhitelist: { hosts: [], paths: [] },
    engines: [],
    callbackApi: {
      enabled: false,
      url: "",
      method: "POST",
      headers: {},
      authHeader: "Authorization",
      authToken: "",
    },
    auth: {
      enabled: false,
      users: [],
      password: "",
      tokenTtlMinutes: 720,
    },
  };

  try {
    const raw = fs.readFileSync(configPath, "utf8");
    const parsed = JSON.parse(raw);

    return {
      server: { ...defaults.server, ...(parsed.server || {}) },
      imageWhitelist: {
        ...defaults.imageWhitelist,
        ...(parsed.imageWhitelist || {}),
      },
      engines: Array.isArray(parsed.engines) ? parsed.engines : defaults.engines,
      callbackApi: { ...defaults.callbackApi, ...(parsed.callbackApi || {}) },
      auth: { ...defaults.auth, ...(parsed.auth || {}) },
    };
  } catch {
    return defaults;
  }
}

/********************************************************************
 * functionSignature: getEnabledEngines(config)
 * purpose: Returns only engines that are enabled.
 ********************************************************************/
function getEnabledEngines(config) {
  return (config.engines || []).filter((e) => e && e.enabled !== false);
}

/********************************************************************
 * functionSignature: getDefaultEngineId(config)
 * purpose: Returns the default engine id or the first enabled one.
 ********************************************************************/
function getDefaultEngineId(config) {
  const enabled = getEnabledEngines(config);
  if (!enabled.length) return null;

  const explicit = enabled.find((e) => e.default);
  return (explicit || enabled[0]).id || null;
}

/********************************************************************
 * functionSignature: getEngineById(config, id)
 * purpose: Looks up an engine by id.
 ********************************************************************/
function getEngineById(config, id) {
  return (config.engines || []).find((e) => e.id === id) || null;
}

/********************************************************************
 * functionSignature: getIsOriginWhitelisted(config, origin)
 * purpose: Checks if origin URL matches whitelist hosts and paths.
 ********************************************************************/
function getIsOriginWhitelisted(config, origin) {
  if (!origin) return false;

  const wl = config.imageWhitelist || {};
  const hosts = wl.hosts || [];
  const paths = wl.paths || [];
  if (!hosts.length) return false;

  try {
    const u = new URL(origin);
    if (!hosts.includes(u.hostname)) return false;
    if (paths.length) return paths.some((p) => u.pathname.startsWith(p));
    return true;
  } catch {
    return false;
  }
}

/********************************************************************
 * functionSignature: getRequestHostname(req)
 * purpose: Returns hostname (no port), supports reverse proxies.
 ********************************************************************/
function getRequestHostname(req) {
  try {
    const rawHost = String(
      req.headers["x-forwarded-host"] || req.get("host") || ""
    );
    const first = rawHost.split(",")[0].trim();
    const hostNoPort = first.split(":")[0].trim();
    return String(hostNoPort || "").toLowerCase();
  } catch {
    return "";
  }
}

/********************************************************************
 * functionSignature: getIsSelfResultsOriginAllowed(req, origin)
 * purpose: Allows editing for origins hosted on this server under
 *          /results/ for common image types.
 ********************************************************************/
function getIsSelfResultsOriginAllowed(req, origin) {
  if (!origin) return false;

  try {
    const u = new URL(origin);

    const reqHost = getRequestHostname(req);
    const originHost = String(u.hostname || "").toLowerCase();
    if (!reqHost || reqHost !== originHost) return false;

    const p = String(u.pathname || "");
    if (!p.startsWith("/results/")) return false;

    if (!/\.(png|jpe?g|webp|gif|bmp)$/i.test(p)) return false;

    return true;
  } catch {
    return false;
  }
}

/********************************************************************
 * functionSignature: getEnginePublicSummary(config)
 * purpose: Returns non-sensitive engine info for clients.
 ********************************************************************/
function getEnginePublicSummary(config) {
  return getEnabledEngines(config).map((e) => ({
    id: e.id,
    label: e.label,
    type: e.type,
    enabled: e.enabled !== false,
    default: !!e.default,
  }));
}

/********************************************************************
 * functionSignature: getFileAsBase64(filePath)
 * purpose: Reads a file and returns its Base64 string.
 ********************************************************************/
function getFileAsBase64(filePath) {
  const data = fs.readFileSync(filePath);
  return data.toString("base64");
}

/********************************************************************
 * functionSignature: getEngineMaskPath(maskFilePath)
 * purpose: Converts UI mask (alpha) into engine mask (B/W).
 ********************************************************************/
function getEngineMaskPath(maskFilePath) {
  const buffer = fs.readFileSync(maskFilePath);
  const png = PNG.sync.read(buffer);
  const { data } = png;

  for (let i = 0; i < data.length; i += 4) {
    const a = data[i + 3];
    const isInpaint = a < 250;

    if (isInpaint) {
      data[i] = 255;
      data[i + 1] = 255;
      data[i + 2] = 255;
      data[i + 3] = 255;
    } else {
      data[i] = 0;
      data[i + 1] = 0;
      data[i + 2] = 0;
      data[i + 3] = 255;
    }
  }

  const outBuffer = PNG.sync.write(png);
  const outPath = `${maskFilePath}.engine-mask.png`;
  fs.writeFileSync(outPath, outBuffer);
  return outPath;
}

/********************************************************************
 * functionSignature: getEngineName(engine)
 * purpose: Renders a human-readable engine name.
 ********************************************************************/
function getEngineName(engine) {
  if (!engine) return "unknown";
  return `${engine.type}:${engine.id}`;
}

/********************************************************************
 * functionSignature: setCleanupTempFiles(...files)
 * purpose: Deletes temp files if present.
 ********************************************************************/
function setCleanupTempFiles(...files) {
  for (const f of files) {
    if (f && f.path) {
      try {
        fs.unlinkSync(f.path);
      } catch {}
    }
  }
}

/********************************************************************
 * functionSignature: getCallbackEnabled(config)
 * purpose: Returns true if callbackApi is configured.
 ********************************************************************/
function getCallbackEnabled(config) {
  const cb = config && config.callbackApi ? config.callbackApi : {};
  return !!(cb && cb.enabled && cb.url);
}

/********************************************************************
 * functionSignature: getAuthUsers(config)
 * purpose: Returns normalized auth users from env and config.
 ********************************************************************/
function getAuthUsers(config) {
  const cfg = config && config.auth ? config.auth : {};

  const fromEnvUser =
    process.env.INPAINT_AUTH_USERNAME ||
    process.env.INPAINT_USERNAME ||
    process.env.AUTH_USERNAME;

  const fromEnvPass =
    process.env.INPAINT_AUTH_PASSWORD ||
    process.env.INPAINT_PASSWORD ||
    process.env.AUTH_PASSWORD;

  const out = [];

  if (fromEnvPass) {
    out.push({
      username: String(fromEnvUser || "default").trim(),
      password: String(fromEnvPass).trim(),
    });
  }

  if (Array.isArray(cfg.users)) {
    for (const u of cfg.users) {
      const username = String(u && u.username ? u.username : "").trim();
      const password = String(u && u.password ? u.password : "").trim();
      if (username && password) out.push({ username, password });
    }
  }

  const legacy = String(cfg.password || "").trim();
  if (legacy) out.push({ username: "default", password: legacy });

  const unique = [];
  const seen = new Set();
  for (const u of out) {
    const key = `${u.username}::${u.password}`;
    if (!seen.has(key)) {
      unique.push(u);
      seen.add(key);
    }
  }

  return unique;
}

/********************************************************************
 * functionSignature: getAuthEnabled(config)
 * purpose: Returns true if password protection is enabled.
 ********************************************************************/
function getAuthEnabled(config) {
  const cfg = config && config.auth ? config.auth : {};
  const enabledFlag = cfg.enabled !== false;
  const users = getAuthUsers(config);
  return !!(enabledFlag && users.length);
}

/********************************************************************
 * functionSignature: getAuthTtlMinutes(config)
 * purpose: Returns token TTL in minutes.
 ********************************************************************/
function getAuthTtlMinutes(config) {
  const cfg = config && config.auth ? config.auth : {};
  const n = Number(cfg.tokenTtlMinutes);
  if (!Number.isFinite(n) || n <= 0) return 720;
  return Math.min(24 * 60 * 7, Math.floor(n));
}

/********************************************************************
 * functionSignature: getServer()
 * purpose: Creates and starts the HTTP server.
 ********************************************************************/
function getServer() {
  const config = getConfig(CONFIG_PATH);

  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
  fs.mkdirSync(RESULTS_DIR, { recursive: true });

  const app = express();
  const upload = multer({ dest: UPLOAD_DIR });

  const authTokens = new Map();

  /********************************************************************
   * functionSignature: getTokenFromRequest(req)
   * purpose: Extracts auth token from headers.
   ********************************************************************/
  function getTokenFromRequest(req) {
    const direct = String(req.headers["x-inpaint-auth"] || "").trim();
    if (direct) return direct;

    const auth = String(req.headers["authorization"] || "").trim();
    if (!auth) return "";

    const m = auth.match(/^Bearer\s+(.+)$/i);
    return String((m && m[1]) || "").trim();
  }

  /********************************************************************
   * functionSignature: getIsTokenValid(token)
   * purpose: Returns true if token exists and is not expired.
   ********************************************************************/
  function getIsTokenValid(token) {
    const t = String(token || "").trim();
    if (!t) return false;

    const entry = authTokens.get(t);
    if (!entry) return false;

    const now = Date.now();
    if (entry.expiresAtMs && now > entry.expiresAtMs) {
      authTokens.delete(t);
      return false;
    }

    return true;
  }

  /********************************************************************
   * functionSignature: getIsAuthed(req)
   * purpose: Returns true if request carries a valid token.
   ********************************************************************/
  function getIsAuthed(req) {
    const token = getTokenFromRequest(req);
    return getIsTokenValid(token);
  }

  /********************************************************************
   * functionSignature: issueToken(config, username)
   * purpose: Issues a new auth token and stores it with expiry.
   ********************************************************************/
  function issueToken(config, username) {
    const token = `t_${Date.now()}_${Math.random()
      .toString(16)
      .slice(2)}_${Math.random().toString(16).slice(2)}`;

    const ttlMin = getAuthTtlMinutes(config);
    const expiresAtMs = Date.now() + ttlMin * 60 * 1000;

    authTokens.set(token, { expiresAtMs, username: String(username || "") });
    return { token, expiresAtMs };
  }

  app.set("trust proxy", true);
  app.use(express.json());

  /********************************************************************
   * functionSignature: redirectResultsToUiMiddleware(req, res, next)
   * purpose: Redirects /results/* image requests to UI when ?id=...
   *          is present, loop-safe via ?raw=1, and preserves Discord
   *          preview behavior by not redirecting Discord requests.
   ********************************************************************/
  function redirectResultsToUiMiddleware(req, res, next) {
    try {
      const p = String(req.path || "");
      const q = req.query || {};

      if (String(q.raw || "") === "1") return next();

      const isResultImage =
        p.startsWith("/results/") && /\.(png|jpe?g|webp|gif|bmp)$/i.test(p);
      if (!isResultImage) return next();

      const id =
        typeof q.id === "string"
          ? q.id
          : Array.isArray(q.id)
          ? String(q.id[0] || "")
          : "";

      if (!id) return next();

      const ua = String(req.headers["user-agent"] || "").toLowerCase();
      const ref = String(req.headers["referer"] || "").toLowerCase();
      const isDiscord = ua.includes("discord") || ref.includes("discord");
      if (isDiscord) return next();

      if (ref.includes("/?src=") || ref.includes("/index.html")) return next();

      const proto = String(
        req.headers["x-forwarded-proto"] || req.protocol || "http"
      );
      const host = String(req.headers["x-forwarded-host"] || req.get("host") || "");
      if (!host) return next();

      const rawSrc = `${proto}://${host}${p}?raw=1`;
      const target = `/?src=${encodeURIComponent(rawSrc)}&id=${encodeURIComponent(
        id
      )}`;

      return res.redirect(303, target);
    } catch {
      return next();
    }
  }

  app.use(redirectResultsToUiMiddleware);
  app.use(express.static(PUBLIC_DIR));

  /********************************************************************
   * functionSignature: handleGetConfig(_req, res)
   * purpose: Returns whitelist and engine metadata for clients.
   ********************************************************************/
  function handleGetConfig(_req, res) {
    res.json({
      hostsWhitelist: (config.imageWhitelist && config.imageWhitelist.hosts) || [],
      engines: getEnginePublicSummary(config),
      defaultEngineId: getDefaultEngineId(config),
      callbackApiEnabled: getCallbackEnabled(config),
      supportsUnlock: getAuthEnabled(config),
      supportsUpload: getAuthEnabled(config),
    });
  }

  app.get("/api/config", handleGetConfig);

  /********************************************************************
   * functionSignature: handleGetHealth(_req, res)
   * purpose: Returns health status and server capability metadata.
   ********************************************************************/
  function handleGetHealth(_req, res) {
    res.json({
      status: "ok",
      engines: getEnginePublicSummary(config),
      defaultEngineId: getDefaultEngineId(config),
      callbackApiEnabled: getCallbackEnabled(config),
      supportsUnlock: getAuthEnabled(config),
      supportsUpload: getAuthEnabled(config),
      imageWhitelist: {
        hosts: (config.imageWhitelist && config.imageWhitelist.hosts) || [],
        paths: (config.imageWhitelist && config.imageWhitelist.paths) || [],
      },
    });
  }

  app.get("/api/health", handleGetHealth);

  /********************************************************************
   * functionSignature: handleCanEdit(req, res)
   * purpose: Checks whether the provided origin is allowed to edit.
   ********************************************************************/
  function handleCanEdit(req, res) {
    const origin = req.body.origin || "";
    const allowed =
      getIsOriginWhitelisted(config, origin) ||
      getIsSelfResultsOriginAllowed(req, origin) ||
      getIsAuthed(req);

    res.json({
      allowed,
      supportsUnlock: getAuthEnabled(config),
      supportsUpload: getAuthEnabled(config),
      engines: getEnginePublicSummary(config),
      defaultEngineId: getDefaultEngineId(config),
    });
  }

  app.post("/api/can-edit", handleCanEdit);

  /********************************************************************
   * functionSignature: handleUnlock(req, res)
   * purpose: Validates username/password and issues an auth token.
   ********************************************************************/
  function handleUnlock(req, res) {
    const enabled = getAuthEnabled(config);
    if (!enabled) return res.status(404).json({ error: "unlock_disabled" });

    const username = String(req.body?.username || "").trim();
    const password = String(req.body?.password || "").trim();

    if (!username || !password) {
      return res.status(400).json({ error: "username_password_required" });
    }

    const users = getAuthUsers(config);
    const ok = users.some(
      (u) => u.username === username && u.password === password
    );

    if (!ok) {
      return res.status(401).json({ error: "invalid_credentials" });
    }

    const issued = issueToken(config, username);
    return res.json({ token: issued.token, expiresAtMs: issued.expiresAtMs });
  }

  app.post("/api/unlock", handleUnlock);

  /********************************************************************
   * functionSignature: handleValidateToken(req, res)
   * purpose: Validates token from headers.
   ********************************************************************/
  function handleValidateToken(req, res) {
    const enabled = getAuthEnabled(config);
    if (!enabled) return res.json({ valid: false });

    const token = getTokenFromRequest(req);
    const valid = getIsTokenValid(token);

    return res.json({ valid });
  }

  app.post("/api/validate-token", handleValidateToken);

  /********************************************************************
   * functionSignature: handleUploadLocal(req, res)
   * purpose: Stores a local upload into /public/results (auth required).
   ********************************************************************/
  function handleUploadLocal(req, res) {
    const enabled = getAuthEnabled(config);
    if (!enabled) return res.status(404).json({ error: "upload_disabled" });

    if (!getIsAuthed(req)) {
      if (req.file && req.file.path) {
        try {
          fs.unlinkSync(req.file.path);
        } catch {}
      }
      return res.status(401).json({ error: "unauthorized" });
    }

    const imageFile = req.file;
    if (!imageFile) return res.status(400).json({ error: "image_required" });

    const original = String(imageFile.originalname || "").toLowerCase();
    const ext = path.extname(original);
    const safeExt = /\.(png|jpe?g|webp|gif|bmp)$/i.test(ext) ? ext : ".png";

    const filename = `upload-${Date.now()}${safeExt}`;
    const outPath = path.join(RESULTS_DIR, filename);

    try {
      fs.renameSync(imageFile.path, outPath);
      return res.json({ url: `/results/${filename}` });
    } catch (e) {
      try {
        fs.unlinkSync(imageFile.path);
      } catch {}

      return res.status(500).json({
        error: "upload_failed",
        details: String((e && e.message) || e),
      });
    }
  }

  app.post("/api/upload-local", upload.single("image"), handleUploadLocal);

  /********************************************************************
   * functionSignature: handleStore(req, res)
   * purpose: Stores an uploaded image into /public/results and returns
   *          a public URL (/results/...).
   ********************************************************************/
  function handleStore(req, res) {
    const imageFile = req.file;
    if (!imageFile) return res.status(400).json({ error: "image_required" });

    const filename = `client-${Date.now()}.png`;
    const outPath = path.join(RESULTS_DIR, filename);

    try {
      fs.renameSync(imageFile.path, outPath);
      return res.json({ url: `/results/${filename}` });
    } catch (e) {
      try {
        fs.unlinkSync(imageFile.path);
      } catch {}

      return res
        .status(500)
        .json({ error: "store_failed", details: String((e && e.message) || e) });
    }
  }

  app.post("/api/store", upload.single("image"), handleStore);

  /********************************************************************
   * functionSignature: handlePublish(req, res)
   * purpose: Sends { id, payload } to callback API, where payload is
   *          the edited image URL.
   ********************************************************************/
  async function handlePublish(req, res) {
    const cb = config.callbackApi || {};
    const enabled = !!(cb.enabled && cb.url);
    if (!enabled) return res.status(503).json({ error: "callback_disabled" });

    const id = String(req.body?.id || "").trim();
    const editedUrl = String(req.body?.editedUrl || "").trim();

    if (!id) return res.status(400).json({ error: "missing_id" });
    if (!editedUrl) return res.status(400).json({ error: "missing_editedUrl" });

    const apiBody = { id, payload: editedUrl };
    const headers = { "Content-Type": "application/json", ...(cb.headers || {}) };

    const authHeader = String(cb.authHeader || "Authorization");
    const authToken = String(cb.authToken || "").trim();
    if (authToken) {
      headers[authHeader] = authToken.startsWith("Bearer ")
        ? authToken
        : `Bearer ${authToken}`;
    }

    try {
      const resp = await fetch(cb.url, {
        method: String(cb.method || "POST").toUpperCase(),
        headers,
        body: JSON.stringify(apiBody),
      });

      const text = await resp.text().catch(() => "");
      if (!resp.ok) {
        return res.status(502).json({
          error: "callback_failed",
          status: resp.status,
          statusText: resp.statusText,
          body: text.slice(0, 2000),
        });
      }

      return res.json({ ok: true, forwardedStatus: resp.status });
    } catch (e) {
      return res
        .status(502)
        .json({ error: "callback_error", details: String((e && e.message) || e) });
    }
  }

  app.post("/api/publish", handlePublish);

  /********************************************************************
   * functionSignature: handleEdit(req, res)
   * purpose: Runs inpainting/edit using the selected engine and stores
   *          output under /public/results.
   ********************************************************************/
  async function handleEdit(req, res) {
    const prompt =
      req.body.prompt ||
      "Edit the transparent areas of the mask in a reasonable way.";
    const origin = req.body.origin || "";
    const requestedEngineId = req.body.engineId || getDefaultEngineId(config);

    const imageFile = req.files?.image?.[0];
    const maskFile = req.files?.mask?.[0];

    if (!imageFile || !maskFile) {
      return res
        .status(400)
        .json({ error: "Both 'image' and 'mask' are required." });
    }

    const allowedByWhitelist = getIsOriginWhitelisted(config, origin);
    const allowedBySelfResults = getIsSelfResultsOriginAllowed(req, origin);
    const allowedByAuth = getIsAuthed(req);

    if (!allowedByWhitelist && !allowedBySelfResults && !allowedByAuth) {
      setCleanupTempFiles(imageFile, maskFile);
      return res.status(403).json({
        error: "not_whitelisted",
        message:
          "The provided image origin is not allowed for inpainting (whitelist or unlock required).",
      });
    }

    const engine = getEngineById(config, requestedEngineId);
    if (!engine || engine.enabled === false) {
      setCleanupTempFiles(imageFile, maskFile);
      return res.status(400).json({
        error: "invalid_engine",
        message: "Invalid or disabled engine.",
      });
    }

    const type = engine.type;
    const cfg = engine.config || {};
    let engineMaskPath = null;

    try {
      let filename;

      if (type === "openai") {
        const apiKey = cfg.apiKey;
        const model = cfg.model || "dall-e-2";
        const size = cfg.size || "1024x1024";
        if (!apiKey) throw new Error("Missing OpenAI apiKey in config.json");

        const form = new FormData();
        form.append("model", model);
        form.append("prompt", prompt);
        form.append("image", fs.createReadStream(imageFile.path), "image.png");
        form.append("mask", fs.createReadStream(maskFile.path), "mask.png");
        form.append("size", size);
        form.append("n", "1");

        const response = await fetch("https://api.openai.com/v1/images/edits", {
          method: "POST",
          headers: { Authorization: `Bearer ${apiKey}`, ...form.getHeaders() },
          body: form,
        });

        if (!response.ok) {
          const text = await response.text();
          throw new Error(
            `OpenAI error ${response.status}: ${response.statusText} – ${text}`
          );
        }

        const json = await response.json();
        const data0 = json.data?.[0];
        let buffer;

        if (data0?.b64_json) {
          buffer = Buffer.from(data0.b64_json, "base64");
        } else if (data0?.url) {
          const imgRes = await fetch(data0.url);
          const arrayBuf = await imgRes.arrayBuffer();
          buffer = Buffer.from(arrayBuf);
        } else {
          throw new Error("OpenAI returned neither URL nor Base64");
        }

        filename = `edit-openai-${Date.now()}.png`;
        fs.writeFileSync(path.join(RESULTS_DIR, filename), buffer);
      } else if (type === "a1111") {
        const sdUrl = cfg.sdUrl || "http://127.0.0.1:7860";
        const width = cfg.width || 1024;
        const height = cfg.height || 1024;
        const steps = cfg.steps || 25;
        const cfgScale = cfg.cfgScale || 7;
        const denoisingStrength = cfg.denoisingStrength ?? 0.75;

        engineMaskPath = getEngineMaskPath(maskFile.path);
        const imageB64 = getFileAsBase64(imageFile.path);
        const maskB64 = getFileAsBase64(engineMaskPath);

        const payload = {
          init_images: [`data:image/png;base64,${imageB64}`],
          mask: `data:image/png;base64,${maskB64}`,
          prompt,
          negative_prompt: "",
          denoising_strength: denoisingStrength,
          cfg_scale: cfgScale,
          steps,
          sampler_name: "Euler a",
          width,
          height,
          inpaint_full_res: true,
          inpaint_full_res_padding: 32,
          mask_blur: 4,
          inpainting_fill: 1,
          inpaint_only_masked: true,
          inpainting_mask_invert: 0,
        };

        const response = await fetch(`${sdUrl}/sdapi/v1/img2img`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });

        const json = await response.json();
        const outB64 = json.images?.[0] || "";
        const pure = outB64.replace(/^data:image\/png;base64,/, "");
        const buffer = Buffer.from(pure, "base64");

        filename = `edit-sd-${Date.now()}.png`;
        fs.writeFileSync(path.join(RESULTS_DIR, filename), buffer);
      } else if (type === "replicate") {
        const apiToken = cfg.apiToken;
        const apiUrl = cfg.apiUrl || "https://api.replicate.com/v1";
        const modelVersion = cfg.modelVersion;
        if (!apiToken || !modelVersion) {
          throw new Error("Missing Replicate apiToken or modelVersion");
        }

        engineMaskPath = getEngineMaskPath(maskFile.path);
        const imageB64 = getFileAsBase64(imageFile.path);
        const maskB64 = getFileAsBase64(engineMaskPath);

        const predictionPayload = {
          version: modelVersion,
          input: {
            prompt,
            image: `data:image/png;base64,${imageB64}`,
            mask: `data:image/png;base64,${maskB64}`,
          },
        };

        let response = await fetch(`${apiUrl}/predictions`, {
          method: "POST",
          headers: {
            Authorization: `Token ${apiToken}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify(predictionPayload),
        });

        let prediction = await response.json();

        while (["starting", "processing", "queued"].includes(prediction.status)) {
          await new Promise((r) => setTimeout(r, 2000));
          response = await fetch(`${apiUrl}/predictions/${prediction.id}`, {
            headers: { Authorization: `Token ${apiToken}` },
          });
          prediction = await response.json();
        }

        if (prediction.status !== "succeeded") {
          throw new Error(`Replicate failed: ${prediction.status}`);
        }

        const outUrl = prediction.output?.[0];
        const imgRes = await fetch(outUrl);
        const buffer = Buffer.from(await imgRes.arrayBuffer());

        filename = `edit-replicate-${Date.now()}.png`;
        fs.writeFileSync(path.join(RESULTS_DIR, filename), buffer);
      } else {
        throw new Error(`Unknown engine type: ${type}`);
      }

      setCleanupTempFiles(
        imageFile,
        maskFile,
        engineMaskPath && { path: engineMaskPath }
      );

      res.json({ url: `/results/${filename}`, engine: getEngineName(engine) });
    } catch (err) {
      setCleanupTempFiles(
        imageFile,
        maskFile,
        engineMaskPath && { path: engineMaskPath }
      );

      res.status(500).json({
        error: "Image edit failed",
        details: String((err && err.message) || err),
      });
    }
  }

  app.post(
    "/api/edit",
    upload.fields([
      { name: "image", maxCount: 1 },
      { name: "mask", maxCount: 1 },
    ]),
    handleEdit
  );

  const PORT = config.server.port || 3300;
  const HOST = config.server.host || "0.0.0.0";

  app.listen(PORT, HOST, () => {});

  return app;
}

getServer();
