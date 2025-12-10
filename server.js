/**************************************************************
/* filename: "server.js"                                     *
/* Version 1.0                                               *
/* Purpose: Image edit API with multi-engine support and     *
/* whitelist validation; serves results and basic metadata.  *
/**************************************************************/
/**************************************************************
/*                                                          *
/**************************************************************/

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

/**************************************************************
/* functionSignature: getConfig (configPath)                 *
/* Loads configuration with safe defaults and deep merges.   *
/**************************************************************/
function getConfig(configPath) {
  const defaults = {
    server: { host: "0.0.0.0", port: 3300 },
    imageWhitelist: { hosts: [], paths: [] },
    engines: []
  };
  try {
    const raw = fs.readFileSync(configPath, "utf8");
    const parsed = JSON.parse(raw);
    const merged = {
      server: { ...defaults.server, ...(parsed.server || {}) },
      imageWhitelist: { ...defaults.imageWhitelist, ...(parsed.imageWhitelist || {}) },
      engines: Array.isArray(parsed.engines) ? parsed.engines : defaults.engines
    };
    return merged;
  } catch {
    return defaults;
  }
}

/**************************************************************
/* functionSignature: getEnabledEngines (config)             *
/* Returns only engines that are enabled.                    *
/**************************************************************/
function getEnabledEngines(config) {
  return (config.engines || []).filter(e => e && e.enabled !== false);
}

/**************************************************************
/* functionSignature: getDefaultEngineId (config)            *
/* Returns the default engine id or the first enabled one.   *
/**************************************************************/
function getDefaultEngineId(config) {
  const enabled = getEnabledEngines(config);
  if (!enabled.length) return null;
  const explicit = enabled.find(e => e.default);
  return (explicit || enabled[0]).id || null;
}

/**************************************************************
/* functionSignature: getEngineById (config, id)             *
/* Looks up an engine by id.                                 *
/**************************************************************/
function getEngineById(config, id) {
  return (config.engines || []).find(e => e.id === id) || null;
}

/**************************************************************
/* functionSignature: getIsOriginWhitelisted (config, url)   *
/* Checks if origin URL matches whitelist hosts and paths.    *
/**************************************************************/
function getIsOriginWhitelisted(config, origin) {
  if (!origin) return false;
  const wl = config.imageWhitelist || {};
  const hosts = wl.hosts || [];
  const paths = wl.paths || [];
  if (!hosts.length) return false;
  try {
    const u = new URL(origin);
    if (!hosts.includes(u.hostname)) return false;
    if (paths.length) return paths.some(p => u.pathname.startsWith(p));
    return true;
  } catch {
    return false;
  }
}

/**************************************************************
/* functionSignature: getEnginePublicSummary (config)        *
/* Returns non-sensitive engine info for clients.            *
/**************************************************************/
function getEnginePublicSummary(config) {
  return getEnabledEngines(config).map(e => ({
    id: e.id,
    label: e.label,
    type: e.type,
    enabled: e.enabled !== false,
    default: !!e.default
  }));
}

/**************************************************************
/* functionSignature: getFileAsBase64 (filePath)             *
/* Reads a file and returns its Base64 string.               *
/**************************************************************/
function getFileAsBase64(filePath) {
  const data = fs.readFileSync(filePath);
  return data.toString("base64");
}

/**************************************************************
/* functionSignature: getEngineMaskPath (maskFilePath)       *
/* Converts UI mask (alpha) into engine mask (B/W).          *
/**************************************************************/
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
  const outPath = maskFilePath + ".engine-mask.png";
  fs.writeFileSync(outPath, outBuffer);
  return outPath;
}

/**************************************************************
/* functionSignature: getEngineName (engine)                 *
/* Renders a human-readable engine name.                     *
/**************************************************************/
function getEngineName(engine) {
  if (!engine) return "unknown";
  return `${engine.type}:${engine.id}`;
}

/**************************************************************
/* functionSignature: setCleanupTempFiles (...files)         *
/* Deletes temp files if present.                            *
/**************************************************************/
function setCleanupTempFiles(...files) {
  for (const f of files) {
    if (f && f.path) {
      try { fs.unlinkSync(f.path); } catch {}
    }
  }
}

/**************************************************************
/* functionSignature: getServer ()                           *
/* Creates and starts the HTTP server.                       *
/**************************************************************/
function getServer() {
  const config = getConfig(CONFIG_PATH);

  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
  fs.mkdirSync(RESULTS_DIR, { recursive: true });

  const app = express();
  const upload = multer({ dest: UPLOAD_DIR });

  app.use(express.json());
  app.use(express.static(PUBLIC_DIR));

  app.get("/api/config", (_req, res) => {
    res.json({
      hostsWhitelist: (config.imageWhitelist && config.imageWhitelist.hosts) || [],
      engines: getEnginePublicSummary(config),
      defaultEngineId: getDefaultEngineId(config)
    });
  });

  app.get("/api/health", (_req, res) => {
    res.json({
      status: "ok",
      engines: getEnginePublicSummary(config),
      defaultEngineId: getDefaultEngineId(config),
      imageWhitelist: {
        hosts: (config.imageWhitelist && config.imageWhitelist.hosts) || [],
        paths: (config.imageWhitelist && config.imageWhitelist.paths) || []
      }
    });
  });

  app.post("/api/can-edit", (req, res) => {
    const origin = req.body.origin || "";
    const allowed = getIsOriginWhitelisted(config, origin);
    res.json({
      allowed,
      engines: getEnginePublicSummary(config),
      defaultEngineId: getDefaultEngineId(config)
    });
  });

  app.post(
    "/api/edit",
    upload.fields([{ name: "image", maxCount: 1 }, { name: "mask", maxCount: 1 }]),
    async (req, res) => {
      const prompt = req.body.prompt || "Edit the transparent areas of the mask in a reasonable way.";
      const origin = req.body.origin || "";
      const requestedEngineId = req.body.engineId || getDefaultEngineId(config);

      const imageFile = req.files?.image?.[0];
      const maskFile = req.files?.mask?.[0];

      if (!imageFile || !maskFile) {
        return res.status(400).json({ error: "Both 'image' and 'mask' are required." });
      }

      if (!getIsOriginWhitelisted(config, origin)) {
        setCleanupTempFiles(imageFile, maskFile);
        return res.status(403).json({
          error: "not_whitelisted",
          message: "The provided image origin is not allowed for inpainting."
        });
      }

      const engine = getEngineById(config, requestedEngineId);
      if (!engine || engine.enabled === false) {
        setCleanupTempFiles(imageFile, maskFile);
        return res.status(400).json({
          error: "invalid_engine",
          message: "Invalid or disabled engine."
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
            body: form
          });

          if (!response.ok) {
            const text = await response.text();
            throw new Error(`OpenAI error ${response.status}: ${response.statusText} – ${text}`);
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
        }

        else if (type === "a1111") {
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
            inpainting_mask_invert: 0
          };

          const response = await fetch(`${sdUrl}/sdapi/v1/img2img`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload)
          });

          const json = await response.json();
          const outB64 = json.images?.[0] || "";
          const pure = outB64.replace(/^data:image\/png;base64,/, "");
          const buffer = Buffer.from(pure, "base64");

          filename = `edit-sd-${Date.now()}.png`;
          fs.writeFileSync(path.join(RESULTS_DIR, filename), buffer);
        }

        else if (type === "replicate") {
          const apiToken = cfg.apiToken;
          const apiUrl = cfg.apiUrl || "https://api.replicate.com/v1";
          const modelVersion = cfg.modelVersion;
          if (!apiToken || !modelVersion) throw new Error("Missing Replicate apiToken or modelVersion");

          engineMaskPath = getEngineMaskPath(maskFile.path);
          const imageB64 = getFileAsBase64(imageFile.path);
          const maskB64 = getFileAsBase64(engineMaskPath);

          const predictionPayload = {
            version: modelVersion,
            input: {
              prompt,
              image: `data:image/png;base64,${imageB64}`,
              mask: `data:image/png;base64,${maskB64}`
            }
          };

          let response = await fetch(`${apiUrl}/predictions`, {
            method: "POST",
            headers: { Authorization: `Token ${apiToken}`, "Content-Type": "application/json" },
            body: JSON.stringify(predictionPayload)
          });

          let prediction = await response.json();

          while (["starting", "processing", "queued"].includes(prediction.status)) {
            await new Promise(r => setTimeout(r, 2000));
            response = await fetch(`${apiUrl}/predictions/${prediction.id}`, {
              headers: { Authorization: `Token ${apiToken}` }
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
        }

        else {
          throw new Error(`Unknown engine type: ${type}`);
        }

        setCleanupTempFiles(imageFile, maskFile, engineMaskPath && { path: engineMaskPath });
        res.json({ url: `/results/${filename}`, engine: getEngineName(engine) });
      } catch (err) {
        setCleanupTempFiles(imageFile, maskFile, engineMaskPath && { path: engineMaskPath });
        res.status(500).json({ error: "Image edit failed", details: String(err && err.message || err) });
      }
    }
  );

  const PORT = config.server.port || 3300;
  const HOST = config.server.host || "0.0.0.0";
  app.listen(PORT, HOST, () => {
    console.log(`Image tool at http://${HOST}:${PORT} – DefaultEngine=${getDefaultEngineId(config)}`);
  });

  return app;
}

getServer();
