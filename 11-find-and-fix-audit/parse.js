// parse.js — the data layer (VULNERABLE STARTER).
//
// This module turns server-style JSON into application values. It contains the
// app's DATA flaws (insecure parsing / object handling). Audit each function by
// tracing where the untrusted text comes from and what is done with the result.
//
// Entry points (driven by app.js and by verify.js):
//   parseConfig(text)         -> reads a fetched config blob
//   applySettings(text)       -> merges a fetched settings blob into defaults
//
// NOTE: there are no // TODO markers in this lab. Finding the flaws is the work.
// Trace each untrusted value to where it lands; the flaw is the unbroken path.

// App defaults that the fetched settings are merged on top of.
const DEFAULT_SETTINGS = { theme: "light", pageSize: 10 };

// Read a fetched config blob and hand back its fields.
function parseConfig(text) {
  // A bare JSON.parse: no try/catch (a malformed body throws straight through
  // the caller), and the result is read with no shape or type checks at all.
  let cfg;
  try {
    cfg = JSON.parse(text);
  } catch {
    return null;
  }

  if (cfg === null || typeof cfg !== "object" || Array.isArray(cfg)) {
    return null;
  }

  if (!Object.hasOwn(cfg, "title") || typeof cfg.title !== "string") {
    return null;
  }

  if (!Object.hasOwn(cfg, "maxItems") || !Number.isFinite(cfg.maxItems)) {
    return null;
  }

  return { title: cfg.title, maxItems: cfg.maxItems };
}

// Recursively deep-merge `source` onto `target` (so nested settings objects are
// combined rather than replaced). This is a classic prototype-pollution vector:
// when a key is "__proto__", `target[key]` reaches Object.prototype, and the
// nested merge writes onto it.
function isSettingsObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function deepMerge(target, source) {
  for (const key in source) {
    if (!Object.hasOwn(source, key)) continue;

    const value = source[key];
    if (isSettingsObject(value)) {
      if (!isSettingsObject(target[key])) {
        target[key] = Object.create(null);
      }
      deepMerge(target[key], value);
    } else {
      target[key] = value;
    }
  }

  return target;
}

function applySettings(text) {
  const blockedKeys = new Set(["__proto__", "constructor", "prototype"]);
  let parsed;

  try {
    parsed = JSON.parse(text, (key, value) => {
      if (blockedKeys.has(key)) {
        throw new SyntaxError("Blocked settings key");
      }
      return value;
    });
  } catch {
    return null;
  }

  if (!isSettingsObject(parsed)) return null;

  const settings = deepMerge(Object.create(null), DEFAULT_SETTINGS);
  return deepMerge(settings, parsed);
}

// Expose entry points for app.js and the harness.
window.DEFAULT_SETTINGS = DEFAULT_SETTINGS;
window.parseConfig = parseConfig;
window.applySettings = applySettings;
