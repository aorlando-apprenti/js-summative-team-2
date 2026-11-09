// app.js — the settings merge under test.
//
// An app applies server-sent settings over local defaults using a recursive
// deep-merge. The merge walks the source object and assigns each key onto the
// target. That is the classic prototype-pollution sink: when the source is
// parsed from untrusted JSON and the routine does not screen keys, a single
// crafted payload poisons Object.prototype for the whole page.
//
// JSON.parse itself is safe — it stores "__proto__" as an ordinary own key and
// pollutes nothing. The vulnerability is here, in what this insecure merge does
// with that key afterward: `target["__proto__"] = ...` on a plain object
// triggers the setter and writes through to the shared prototype.
//
// `verify.js` parses a benign payload and two attack payloads, merges each, and
// checks whether Object.prototype got polluted. In this starter it does, so the
// harness reports the attack REPRODUCED.

import { DEFAULT_SETTINGS } from "./defaults.js";

function isObject(v) {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

// parseSettings deserializes the raw body. The parse is harmless on its own.
export function parseSettings(rawText) {
  return JSON.parse(rawText);
}

// The naive recursive merge. There is NO key guard, so "__proto__",
// "constructor", and "prototype" are treated like any other field — including
// inside the recursion, which is how a nested payload reaches the prototype too.
const BLOCKED_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function deepMerge(target, source) {
  for (const key in source) {
    if (!Object.hasOwn(source, key) || BLOCKED_KEYS.has(key)) {
      continue;
    }

    const value = source[key];
    if (isObject(value)) {
      if (!isObject(target[key])) {
        target[key] = Object.create(null);
      }
      deepMerge(target[key], value);
    } else {
      target[key] = value;
    }
  }

  return target;
}

// Apply a parsed settings source over a fresh copy of the defaults.
export function applySettings(parsedSource) {
  // TODOne: This is the fix point. This merge is unsafe in two ways:
  //   1. It builds onto a plain {} whose prototype is Object.prototype, so a
  //      "__proto__" / "constructor" key writes through to the shared prototype.
  //   2. It has no key guard at any level, so flat AND nested payloads pollute.
  // Harden it: build the result on Object.create(null); skip any key equal to
  // "__proto__", "constructor", or "prototype" at EVERY recursion level; copy
  // only own keys with Object.hasOwn; and (optionally) strip dangerous keys at
  // parse time with a JSON.parse reviver in parseSettings above.
  // plain object — prototype is Object.prototype
  // Seed with a shallow copy of the defaults so a real update merges over them.
  const target = deepMerge(Object.create(null), DEFAULT_SETTINGS);
  return deepMerge(target, parsedSource);
}
