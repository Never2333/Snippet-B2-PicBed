const DEBUG = false;
const DEFAULT_B2_REGION = "us-west-004";
const DEFAULT_CACHE_DURATION_SECONDS = 31536000;
const ERROR_CACHE_DURATION_SECONDS = 7200;
const EMPTY_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

export default {
  async fetch(request, env, ctx) {
    try {
      if (request.method === "OPTIONS") {
        return withCors(new Response(null, {
          headers: {
            "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
            "Access-Control-Allow-Headers": "Range",
            "Access-Control-Max-Age": "86400",
          },
        }));
      }

      if (request.method !== "GET" && request.method !== "HEAD") {
        return withCors(new Response("Method Not Allowed", { status: 405 }));
      }

      const config = getConfig(env);
      const url = new URL(request.url);

      if (config.debug && url.pathname === "/__debug/sign") {
        const fileParam = url.searchParams.get("path") || url.searchParams.get("file");
        if (!fileParam) return withCors(new Response("Missing parameter: path or file", { status: 400 }));

        const expStr = url.searchParams.get("exp");
        const normalizedPath = fileParam.startsWith("/") ? fileParam : `/${fileParam}`;
        const sign = await computeSignature(normalizedPath, expStr, config.signSecret);
        return withCors(new Response(sign, {
          headers: { "Content-Type": "text/plain; charset=utf-8" },
        }));
      }

      const path = url.pathname === "/" ? "/index.html" : url.pathname;
      const sign = url.searchParams.get("sign");
      const expStr = url.searchParams.get("exp");

      if (!sign) {
        return notFound("missing-sign");
      }

      const isValid = await validateSignature(path, sign, expStr, config.signSecret);
      if (!isValid) {
        return notFound("invalid-sign");
      }

      const cacheUrl = new URL(url.origin + path);
      cacheUrl.search = "";
      const cacheKey = new Request(cacheUrl.toString(), { method: "GET" });
      const cache = caches.default;

      const hasRange = request.headers.has("Range");
      let response = hasRange ? null : await cache.match(cacheKey);

      if (!response) {
        const b2Url = `https://${config.b2Bucket}.${config.b2Endpoint}${path}`;
        const signedHeaders = await signV4(
          b2Url,
          request.method,
          config.awsAccessKeyId,
          config.awsSecretAccessKey,
          config.b2Region,
          request.headers.get("Range"),
        );

        const b2Response = await fetch(b2Url, {
          method: request.method,
          headers: signedHeaders,
        });

        if (b2Response.ok || b2Response.status === 304 || b2Response.status === 206) {
          response = new Response(b2Response.body, b2Response);
          applyFileHeaders(response, path, config.cacheDurationSeconds, b2Response.headers);
        } else if ([403, 404, 500, 502].includes(b2Response.status)) {
          const errorBody = await b2Response.text();
          response = new Response(errorBody || "Error from B2", {
            status: b2Response.status,
            statusText: b2Response.statusText,
            headers: {
              "Content-Type": "text/plain; charset=utf-8",
              "Cache-Control": `public, max-age=${ERROR_CACHE_DURATION_SECONDS}, s-maxage=${ERROR_CACHE_DURATION_SECONDS}`,
              "CDN-Cache-Control": `max-age=${ERROR_CACHE_DURATION_SECONDS}`,
              "x-snippets-cache": `stored-error-${b2Response.status}`,
            },
          });
        } else {
          return withCors(b2Response);
        }

        if (request.method === "GET" && !hasRange && response.ok) {
          try {
            await cache.put(cacheKey, response.clone());
          } catch (cacheErr) {
            response.headers.set("x-cache-put-error", String(cacheErr.message || cacheErr).replace(/\n/g, " "));
          }
        }
      } else {
        response = new Response(response.body, response);
        response.headers.set("x-snippets-cache", "hit");
      }

      if (config.debug) {
        response.headers.set("x-debug-mode", "enabled");
        response.headers.set("x-debug-request-path", path);
        response.headers.set("x-debug-b2-bucket", config.b2Bucket);
        response.headers.set("x-debug-sign-checked", "yes");
      }

      return withCors(response);
    } catch (err) {
      const message = DEBUG ? `CRITICAL ERROR\n${err.message}\n${err.stack}` : "Internal Server Error";
      return withCors(new Response(message, {
        status: 500,
        headers: { "Content-Type": "text/plain; charset=utf-8" },
      }));
    }
  },
};

function getConfig(env) {
  const b2Region = env.B2_REGION || DEFAULT_B2_REGION;
  const b2Endpoint = env.B2_ENDPOINT || `s3.${b2Region}.backblazeb2.com`;
  const cacheDurationSeconds = Number(env.CACHE_DURATION_SECONDS || DEFAULT_CACHE_DURATION_SECONDS);

  const required = {
    B2_BUCKET: env.B2_BUCKET,
    AWS_ACCESS_KEY_ID: env.AWS_ACCESS_KEY_ID,
    AWS_SECRET_ACCESS_KEY: env.AWS_SECRET_ACCESS_KEY,
    SIGN_SECRET: env.SIGN_SECRET,
  };

  for (const [key, value] of Object.entries(required)) {
    if (!value) throw new Error(`Missing required environment variable: ${key}`);
  }

  return {
    debug: env.DEBUG === "true" || DEBUG,
    b2Region,
    b2Endpoint,
    b2Bucket: env.B2_BUCKET,
    awsAccessKeyId: env.AWS_ACCESS_KEY_ID,
    awsSecretAccessKey: env.AWS_SECRET_ACCESS_KEY,
    signSecret: env.SIGN_SECRET,
    cacheDurationSeconds: Number.isFinite(cacheDurationSeconds) ? cacheDurationSeconds : DEFAULT_CACHE_DURATION_SECONDS,
  };
}

function withCors(response) {
  const newResponse = new Response(response.body, response);
  newResponse.headers.set("Access-Control-Allow-Origin", "*");
  newResponse.headers.set("Vary", "Origin");
  return newResponse;
}

function notFound(reason) {
  return withCors(new Response("Not Found", {
    status: 404,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": `public, max-age=${ERROR_CACHE_DURATION_SECONDS}, s-maxage=${ERROR_CACHE_DURATION_SECONDS}`,
      "CDN-Cache-Control": `max-age=${ERROR_CACHE_DURATION_SECONDS}`,
      "x-debug-reason": reason,
      "x-snippets-cache": reason,
    },
  }));
}

function applyFileHeaders(response, path, cacheDurationSeconds, sourceHeaders) {
  const lowerPath = path.toLowerCase();
  const ext = lowerPath.split(".").pop() || "";
  let contentType = sourceHeaders.get("Content-Type") || "application/octet-stream";

  if (contentType === "application/octet-stream" || contentType.startsWith("binary/")) {
    contentType = guessContentType(ext, contentType);
  }

  response.headers.set("Content-Type", contentType);

  const imageExts = ["jpg", "jpeg", "png", "gif", "webp", "svg", "bmp", "tif", "tiff"];
  if (imageExts.includes(ext)) {
    response.headers.set("Content-Disposition", "inline");
  }

  response.headers.set("Cache-Control", `public, max-age=${cacheDurationSeconds}, s-maxage=${cacheDurationSeconds}, immutable`);
  response.headers.set("x-snippets-cache", "stored-success");
}

function guessContentType(ext, fallback) {
  const types = {
    jpg: "image/jpeg",
    jpeg: "image/jpeg",
    png: "image/png",
    gif: "image/gif",
    webp: "image/webp",
    svg: "image/svg+xml",
    bmp: "image/bmp",
    tif: "image/tiff",
    tiff: "image/tiff",
    pdf: "application/pdf",
    txt: "text/plain; charset=utf-8",
    html: "text/html; charset=utf-8",
    htm: "text/html; charset=utf-8",
    json: "application/json",
    css: "text/css",
    js: "application/javascript",
  };
  return types[ext] || fallback;
}

async function computeSignature(path, expStr, secret) {
  const message = expStr ? `${path}|${expStr}` : path;
  return toHex(await hmac(secret, message));
}

async function validateSignature(path, providedSign, expStr, secret) {
  if (typeof providedSign !== "string" || providedSign.length < 8) return false;

  if (expStr) {
    const exp = Number(expStr);
    if (!Number.isFinite(exp)) return false;
    if (Date.now() > exp * 1000) return false;
  }

  const computed = await computeSignature(path, expStr, secret);
  return timingSafeEqual(computed, providedSign);
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let mismatch = 0;
  for (let i = 0; i < a.length; i++) {
    mismatch |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return mismatch === 0;
}

async function hmac(key, string) {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    typeof key === "string" ? new TextEncoder().encode(key) : key,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", cryptoKey, new TextEncoder().encode(string));
  return new Uint8Array(signature);
}

async function hash(string) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(string));
  return new Uint8Array(digest);
}

function toHex(buffer) {
  return Array.from(buffer).map((b) => b.toString(16).padStart(2, "0")).join("");
}

function awsUriEncode(path) {
  return path.split("/").map((segment) => {
    let decoded = segment;
    try {
      decoded = decodeURIComponent(segment);
    } catch (_) {}
    return encodeURIComponent(decoded).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
  }).join("/");
}

async function signV4(url, method, accessKeyId, secretAccessKey, region, rangeHeader) {
  const urlObj = new URL(url);
  const host = urlObj.host;
  const canonicalUri = awsUriEncode(urlObj.pathname);
  const amzDate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, "");
  const dateStr = amzDate.substring(0, 8);
  const service = "s3";

  const headerEntries = [
    ["host", host],
    ["x-amz-content-sha256", EMPTY_HASH],
    ["x-amz-date", amzDate],
  ];

  if (rangeHeader) {
    headerEntries.push(["range", rangeHeader.trim()]);
  }

  headerEntries.sort(([a], [b]) => a.localeCompare(b));

  const canonicalHeaders = headerEntries.map(([key, value]) => `${key}:${value}\n`).join("");
  const signedHeaders = headerEntries.map(([key]) => key).join(";");
  const canonicalRequest = `${method}\n${canonicalUri}\n\n${canonicalHeaders}\n${signedHeaders}\n${EMPTY_HASH}`;
  const hashedCanonicalRequest = toHex(await hash(canonicalRequest));

  const credentialScope = `${dateStr}/${region}/${service}/aws4_request`;
  const stringToSign = `AWS4-HMAC-SHA256\n${amzDate}\n${credentialScope}\n${hashedCanonicalRequest}`;

  const kDate = await hmac(`AWS4${secretAccessKey}`, dateStr);
  const kRegion = await hmac(kDate, region);
  const kService = await hmac(kRegion, service);
  const kSigning = await hmac(kService, "aws4_request");
  const signature = toHex(await hmac(kSigning, stringToSign));

  const headers = {
    Authorization: `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`,
    "x-amz-date": amzDate,
    "x-amz-content-sha256": EMPTY_HASH,
  };

  if (rangeHeader) {
    headers.Range = rangeHeader;
  }

  return headers;
}
