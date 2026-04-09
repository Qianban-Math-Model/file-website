function escapeHtml(input) {
  return input
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function normalizePrefix(rawPrefix) {
  if (!rawPrefix) return "";
  const trimmed = rawPrefix.replace(/^\/+/, "").replace(/\/+$/, "");
  return trimmed ? `${trimmed}/` : "";
}

function parentPrefix(prefix) {
  if (!prefix) return "";
  const withoutSlash = prefix.slice(0, -1);
  const idx = withoutSlash.lastIndexOf("/");
  if (idx === -1) return "";
  return withoutSlash.slice(0, idx + 1);
}

function nameFromKey(key, prefix) {
  return key.startsWith(prefix) ? key.slice(prefix.length) : key;
}

function encodeRfc3986(value) {
  return encodeURIComponent(value).replace(
    /[!'()*]/g,
    (ch) => `%${ch.charCodeAt(0).toString(16).toUpperCase()}`,
  );
}

function formatAmzDate(date) {
  const yyyy = date.getUTCFullYear();
  const mm = String(date.getUTCMonth() + 1).padStart(2, "0");
  const dd = String(date.getUTCDate()).padStart(2, "0");
  const hh = String(date.getUTCHours()).padStart(2, "0");
  const mi = String(date.getUTCMinutes()).padStart(2, "0");
  const ss = String(date.getUTCSeconds()).padStart(2, "0");
  return `${yyyy}${mm}${dd}T${hh}${mi}${ss}Z`;
}

function toHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function canonicalQuery(entries) {
  return entries
    .map(([key, value]) => [encodeRfc3986(key), encodeRfc3986(value)])
    .sort((a, b) => {
      if (a[0] < b[0]) return -1;
      if (a[0] > b[0]) return 1;
      if (a[1] < b[1]) return -1;
      if (a[1] > b[1]) return 1;
      return 0;
    })
    .map(([key, value]) => `${key}=${value}`)
    .join("&");
}

function parsePresignExpiry(rawValue) {
  const parsed = Number.parseInt(rawValue ?? "", 10);
  if (!Number.isFinite(parsed)) return 300;
  return Math.max(1, Math.min(604800, parsed));
}

function json(data, init = {}) {
  const headers = new Headers(init.headers);
  if (!headers.has("content-type")) {
    headers.set("content-type", "application/json; charset=utf-8");
  }
  return new Response(JSON.stringify(data), { ...init, headers });
}

function getPasswordSha256(env) {
  return String(env.PASSWORD_SHA256 || "")
    .trim()
    .toLowerCase();
}

async function verifyPassword(request, env) {
  const expected = getPasswordSha256(env);
  if (!expected) return true;

  let provided = request.headers.get("x-access-password") || "";
  if (!provided) {
    const url = new URL(request.url);
    provided = url.searchParams.get("password") || "";
  }
  if (!provided && request.method === "POST") {
    const formData = await request.clone().formData();
    provided = String(formData.get("password") || "");
  }
  if (!provided) return false;

  return (await sha256Hex(provided)) === expected;
}

async function listDirectory(bucket, prefix) {
  let cursor;
  const folders = new Set();
  const files = [];

  do {
    const page = await bucket.list({
      prefix,
      delimiter: "/",
      cursor,
    });

    for (const folderPrefix of page.delimitedPrefixes || []) {
      folders.add(folderPrefix);
    }

    for (const obj of page.objects) {
      if (obj.key !== prefix) files.push(obj.key);
    }

    cursor = page.truncated ? page.cursor : undefined;
  } while (cursor);

  return {
    folders: Array.from(folders)
      .sort((a, b) => a.localeCompare(b))
      .map((folderPrefix) => ({
        key: folderPrefix,
        name: `${nameFromKey(folderPrefix, prefix).replace(/\/$/, "")}/`,
      })),
    files: files
      .sort((a, b) => a.localeCompare(b))
      .map((key) => ({
        key,
        name: nameFromKey(key, prefix),
      })),
    parent: parentPrefix(prefix),
    prefix,
  };
}

async function hmacSha256(key, data) {
  const keyData =
    typeof key === "string" ? new TextEncoder().encode(key) : key.buffer;
  const dataBytes =
    typeof data === "string" ? new TextEncoder().encode(data) : data.buffer;
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyData,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", cryptoKey, dataBytes);
  return new Uint8Array(signature);
}

async function sha256Hex(data) {
  const dataBytes =
    typeof data === "string" ? new TextEncoder().encode(data) : data.buffer;
  return toHex(await crypto.subtle.digest("SHA-256", dataBytes));
}

async function buildPresignedDownloadUrl({
  accountId,
  bucketName,
  key,
  accessKeyId,
  secretAccessKey,
  expiresIn,
}) {
  const host = `${bucketName}.${accountId}.r2.cloudflarestorage.com`;
  const encodedKey = key.split("/").map(encodeRfc3986).join("/");
  const amzDate = formatAmzDate(new Date());
  const dateStamp = amzDate.slice(0, 8);
  const scope = `${dateStamp}/auto/s3/aws4_request`;
  const filename = key.split("/").pop() || "file";
  const disposition = `attachment; filename="${filename.replaceAll('"', "")}"`;

  const presignParams = [
    ["X-Amz-Algorithm", "AWS4-HMAC-SHA256"],
    ["X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD"],
    ["X-Amz-Credential", `${accessKeyId}/${scope}`],
    ["X-Amz-Date", amzDate],
    ["X-Amz-Expires", String(expiresIn)],
    ["X-Amz-SignedHeaders", "host"],
    ["response-content-disposition", disposition],
    ["x-id", "GetObject"],
  ];

  const canonicalQueryString = canonicalQuery(presignParams);
  const canonicalRequest = [
    "GET",
    `/${encodedKey}`,
    canonicalQueryString,
    `host:${host}\n`,
    "host",
    "UNSIGNED-PAYLOAD",
  ].join("\n");

  const stringToSign = [
    "AWS4-HMAC-SHA256",
    amzDate,
    scope,
    await sha256Hex(canonicalRequest),
  ].join("\n");

  const kDate = await hmacSha256(`AWS4${secretAccessKey}`, dateStamp);
  const kRegion = await hmacSha256(kDate, "auto");
  const kService = await hmacSha256(kRegion, "s3");
  const kSigning = await hmacSha256(kService, "aws4_request");
  const signature = toHex(await hmacSha256(kSigning, stringToSign));

  return `https://${host}/${encodedKey}?${canonicalQueryString}&X-Amz-Signature=${signature}`;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/list") {
      if (!(await verifyPassword(request, env))) {
        return json({ error: "unauthorized" }, { status: 401 });
      }

      const prefix = normalizePrefix(url.searchParams.get("path") || "");
      return json(await listDirectory(env.R2_BUCKET, prefix));
    }

    if (url.pathname === "/api/download") {
      if (!(await verifyPassword(request, env))) {
        return new Response("unauthorized", { status: 401 });
      }

      let key = url.searchParams.get("key");
      if (!key && request.method === "POST") {
        const formData = await request.formData();
        key = String(formData.get("key") || "");
      }
      if (!key) return new Response("missing key", { status: 400 });

      const r2AccountId = String(env.R2_ACCOUNT_ID || "").trim();
      const r2BucketName = String(env.R2_BUCKET_NAME || "").trim();
      const r2AccessKeyId = String(env.R2_ACCESS_KEY_ID || "").trim();
      const r2SecretAccessKey = String(env.R2_SECRET_ACCESS_KEY || "").trim();

      const canPresign =
        r2AccountId && r2BucketName && r2AccessKeyId && r2SecretAccessKey;
      if (canPresign) {
        try {
          const presignedUrl = await buildPresignedDownloadUrl({
            accountId: r2AccountId,
            bucketName: r2BucketName,
            key,
            accessKeyId: r2AccessKeyId,
            secretAccessKey: r2SecretAccessKey,
            expiresIn: parsePresignExpiry(env.R2_PRESIGN_EXPIRES),
          });
          return Response.redirect(presignedUrl, 302);
        } catch (error) {
          console.error("failed to create presigned URL", error);
        }
      }

      const object = await env.R2_BUCKET.get(key);
      if (!object) return new Response("not found", { status: 404 });

      const headers = new Headers();
      object.writeHttpMetadata(headers);
      headers.set("etag", object.httpEtag);
      headers.set(
        "content-disposition",
        `attachment; filename="${key.split("/").pop() || "file"}"`,
      );
      return new Response(object.body, { headers });
    }

    if (url.pathname !== "/") {
      return new Response("not found", { status: 404 });
    }

    const html = `<!doctype html>
<meta charset="utf-8">
<title>File Index</title>
<h3 id="heading">Locked</h3>
<div id="note">Refresh clears the password.</div>
<form id="auth-form">
  <input id="password-input" type="password" placeholder="Password" autocomplete="off" required>
  <button type="submit">OK</button>
</form>
<div id="toolbar" style="display:none">
  <a href="#" id="up-link">..</a>
  <button id="clear-button" type="button">clear password</button>
</div>
<div id="status"></div>
<div id="list"></div>
<script>
    let sessionPassword = "";
    let currentPrefix = "";
    let currentParent = "";

    const authForm = document.getElementById("auth-form");
    const passwordInput = document.getElementById("password-input");
    const toolbar = document.getElementById("toolbar");
    const upLink = document.getElementById("up-link");
    const clearButton = document.getElementById("clear-button");
    const heading = document.getElementById("heading");
    const statusEl = document.getElementById("status");
    const listEl = document.getElementById("list");

    function setStatus(message, isError = false) {
      statusEl.textContent = message;
      statusEl.style.color = isError ? "red" : "";
    }

    function resetSession(message) {
      sessionPassword = "";
      currentPrefix = "";
      currentParent = "";
      authForm.style.display = "";
      toolbar.style.display = "none";
      listEl.innerHTML = "";
      heading.textContent = "Locked";
      passwordInput.value = "";
      setStatus(message || "Password required");
    }

    async function fetchWithPassword(pathname, params) {
      const url = new URL(pathname, window.location.origin);
      if (params) {
        for (const [key, value] of Object.entries(params)) {
          url.searchParams.set(key, value);
        }
      }

      return fetch(url, {
        headers: {
          "x-access-password": sessionPassword,
        },
      });
    }

    function renderList(data) {
      currentPrefix = data.prefix || "";
      currentParent = data.parent || "";
      heading.textContent = "Index of /" + currentPrefix;
      toolbar.style.display = "";
      upLink.style.display = currentPrefix ? "" : "none";
      listEl.innerHTML = "";

      const entries = [];
      for (const folder of data.folders) {
        entries.push({
          name: folder.name,
          href: "/?path=" + encodeURIComponent(folder.key),
          onClick: () => loadDirectory(folder.key),
        });
      }

      for (const file of data.files) {
        entries.push({
          name: file.name,
          href: "/api/download?key=" + encodeURIComponent(file.key),
          onClick: () => downloadFile(file.key),
        });
      }

      if (!entries.length) {
        listEl.innerHTML = '<div class="empty">(empty)</div>';
        return;
      }

      for (const entry of entries) {
        const div = document.createElement("div");
        const link = document.createElement("a");
        link.href = entry.href;
        link.textContent = entry.name;
        link.addEventListener("click", (event) => {
          event.preventDefault();
          entry.onClick();
        });
        div.appendChild(link);
        listEl.appendChild(div);
      }
    }

    async function loadDirectory(prefix = "") {
      if (!sessionPassword) {
        resetSession("Password required");
        return;
      }

      setStatus("Loading...");
      const response = await fetchWithPassword("/api/list", { path: prefix });
      if (response.status === 401) {
        resetSession("Password incorrect or expired");
        return;
      }
      if (!response.ok) {
        setStatus("Failed to load directory", true);
        return;
      }

      const data = await response.json();
      renderList(data);
      setStatus("");
      const nextUrl = prefix ? "/?path=" + encodeURIComponent(prefix) : "/";
      window.history.replaceState({ prefix }, "", nextUrl);
    }

    async function downloadFile(key) {
      const form = document.createElement("form");
      form.method = "POST";
      form.action = "/api/download";
      form.target = "_blank";
      form.style.display = "none";

      const keyInput = document.createElement("input");
      keyInput.type = "hidden";
      keyInput.name = "key";
      keyInput.value = key;
      form.appendChild(keyInput);

      const passwordField = document.createElement("input");
      passwordField.type = "hidden";
      passwordField.name = "password";
      passwordField.value = sessionPassword;
      form.appendChild(passwordField);

      document.body.appendChild(form);
      form.submit();
      form.remove();
      setStatus("");
    }

    authForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      sessionPassword = passwordInput.value;
      authForm.style.display = "none";
      await loadDirectory(new URL(window.location.href).searchParams.get("path") || "");
    });

    upLink.addEventListener("click", (event) => {
      event.preventDefault();
      if (currentPrefix) loadDirectory(currentParent);
    });

    clearButton.addEventListener("click", () => {
      resetSession("Password cleared");
    });

    window.addEventListener("popstate", () => {
      if (!sessionPassword) return;
      loadDirectory(new URL(window.location.href).searchParams.get("path") || "");
    });

    resetSession("Password required");
  </script>
</body>
</html>`;

    return new Response(html, {
      headers: { "content-type": "text/html; charset=utf-8" },
    });
  },
};
