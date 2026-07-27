// Let's Learn — password gate
// Same working pattern as SKO's home base auth.js: runs on every request,
// checks for a valid signed cookie, and serves a password prompt instead of
// the page if it's missing or expired. No password is ever stored in this
// code — it lives in Netlify's environment variables.

const COOKIE_NAME = "ll_auth";
const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000;

async function sign(value, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sigBuf = await crypto.subtle.sign("HMAC", key, enc.encode(value));
  return btoa(String.fromCharCode(...new Uint8Array(sigBuf)));
}

function getCookie(request, name) {
  const header = request.headers.get("cookie") || "";
  const match = header.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  return match ? decodeURIComponent(match[1]) : null;
}

function loginPage(redirectTo, showError) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="robots" content="noindex, nofollow">
<title>Let's Learn — Sign In</title>
<style>
  body { margin:0; font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;
    background:#1c1c22; display:flex; align-items:center; justify-content:center; min-height:100vh; }
  .box { background:#fff; padding:32px 28px; border-radius:12px; width:100%; max-width:320px;
    box-shadow:0 12px 30px rgba(0,0,0,0.3); text-align:center; }
  h1 { font-size:1.05rem; color:#222; margin:0 0 4px; }
  p.sub { color:#777; font-size:0.85rem; margin:0 0 20px; }
  input[type=password] { width:100%; padding:10px 12px; border:1px solid #ccc; border-radius:8px;
    font-size:1rem; margin-bottom:12px; box-sizing:border-box; }
  button { width:100%; padding:11px; background:#333; color:#fff; border:none; border-radius:8px;
    font-size:1rem; font-weight:600; cursor:pointer; }
  button:hover { background:#111; }
  .error { color:#a33; font-size:0.85rem; margin:-4px 0 12px; }
</style>
</head>
<body>
  <form class="box" method="POST" action="/__auth">
    <h1>Let's Learn: Playwright</h1>
    <p class="sub">Enter the password to continue.</p>
    ${showError ? '<div class="error">That password didn\'t work — try again.</div>' : ""}
    <input type="hidden" name="redirect" value="${redirectTo}">
    <input type="password" name="password" placeholder="Password" autofocus required>
    <button type="submit">Enter</button>
  </form>
</body>
</html>`;
}

export default async (request, context) => {
  const url = new URL(request.url);
  const secret = Deno.env.get("AUTH_SECRET");
  const sitePassword = Deno.env.get("SITE_PASSWORD");

  // Handle login form submission
  if (request.method === "POST" && url.pathname === "/__auth") {
    const form = await request.formData();
    const submitted = form.get("password");
    const redirectTo = form.get("redirect") || "/";

    if (submitted === sitePassword) {
      const expiry = String(Date.now() + THIRTY_DAYS_MS);
      const sig = await sign(expiry, secret);
      const cookieValue = encodeURIComponent(`${expiry}.${sig}`);
      const headers = new Headers();
      headers.set("Location", redirectTo);
      headers.append(
        "Set-Cookie",
        `${COOKIE_NAME}=${cookieValue}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${THIRTY_DAYS_MS / 1000}`
      );
      return new Response(null, { status: 302, headers });
    }
    return new Response(loginPage(redirectTo, true), {
      status: 401,
      headers: { "content-type": "text/html; charset=utf-8" },
    });
  }

  // Check for a valid session cookie — this is what lets Netlify Forms
  // submissions (POST to "/") pass straight through instead of getting
  // caught as a login attempt: only POSTs to /__auth are treated as login.
  const cookieVal = getCookie(request, COOKIE_NAME);
  if (cookieVal) {
    const [expiry, sig] = cookieVal.split(".");
    if (expiry && sig) {
      const expected = await sign(expiry, secret);
      if (sig === expected && Number(expiry) > Date.now()) {
        return context.next(); // valid session — serve the real page
      }
    }
  }

  // No valid session — show the login page (works for any path, any method)
  return new Response(loginPage(url.pathname, false), {
    status: 401,
    headers: { "content-type": "text/html; charset=utf-8" },
  });
};
