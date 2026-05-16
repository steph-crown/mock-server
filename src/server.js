/**
 * TEMPORARY — Mock auth + API server for CMS MFE POC demo only.
 *
 * Not a production server. Exists solely to demonstrate auth behaviour in the
 * micro-frontend architecture: login, HttpOnly cookie session, refresh token
 * rotation, protected API endpoints, and RBAC.
 *
 * In-memory state is lost on every restart. No real database, no password
 * hashing, secrets are hardcoded. Replace with a real auth service before
 * any real deployment.
 */

import { Hono } from "hono";
import { cors } from "hono/cors";
import { getCookie, setCookie, deleteCookie } from "hono/cookie";
import { SignJWT, jwtVerify } from "jose";

const app = new Hono();

app.use(
  "*",
  cors({
    origin: (origin) => {
      if (!origin) return null;
      if (
        /^https?:\/\/localhost(:\d+)?$/.test(origin) ||
        origin.endsWith(".vercel.app")
      )
        return origin;
      return null;
    },
    credentials: true,
    allowHeaders: ["Content-Type"],
    allowMethods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    maxAge: 600,
  }),
);

// ─── Secrets (hardcoded for demo only) ───────────────────────────────────────

const ACCESS_SECRET = new TextEncoder().encode(
  "demo-access-secret-not-for-production",
);
const REFRESH_SECRET = new TextEncoder().encode(
  "demo-refresh-secret-not-for-production",
);

// ─── In-memory stores ─────────────────────────────────────────────────────────

const USERS = [
  {
    id: "u1",
    name: "Admin User",
    email: "admin@demo.com",
    password: "admin123",
    roles: ["admin", "super_admin"],
  },
  {
    id: "u2",
    name: "Regular User",
    email: "user@demo.com",
    password: "user123",
    roles: [],
  },
  {
    id: "u3",
    name: "Manager",
    email: "manager@demo.com",
    password: "manager123",
    roles: ["admin"],
  },
];

const CARDS = [
  {
    id: "c1",
    holder: "John Doe",
    type: "Visa Debit",
    last4: "4521",
    status: "active",
    limit: 50000,
  },
  {
    id: "c2",
    holder: "Jane Smith",
    type: "Prepaid",
    last4: "9103",
    status: "active",
    limit: 10000,
  },
  {
    id: "c3",
    holder: "Bob Johnson",
    type: "Mastercard",
    last4: "7734",
    status: "blocked",
    limit: 25000,
  },
  {
    id: "c4",
    holder: "Alice Brown",
    type: "Visa Debit",
    last4: "2290",
    status: "expired",
    limit: 30000,
  },
];

// JTI revocation store (refresh token rotation)
const validJtis = new Map(); // jti → userId

// Per-user notification preferences
const notificationPrefs = new Map(); // userId → prefs

// ─── Helpers ──────────────────────────────────────────────────────────────────

function defaultNotificationPrefs() {
  return { email: true, push: false, digest: true };
}

function publicUser(user) {
  return { id: user.id, email: user.email, name: user.name, roles: user.roles };
}

async function issueTokens(user) {
  const jti = crypto.randomUUID();
  validJtis.set(jti, user.id);

  const payload = {
    sub: user.id,
    email: user.email,
    name: user.name,
    roles: user.roles,
  };

  const accessToken = await new SignJWT(payload)
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime("15m")
    .sign(ACCESS_SECRET);

  const refreshToken = await new SignJWT({ sub: user.id, jti })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime("7d")
    .sign(REFRESH_SECRET);

  return { accessToken, refreshToken };
}

// Checks x-forwarded-proto first so cookies are marked Secure behind a proxy
function isSecure(c) {
  return (
    c.req.header("x-forwarded-proto") === "https" ||
    c.req.url.startsWith("https:")
  );
}

function setAccessCookie(c, token) {
  setCookie(c, "access_token", token, {
    httpOnly: true,
    secure: isSecure(c),
    sameSite: "None",
    path: "/",
    maxAge: 15 * 60,
  });
}

function clearAccessCookie(c) {
  deleteCookie(c, "access_token", { path: "/" });
}

function setRefreshCookie(c, token) {
  setCookie(c, "refresh_token", token, {
    httpOnly: true,
    secure: isSecure(c),
    sameSite: "None",
    path: "/api/auth/refresh",
    maxAge: 7 * 24 * 60 * 60,
  });
}

function clearRefreshCookie(c) {
  deleteCookie(c, "refresh_token", { path: "/api/auth/refresh" });
}

// ─── Auth middleware ───────────────────────────────────────────────────────────

const requireAuth = async (c, next) => {
  const token = getCookie(c, "access_token");
  if (!token) return c.json({ error: "Not authenticated" }, 401);

  try {
    const { payload } = await jwtVerify(token, ACCESS_SECRET);
    c.set("user", payload);
    await next();
  } catch {
    return c.json({ error: "Invalid or expired access token" }, 401);
  }
};

const requireRole =
  (...roles) =>
  async (c, next) => {
    const userRoles = c.get("user")?.roles ?? [];
    if (!roles.some((r) => userRoles.includes(r))) {
      return c.json({ error: "Insufficient permissions" }, 403);
    }
    await next();
  };

// ─── Logging middleware ───────────────────────────────────────────────────────

app.use("*", async (c, next) => {
  console.log(`[mock-server] ${c.req.method} ${new URL(c.req.url).pathname}`);
  await next();
});

// ─── Auth endpoints ───────────────────────────────────────────────────────────

app.post("/api/auth/login", async (c) => {
  const { email, password } = await c.req.json().catch(() => ({}));

  const user = USERS.find((u) => u.email === email && u.password === password);
  if (!user) return c.json({ error: "Invalid email or password" }, 401);

  const { accessToken, refreshToken } = await issueTokens(user);
  setAccessCookie(c, accessToken);
  setRefreshCookie(c, refreshToken);

  return c.json({ user: publicUser(user) });
});

app.post("/api/auth/refresh", async (c) => {
  const token = getCookie(c, "refresh_token");
  if (!token) return c.json({ error: "No refresh token" }, 401);

  let payload;
  try {
    ({ payload } = await jwtVerify(token, REFRESH_SECRET));
  } catch {
    clearRefreshCookie(c);
    return c.json({ error: "Invalid or expired refresh token" }, 401);
  }

  const { sub: userId, jti } = payload;

  if (!validJtis.has(jti)) {
    clearAccessCookie(c);
    clearRefreshCookie(c);
    return c.json({ error: "Refresh token already used" }, 401);
  }

  validJtis.delete(jti);

  const user = USERS.find((u) => u.id === userId);
  if (!user) {
    clearAccessCookie(c);
    clearRefreshCookie(c);
    return c.json({ error: "User not found" }, 401);
  }

  const { accessToken, refreshToken: newRefreshToken } = await issueTokens(user);
  setAccessCookie(c, accessToken);
  setRefreshCookie(c, newRefreshToken);

  return c.json({ user: publicUser(user) });
});

app.post("/api/auth/logout", async (c) => {
  const token = getCookie(c, "refresh_token");
  if (token) {
    try {
      const { payload } = await jwtVerify(token, REFRESH_SECRET);
      validJtis.delete(payload.jti);
    } catch {
      // already expired — nothing to revoke
    }
  }
  clearAccessCookie(c);
  clearRefreshCookie(c);
  return c.json({ ok: true });
});

app.get("/api/auth/me", requireAuth, async (c) => {
  const user = USERS.find((u) => u.id === c.get("user").sub);
  if (!user) return c.json({ error: "User not found" }, 404);
  return c.json(publicUser(user));
});

// ─── Dashboard endpoints ──────────────────────────────────────────────────────

app.get("/api/dashboard/summary", requireAuth, async (c) => {
  return c.json({
    totalCards: CARDS.length,
    activeCards: CARDS.filter((card) => card.status === "active").length,
    pendingRequests: 7,
    lastUpdated: new Date().toISOString(),
    greeting: `Hello, ${c.get("user").name}`,
  });
});

app.get("/api/dashboard/activity", requireAuth, async (c) => {
  return c.json([
    {
      id: "a1",
      type: "card_issued",
      description: "Visa debit card issued to John Doe",
      time: "2 min ago",
    },
    {
      id: "a2",
      type: "card_blocked",
      description: "Mastercard blocked — reported lost",
      time: "18 min ago",
    },
    {
      id: "a3",
      type: "limit_updated",
      description: "Daily limit updated for card ending 4521",
      time: "1 hr ago",
    },
    {
      id: "a4",
      type: "card_expired",
      description: "3 cards expired — renewal reminders sent",
      time: "3 hr ago",
    },
    {
      id: "a5",
      type: "card_issued",
      description: "Prepaid card issued to Jane Smith",
      time: "5 hr ago",
    },
  ]);
});

// ─── Card management endpoints (admin only) ───────────────────────────────────

app.get(
  "/api/cards",
  requireAuth,
  requireRole("admin", "super_admin"),
  async (c) => {
    return c.json(CARDS);
  },
);

app.patch(
  "/api/cards/:id/status",
  requireAuth,
  requireRole("admin", "super_admin"),
  async (c) => {
    const card = CARDS.find((card) => card.id === c.req.param("id"));
    if (!card) return c.json({ error: "Card not found" }, 404);

    const { status } = await c.req.json().catch(() => ({}));
    if (!["active", "blocked"].includes(status)) {
      return c.json({ error: "status must be 'active' or 'blocked'" }, 400);
    }

    card.status = status;
    return c.json(card);
  },
);

// ─── Settings endpoints ───────────────────────────────────────────────────────

app.get("/api/settings/notifications", requireAuth, async (c) => {
  const prefs =
    notificationPrefs.get(c.get("user").sub) ?? defaultNotificationPrefs();
  return c.json(prefs);
});

app.patch("/api/settings/notifications", requireAuth, async (c) => {
  const current =
    notificationPrefs.get(c.get("user").sub) ?? defaultNotificationPrefs();
  const { email, push, digest } = await c.req.json().catch(() => ({}));
  const updated = {
    email: typeof email === "boolean" ? email : current.email,
    push: typeof push === "boolean" ? push : current.push,
    digest: typeof digest === "boolean" ? digest : current.digest,
  };
  notificationPrefs.set(c.get("user").sub, updated);
  return c.json(updated);
});

// ─── Admin endpoints (super_admin only) ──────────────────────────────────────

app.get(
  "/api/admin/users",
  requireAuth,
  requireRole("super_admin"),
  async (c) => {
    return c.json(USERS.map(publicUser));
  },
);

export default app;
