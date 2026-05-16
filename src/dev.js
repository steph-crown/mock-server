import { serve } from "@hono/node-server";
import app from "./server.js";

const PORT = 4000;

serve({ fetch: app.fetch, port: PORT }, () => {
  console.log(`[mock-server] Listening on http://localhost:${PORT}`);
  console.log("[mock-server] Test accounts:");
  console.log("  admin@demo.com    / admin123   → roles: admin, super_admin");
  console.log("  user@demo.com     / user123    → roles: (none)");
  console.log("  manager@demo.com  / manager123 → roles: admin");
});
