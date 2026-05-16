import { serve } from "@hono/node-server";
import app from "./server.js";

const PORT = parseInt(process.env.PORT ?? "4000", 10);

serve({ fetch: app.fetch, port: PORT }, () => {
  console.log(`[mock-server] Listening on port ${PORT}`);
});
