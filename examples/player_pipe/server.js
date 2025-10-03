import { serve } from "bun";
import { WebSocketServer } from "ws";

// Serve website and player.js
serve({
  fetch(req) {
    const url = new URL(req.url);
    if (url.pathname === "/") {
      const html =
        "<!DOCTYPE html>\n" +
        "<html>\n" +
        "<head>\n" +
        "  <title>RTP PCMU Audio Player</title>\n" +
        "</head>\n" +
        "<body>\n" +
        "  <h1>RTP PCMU Audio Player</h1>\n" +
        '  <button id="play">Play</button>\n' +
        '  <script src="/player.js"></script>\n' +
        "</body>\n" +
        "</html>\n";
      return new Response(html, { headers: { "Content-Type": "text/html" } });
    }
    if (url.pathname === "/player.js") {
      return new Response(Bun.file(import.meta.dir + "/player.js"));
    }
    return new Response("Not found", { status: 404 });
  },
  port: 3000,
});

// WebSocket for browser clients (audio out)
const wssOut = new WebSocketServer({ port: 3001 });

// WebSocket for incoming audio (audio in)
const wssIn = new WebSocketServer({ port: 3002 });

wssIn.on("connection", (wsIn) => {
  wsIn.on("message", (data) => {
    wssOut.clients.forEach((client) => {
      if (client.readyState === client.OPEN) {
        client.send(data);
      }
    });
  });
});
