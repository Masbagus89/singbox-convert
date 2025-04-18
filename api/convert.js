import { Buffer } from "buffer";

export default function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    const { config } = req.body;

    if (!config) throw new Error("No config provided");

    if (config.startsWith("vmess://")) {
      const base64 = config.replace("vmess://", "");
      const jsonStr = Buffer.from(base64, "base64").toString("utf-8");
      const parsed = JSON.parse(jsonStr);

      const result = {
        inbounds: [],
        outbounds: [
          {
            type: "vmess",
            tag: "proxy",
            server: parsed.add,
            server_port: parseInt(parsed.port),
            uuid: parsed.id,
            security: "auto",
            alterId: 0,
            tls: parsed.tls === "tls",
            network: parsed.net,
            ws_opts: parsed.net === "ws" ? {
              path: parsed.path || "/",
              headers: {
                Host: parsed.host || parsed.sni
              }
            } : undefined
          }
        ]
      };
      return res.status(200).json(result);
    }

    return res.status(400).json({ error: "Unsupported config type" });

  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
}
