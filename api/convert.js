import { Buffer } from 'buffer';

export async function POST(req) {
  try {
    const { config } = await req.json();

    if (!config) {
      return new Response(JSON.stringify({ error: 'No config provided' }), { status: 400 });
    }

    if (config.startsWith('vmess://')) {
      const base64 = config.replace('vmess://', '');
      const jsonStr = Buffer.from(base64, 'base64').toString('utf-8');
      let parsed;

      try {
        parsed = JSON.parse(jsonStr);
      } catch {
        return new Response(JSON.stringify({ error: 'Invalid JSON in VMess config' }), { status: 400 });
      }

      const result = {
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

      return new Response(JSON.stringify(result), { status: 200 });
    }

    if (config.startsWith('vless://') || config.startsWith('trojan://')) {
      const isTrojan = config.startsWith('trojan://');
      const url = new URL(config);
      const tag = 'proxy';

      const result = {
        outbounds: [
          {
            type: isTrojan ? 'trojan' : 'vless',
            tag,
            server: url.hostname,
            server_port: parseInt(url.port),
            uuid: isTrojan ? undefined : url.username,
            password: isTrojan ? url.username : undefined,
            tls: url.searchParams.get("security") === "tls",
            network: url.searchParams.get("type") || "tcp",
            ws_opts: url.searchParams.get("type") === "ws" ? {
              path: url.searchParams.get("path") || "/",
              headers: {
                Host: url.searchParams.get("host") || url.hostname
              }
            } : undefined
          }
        ]
      };

      return new Response(JSON.stringify(result), { status: 200 });
    }

    return new Response(JSON.stringify({ error: 'Unsupported config type' }), { status: 400 });

  } catch (err) {
    return new Response(JSON.stringify({ error: err.message || 'Internal Server Error' }), { status: 500 });
  }
}
