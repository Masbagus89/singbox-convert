
// Auto-generated Singbox config converter
export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { data } = req.body;
  if (!data) {
    return res.status(400).json({ error: 'No config provided' });
  }

  try {
    const lines = data.split(/\r?\n/).filter(Boolean);
    const configs = lines.map(parseLine).filter(Boolean);

    const outbounds = configs.map((cfg, index) => {
      const { type, server, port, uuid, alterId, security, host, path, sni, fp, ps } = cfg;
      const tag = ps ? ps.replace(/[^a-zA-Z0-9]/g, "_") : `proxy_${index + 1}`;
      return {
        type,
        tag,
        server,
        server_port: port,
        uuid,
        tls: {
          enabled: true,
          server_name: sni || host,
          insecure: false,
          utls: {
            enabled: true,
            fingerprint: fp || "chrome"
          }
        },
        packet_encoding: "packetaddr",
        transport: {
          type: "ws",
          path: path || "/",
          headers: {
            Host: [host]
          }
        }
      };
    });

    const selector = {
      tag: "select",
      type: "selector",
      default: "auto",
      outbounds: ["auto", ...outbounds.map(o => o.tag)]
    };

    const urltest = {
      tag: "auto",
      type: "urltest",
      outbounds: [...outbounds.map(o => o.tag)],
      url: "https://www.gstatic.com/generate_204",
      interval: "1m",
      tolerance: 50,
      interrupt_exist_connections: false
    };

    const finalConfig = {
      log: {
        disabled: false,
        level: "info",
        timestamp: true
      },
      experimental: {
        clash_api: {
          external_controller: "127.0.0.1:9090",
          external_ui: "ui",
          external_ui_download_url: "",
          external_ui_download_detour: "",
          secret: "",
          default_mode: "Rule"
        },
        cache_file: {
          enabled: true,
          path: "cache.db",
          store_fakeip: true
        }
      },
      dns: {
        servers: [
          {
            tag: "proxydns",
            address: "tls://8.8.8.8/dns-query",
            detour: "select"
          },
          {
            tag: "localdns",
            address: "h3://223.5.5.5/dns-query",
            detour: "direct"
          },
          {
            address: "rcode://refused",
            tag: "block"
          },
          {
            tag: "dns_fakeip",
            address: "fakeip"
          }
        ],
        rules: [
          { outbound: "any", server: "localdns", disable_cache: true },
          { clash_mode: "Global", server: "proxydns" },
          { clash_mode: "Direct", server: "localdns" },
          { rule_set: "geosite-cn", server: "localdns" },
          { rule_set: "geosite-geolocation-!cn", server: "proxydns" },
          {
            rule_set: "geosite-geolocation-!cn",
            query_type: ["A", "AAAA"],
            server: "dns_fakeip"
          }
        ],
        fakeip: {
          enabled: true,
          inet4_range: "198.18.0.0/15",
          inet6_range: "fc00::/18"
        },
        independent_cache: true,
        final: "proxydns"
      },
      inbounds: [
        {
          type: "tun",
          inet4_address: "172.19.0.1/30",
          inet6_address: "fd00::1/126",
          auto_route: true,
          strict_route: true,
          sniff: true,
          sniff_override_destination: true,
          domain_strategy: "prefer_ipv4"
        }
      ],
      outbounds: [selector, ...outbounds, { tag: "direct", type: "direct" }, { tag: "block", type: "block" }, { tag: "dns-out", type: "dns" }, urltest],
      route: {
        rule_set: [
          {
            tag: "geosite-geolocation-!cn",
            type: "remote",
            format: "binary",
            url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/geolocation-!cn.srs",
            download_detour: "select",
            update_interval: "1d"
          },
          {
            tag: "geosite-cn",
            type: "remote",
            format: "binary",
            url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/geolocation-cn.srs",
            download_detour: "select",
            update_interval: "1d"
          },
          {
            tag: "geoip-cn",
            type: "remote",
            format: "binary",
            url: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/cn.srs",
            download_detour: "select",
            update_interval: "1d"
          }
        ],
        auto_detect_interface: true,
        final: "select",
        rules: [
          { outbound: "dns-out", protocol: "dns" },
          { clash_mode: "Direct", outbound: "direct" },
          { clash_mode: "Global", outbound: "select" },
          { rule_set: "geoip-cn", outbound: "direct" },
          { rule_set: "geosite-cn", outbound: "direct" },
          { ip_is_private: true, outbound: "direct" },
          { rule_set: "geosite-geolocation-!cn", outbound: "select" }
        ]
      },
      ntp: {
        enabled: true,
        server: "time.apple.com",
        server_port: 123,
        interval: "30m",
        detour: "direct"
      }
    };

    res.setHeader('Content-Type', 'application/json');
    return res.status(200).json(finalConfig);
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Failed to convert config' });
  }

  function parseLine(str) {
    try {
      const url = new URL(str.trim());
      const type = url.protocol.replace(":", "");
      const info = url.href.split("://")[1];

      if (type === "vmess") {
        const decoded = JSON.parse(Buffer.from(info, "base64").toString());
        return {
          type: "vmess",
          server: decoded.add,
          port: parseInt(decoded.port),
          uuid: decoded.id,
          alterId: decoded.aid,
          security: decoded.security,
          host: decoded.host,
          path: decoded.path,
          sni: decoded.sni,
          fp: decoded.fp,
          ps: decoded.ps
        };
      } else if (type === "vless" || type === "trojan") {
        const [uuidAndServer, queryStr] = str.split("?");
        const [_protocol, rest] = uuidAndServer.split("://");
        const [uuid, hostPort] = rest.split("@");
        const [host, port] = hostPort.split(":");

        const query = Object.fromEntries(new URLSearchParams(queryStr));
        return {
          type,
          server: host,
          port: parseInt(port),
          uuid,
          host: query.host || host,
          path: query.path || "/",
          sni: query.sni || query.host || host,
          fp: query.fp || "chrome",
          ps: query.ps || `${host}_${port}`
        };
      }
    } catch (e) {
      return null;
    }
  }
}
