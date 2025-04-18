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

    
    if (config.startsWith('vless://')) {
      const url = new URL(config);
      const newOutbound = {
      "server": "172.67.5.14",
      "server_port": 443,
      "tag": "Google jkt",
      "tls": {
            "enabled": true,
            "server_name": "aio.kerker.web.id",
            "insecure": false,
            "utls": {
                  "enabled": true,
                  "fingerprint": "chrome"
            }
      },
      "packet_encoding": "packetaddr",
      "transport": {
            "headers": {
                  "Host": [
                        "aio.kerker.web.id"
                  ]
            },
            "path": "/vl=35.219.15.90=443",
            "type": "ws"
      },
      "type": "vless",
      "uuid": "065c0e0a-b419-42f8-a1f1-c1c385b10bef"
};
      newOutbound.server = url.hostname;
      newOutbound.server_port = parseInt(url.port);
      newOutbound.uuid = url.username;
      newOutbound.tls.enabled = url.searchParams.get("security") === "tls";
      newOutbound.tls.server_name = url.searchParams.get("sni") || url.hostname;
      newOutbound.transport.path = url.searchParams.get("path") || "/";
      newOutbound.transport.headers.Host = [url.searchParams.get("host") || url.hostname];

      const fullConfig = {
      "log": {
            "disabled": false,
            "level": "info",
            "timestamp": true
      },
      "experimental": {
            "clash_api": {
                  "external_controller": "127.0.0.1:9090",
                  "external_ui": "ui",
                  "external_ui_download_url": "",
                  "external_ui_download_detour": "",
                  "secret": "",
                  "default_mode": "Rule"
            },
            "cache_file": {
                  "enabled": true,
                  "path": "cache.db",
                  "store_fakeip": true
            }
      },
      "dns": {
            "servers": [
                  {
                        "tag": "proxydns",
                        "address": "tls://8.8.8.8/dns-query",
                        "detour": "select"
                  },
                  {
                        "tag": "localdns",
                        "address": "h3://223.5.5.5/dns-query",
                        "detour": "direct"
                  },
                  {
                        "address": "rcode://refused",
                        "tag": "block"
                  },
                  {
                        "tag": "dns_fakeip",
                        "address": "fakeip"
                  }
            ],
            "rules": [
                  {
                        "outbound": "any",
                        "server": "localdns",
                        "disable_cache": true
                  },
                  {
                        "clash_mode": "Global",
                        "server": "proxydns"
                  },
                  {
                        "clash_mode": "Direct",
                        "server": "localdns"
                  },
                  {
                        "rule_set": "geosite-cn",
                        "server": "localdns"
                  },
                  {
                        "rule_set": "geosite-geolocation-!cn",
                        "server": "proxydns"
                  },
                  {
                        "rule_set": "geosite-geolocation-!cn",
                        "query_type": [
                              "A",
                              "AAAA"
                        ],
                        "server": "dns_fakeip"
                  }
            ],
            "fakeip": {
                  "enabled": true,
                  "inet4_range": "198.18.0.0/15",
                  "inet6_range": "fc00::/18"
            },
            "independent_cache": true,
            "final": "proxydns"
      },
      "inbounds": [
            {
                  "type": "tun",
                  "inet4_address": "172.19.0.1/30",
                  "inet6_address": "fd00::1/126",
                  "auto_route": true,
                  "strict_route": true,
                  "sniff": true,
                  "sniff_override_destination": true,
                  "domain_strategy": "prefer_ipv4"
            }
      ],
      "outbounds": [
            {
                  "tag": "select",
                  "type": "selector",
                  "default": "auto",
                  "outbounds": [
                        "auto",
                        "Google jkt"
                  ]
            },
            {
                  "server": "172.67.5.14",
                  "server_port": 443,
                  "tag": "Google jkt",
                  "tls": {
                        "enabled": true,
                        "server_name": "aio.kerker.web.id",
                        "insecure": false,
                        "utls": {
                              "enabled": true,
                              "fingerprint": "chrome"
                        }
                  },
                  "packet_encoding": "packetaddr",
                  "transport": {
                        "headers": {
                              "Host": [
                                    "aio.kerker.web.id"
                              ]
                        },
                        "path": "/vl=35.219.15.90=443",
                        "type": "ws"
                  },
                  "type": "vless",
                  "uuid": "065c0e0a-b419-42f8-a1f1-c1c385b10bef"
            },
            {
                  "tag": "direct",
                  "type": "direct"
            },
            {
                  "tag": "block",
                  "type": "block"
            },
            {
                  "tag": "dns-out",
                  "type": "dns"
            },
            {
                  "tag": "auto",
                  "type": "urltest",
                  "outbounds": [
                        "Google jkt"
                  ],
                  "url": "https://www.gstatic.com/generate_204",
                  "interval": "1m",
                  "tolerance": 50,
                  "interrupt_exist_connections": false
            }
      ],
      "route": {
            "rule_set": [
                  {
                        "tag": "geosite-geolocation-!cn",
                        "type": "remote",
                        "format": "binary",
                        "url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/geolocation-!cn.srs",
                        "download_detour": "select",
                        "update_interval": "1d"
                  },
                  {
                        "tag": "geosite-cn",
                        "type": "remote",
                        "format": "binary",
                        "url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/geolocation-cn.srs",
                        "download_detour": "select",
                        "update_interval": "1d"
                  },
                  {
                        "tag": "geoip-cn",
                        "type": "remote",
                        "format": "binary",
                        "url": "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/cn.srs",
                        "download_detour": "select",
                        "update_interval": "1d"
                  }
            ],
            "auto_detect_interface": true,
            "final": "select",
            "rules": [
                  {
                        "outbound": "dns-out",
                        "protocol": "dns"
                  },
                  {
                        "clash_mode": "Direct",
                        "outbound": "direct"
                  },
                  {
                        "clash_mode": "Global",
                        "outbound": "select"
                  },
                  {
                        "rule_set": "geoip-cn",
                        "outbound": "direct"
                  },
                  {
                        "rule_set": "geosite-cn",
                        "outbound": "direct"
                  },
                  {
                        "ip_is_private": true,
                        "outbound": "direct"
                  },
                  {
                        "rule_set": "geosite-geolocation-!cn",
                        "outbound": "select"
                  }
            ]
      },
      "ntp": {
            "enabled": true,
            "server": "time.apple.com",
            "server_port": 123,
            "interval": "30m",
            "detour": "direct"
      }
};
      fullConfig.outbounds[1] = newOutbound;

      return new Response(JSON.stringify(fullConfig, null, 2), { status: 200 });
    }

    return new Response(JSON.stringify({ error: 'Unsupported config type' }), { status: 400 });

  } catch (err) {
    return new Response(JSON.stringify({ error: err.message || 'Internal Server Error' }), { status: 500 });
  }
}
