import type { NextConfig } from "next";

const bridgeApiBase =
  process.env.BRIDGE_API_BASE ||
  process.env.NEXT_PUBLIC_BRIDGE_API_BASE ||
  "http://127.0.0.1:8001";

if (/^https:\/\/(127\.0\.0\.1|localhost):/i.test(bridgeApiBase)) {
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
}

const nextConfig: NextConfig = {
  allowedDevOrigins: ["127.0.0.1"],
};

export default nextConfig;
