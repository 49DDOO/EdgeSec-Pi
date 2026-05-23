import http from "node:http";
import https from "node:https";
import { URL } from "node:url";

const bridgeApiBase =
  process.env.BRIDGE_API_BASE ||
  process.env.NEXT_PUBLIC_BRIDGE_API_BASE ||
  "http://127.0.0.1:8001";

type RouteContext = {
  params: Promise<{ path?: string[] }>;
};

function shouldSkipHeader(name: string) {
  return ["connection", "content-length", "host", "transfer-encoding"].includes(name.toLowerCase());
}

function isLocalHttps(url: URL) {
  return url.protocol === "https:" && ["127.0.0.1", "localhost"].includes(url.hostname);
}

async function proxyDashboardApi(request: Request, context: RouteContext) {
  const params = await context.params;
  const path = params.path?.join("/") || "";
  const incomingUrl = new URL(request.url);
  const target = new URL(`/api/dashboard/${path}${incomingUrl.search}`, bridgeApiBase);
  const body =
    request.method === "GET" || request.method === "HEAD"
      ? undefined
      : Buffer.from(await request.arrayBuffer());

  const headers: Record<string, string> = {};
  request.headers.forEach((value, key) => {
    if (!shouldSkipHeader(key)) headers[key] = value;
  });

  const transport = target.protocol === "https:" ? https : http;
  const response = await new Promise<Response>((resolve, reject) => {
    const proxyRequest = transport.request(
      target,
      {
        method: request.method,
        headers,
        rejectUnauthorized: !isLocalHttps(target),
      },
      (proxyResponse) => {
        const chunks: Buffer[] = [];
        proxyResponse.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
        proxyResponse.on("end", () => {
          const responseHeaders = new Headers();
          for (const [key, value] of Object.entries(proxyResponse.headers)) {
            if (!value || shouldSkipHeader(key)) continue;
            responseHeaders.set(key, Array.isArray(value) ? value.join(", ") : String(value));
          }
          resolve(
            new Response(Buffer.concat(chunks), {
              status: proxyResponse.statusCode || 502,
              headers: responseHeaders,
            })
          );
        });
      }
    );
    proxyRequest.on("error", reject);
    if (body) proxyRequest.write(body);
    proxyRequest.end();
  });

  return response;
}

export const GET = proxyDashboardApi;
export const POST = proxyDashboardApi;
export const PUT = proxyDashboardApi;
export const PATCH = proxyDashboardApi;
export const DELETE = proxyDashboardApi;
