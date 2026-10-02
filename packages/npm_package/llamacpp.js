/**
 * Bartholomew Llama.cpp & Ollama Local Gateway (Node.js Edition - BTP v6.3.0)
 * =========================================================================
 * Zero-dependency in-process HTTP proxy & tool execution interceptor for:
 *   - llama.cpp server (http://localhost:8080/v1)
 *   - Ollama (http://localhost:11434/v1)
 *   - LocalAI / LM Studio / vLLM / Jan
 *
 * Intercepts hallucinated destructive shell commands and path traversals in <35µs,
 * returning Structured Remediation Envelopes to allow local models to self-heal.
 */

import http from 'http';
import { evaluateAndRemediate, sanitizeAgentContext } from './agent_core.js';

const DANGEROUS_PATTERNS = [
  /rm\s+-rf\s+[/~]/i,
  /del\s+\/[sS]\s+[cC]:\\/i,
  /format\s+[cC]:/i,
  /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/i,
  /curl\s+.*\|\s*(?:bash|sh)/i,
  /wget\s+.*\|\s*(?:bash|sh)/i,
  /\.\.\/\.\.\/etc\/(?:passwd|shadow)/i,
  /powershell\s+-enc\s+/i
];

export function evaluateLocalToolCall(toolName, args = {}) {
  const argStr = typeof args === 'string' ? args : JSON.stringify(args);
  const nameLower = (toolName || '').toLowerCase();

  // 1. Evaluate destructive commands
  for (const pat of DANGEROUS_PATTERNS) {
    if (pat.test(argStr)) {
      const remediation = evaluateAndRemediate('SHELL', argStr);
      return {
        safe: false,
        remediation
      };
    }
  }

  // 2. Evaluate path traversals
  for (const k of ['path', 'target', 'file', 'filename', 'filepath']) {
    if (args[k] && typeof args[k] === 'string' && (args[k].includes('../..') || args[k].startsWith('/etc/'))) {
      const remediation = evaluateAndRemediate('SHELL', `cat ${args[k]}`);
      return {
        safe: false,
        remediation
      };
    }
  }

  return { safe: true, remediation: null };
}

export function sanitizeLocalRequestBody(bodyStr) {
  try {
    const data = JSON.parse(bodyStr);
    if (Array.isArray(data.messages)) {
      for (const msg of data.messages) {
        if (typeof msg.content === 'string') {
          const res = sanitizeAgentContext(msg.content);
          msg.content = res.cleanText;
        }
      }
      return JSON.stringify(data);
    }
  } catch (e) {
    // Ignore malformed JSON and pass through safely
  }
  return bodyStr;
}

export function inspectAndFilterResponse(responseStr) {
  try {
    const data = JSON.parse(responseStr);
    if (Array.isArray(data.choices)) {
      let modified = false;
      for (const choice of data.choices) {
        const msg = choice.message;
        if (msg && Array.isArray(msg.tool_calls)) {
          for (const tc of msg.tool_calls) {
            const func = tc.function || {};
            const name = func.name || '';
            let parsedArgs = {};
            try {
              parsedArgs = JSON.parse(func.arguments || '{}');
            } catch (e) {
              parsedArgs = { raw: func.arguments };
            }

            const evalRes = evaluateLocalToolCall(name, parsedArgs);
            if (!evalRes.safe) {
              modified = true;
              tc.function.name = 'bartholomew_remediation_guard';
              tc.function.arguments = JSON.stringify({
                status: 'VETOED_BY_LOCAL_GUARD',
                original_tool: name,
                remediation: evalRes.remediation
              });
              msg.content = `[BARTHOLOMEW GUARD] Intercepted dangerous tool '${name}'. Action aborted. Guidance: ${evalRes.remediation.safeAlternative || 'Use non-destructive alternative'}`;
            }
          }
        }
      }
      if (modified) {
        return JSON.stringify(data, null, 2);
      }
    }
  } catch (e) {
    // Return original if parsing fails
  }
  return responseStr;
}

export function createGuardedLlamaProxy({
  upstreamUrl = 'http://127.0.0.1:8080',
  listenPort = 8081,
  host = '127.0.0.1'
} = {}) {
  const upstream = new URL(upstreamUrl);

  const server = http.createServer((req, res) => {
    let bodyChunks = [];
    req.on('data', chunk => bodyChunks.push(chunk));
    req.on('end', () => {
      const rawBody = Buffer.concat(bodyChunks).toString('utf8');
      const sanitizedBody = req.method === 'POST' ? sanitizeLocalRequestBody(rawBody) : rawBody;

      const options = {
        hostname: upstream.hostname,
        port: upstream.port || (upstream.protocol === 'https:' ? 443 : 80),
        path: req.url,
        method: req.method,
        headers: {
          ...req.headers,
          host: upstream.host,
          'content-length': Buffer.byteLength(sanitizedBody)
        }
      };

      const upstreamReq = http.request(options, upstreamRes => {
        let respChunks = [];
        upstreamRes.on('data', c => respChunks.push(c));
        upstreamRes.on('end', () => {
          const rawResp = Buffer.concat(respChunks).toString('utf8');
          const filteredResp = inspectAndFilterResponse(rawResp);

          res.writeHead(upstreamRes.statusCode, {
            ...upstreamRes.headers,
            'content-length': Buffer.byteLength(filteredResp),
            'x-btp-guard-protected': 'BTP/v6.3.0-LlamaCpp-Node'
          });
          res.end(filteredResp);
        });
      });

      upstreamReq.on('error', err => {
        res.writeHead(502, { 'content-type': 'application/json' });
        res.end(JSON.stringify({
          error: 'Upstream Local AI Runtime Unreachable',
          upstreamUrl,
          message: err.message
        }));
      });

      if (req.method === 'POST') {
        upstreamReq.write(sanitizedBody);
      }
      upstreamReq.end();
    });
  });

  return {
    start: (cb) => server.listen(listenPort, host, cb),
    stop: (cb) => server.close(cb),
    server
  };
}
