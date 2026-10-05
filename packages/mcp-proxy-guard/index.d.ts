export interface ToolCheckResult {
  allowed: boolean;
  reason: string;
  latency_us: number;
  receipt_hash: string;
}

export interface ScrubResult<T = any> {
  data: T;
  redactionCount: number;
}

export interface LicenseStatus {
  licensed: boolean;
  tier: 'COMMUNITY' | 'PRO' | 'ENTERPRISE' | 'SOVEREIGN_ENTERPRISE';
  status: string;
}

export function evaluateToolCall(toolName: string, args: Record<string, any>, options?: { passkey?: any }): ToolCheckResult;
export function scrubSecrets<T = any>(data: T): ScrubResult<T>;
export function loadLicense(): LicenseStatus;
export function getActivePasskey(): Record<string, any> | null;

