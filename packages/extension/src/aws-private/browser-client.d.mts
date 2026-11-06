import type { PrivateProofModule, GcpPrivateSession, GcpPrivateRevealPlan } from '../offscreen/gcpPrivateWitness';

export interface AwsPrivateAttempt {
  proofId: string; pluginSha256: string; nonceMac: string;
  identityService: 'iam'; region: 'us-east-1'; issuedAt: number; expiresAt: number;
}
export interface AwsPrivateResult {
  kind: 'AWS_PRIVATE_RESULT'; version: 1; sessionIds: string[];
  proofs: Array<{ circuitId: string; proof: string; publicInputs: string[] }>;
}
export interface AwsPrivateModule extends PrivateProofModule {
  clear(): void;
  getRevealPlan(session: Readonly<GcpPrivateSession>, transcripts: { sent: Uint8Array; recv: Uint8Array }): GcpPrivateRevealPlan;
}
export function validateAwsAttempt(value: unknown, now?: number): void;
export interface AwsCredentials { accessKeyId: string; secretAccessKey: string; sessionToken: string; expiration: string }
export interface AwsCapture { credentials: AwsCredentials; accountId?: string }
export interface AwsSignedRequest { url: string; method: string; headers: Record<string, string>; body: string }
export function awsPrivateCredentials(value: unknown, now?: number): AwsCredentials;
export function awsConsoleSession(value: unknown, now?: number): { url: string; headers: Record<string, string>; accountId?: string };
export function readAwsPrivateResponse(url: string, options: RequestInit, deps?: { fetchAws?: typeof fetch; signal?: AbortSignal }): Promise<string>;
export function createAwsLocalSession(options: { attempt: AwsPrivateAttempt }): {
  prepare(capture: AwsCapture): Promise<AwsSignedRequest[]>; clear(): void;
};
export function sanitizeAwsPrivateResult(value: unknown): AwsPrivateResult;
export function createAwsPrivateModule(options: {
  attempt: AwsPrivateAttempt; workerUrl: string; onProgress?: (value: { completedProofs: number }) => void;
}): AwsPrivateModule;
