import type { PrivateProofModule } from '../offscreen/gcpPrivateWitness';
export function createAzurePrivateModule(options: { attempt: unknown; workerUrl: string; onProgress?: (value: { completedProofs: number; totalProofs: number }) => void }): PrivateProofModule & { clear(): void };
