import type { GcpPrivateProofModule } from '../offscreen/gcpPrivateWitness';

export function createGcpPrivateModule(options: {
  projectId: string;
  policy: { cutoff: number; windowDays: number };
  workerUrl: string;
  onProgress?: (value: { completedProofs: number }) => void;
}): GcpPrivateProofModule & { clear(): void };
