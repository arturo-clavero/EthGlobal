import { PrivateWitnessRun } from './gcpPrivateWitness';
import { sanitizeAwsPrivateResult, validateAwsAttempt, createAwsLocalSession, type AwsPrivateAttempt, type AwsPrivateModule, type AwsCapture } from '../aws-private/browser-client.mjs';

export const AWS_PRIVATE_TIMEOUT_MS = 13 * 60 * 1000;

/** Compiled runner policy; page/plugin data cannot select the witness implementation. */
export class AwsPrivateWitnessRun extends PrivateWitnessRun {
  private deadline: ReturnType<typeof setTimeout>;
  private collection?: ReturnType<typeof createAwsLocalSession>;
  private attempt: AwsPrivateAttempt;
  private stopped = false;
  private readonly collectionSteps: { step: string; host: string }[];
  constructor(run: Record<string, string>, requestId: string | null, attempt: AwsPrivateAttempt, module: AwsPrivateModule) {
    validateAwsAttempt(attempt);
    if (run.proofId !== attempt.proofId || run.pluginSha256 !== attempt.pluginSha256 ||
        typeof module.getRevealPlan !== 'function') throw new Error('AWS_PRIVATE_PROVING_FAILED');
    const steps = [{ step: 'identity', host: 'iam.amazonaws.com' }, { step: 'E0', host: 'cloudtrail.us-east-1.amazonaws.com' }];
    super(run, requestId, module, {
      method: 'AWS_ACCOUNT', nonceMac: attempt.nonceMac, proveTimeoutMs: AWS_PRIVATE_TIMEOUT_MS,
      steps,
      finish(result, sessionIds) {
        const envelope = sanitizeAwsPrivateResult(result);
        if (envelope.sessionIds.length !== sessionIds.length || envelope.sessionIds.some((id, index) => id !== sessionIds[index])) throw new Error('AWS_PRIVATE_PROVING_FAILED');
        return envelope;
      },
    });
    this.collectionSteps = steps;
    this.attempt = { ...attempt };
    this.deadline = setTimeout(() => this.clear(), Math.min(AWS_PRIVATE_TIMEOUT_MS, attempt.expiresAt - Date.now()));
  }
  async collect(capture: () => Promise<AwsCapture>) {
    if (this.stopped || this.collection) throw new Error('AWS_PRIVATE_COLLECTION_FAILED');
    this.collection = createAwsLocalSession({ attempt: this.attempt });
    const value = await capture();
    try {
      const requests = await this.collection.prepare(value);
      if (this.stopped || requests.length < 2 || requests.length > 4) throw new Error('AWS_PRIVATE_COLLECTION_FAILED');
      this.collectionSteps.splice(0, this.collectionSteps.length, ...requests.map((_, index) => ({
        step: index ? `E${index - 1}` : 'identity', host: index ? 'cloudtrail.us-east-1.amazonaws.com' : 'iam.amazonaws.com',
      })));
      return requests;
    }
    finally { if (value?.credentials) for (const key of Object.keys(value.credentials)) value.credentials[key as keyof AwsCapture['credentials']] = ''; }
  }
  clear(): void {
    this.stopped = true;
    clearTimeout(this.deadline);
    this.collection?.clear();
    super.clear();
  }
}
