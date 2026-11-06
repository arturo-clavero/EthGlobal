import { authenticatedAwsTranscript } from './authenticated-transcript.mjs';
import { privateCredentialScanView } from '../gcp/credential-scan-view.mjs';

/** Scanner-only view; authenticate the receipt first and never store this altered view. */
export function awsCredentialScanView(receipt, expected, now = Date.now()) {
  try {
    return privateCredentialScanView(receipt, authenticatedAwsTranscript(receipt, expected, now), false);
  } catch {
    throw new Error('AWS_PRIVATE_TRANSCRIPT_INVALID');
  }
}
