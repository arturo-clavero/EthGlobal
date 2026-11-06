export const AWS_REGION = 'us-east-1';
export const AWS_HOSTS = [`sts.${AWS_REGION}.amazonaws.com`, `cloudtrail.${AWS_REGION}.amazonaws.com`, 'iam.amazonaws.com'];
export const AWS_SOURCES = ['ec2.amazonaws.com', 'lambda.amazonaws.com', 'monitoring.amazonaws.com', 'iam.amazonaws.com'];
export const AWS_LIMITS = Object.freeze({ attempts: 24, pageSize: 25, discoveryBytes: 2097152,
  selected: 6, proofs: 12, bodyBytes: 65536, deadlineMs: 300000, intervalMs: 650 });
export const AWS_EVENT_ID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;

// shortcut: one reviewed Region; add another only alongside all extension and verifier allowlists.
export function buildAwsRequest({ region = AWS_REGION, kind, identityService = 'sts', eventId, source, start, end, nextToken } = {}) {
  if (region !== AWS_REGION) throw new Error('AWS_REGION_UNSUPPORTED');
  if (!['sts', 'iam'].includes(identityService)) throw new Error('AWS_IDENTITY_INVALID');
  if (kind === 'identity') return { url: `https://${identityService === 'iam' ? AWS_HOSTS[2] : AWS_HOSTS[0]}/`, method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: identityService === 'iam' ? 'Action=GetUser&Version=2010-05-08' : 'Action=GetCallerIdentity&Version=2011-06-15' };
  let params;
  if (kind === 'event' && typeof eventId === 'string' && AWS_EVENT_ID.test(eventId)) {
    params = { LookupAttributes: [{ AttributeKey: 'EventId', AttributeValue: eventId }], MaxResults: 1 };
  } else if (kind === 'discovery' && AWS_SOURCES.includes(source) && Number.isSafeInteger(start) &&
      Number.isSafeInteger(end) && start >= 0 && end > start && end - start <= 90 * 86400 &&
      (nextToken === undefined || typeof nextToken === 'string' && nextToken.length > 0 && nextToken.length <= 8192)) {
    params = { LookupAttributes: [{ AttributeKey: 'EventSource', AttributeValue: source }],
      StartTime: start, EndTime: end, MaxResults: AWS_LIMITS.pageSize, ...(nextToken ? { NextToken: nextToken } : {}) };
  } else throw new Error('AWS_REQUEST_INVALID');
  return { url: `https://${AWS_HOSTS[1]}/`, method: 'POST',
    headers: { 'content-type': 'application/x-amz-json-1.1', 'x-amz-target': 'com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents' },
    body: JSON.stringify(params) };
}
