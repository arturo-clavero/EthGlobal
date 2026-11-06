// Activity evidence only: neither configuration correctness nor downstream outcomes.
export const AWS_ACTIVITY_PROFILES = Object.freeze([
  Object.freeze({ id: 'iam-role-trust-update', label: 'IAM role trust-policy updates',
    source: 'iam.amazonaws.com', operations: Object.freeze(['UpdateAssumeRolePolicy']), resource: 'roleName' }),
  Object.freeze({ id: 'lambda-configuration-update', label: 'Lambda configuration updates',
    source: 'lambda.amazonaws.com', operations: Object.freeze(['UpdateFunctionConfiguration20150331v2']), resource: 'functionName' }),
  Object.freeze({ id: 'security-group-ingress', label: 'Security-group ingress authorizations',
    source: 'ec2.amazonaws.com', operations: Object.freeze(['AuthorizeSecurityGroupIngress']), resource: 'groupId' }),
]);

export function awsActivityProfile(source, operation) {
  return AWS_ACTIVITY_PROFILES.find(profile => profile.source === source && profile.operations.includes(operation));
}
