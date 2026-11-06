import { identityFixture } from './identity-fixture.mjs';
import { eventFixture, activityEventFixture } from './event-fixture.mjs';

// Synthetic fixtures only; no authenticated AWS provenance.
export function groupedFixture(families = ['iam', 'lambda', 'network']) {
  return [identityFixture(), ...families.map((family, index) => {
    const options = { blinderSeed: `group-${index}`, eventId: `aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa${index}`,
      mutateEvent(event) { event.userIdentity.arn = 'arn:aws:iam::111122223333:user/engineering/AWS_PRIVATE_USER_SENTINEL'; } };
    const fixture = family === 'iam' ? eventFixture(options) : activityEventFixture(family, options);
    fixture.expected.sessionId = `33333333-3333-4333-8333-33333333333${index}`;
    fixture.expected.step = `E${index}`;
    fixture.receipt.session.id = fixture.expected.sessionId;
    fixture.receipt.session.step = fixture.expected.step;
    return fixture;
  })];
}
