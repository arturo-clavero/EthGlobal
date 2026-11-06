const decoder = new TextDecoder('utf-8', { fatal: true });
const fail = () => { throw new Error('AWS_PRIVATE_CLIENT_INVALID'); };

export function eraseAwsInputs(value) {
  if (!value || typeof value !== 'object') return;
  if (value instanceof Uint8Array) { value.fill(0); return; }
  for (const key of Object.keys(value)) {
    if (typeof value[key] === 'number') value[key] = 0;
    else eraseAwsInputs(value[key]);
  }
}

/** Openings must already be matched to native selections and independently hashed. */
export function awsCircuitInputs({ circuitId: id, publicInputs: values }, openings) {
  const inputs = {}, take = (start, count) => values.slice(start, start + count);
  const opening = (commitment, length, capacity) => {
    const bytes = Array(capacity).fill(0);
    if (length) {
      const digest = commitment.map(byte => byte.toString(16).padStart(2, '0')).join(''), value = openings.get(digest);
      if (!(value instanceof Uint8Array) || value.length !== length + 16 || value.length > capacity) fail();
      value.forEach((byte, index) => { bytes[index] = byte; });
    }
    return bytes;
  };
  try {
    if (id === 'aws-identity-link-v1' || id === 'aws-event-link-v1') {
      const fields = id === 'aws-identity-link-v1'
        ? [['id_preimage', 144], ['arn_preimage', 528], ['path_preimage', 528], ['user_preimage', 80],
          ['actor_id_preimage', 146], ['actor_arn_preimage', 530], ['actor_account_preimage', 30], ['recipient_preimage', 30]]
        : [['request_id_preimage', 54], ['outer_id_preimage', 54], ['event_id_preimage', 54],
          ['outer_time_preimage', 528], ['event_time_preimage', 48], ['role_preimage', 82]];
      inputs.hashes = fields.map((_, index) => take(index * 32, 32)); inputs.lengths = take(fields.length * 32, fields.length);
      fields.forEach(([name, size], i) => { inputs[name] = opening(inputs.hashes[i], inputs.lengths[i], size); });
      if (id === 'aws-event-link-v1') {
        inputs.cutoff_ms = values[198];
        const bytes = Uint8Array.from(inputs.event_time_preimage.slice(0, inputs.lengths[4]));
        try { inputs.epoch_ms = Date.parse(JSON.parse(decoder.decode(bytes))); }
        finally { bytes.fill(0); }
        if (!Number.isSafeInteger(inputs.epoch_ms) || inputs.epoch_ms < 0) fail();
      }
    } else if (['headers-small-v1', 'atoms-small-v1', 'aws-escaped-atoms-small-v1'].includes(id)) {
      const count = id === 'headers-small-v1' ? 16 : 8, bridge = id.startsWith('aws-escaped-');
      const hashes = Array.from({ length: count }, (_, i) => take(i * 32, 32)), lengths = take(count * 32, count);
      if (bridge) Object.assign(inputs, { encoded_hashes: hashes, encoded_lengths: lengths,
        decoded_hashes: Array.from({ length: 8 }, (_, i) => take(264 + i * 32, 32)), decoded_lengths: take(520, 8), kinds: take(528, 8) });
      else Object.assign(inputs, { hashes, lengths, ...(id === 'atoms-small-v1' ? { kinds: take(264, 8) } : {}) });
      const name = bridge ? 'encoded_preimages' : 'preimages'; inputs[name] = [];
      for (let i = 0; i < count; i++) inputs[name].push(opening(hashes[i], lengths[i], 80));
      if (bridge) {
        inputs.decoded_preimages = [];
        for (let i = 0; i < 8; i++) inputs.decoded_preimages.push(opening(inputs.decoded_hashes[i], inputs.decoded_lengths[i], 80));
      }
    } else if (id === 'aws-escaped-atom-v1' || id === 'aws-escaped-atom-small-v1') {
      Object.assign(inputs, { encoded_commitment: take(0, 32), encoded_length: values[32], decoded_commitment: take(33, 32), decoded_length: values[65] });
      const capacity = id === 'aws-escaped-atom-v1' ? 528 : 80;
      inputs.encoded_preimage = opening(inputs.encoded_commitment, inputs.encoded_length, capacity);
      inputs.decoded_preimage = opening(inputs.decoded_commitment, inputs.decoded_length, capacity);
    } else if (['header-v1', 'atom-v1', 'aws-xml-text-v1'].includes(id)) {
      inputs.commitment = take(0, 32); inputs.length = values[32];
      inputs.preimage = opening(inputs.commitment, inputs.length, id === 'header-v1' ? 2064 : 528);
    } else fail();
    return inputs;
  } catch { eraseAwsInputs(inputs); fail(); }
}
