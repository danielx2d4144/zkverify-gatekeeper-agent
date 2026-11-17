import { keccak256, toBytes } from 'viem';
import { FIELD_PRIME as P } from './proofs.mjs';

// The platform's task_id -> field mapping is not published and can't be derived
// offline. GK_TASKID_ENCODING picks a candidate so practice can settle it without a code change.
const kec = id => BigInt(keccak256(toBytes(id)));
export const TASK_ID_ENCODINGS = {
  keccakModP: id => kec(id) % P,
  keccakShr8: id => kec(id) >> 8n,
  utf8BigEndian: id => BigInt(`0x${Buffer.from(id, 'utf8').toString('hex') || '0'}`) % P,
  uuidTail: id => { const m = id.match(/[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}$/i); return m ? BigInt(`0x${m[0].replace(/-/g, '')}`) : kec(id) % P; },
  hexDigits: id => BigInt(`0x${id.replace(/[^0-9a-f]/gi, '') || '0'}`) % P,
};

export function encodeTaskId(id, name = process.env.GK_TASKID_ENCODING || 'keccakModP') {
  if (typeof id !== 'string' || !id) throw new Error('missing task_id');
  return TASK_ID_ENCODINGS[name](id).toString();
}
