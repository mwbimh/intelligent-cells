import { fail, isObject } from './errors.mjs';
const valid = value => typeof value === 'string' && /^[a-zA-Z0-9_-]{1,64}$/.test(value);
/** Master owner configuration only. Resource text and model arguments cannot grant these approvals. */
export function validatePiConfiguration(raw = {}) {
  if (!isObject(raw) || Object.keys(raw).some(key => !['resources','trustedExtensions'].includes(key)) ||
      !Array.isArray(raw.resources ?? []) || (raw.resources ?? []).length > 32 || !Array.isArray(raw.trustedExtensions ?? [])) fail('INVALID_CONFIG','Invalid explicit Pi resource configuration');
  const resources = (raw.resources ?? []).map(item => {
    if (!isObject(item) || Object.keys(item).some(key => !['peerId','resource'].includes(key)) || !valid(item.peerId) || !valid(item.resource)) fail('INVALID_CONFIG','Pi resources must name a configured peer and resource alias');
    return { peerId:item.peerId,resource:item.resource };
  });
  if(new Set(resources.map(item=>`${item.peerId}/${item.resource}`)).size!==resources.length)fail('INVALID_CONFIG','Duplicate Pi resource selection');
  const trustedExtensions = (raw.trustedExtensions ?? []).map(item => {
    if(!isObject(item)||item.id!=='remote-audit-v1'||item.approved!==true||Object.keys(item).some(key=>!['id','approved'].includes(key)))fail('UNTRUSTED_EXTENSION','Only the owner-approved built-in remote-audit-v1 adapter is supported; arbitrary extension code is disabled');
    return {id:item.id,approved:true};
  });
  if(trustedExtensions.length>1)fail('INVALID_CONFIG','Duplicate trusted extension');
  return {resources,trustedExtensions};
}
