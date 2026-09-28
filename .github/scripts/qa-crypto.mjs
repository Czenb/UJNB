import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { existsSync, readFileSync, statSync, unlinkSync, writeFileSync } from 'node:fs';

const magic = Buffer.from('UJNB40QA1');
const aad = Buffer.from('Czenb/UJNB B40 release blackbox v1');
const maxBytes = 100 * 1024 * 1024;
const [mode, input, output, keyFile] = process.argv.slice(2);

if (!['encrypt', 'decrypt'].includes(mode) || !input || !output ||
    (mode === 'encrypt' && !keyFile) || existsSync(output)) {
  throw new Error('usage: qa-crypto.mjs encrypt input output keyFile | decrypt input output');
}
if (statSync(input).size > maxBytes) throw new Error('QA payload exceeds 100 MiB');

if (mode === 'encrypt') {
  if (existsSync(keyFile)) throw new Error('key file already exists');
  const key = randomBytes(32);
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(aad);
  const encrypted = Buffer.concat([cipher.update(readFileSync(input)), cipher.final()]);
  const payload = Buffer.concat([magic, nonce, cipher.getAuthTag(), encrypted]);
  writeFileSync(output, payload, { flag: 'wx', mode: 0o600 });
  try {
    writeFileSync(keyFile, key.toString('hex') + '\n', { flag: 'wx', mode: 0o600 });
  } catch (error) {
    unlinkSync(output);
    throw error;
  }
  console.log(`encrypted ${payload.length} bytes`);
} else {
  const secret = process.env.UJNB_B40_QA_KEY?.trim();
  if (!secret || !/^[0-9a-fA-F]{64}$/.test(secret)) throw new Error('invalid QA key');
  const payload = readFileSync(input);
  if (payload.length < magic.length + 28 ||
      !payload.subarray(0, magic.length).equals(magic)) {
    throw new Error('invalid QA payload header');
  }
  const nonce = payload.subarray(magic.length, magic.length + 12);
  const tag = payload.subarray(magic.length + 12, magic.length + 28);
  const decipher = createDecipheriv('aes-256-gcm', Buffer.from(secret, 'hex'), nonce);
  decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(payload.subarray(magic.length + 28)),
    decipher.final()]);
  writeFileSync(output, plaintext, { flag: 'wx', mode: 0o600 });
  console.log(`authenticated ${plaintext.length} bytes`);
}
