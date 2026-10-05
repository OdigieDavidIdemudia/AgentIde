import selfsigned from 'selfsigned';
import fs from 'fs';
import path from 'path';

const certsDir = path.join(process.cwd(), 'certs');
if (!fs.existsSync(certsDir)) {
  fs.mkdirSync(certsDir);
}

const keyPath = path.join(certsDir, 'key.pem');
const certPath = path.join(certsDir, 'cert.pem');

if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
  console.log('✅ TLS Certificates already exist in certs/');
  process.exit(0);
}

console.log('Generating self-signed TLS certificate for localhost...');
const attrs = [{ name: 'commonName', value: 'localhost' }];
const pems = selfsigned.generate(attrs, { days: 365, keySize: 2048 });

fs.writeFileSync(keyPath, pems.private);
fs.writeFileSync(certPath, pems.cert);
console.log('✅ TLS Certificates generated successfully in certs/');
