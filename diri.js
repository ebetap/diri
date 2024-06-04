const crypto = require('crypto');

// Generate RSA key pair
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});

// Function to generate AES key and IV
function generateAESKey() {
  const aesKey = crypto.randomBytes(32); // 256-bit key
  const iv = crypto.randomBytes(12); // 96-bit IV for GCM
  return { aesKey, iv };
}

// Function to encrypt AES key with RSA-OAEP
function encryptAESKey(aesKey, publicKey) {
  return crypto.publicEncrypt(
    { key: publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
    aesKey
  );
}

// Function to encrypt data with AES-GCM
function encryptData(data, aesKey, iv) {
  const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const tag = cipher.getAuthTag().toString('hex');
  return { encrypted, tag };
}

// Function to decrypt AES key with RSA-OAEP
function decryptAESKey(encryptedAesKey, privateKey) {
  return crypto.privateDecrypt(
    { key: privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
    encryptedAesKey
  );
}

// Function to decrypt data with AES-GCM
function decryptData(encrypted, tag, aesKey, iv) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, iv);
  decipher.setAuthTag(Buffer.from(tag, 'hex'));
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// Encrypt function combining all steps
function encryptMessage(data, publicKey) {
  const { aesKey, iv } = generateAESKey();
  const encryptedAesKey = encryptAESKey(aesKey, publicKey);
  const { encrypted, tag } = encryptData(data, aesKey, iv);

  return {
    encryptedAesKey: encryptedAesKey.toString('hex'),
    iv: iv.toString('hex'),
    tag,
    encryptedData: encrypted
  };
}

// Decrypt function combining all steps
function decryptMessage(encryptedPackage, privateKey) {
  const encryptedAesKey = Buffer.from(encryptedPackage.encryptedAesKey, 'hex');
  const iv = Buffer.from(encryptedPackage.iv, 'hex');
  const aesKey = decryptAESKey(encryptedAesKey, privateKey);
  return decryptData(encryptedPackage.encryptedData, encryptedPackage.tag, aesKey, iv);
}
