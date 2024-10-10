const crypto = require('crypto');
const jwt = require('jsonwebtoken');

console.log('Authentication Flow Proof of Concept\n');

function generateKeyPair() {
  return crypto.generateKeyPairSync('ec', {
    namedCurve: 'P-256',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
}

console.log('Generating keys...');
const deelKeys = generateKeyPair();
const revolutKeys = generateKeyPair();

console.log('Deel Public Key (truncated):', deelKeys.publicKey.split('\n').slice(1, -1).join('').substr(0, 32) + '...');
console.log('Revolut Public Key (truncated):', revolutKeys.publicKey.split('\n').slice(1, -1).join('').substr(0, 32) + '...');

const deel = {
  generateUrlToken: (userId, clientId, contractId) => {
    const payload = { user_id: userId, white_label_client_id: clientId, contract_id: contractId };
    return jwt.sign(payload, deelKeys.privateKey, { algorithm: 'ES256', expiresIn: '15m' });
  },
  verifySignature: (urlToken, signature) => {
    try {
      const verify = crypto.createVerify('SHA256');
      verify.update(urlToken);
      return verify.verify(revolutKeys.publicKey, signature, 'base64');
    } catch (error) {
      console.error('Signature verification failed:', error.message);
      return false;
    }
  },
  generateAuthToken: (userId, clientId, contractId, scopes) => {
    const payload = { user_id: userId, white_label_org_id: clientId, contract_id: contractId, scopes };
    return jwt.sign(payload, deelKeys.privateKey, { algorithm: 'ES256', expiresIn: '7d' });
  },
  validateAuthToken: (token) => {
    try {
      return jwt.verify(token, deelKeys.publicKey, { algorithms: ['ES256'] });
    } catch (error) {
      console.error('Token validation failed:', error.message);
      return null;
    }
  }
};

const revolut = {
  signToken: (urlToken) => {
    try {
      const sign = crypto.createSign('SHA256');
      sign.update(urlToken);
      return sign.sign(revolutKeys.privateKey, 'base64');
    } catch (error) {
      console.error('Token signing failed:', error.message);
      return null;
    }
  }
};

console.log('\nSimulating the authentication flow...\n');

try {
  const urlToken = deel.generateUrlToken('user_123', 'revolut_client_id_12345', 'contract_456');
  console.log('1. Deel generated URL token (truncated):', urlToken.substr(0, 32) + '...');

  const clientSignature = revolut.signToken(urlToken);
  if (!clientSignature) throw new Error('Failed to generate client signature');
  console.log('2. Revolut signed the URL token. Signature (truncated):', clientSignature.substr(0, 32) + '...');

  if (deel.verifySignature(urlToken, clientSignature)) {
    console.log('3. Deel verified Revolut\'s signature successfully');
    const authToken = deel.generateAuthToken('user_123', 'revolut_client_id_12345', 'contract_456', ['read:profile', 'begin_onboarding']);
    console.log('   Deel generated auth token (truncated):', authToken.substr(0, 32) + '...');

    const validatedToken = deel.validateAuthToken(authToken);
    if (validatedToken) {
      console.log('\n4. Auth token validated successfully');
      console.log('   Decoded token:', JSON.stringify(validatedToken, null, 2));
    } else {
      throw new Error('Auth token validation failed');
    }
  } else {
    throw new Error('Signature verification failed');
  }

  console.log('\nAuthentication flow completed successfully!');
} catch (error) {
  console.error('\nError in authentication flow:', error.message);
}