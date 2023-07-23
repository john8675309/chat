const crypto = require('crypto');
const fs = require('fs');
const createHash = require('create-hash');
const bs58check = require('bs58check');
const yargs = require('yargs/yargs');
const { hideBin } = require('yargs/helpers');
const QRCode = require('qrcode-terminal');
const elliptic = require('elliptic');
const path = require('path');

const EC = elliptic.ec;

function generateKeyPair() {
  // Define file paths
  const publicKeyPath = './public.pem';
  const privateKeyPath = './private.pem';

  // Check if keys already exist
  if (fs.existsSync(publicKeyPath) && fs.existsSync(privateKeyPath)) {
    const publicKey = fs.readFileSync(publicKeyPath, 'utf8');
    const privateKey = fs.readFileSync(privateKeyPath, 'utf8');

    return { publicKey, privateKey };
  } 

  // Generate new key pair if keys don't exist
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'secp256k1',
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  // Write keys to files
  fs.writeFileSync(publicKeyPath, publicKey);
  fs.writeFileSync(privateKeyPath, privateKey);

  const username = deriveUsernameFromPublicKey(publicKey);

  return { publicKey, privateKey, username };
}

function deriveUsernameFromPublicKey(publicKey) {
  const publicKeyHash = crypto.createHash('sha256').update(publicKey).digest();
  const ripemd160Hash = createHash('rmd160').update(publicKeyHash).digest();
  const versionedPayload = Buffer.concat([Buffer.from([0x00]), ripemd160Hash]); // 0x00 for main network
  const checksum = crypto.createHash('sha256').update(versionedPayload).digest();
  const payloadWithChecksum = Buffer.concat([versionedPayload, checksum.slice(0, 4)]);
  const username = bs58check.encode(payloadWithChecksum);

  return username;
}


function signMessage(privateKey, message) {
  const sign = crypto.createSign('SHA256');
  sign.update(message);
  sign.end();
  const signature = sign.sign(privateKey, 'hex');
  return signature;
}

function encryptMessage(publicKey, privateKey, message) {
  const sharedSecret = getSharedSecret(publicKey, privateKey);
  
  // Create an AES cipher using our shared secret
  const cipher = crypto.createCipheriv('aes-256-cbc', sharedSecret, Buffer.alloc(16, 0));
  let encrypted = cipher.update(message, 'utf8', 'base64');
  encrypted += cipher.final('base64');

  return encrypted;
}

function encryptFile(publicKey, privateKey, filePath) {
  const fileData = fs.readFileSync(filePath, 'utf8');
  const encryptedData = encryptMessage(publicKey, privateKey, fileData);
  fs.writeFileSync(path.basename(filePath) + '.enc', encryptedData, 'utf8');
}

function decryptFile(publicKey, privateKey, filePath) {
  const fileData = fs.readFileSync(filePath, 'utf8');
  const decryptedData = decryptMessage(publicKey, privateKey, fileData);
  
  // Remove the .enc extension from the file path for the decrypted file
  let decryptedFilePath = path.basename(filePath);
  if (decryptedFilePath.endsWith('.enc')) {
    decryptedFilePath = decryptedFilePath.substring(0, decryptedFilePath.length - 4);
  }

  fs.writeFileSync(decryptedFilePath, decryptedData, 'utf8');
}

function getSharedSecret(theirPublicKeyPem, myPrivateKeyPem) {
  // 'elliptic' package can interpret 'pkcs8' private keys
  const ec = new EC('secp256k1');
  const myPrivateKeyObj = ec.keyFromPrivate(
    // Strip the PEM "header" and "footer" and base64 decode the middle
    Buffer.from(myPrivateKeyPem.replace(/-----[^-]+-----/g, ''), 'base64')
  );

  // Convert their PEM public key to raw public key
  const theirPublicKeyObj = crypto.createPublicKey({
    key: theirPublicKeyPem,
    format: 'pem',
    type: 'spki'
  });
  const theirPublicKeyRaw = theirPublicKeyObj.export({
    type: 'spki',
    format: 'der'
  });

  // Create an elliptic.js key object from the raw public key
  const theirPublicKeyEC = ec.keyFromPublic(theirPublicKeyRaw.slice(23));

  // Export their public key to an uncompressed, raw format
  const theirPublicKeyUncompressed = theirPublicKeyEC.getPublic(false, 'hex');

  // Now 'myPrivateKeyObj' is an 'elliptic' key pair object
  const myPrivateKey = myPrivateKeyObj.getPrivate();

  // ECDH computation
  const ecdh = crypto.createECDH('secp256k1');
  ecdh.setPrivateKey(myPrivateKey.toString(16), 'hex');
  const sharedSecret = ecdh.computeSecret(theirPublicKeyUncompressed, 'hex');

  // Hash the shared secret to get a consistent length
  const sharedSecretHash = crypto.createHash('sha256').update(sharedSecret).digest();

  return sharedSecretHash;
}

function decryptMessage(publicKey, privateKey, encryptedMessage) {
  const sharedSecret = getSharedSecret(publicKey, privateKey);
  // Create an AES decipher using our shared secret
  const decipher = crypto.createDecipheriv('aes-256-cbc', sharedSecret, Buffer.alloc(16, 0));
  //let decrypted = decipher.update(Buffer.from(encryptedMessage));
  //decrypted = Buffer.concat([decrypted, decipher.final()]);
  let decrypted = decipher.update(encryptedMessage, 'base64', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}



yargs(hideBin(process.argv))
  .command('generate', 'Generate a key pair', {}, (argv) => {
    const { publicKey, privateKey } = generateKeyPair();
    console.log(`Public Key:\n${publicKey}`);
    console.log(`Private Key (keep this secret!):\n${privateKey}`);
  })
  .command('publickey', 'Show the public key', {}, (argv) => {
    const publicKey = fs.readFileSync('./public.pem', 'utf8');
    console.log(`Public Key:\n${publicKey}`);
  })
  .command('username', 'Show the username', {}, (argv) => {
    const publicKey = fs.readFileSync('./public.pem', 'utf8');
    const username = deriveUsernameFromPublicKey(publicKey);
    console.log(`User Name:\n${username}`);
  })
  .command('encrypt-file <filePath>', 'Encrypt a file', (yargs) => {
    yargs.positional('filePath', {
      describe: 'The path to the file to encrypt',
      type: 'string'
    });
  }, (argv) => {
    const publicKey = fs.readFileSync('./public.pem', 'utf8');
    const privateKey = fs.readFileSync('./private.pem', 'utf8');
    encryptFile(publicKey, privateKey, argv.filePath);
    console.log('File encrypted successfully');
  })
  .command('decrypt-file <filePath>', 'Decrypt a file', (yargs) => {
    yargs.positional('filePath', {
      describe: 'The path to the file to decrypt',
      type: 'string'
    });
  }, (argv) => {
    const publicKey = fs.readFileSync('./public.pem', 'utf8');
    const privateKey = fs.readFileSync('./private.pem', 'utf8');
    decryptFile(publicKey, privateKey, argv.filePath);
    console.log('File decrypted successfully');
  })
  .command('encrypt <message>', 'Encrypt a message', (yargs) => {
    yargs.positional('message', {
      describe: 'The message to encrypt',
      type: 'string'
    });
  }, (argv) => {
    const publicKey = fs.readFileSync('./public.pem', 'utf8');
    const privateKey = fs.readFileSync('./private.pem', 'utf8');
    const encryptedMessage = encryptMessage(publicKey, privateKey, argv.message);
    console.log(`Encrypted Message:\n${encryptedMessage}`);
  })
  .command('decrypt <encryptedMessage>', 'Decrypt a message', (yargs) => {
    yargs.positional('encryptedMessage', {
      describe: 'The encrypted message to decrypt',
      type: 'string'
    });
  }, (argv) => {
    const publicKey = fs.readFileSync('./public.pem', 'utf8');
    const privateKey = fs.readFileSync('./private.pem', 'utf8');
    const decryptedMessage = decryptMessage(publicKey, privateKey, argv.encryptedMessage);
    console.log(`Decrypted Message:\n${decryptedMessage}`);
  })
  .command('qrcode', 'Show the public key as a QR code', {}, (argv) => {
    const publicKey = fs.readFileSync('./public.pem', 'utf8');
    QRCode.generate(publicKey, { small: true });
  })
  .command('sign <message>', 'Sign a message', (yargs) => {
    yargs.positional('message', {
      describe: 'The message to sign',
      type: 'string'
    });
  }, (argv) => {
    const { publicKey, privateKey, username } = generateKeyPair(); 
    const signature = signMessage(privateKey, argv.message);
    console.log(`Signature:\n${signature}`);
  })
  .help()
  .argv;
