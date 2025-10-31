#!/usr/bin/env node

const nacl = require('tweetnacl');
const { sha3_256 } = require('js-sha3');
const fs = require('fs');
const readline = require('readline');

function hexToBuffer(hex) {
  if (hex.length % 2) throw new Error('Hex length must be even');
  return Buffer.from(hex, 'hex');
}

function base32Encode(buf) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  let output = '';

  for (let i = 0; i < buf.length; i++) {
    value = (value << 8) | buf[i];
    bits += 8;
    while (bits >= 5) {
      const index = (value >>> (bits - 5)) & 0x1f;
      output += alphabet[index];
      bits -= 5;
    }
  }
  if (bits > 0) {
    const index = (value << (5 - bits)) & 0x1f;
    output += alphabet[index];
  }
  return output.toLowerCase();
}

function calcOnionFromPub(pubBuf) {
  const prefix = Buffer.from('.onion checksum', 'utf8');
  const version = Buffer.from([0x03]);
  const concat = Buffer.concat([prefix, pubBuf, version]);
  const hashHex = sha3_256(concat);
  const hashBuf = Buffer.from(hashHex, 'hex');
  const checksum = hashBuf.slice(0, 2);
  const onionBytes = Buffer.concat([pubBuf, checksum, version]);
  const b32 = base32Encode(onionBytes).replace(/=/g, '');
  return b32 + '.onion';
}

function derivePubFromSeedHex(seedHex) {
  const clean = seedHex.trim().toLowerCase();
  if (!/^[0-9a-f]+$/.test(clean)) throw new Error('Seed hex format error');
  if (clean.length !== 64) {
    throw new Error('Seed must be 64 hex characters (32 bytes).');
  }
  const seed = hexToBuffer(clean);
  const kp = nacl.sign.keyPair.fromSeed(new Uint8Array(seed));
  return Buffer.from(kp.publicKey).toString('hex');
}

function expandSeed(seed) {
  const crypto = require('crypto');
  const hash = crypto.createHash('sha512').update(seed).digest();
  const expanded = Buffer.from(hash);
  expanded[0] &= 248;
  expanded[31] &= 127;
  expanded[31] |= 64;
  return expanded;
}

function parseArgs() {
  const args = process.argv.slice(2);
  const out = {};
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--json' || a === '-j') out.json = args[++i];
    else if (a === '--onion' || a === '-o') out.onion = args[++i];
    else if (a === '--pub' || a === '-p') out.pub = args[++i];
    else if (a === '--seed' || a === '-s') out.seed = args[++i];
    else if (a === '--expanded' || a === '-e') out.expanded = args[++i];
    else if (a === '--help' || a === '-h') out.help = true;
    else if (!out.json && a.endsWith('.json')) {
      out.json = a;
    } else {
      if (!out.onion) out.onion = a;
      else if (!out.pub) out.pub = a;
      else if (!out.seed) out.seed = a;
      else if (!out.expanded) out.expanded = a;
    }
  }
  return out;
}

async function interactivePrompt(q) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise(resolve => rl.question(q, ans => { rl.close(); resolve(ans); }));
}

(async function main() {
  try {
    const args = parseArgs();
    if (args.help) {
      console.log('Usage: node test.js [--json <file.json>] [--onion <address>] [--pub <pubhex>] [--seed <seedhex>] [--expanded <expandedhex>]');
      console.log('');
      console.log('  --json, -j     JSON file path (contains onionAddress, publicKey, seed, expandedSecretKey)');
      console.log('  --onion, -o    Onion address (56 base32 characters)');
      console.log('  --pub, -p      Public key (64 hex characters)');
      console.log('  --seed, -s     Seed (64 hex characters)');
      console.log('  --expanded, -e Expanded secret key (128 hex characters)');
      console.log('');
      console.log('If no JSON file is provided, prompts for missing values.');
      process.exit(0);
    }

    let onion, pubHex, seedHex, expandedHex;

    if (args.json) {
      try {
        const jsonData = JSON.parse(fs.readFileSync(args.json, 'utf8'));
        onion = jsonData.onionAddress || '';
        pubHex = jsonData.publicKey || '';
        seedHex = jsonData.seed || '';
        expandedHex = jsonData.expandedSecretKey || '';
      } catch (err) {
        throw new Error(`Failed to read JSON file: ${err.message}`);
      }
    } else {
      onion = args.onion || '';
      pubHex = args.pub || '';
      seedHex = args.seed || '';
      expandedHex = args.expanded || '';
    }

    if (!onion) {
      onion = (await interactivePrompt('Enter .onion address: ')).trim();
    }
    if (!pubHex) {
      pubHex = (await interactivePrompt('Enter public key (hex, 64 chars): ')).trim();
    }
    if (!seedHex) {
      seedHex = (await interactivePrompt('Enter seed (hex, 64 chars): ')).trim();
    }
    if (!expandedHex) {
      expandedHex = (await interactivePrompt('Enter expanded secret key (hex, 128 chars): ')).trim();
    }

    onion = onion.trim().toLowerCase().replace(/\.onion$/, '');
    pubHex = pubHex.trim().toLowerCase();
    seedHex = seedHex.trim().toLowerCase();
    expandedHex = expandedHex.trim().toLowerCase();

    if (!onion || onion.length === 0) {
      throw new Error('Onion address is required');
    }
    if (!/^[a-z2-7]{56}$/.test(onion)) {
      throw new Error('Invalid onion address (must be 56 base32 characters, a-z and 2-7).');
    }
    if (!pubHex || pubHex.length === 0) {
      throw new Error('Public key is required');
    }
    if (!/^[0-9a-f]{64}$/.test(pubHex)) {
      throw new Error('Public key must be 64 hex characters (32 bytes).');
    }
    if (seedHex && !/^[0-9a-f]{64}$/.test(seedHex)) {
      throw new Error('Seed must be 64 hex characters (32 bytes).');
    }
    if (expandedHex && !/^[0-9a-f]{128}$/.test(expandedHex)) {
      throw new Error('Expanded secret key must be 128 hex characters (64 bytes).');
    }

    const pubBuf = hexToBuffer(pubHex);

    const calcOnion = calcOnionFromPub(pubBuf).replace(/\.onion$/, '');
    const onionMatchesPub = (calcOnion === onion);
    
    console.log('Input Data:');
    console.log(`Onion Address: ${onion + '.onion'}`);
    console.log(`Public Key: ${pubHex}`);
    if (seedHex) {
      console.log(`Seed: ${seedHex}`);
    }
    if (expandedHex) {
      console.log(`Expanded Secret Key: ${expandedHex}`);
    }
    console.log('');

    console.log('1. Onion Address ↔ Public Key:');
    console.log(`   Calculated: ${calcOnion + '.onion'}`);
    console.log(`   Given:      ${onion + '.onion'}`);
    console.log(`   Match: ${onionMatchesPub ? 'OK' : 'MISMATCH'}`);
    console.log('');

    let derivedPubHex;
    let expandedFromSeed;
    let seedMatchesExpanded = false;
    
    if (seedHex) {
      console.log('2. Seed ↔ Public Key:');
      try {
        derivedPubHex = derivePubFromSeedHex(seedHex);
        console.log(`   Public from seed: ${derivedPubHex}`);
        console.log(`   Match: ${derivedPubHex === pubHex ? 'OK' : 'MISMATCH'}`);
        
        const seed = hexToBuffer(seedHex);
        expandedFromSeed = expandSeed(seed);
        
        if (expandedHex) {
          const givenExpanded = hexToBuffer(expandedHex);
          seedMatchesExpanded = expandedFromSeed.equals(givenExpanded);
          console.log(`   Expanded secret match: ${seedMatchesExpanded ? 'OK' : 'MISMATCH'}`);
        }
        console.log('');
      } catch (err) {
        console.log(`   Error: ${err.message}`);
        console.log('');
      }
    }
    
    if (expandedHex && !seedHex) {
      console.log('2. Expanded Secret Key:');
      console.log('   Error: Cannot derive seed from expanded secret key');
      console.log('');
    }

    console.log('Summary:');
    
    let allChecks = [];
    
    allChecks.push({
      name: 'Onion ↔ Public Key',
      result: onionMatchesPub
    });
    
    if (seedHex && derivedPubHex) {
      allChecks.push({
        name: 'Seed ↔ Public Key',
        result: derivedPubHex === pubHex
      });
    }
    
    if (seedHex && expandedFromSeed) {
      if (expandedHex) {
        allChecks.push({
          name: 'Seed → Expanded Secret Key',
          result: seedMatchesExpanded
        });
      } else {
        allChecks.push({
          name: 'Seed → Expanded Secret Key',
          result: true
        });
      }
    }
    
    allChecks.forEach(check => {
      console.log(`  ${check.result ? 'OK' : 'FAIL'} ${check.name}`);
    });
    
    const allOk = allChecks.length > 0 && allChecks.every(check => check.result);
    
    console.log('');
    console.log(`Result: ${allOk ? 'OK' : 'FAIL'}`);

    process.exit(0);

  } catch (err) {
    console.error('Error:', err.message || err);
    process.exit(1);
  }
})();
