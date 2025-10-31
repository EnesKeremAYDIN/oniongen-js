#!/usr/bin/env node

const crypto = require('crypto');
const fs = require('fs');
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');
const os = require('os');

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const BASE32_PADDING = '=';

function base32Encode(data) {
    let bits = 0;
    let value = 0;
    let output = '';

    for (let i = 0; i < data.length; i++) {
        value = (value << 8) | data[i];
        bits += 8;

        while (bits >= 5) {
            output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
            bits -= 5;
        }
    }

    if (bits > 0) {
        output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
    }

    while (output.length % 8 !== 0) {
        output += BASE32_PADDING;
    }

    return output.toLowerCase();
}

function sha3_256(data) {
    return crypto.createHash('sha3-256').update(data).digest();
}

function generateOnionAddress() {
    let rawPublicKey, rawPrivateKey;
    
    try {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
        });
        
        const publicKeyObj = crypto.createPublicKey(publicKey);
        const privateKeyObj = crypto.createPrivateKey(privateKey);
        
        rawPublicKey = publicKeyObj.export({ type: 'spki', format: 'der' });
        rawPrivateKey = privateKeyObj.export({ type: 'pkcs8', format: 'der' });
        
        let pubOffset = -1;
        for (let i = 0; i < rawPublicKey.length - 32; i++) {
            if (rawPublicKey[i] === 0x03 && rawPublicKey[i + 1] === 0x21 && rawPublicKey[i + 2] === 0x00) {
                pubOffset = i + 3;
                break;
            }
        }
        if (pubOffset === -1) {
            rawPublicKey = rawPublicKey.slice(-32);
        } else {
            rawPublicKey = rawPublicKey.slice(pubOffset, pubOffset + 32);
        }
        
        let seedOffset = -1;
        for (let i = 0; i < rawPrivateKey.length - 33; i++) {
            if (rawPrivateKey[i] === 0x04 && rawPrivateKey[i + 1] === 0x20) {
                seedOffset = i + 2;
                break;
            }
        }
        if (seedOffset === -1) {
            rawPrivateKey = rawPrivateKey.slice(-32);
        } else {
            rawPrivateKey = rawPrivateKey.slice(seedOffset, seedOffset + 32);
        }
    } catch (error) {
        throw new Error('Failed to generate Ed25519 keys: ' + error.message);
    }

    const checksumBytes = Buffer.concat([
        Buffer.from('.onion checksum'),
        rawPublicKey,
        Buffer.from([0x03])
    ]);
    const checksum = sha3_256(checksumBytes);

    const onionAddressBytes = Buffer.concat([
        rawPublicKey,
        checksum.slice(0, 2),
        Buffer.from([0x03])
    ]);

    const onionAddress = base32Encode(onionAddressBytes);

    return { onionAddress, publicKey: rawPublicKey, privateKey: rawPrivateKey };
}

function expandSecretKey(seed) {
    const hash = crypto.createHash('sha512').update(seed).digest();
    
    const expanded = Buffer.from(hash);
    expanded[0] &= 248;
    expanded[31] &= 127;
    expanded[31] |= 64;
    
    return expanded;
}

function formatDuration(ms) {
    const seconds = Math.floor(ms / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    
    if (hours > 0) {
        return `${hours}h ${minutes % 60}m ${seconds % 60}s`;
    } else if (minutes > 0) {
        return `${minutes}m ${seconds % 60}s`;
    } else {
        return `${seconds}s`;
    }
}


function workerMain() {
    const { regexPattern, workerId } = workerData;
    const regex = new RegExp(regexPattern);
    let attempts = 0;
    let lastStatsAttempts = 0;

    while (true) {
        try {
            const { onionAddress, publicKey, privateKey } = generateOnionAddress();
            attempts++;

            if (regex.test(onionAddress)) {
                const seed = privateKey.slice(0, 32);
                const expandedSecretKey = expandSecretKey(seed);
                
                parentPort.postMessage({
                    type: 'match',
                    onionAddress,
                    publicKey: publicKey.toString('base64'),
                    secretKey: expandedSecretKey.toString('base64'),
                    seed: seed.toString('base64'),
                    attempts: attempts,
                    workerId: workerId
                });
                lastStatsAttempts += attempts;
                attempts = 0;
            }

            if (attempts % 1000 === 0) {
                parentPort.postMessage({
                    type: 'stats',
                    attempts: attempts - lastStatsAttempts,
                    workerId: workerId
                });
                lastStatsAttempts = attempts;
            }
        } catch (error) {
            parentPort.postMessage({
                type: 'error',
                error: error.message,
                workerId: workerId
            });
        }
    }
}

function main() {
    if (isMainThread) {
        if (process.argv.length < 4) {
            console.error('Usage: node oniongen.js <regex> <number>');
            console.error('');
            console.error('  regex   regex pattern addresses should match (a-z, 2-7)');
            console.error('  number  number of matching addresses to generate');
            console.error('');
            console.error('Example:');
            console.error('  node oniongen.js "^test" 5');
            console.error('  node oniongen.js "^hello[a-z]*" 10');
            process.exit(1);
        }

        const regexPattern = process.argv[2];
        const numAddresses = parseInt(process.argv[3], 10);

        if (isNaN(numAddresses) || numAddresses <= 0) {
            console.error('Error: number must be a positive integer');
            process.exit(1);
        }

        let normalizedPattern = regexPattern;
        if (!normalizedPattern.startsWith('^')) {
            normalizedPattern = '^' + normalizedPattern;
        }
        
        let regex;
        try {
            regex = new RegExp(normalizedPattern);
        } catch (error) {
            console.error(`Error: Invalid regex pattern: ${error.message}`);
            process.exit(1);
        }

        const startTime = Date.now();
        const numWorkers = os.cpus().length;
        
        console.log('Tor v3 .onion Address Vanity Generator');
        console.log(`Pattern: ${normalizedPattern}`);
        if (normalizedPattern !== regexPattern) {
            console.log(`(Original: ${regexPattern} -> auto-prefixed with '^')`);
        }
        console.log(`Target: ${numAddresses} matching address(es)`);
        console.log(`Workers: ${numWorkers} CPU core(s)`);

        let foundCount = 0;
        let totalAttempts = 0;
        const workerAttempts = new Array(numWorkers).fill(0);
        const workers = [];
        let lastStatsTime = Date.now();
        let statsInterval;

        function printStats() {
            const elapsed = Date.now() - startTime;
            const rate = totalAttempts > 0 ? (totalAttempts / (elapsed / 1000)).toFixed(0) : 0;
            
            process.stdout.write(`\rProgress: ${foundCount}/${numAddresses} found | `);
            process.stdout.write(`Attempts: ${totalAttempts.toLocaleString('en-US')} | `);
            process.stdout.write(`Rate: ${rate}/s | `);
            process.stdout.write(`Time: ${formatDuration(elapsed)}`);
            lastStatsTime = Date.now();
        }

        function saveToJSON(data) {
            const publicKey = Buffer.from(data.publicKey, 'base64');
            const secretKey = Buffer.from(data.secretKey, 'base64');
            const seed = Buffer.from(data.seed || '', 'base64');
            
            const jsonData = {
                onionAddress: data.onionAddress,
                publicKey: publicKey.toString('hex'),
                seed: seed.toString('hex'),
                expandedSecretKey: secretKey.toString('hex')
            };
            
            const filename = `${data.onionAddress}.json`;
            fs.writeFileSync(filename, JSON.stringify(jsonData, null, 2));
            return filename;
        }

        function printMatch(data) {
            const elapsed = Date.now() - startTime;
            const publicKey = Buffer.from(data.publicKey, 'base64');
            const secretKey = Buffer.from(data.secretKey, 'base64');
            const seed = Buffer.from(data.seed || '', 'base64');
            
            const jsonFile = saveToJSON(data);
            
            console.log('');
            console.log(`Match #${foundCount} found after ${data.attempts.toLocaleString('en-US')} attempts`);
            console.log(`Onion Address: ${data.onionAddress}.onion`);
            console.log(`Public Key: ${publicKey.toString('hex')}`);
            if (seed.length === 32) {
                console.log(`Seed: ${seed.toString('hex')}`);
            }
            console.log(`Expanded Secret Key: ${secretKey.toString('hex')}`);
            console.log(`Saved to: ${jsonFile}`);
            console.log(`Time: ${formatDuration(elapsed)} | Found: ${foundCount}/${numAddresses} | Attempts: ${totalAttempts.toLocaleString('en-US')} | Rate: ${totalAttempts > 0 ? (totalAttempts / (elapsed / 1000)).toFixed(0) : 0}/s`);
            process.stdout.write('\r');
        }

        function printSummary() {
            const elapsed = Date.now() - startTime;
            const avgRate = totalAttempts > 0 ? (totalAttempts / (elapsed / 1000)).toFixed(2) : 0;
            
            console.log('');
            console.log('Generation Complete!');
            console.log(`Addresses found: ${foundCount}/${numAddresses}`);
            console.log(`Total attempts: ${totalAttempts.toLocaleString('en-US')}`);
            console.log(`Total time: ${formatDuration(elapsed)}`);
            console.log(`Average rate: ${avgRate} attempts/sec`);
        }

        for (let i = 0; i < numWorkers; i++) {
            const worker = new Worker(__filename, {
                workerData: { regexPattern: normalizedPattern, workerId: i }
            });

            worker.on('message', (data) => {
                if (data.type === 'match' && foundCount < numAddresses) {
                    totalAttempts += data.attempts;
                    workerAttempts[data.workerId] += data.attempts;
                    foundCount++;
                    
                    printMatch(data);

                    if (foundCount >= numAddresses) {
                        if (statsInterval) clearInterval(statsInterval);
                        workers.forEach(w => w.terminate());
                        printSummary();
                        process.exit(0);
                    }
                } else if (data.type === 'stats') {
                    workerAttempts[data.workerId] += data.attempts;
                    totalAttempts += data.attempts;
                } else if (data.type === 'error') {
                    console.error(`\nWorker #${data.workerId + 1} error: ${data.error}`);
                }
            });

            worker.on('error', (error) => {
                console.error(`\nWorker #${i + 1} fatal error:`, error);
            });

            workers.push(worker);
        }

        statsInterval = setInterval(printStats, 1000);

        process.on('SIGINT', () => {
            if (statsInterval) clearInterval(statsInterval);
            console.log('\n\nInterrupted by user');
            printSummary();
            workers.forEach(w => w.terminate());
            process.exit(0);
        });
    } else {
        workerMain();
    }
}

main();
