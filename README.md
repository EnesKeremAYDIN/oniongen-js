# oniongen-js

Tor v3 .onion address vanity URL generator and verifier written in Node.js.

## Features

- Generates Tor v3 .onion addresses matching custom regex patterns.
- Multi-threaded parallel generation using all available CPU cores for optimal performance.
- Verifies .onion addresses and their associated Ed25519 key pairs.
- Exports generated addresses to JSON format with all cryptographic keys.
- Built with Node.js worker threads for efficient parallel processing.

## Files

- **`oniongen.js`**: Main generator script that creates Tor v3 .onion addresses matching custom regex patterns. Uses worker threads for parallel processing and exports results to JSON files.

- **`test.js`**: Verification tool that checks the relationships between .onion addresses, public keys, seeds, and expanded secret keys. Supports JSON input, command-line arguments, and interactive mode.

## Requirements

- Node.js 16.0.0 or higher
- Dependencies: `tweetnacl` and `js-sha3` (install via `npm install tweetnacl js-sha3`)

## Installation and Usage

1. **Clone the repository**:
   ```bash
   git clone https://github.com/EnesKeremAYDIN/oniongen-js.git
   cd oniongen-js

2. **Generate addresses**:
   ```bash
   node oniongen.js <regex> <number>
   ```
   - `regex` - Regex pattern that addresses should match (a-z, 2-7)
   - `number` - Number of matching addresses to generate
   - Example: `node oniongen.js "^test" 5`

3. **Verify addresses**:
   ```bash
   node test.js [options]
   ```
   - Using JSON file: `node test.js --json xxxx.json`
   - With command line arguments: `node test.js --onion xxxx.onion --pub <hex> --seed <hex> --expanded <hex>`
   - Interactive mode: `node test.js`

## Output Format

Generated addresses are saved to `<onionaddress>.json` files containing:
- `onionAddress` - The .onion address (without .onion suffix)
- `publicKey` - Public key in hex format (64 characters)
- `seed` - Seed in hex format (64 characters)
- `expandedSecretKey` - Expanded secret key in hex format (128 characters)

## Verification

The verification tool checks:
1. Onion Address ↔ Public Key derivation
2. Seed ↔ Public Key derivation (if seed provided)
3. Seed → Expanded Secret Key derivation (if both provided)

## Disclaimer

This tool is intended for educational purposes or personal use.
