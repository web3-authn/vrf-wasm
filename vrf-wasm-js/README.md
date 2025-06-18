# VRF-WASM JavaScript Bindings

JavaScript/TypeScript bindings for the VRF-WASM library, for use in web browsers and Node.js.

## Features

- **Browser Compatible**: Run VRF operations directly in web browsers
- **Cryptographically Secure**: Based on ECVRF using Ristretto255
- **High Performance**: Near-native speed through WebAssembly
- **TypeScript Support**: Full type definitions included
- **Lightweight**: Optimized bundle size (~200KB, ~80KB compressed)

## Installation

### Build from Source

```bash
# Navigate to the JavaScript bindings directory
cd vrf-wasm-js

# Build for web browsers
wasm-pack build --target web --out-dir pkg

# Or build for bundlers (webpack, vite, etc.)
wasm-pack build --target bundler --out-dir pkg

# Or build for Node.js
wasm-pack build --target nodejs --out-dir pkg
```

### Install in Your Project

```bash
# Install the generated package
npm install ./vrf-wasm-js/pkg

# Or copy to your project and install
cp -r vrf-wasm-js/pkg ./my-project/
cd my-project
npm install ./pkg
```

## API Reference

### VRFKeyPairJS

Main class for VRF operations:

```typescript
class VRFKeyPairJS {
    constructor();
    getPublicKey(): Uint8Array;
    prove(input: Uint8Array): Uint8Array;
    output(input: Uint8Array): VRFOutputJS;
}
```

### VRFOutputJS

Contains both the VRF hash and proof:

```typescript
class VRFOutputJS {
    readonly hash: Uint8Array;    // 64-byte VRF output
    readonly proof: Uint8Array;   // Serialized proof
}
```

### Utility Functions

```typescript
// Verify a VRF proof
function verifyProof(
    publicKey: Uint8Array,
    input: Uint8Array,
    proof: Uint8Array
): boolean;

// Extract hash from proof
function proofToHash(proof: Uint8Array): Uint8Array;

// Verify proof with expected output
function verifyOutput(
    publicKey: Uint8Array,
    input: Uint8Array,
    proof: Uint8Array,
    expectedHash: Uint8Array
): boolean;

// Create keypair from seed (deterministic)
function keyPairFromSeed(seed: Uint8Array): VRFKeyPairJS;
```

## Usage Examples

### TypeScript Example

```typescript
import init, {
    VRFKeyPairJS,
    VRFOutputJS,
    verifyProof,
    verifyOutput
} from './pkg/vrf_wasm_js';

interface VRFResult {
    publicKey: Uint8Array;
    hash: Uint8Array;
    proof: Uint8Array;
    isValid: boolean;
}

async function generateVRF(input: string): Promise<VRFResult> {
    await init();

    const keypair = new VRFKeyPairJS();
    const publicKey = keypair.getPublicKey();
    const inputBytes = new TextEncoder().encode(input);

    const output: VRFOutputJS = keypair.output(inputBytes);
    const isValid = verifyOutput(publicKey, inputBytes, output.proof, output.hash);

    return {
        publicKey,
        hash: output.hash,
        proof: output.proof,
        isValid
    };
}

// Usage
generateVRF("my-input").then(result => {
    console.log('VRF generated:', {
        publicKey: Buffer.from(result.publicKey).toString('hex'),
        hash: Buffer.from(result.hash).toString('hex'),
        valid: result.isValid
    });
});
```

### React Hook Example

```typescript
// useVRF.ts
import { useState, useCallback, useEffect } from 'react';
import init, { VRFKeyPairJS, VRFOutputJS, verifyProof } from './pkg/vrf_wasm_js';

interface VRFHook {
    generateProof: (input: string) => Promise<VRFOutputJS | null>;
    verify: (publicKey: Uint8Array, input: string, proof: Uint8Array) => Promise<boolean>;
    isLoading: boolean;
    error: string | null;
}

export function useVRF(): VRFHook {
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [initialized, setInitialized] = useState(false);

    useEffect(() => {
        init().then(() => setInitialized(true)).catch(setError);
    }, []);

    const generateProof = useCallback(async (input: string): Promise<VRFOutputJS | null> => {
        if (!initialized) return null;

        try {
            setIsLoading(true);
            setError(null);

            const keypair = new VRFKeyPairJS();
            const inputBytes = new TextEncoder().encode(input);
            const output = keypair.output(inputBytes);

            return output;
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Unknown error');
            return null;
        } finally {
            setIsLoading(false);
        }
    }, [initialized]);

    const verify = useCallback(async (
        publicKey: Uint8Array,
        input: string,
        proof: Uint8Array
    ): Promise<boolean> => {
        if (!initialized) return false;

        try {
            const inputBytes = new TextEncoder().encode(input);
            return verifyProof(publicKey, inputBytes, proof);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Unknown error');
            return false;
        }
    }, [initialized]);

    return { generateProof, verify, isLoading, error };
}
```

## Build Targets

### Web Browser (ES Modules)
```bash
wasm-pack build --target web --out-dir pkg
```
Use with: `<script type="module">`, Vite, modern bundlers

### Bundlers (Webpack, Rollup)
```bash
wasm-pack build --target bundler --out-dir pkg
```
Use with: Webpack, Rollup, Parcel

### Node.js
```bash
wasm-pack build --target nodejs --out-dir pkg
```
Use with: Node.js applications, server-side rendering


## Bundle Sizes

| Build Type | Size | Compressed (Brotli) |
|------------|------|-------------------|
| Debug | ~500KB | ~120KB |
| Release | ~200KB | ~80KB |
| Release + optimization | ~150KB | ~60KB |

## Error Handling

All functions return `Result` types in Rust, which translate to JavaScript:
- Success: Returns the expected value
- Error: Throws a JavaScript Error with descriptive message

Common error cases:
- Invalid public key format
- Invalid proof format
- Seed too short (< 32 bytes)
- Hash length mismatch (must be 64 bytes)

## Contributing

This crate provides JavaScript bindings for the core VRF-WASM library. For core VRF functionality changes, see the parent `vrf-wasm` crate.

