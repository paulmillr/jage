/// <reference types="node" />
export declare function encode(data: string | Uint8Array): string;
export declare function encrypt(key: Uint8Array, plaintext: Uint8Array): Buffer;
export declare function X25519(secret: Uint8Array, point: Uint8Array): Uint8Array;
export declare function HKDF(salt: Uint8Array, label: Uint8Array, key: Uint8Array): Uint8Array;
export declare function HMAC(key: Uint8Array, message: Uint8Array): Uint8Array;
export declare function scrypt(salt: Uint8Array, N: number, password: Uint8Array): Uint8Array;
export declare function random(n: number): Uint8Array;
export declare function getHeader(): string;
