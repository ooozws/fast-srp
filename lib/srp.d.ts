/// <reference types="node" />
import BigInteger = require("../jsbn/jsbn");
import { SrpParams } from "./params";
export { SrpParams } from "./params";
export declare type GenKeyCallback = (err: Error | null, data: Buffer | null) => void;
export declare class SRP {
    static readonly params: {
        1024: {
            N_length_bits: number;
            N: BigInteger;
            g: BigInteger;
            hash: string;
        };
        1536: {
            N_length_bits: number;
            N: BigInteger;
            g: BigInteger;
            hash: string;
        };
        2048: {
            N_length_bits: number;
            N: BigInteger;
            g: BigInteger;
            hash: string;
        };
        3072: {
            N_length_bits: number;
            N: BigInteger;
            g: BigInteger;
            hash: string;
        };
        hap: {
            N_length_bits: number;
            N: BigInteger;
            g: BigInteger;
            hash: string;
        };
        4096: {
            N_length_bits: number;
            N: BigInteger;
            g: BigInteger;
            hash: string;
        };
        6244: {
            N_length_bits: number;
            N: BigInteger;
            g: BigInteger;
            hash: string;
        };
        8192: {
            N_length_bits: number;
            N: BigInteger;
            g: BigInteger;
            hash: string;
        };
    };
    /**
     * The verifier is calculated as described in Section 3 of [SRP-RFC].
     * We give the algorithm here for convenience.
     *
     * The verifier (v) is computed based on the salt (s), user name (I),
     * password (P), and group parameters (N, g).
     *
     *         x = H(s | H(I | ":" | P))
     *         v = g^x % N
     *
     * @param {object} params Group parameters, with .N, .g, .hash
     * @param {Buffer} salt
     * @param {Buffer} I User identity
     * @param {Buffer} P User password
     * @return {Buffer}
     */
    static computeVerifier(params: SrpParams, salt: Buffer, I: Buffer, P: Buffer): Buffer;
    /**
     * Generate a random key with a length of 32 bytes
     *
     * @param {GenKeyCallback} callback
     * @return {void}
     */
    static genKey(callback: GenKeyCallback): void;
    /**
     * Generate a random key.
     *
     * @param {number} bytes Length of key
     * @param {GenKeyCallback} callback
     * @return {void}
     */
    static genKey(bytes: number, callback: GenKeyCallback): void;
    /**
     * Generate a random key.
     *
     * @param {number} bytes Length of key. Defaults to 32.
     * @return {Promise<Buffer>}
     */
    static genKey(bytes?: number): Promise<Buffer>;
}
export declare class SrpClient {
    private readonly _params;
    private readonly _k;
    private readonly _x;
    /** Client private key */
    private readonly _a;
    /** Client public key */
    private readonly _A;
    /** User identity */
    private readonly _I?;
    /** User salt */
    private readonly _s?;
    /** Session key */
    private _K?;
    /** Server public key */
    private _B?;
    private _M1?;
    private _M2?;
    /** Random scrambling parameter */
    private _u?;
    /** Premaster secret */
    private _S?;
    /**
     * Create an SRP client.
     *
     * @param {object} params Group parameters, with .N, .g, .hash
     * @param {Buffer} salt_buf User salt (from server)
     * @param {Buffer} identity_buf Identity/username
     * @param {Buffer} password_buf Password
     * @param {Buffer} secret1_buf Client private key {@see genKey}
     * @param {boolean} hap
     */
    constructor(params: SrpParams, identity_buf: Buffer, secret1_buf: Buffer, precomputed_x?: Buffer, salt_buf?: Buffer, password_buf?: Buffer, hap?: boolean);
    /**
     * Returns the client's public key (A).
     *
     * @return {Buffer}
     */
    computeA(): Buffer;
    /**
     * Sets the server's public key (B).
     *
     * @param {Buffer} B_buf The server's public key
     */
    setB(B_buf: Buffer): void;
    /**
     * Gets the M1 value.
     * This requires setting the server's public key {@see Client.setB}.
     *
     * @return {Buffer}
     */
    computeM1(): Buffer;
    /**
     * Checks the server was able to calculate M2.
     * This requires setting the server's public key {@see Client.setB}.
     *
     * @param M2 The server's M2 value
     */
    checkM2(M2: Buffer): void;
    /**
     * Returns the shared session key.
     *
     * @return {Buffer}
     */
    computeK(): Buffer;
}
export interface BaseIdentity {
    username: Buffer | string;
    salt: Buffer;
}
export declare type PasswordIdentity = BaseIdentity & {
    password: Buffer | string;
};
export declare type VerifierIdentity = BaseIdentity & {
    verifier: Buffer;
};
export declare type Identity = PasswordIdentity | VerifierIdentity;
export declare class SrpServer {
    private readonly _params;
    /** Multiplier parameter (H(N, g)) */
    private readonly _k;
    /** Server private key */
    private readonly _b;
    /** Server public key */
    private readonly _B;
    /** Verifier */
    private readonly _v;
    /** User identity */
    private readonly _I?;
    /** User salt */
    private readonly _s?;
    /** Session key */
    _K?: Buffer;
    _M1?: Buffer;
    _M2?: Buffer;
    /** Random scrambling parameter */
    _u?: BigInteger;
    /** Premaster secret */
    _S?: Buffer;
    /**
     * Create an SRP server.
     *
     * This has two modes:
     * - Using a password: creates the server using a salt, identity and password, optionally in an object
     * - Using a verifier: creates the server using a salt, identity and verifier in an object
     *
     * @param {SrpParams} params Group parameters, with .N, .g, .hash
     * @param {Buffer} salt_buf User salt (from server)
     * @param {Buffer} identity_buf Identity/username
     * @param {Buffer} password_buf Password
     * @param {Buffer} secret2_buf Client private key {@see genKey}
     */
    constructor(params: SrpParams, salt_buf: Buffer, identity_buf: Buffer, password_buf: Buffer, secret2_buf: Buffer);
    constructor(params: SrpParams, verifier_buf: Buffer, secret2_buf: Buffer);
    constructor(params: SrpParams, identity: Identity, secret2_buf: Buffer);
    /**
     * Returns the server's public key (B).
     *
     * @return {Buffer}
     */
    computeB(): Buffer;
    /**
     * Sets the client's public key (A).
     *
     * @param {Buffer} A The client's public key
     */
    setA(A: Buffer): void;
    /**
     * Checks the client was able to calculate M1.
     *
     * @param {Buffer} M1 The client's M1 value
     */
    checkM1(M1: Buffer): void;
    /**
     * Returns the shared session key.
     *
     * @return {Buffer}
     */
    computeK(): Buffer;
    /**
     * Gets the M2 value.
     * This requires setting the client's public key {@see Server.setA}.
     *
     * @return {Buffer}
     */
    computeM2(): Buffer;
}
//# sourceMappingURL=srp.d.ts.map