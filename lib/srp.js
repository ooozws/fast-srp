"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.SrpServer = exports.SrpClient = exports.SRP = void 0;
const crypto_1 = __importDefault(require("crypto"));
const assert_1 = __importDefault(require("assert"));
const BigInteger = require("../jsbn/jsbn");
const params_1 = require("./params");
const zero = new BigInteger(0, 10);
function assert_(val, msg) {
    if (!val) {
        throw new Error(msg || "assertion");
    }
}
function assertIsBuffer(arg, argname = "arg") {
    assert_(Buffer.isBuffer(arg), `Type error: ${argname} must be a buffer`);
}
function assertIsBigInteger(arg, argname = "arg") {
    assert_(arg instanceof BigInteger, `Type error: ${argname} must be a BigInteger`);
}
/**
 * If a conversion is explicitly specified with the operator PAD(),
 * the integer will first be implicitly converted, then the resultant
 * byte-string will be left-padded with zeros (if necessary) until its
 * length equals the implicitly-converted length of N.
 *
 * @param {Buffer} n Number to pad
 * @param {number} len Length of the resulting Buffer
 * @return {Buffer}
 */
function padTo(n, len) {
    assertIsBuffer(n, "n");
    const padding = len - n.length;
    assert_(padding > -1, "Negative padding.  Very uncomfortable.");
    const result = Buffer.alloc(len);
    result.fill(0, 0, padding);
    n.copy(result, padding);
    assert_1.default.strictEqual(result.length, len);
    return result;
}
function padToN(number, params) {
    assertIsBigInteger(number);
    const n = number.toString(16).length % 2 !== 0 ? "0" + number.toString(16) : number.toString(16);
    return padTo(Buffer.from(n, "hex"), params.N_length_bits / 8);
}
/**
 * Compute the intermediate value x as a hash of three buffers:
 * salt, identity, and password.  And a colon.  FOUR buffers.
 *
 *      x = H(s | H(I | ":" | P))
 *
 * @param {object} params
 * @param {Buffer} salt
 * @param {Buffer} I User identity
 * @param {Buffer} P User password
 * @return {BigInteger} User secret
 */
function getx(params, salt, I, P) {
    assertIsBuffer(salt, "salt (salt)");
    assertIsBuffer(I, "identity (I)");
    assertIsBuffer(P, "password (P)");
    const hashIP = crypto_1.default.createHash(params.hash)
        .update(Buffer.concat([I, Buffer.from(":"), P]))
        .digest();
    const hashX = crypto_1.default.createHash(params.hash)
        .update(salt)
        .update(hashIP)
        .digest();
    return new BigInteger(hashX);
}
class SRP {
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
    static computeVerifier(params, salt, I, P) {
        assertIsBuffer(salt, "salt (salt)");
        assertIsBuffer(I, "identity (I)");
        assertIsBuffer(P, "password (P)");
        const v_num = params.g.modPow(getx(params, salt, I, P), params.N);
        return v_num.toBuffer(params.N_length_bits / 8);
    }
    static genKey(bytes = 32, callback) {
        // bytes is optional
        if (typeof bytes !== "number") {
            callback = bytes;
            bytes = 32;
        }
        if (!callback) {
            return new Promise((rs, rj) => SRP.genKey(bytes, (err, data) => err ? rj(err) : rs(data)));
        }
        crypto_1.default.randomBytes(bytes, (err, buf) => {
            if (err) {
                return callback(err, null);
            }
            return callback(null, buf);
        });
    }
}
exports.SRP = SRP;
SRP.params = params_1.params;
/**
 * Calculate the SRP-6 multiplier.
 *
 * @param {object} params Group parameters, with .N, .g, .hash
 * @return {BigInteger}
 */
function getk(params) {
    const k_buf = crypto_1.default
        .createHash(params.hash)
        .update(padToN(params.N, params))
        .update(padToN(params.g, params))
        .digest();
    return new BigInteger(k_buf);
}
/**
 * The server key exchange message also contains the server's public
 * value (B).  The server calculates this value as B = k*v + g^b % N,
 * where b is a random number that SHOULD be at least 256 bits in length
 * and k = H(N | PAD(g)).
 *
 * Note: as the tests imply, the entire expression is mod N.
 *
 * @param {SrpParams} params Group parameters, with .N, .g, .hash
 * @param {BigInteger} k
 * @param {BigInteger} v Verifier (stored)
 * @param {BigInteger} b Server secret exponent
 * @return {Buffer} B - The server public message
 */
function getB(params, k, v, b) {
    assertIsBigInteger(v);
    assertIsBigInteger(k);
    assertIsBigInteger(b);
    const r = k.multiply(v).add(params.g.modPow(b, params.N)).mod(params.N);
    return r.toBuffer(params.N_length_bits / 8);
}
/**
 * The client key exchange message carries the client's public value
 * (A).  The client calculates this value as A = g^a % N, where a is a
 * random number that SHOULD be at least 256 bits in length.
 *
 * Note: for this implementation, we take that to mean 256/8 bytes.
 *
 * @param {object} params Group parameters, with .N, .g, .hash
 * @param {BigInteger} a_num Client secret exponent
 * @return {Buffer} A - The client public message
 */
function getA(params, a_num) {
    assertIsBigInteger(a_num);
    if (Math.ceil(a_num.toString(16).length / 2) < 32) {
        console.warn("getA: client key length %d is less than the recommended 256 bits", a_num.bitLength());
    }
    return params.g.modPow(a_num, params.N).toBuffer(params.N_length_bits / 8);
}
/**
 * getu() hashes the two public messages together, to obtain a scrambling
 * parameter "u" which cannot be predicted by either party ahead of time.
 * This makes it safe to use the message ordering defined in the SRP-6a
 * paper, in which the server reveals their "B" value before the client
 * commits to their "A" value.
 *
 * @param {object} params Group parameters, with .N, .g, .hash
 * @param {Buffer} A Client ephemeral public key
 * @param {Buffer} B Server ephemeral public key
 * @return {BigInteger} u - Shared scrambling parameter
 */
function getu(params, A, B) {
    assertIsBuffer(A, "A");
    assertIsBuffer(B, "B");
    const u_buf = crypto_1.default.createHash(params.hash)
        .update(padTo(A, params.N_length_bits / 8))
        .update(padTo(B, params.N_length_bits / 8))
        .digest();
    return new BigInteger(u_buf);
}
/**
 * The TLS premaster secret as calculated by the client
 *
 * @param {SrpParams} params Group parameters, with .N, .g, .hash
 * @param {BigInteger} k_num
 * @param {BigInteger} x_num
 * @param {BigInteger} a_num
 * @param {BigInteger} B_num
 * @param {BigInteger} u_num
 * @return {Buffer}
 */
function client_getS(params, k_num, x_num, a_num, B_num, u_num) {
    assertIsBigInteger(k_num);
    assertIsBigInteger(x_num);
    assertIsBigInteger(a_num);
    assertIsBigInteger(B_num);
    assertIsBigInteger(u_num);
    if ((zero.compareTo(B_num) >= 0) || (params.N.compareTo(B_num) <= 0)) {
        throw new Error("invalid server-supplied \"B\", must be 1..N-1");
    }
    const S_num = B_num.subtract(k_num.multiply(params.g.modPow(x_num, params.N)))
        .modPow(a_num.add(u_num.multiply(x_num)), params.N)
        .mod(params.N);
    return S_num.toBuffer(params.N_length_bits / 8);
}
/**
 * The TLS premastersecret as calculated by the server
 *
 * @param {BigInteger} params Group parameters, with .N, .g, .hash
 * @param {BigInteger} v_num Verifier (stored on server)
 * @param {BigInteger} A_num Ephemeral client public key (read from client)
 * @param {BigInteger} b_num Server ephemeral private key (generated for session)
 * @param {BigInteger} u_num {@see getu}
 * @return {Buffer}
 */
function server_getS(params, v_num, A_num, b_num, u_num) {
    assertIsBigInteger(v_num);
    assertIsBigInteger(A_num);
    assertIsBigInteger(b_num);
    assertIsBigInteger(u_num);
    if ((zero.compareTo(A_num) >= 0) || (params.N.compareTo(A_num) <= 0)) {
        throw new Error("invalid client-supplied \"A\", must be 1..N-1");
    }
    const S_num = A_num.multiply(v_num.modPow(u_num, params.N))
        .modPow(b_num, params.N)
        .mod(params.N);
    return S_num.toBuffer(params.N_length_bits / 8);
}
/**
 * Compute the shared session key K from S
 *
 * @param {object} params Group parameters, with .N, .g, .hash
 * @param {Buffer} S_buf Session key
 * @return {Buffer}
 */
function getK(params, S_buf) {
    assertIsBuffer(S_buf, "S");
    if (params.hash === "sha1") {
        // use t_mgf1 interleave for short sha1 hashes
        return Buffer.concat([
            crypto_1.default.createHash(params.hash).update(S_buf).update(Buffer.from([0, 0, 0, 0])).digest(),
            crypto_1.default.createHash(params.hash).update(S_buf).update(Buffer.from([0, 0, 0, 1])).digest(),
        ]);
    }
    else {
        // use hash as-is otherwise
        return crypto_1.default.createHash(params.hash).update(S_buf).digest();
    }
}
function getM1(params, u_buf, s_buf, A_buf, B_buf, K_buf) {
    if (arguments.length > 4) {
        assertIsBuffer(u_buf, "identity (I)");
        assertIsBuffer(s_buf, "salt (s)");
        assertIsBuffer(A_buf, "client public key (A)");
        assertIsBuffer(B_buf, "server public key (B)");
        assertIsBuffer(K_buf, "session key (K)");
        const hN = crypto_1.default.createHash(params.hash).update(params.N.toBuffer(true)).digest();
        const hG = crypto_1.default.createHash(params.hash).update(params.g.toBuffer(true)).digest();
        for (let i = 0; i < hN.length; i++) {
            hN[i] ^= hG[i];
        }
        const hU = crypto_1.default.createHash(params.hash).update(u_buf).digest();
        return crypto_1.default.createHash(params.hash)
            .update(hN).update(hU).update(s_buf)
            .update(A_buf).update(B_buf).update(K_buf)
            .digest();
    }
    else {
        [A_buf, B_buf, s_buf] = [u_buf, s_buf, A_buf];
        assertIsBuffer(A_buf, "A");
        assertIsBuffer(B_buf, "B");
        assertIsBuffer(s_buf, "S");
        return crypto_1.default.createHash(params.hash)
            .update(A_buf).update(B_buf).update(s_buf)
            .digest();
    }
}
function getM2(params, A_buf, M1_buf, K_buf) {
    assertIsBuffer(A_buf, "A");
    assertIsBuffer(M1_buf, "M1");
    assertIsBuffer(K_buf, "K");
    return crypto_1.default.createHash(params.hash)
        .update(A_buf).update(M1_buf).update(K_buf)
        .digest();
}
function equal(buf1, buf2) {
    // constant-time comparison. A drop in the ocean compared to our
    // non-constant-time modexp operations, but still good practice.
    return buf1.toString("hex") === buf2.toString("hex");
}
class SrpClient {
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
    constructor(params, identity_buf, secret1_buf, precomputed_x, salt_buf, password_buf, hap = true) {
        this._params = params;
        this._k = getk(params);
        var x = new BigInteger(0);
        if (precomputed_x != undefined) {
            x = new BigInteger(precomputed_x);
        }
        else if (salt_buf != undefined && password_buf != undefined) {
            x = getx(params, salt_buf, identity_buf, password_buf);
        }
        this._x = x;
        this._a = new BigInteger(secret1_buf);
        if (hap) {
            this._I = identity_buf;
            this._s = salt_buf;
        }
        this._A = getA(params, this._a);
    }
    /**
     * Returns the client's public key (A).
     *
     * @return {Buffer}
     */
    computeA() {
        return this._A;
    }
    /**
     * Sets the server's public key (B).
     *
     * @param {Buffer} B_buf The server's public key
     */
    setB(B_buf) {
        const u_num = getu(this._params, this._A, B_buf);
        const S_buf_x = client_getS(this._params, this._k, this._x, this._a, new BigInteger(B_buf), u_num);
        this._K = getK(this._params, S_buf_x);
        this._u = u_num; // only for tests
        this._S = S_buf_x; // only for tests
        this._B = B_buf;
        if (this._I && this._s) {
            this._M1 = getM1(this._params, this._I, this._s, this._A, this._B, this._K);
        }
        else {
            this._M1 = getM1(this._params, this._A, this._B, this._S);
        }
        this._M2 = getM2(this._params, this._A, this._M1, this._K);
    }
    /**
     * Gets the M1 value.
     * This requires setting the server's public key {@see Client.setB}.
     *
     * @return {Buffer}
     */
    computeM1() {
        if (this._M1 === undefined) {
            throw new Error("incomplete protocol");
        }
        return this._M1;
    }
    /**
     * Checks the server was able to calculate M2.
     * This requires setting the server's public key {@see Client.setB}.
     *
     * @param M2 The server's M2 value
     */
    checkM2(M2) {
        if (!equal(this._M2, M2)) {
            throw new Error("server is not authentic");
        }
    }
    /**
     * Returns the shared session key.
     *
     * @return {Buffer}
     */
    computeK() {
        if (this._K === undefined) {
            throw new Error("incomplete protocol");
        }
        return this._K;
    }
}
exports.SrpClient = SrpClient;
class SrpServer {
    constructor(params, salt_buf, identity_buf, password_buf, secret2_buf) {
        this._params = params;
        this._k = getk(params);
        if (arguments.length > 3) {
            assertIsBuffer(salt_buf, "salt (salt)");
            assertIsBuffer(identity_buf, "identity (I)");
            assertIsBuffer(password_buf, "password (P)");
            assertIsBuffer(secret2_buf, "secret2");
            this._b = new BigInteger(secret2_buf);
            this._v = new BigInteger(SRP.computeVerifier(params, salt_buf, identity_buf, password_buf));
            this._I = identity_buf;
            this._s = salt_buf;
        }
        else if (salt_buf instanceof Buffer) {
            const verifier_buf = salt_buf;
            // noinspection JSUnusedAssignment
            [secret2_buf, salt_buf, identity_buf, password_buf] = [identity_buf, undefined, undefined, undefined];
            assertIsBuffer(verifier_buf, "verifier (v)");
            assertIsBuffer(secret2_buf, "secret2");
            this._b = new BigInteger(secret2_buf);
            this._v = new BigInteger(verifier_buf);
        }
        else {
            const identity = salt_buf;
            // noinspection JSUnusedAssignment
            [secret2_buf, salt_buf, identity_buf, password_buf] = [identity_buf, undefined, undefined, undefined];
            // noinspection SuspiciousTypeOfGuard
            assert_1.default(identity.username instanceof Buffer || typeof identity.username === "string", "identity.username (I) must be a string or Buffer");
            assertIsBuffer(identity.salt, "identity.salt (s)");
            assert_1.default("password" in identity || "verifier" in identity, "identity requires a password or verifier");
            if ("verifier" in identity) {
                assertIsBuffer(identity.verifier, "identity.verifier (v)");
            }
            else {
                // noinspection SuspiciousTypeOfGuard
                assert_1.default(identity.password instanceof Buffer || typeof identity.password === "string", "identity.password (p) must be a string or Buffer");
            }
            assertIsBuffer(secret2_buf, "secret2");
            const username = typeof identity.username === "string" ? Buffer.from(identity.username) : identity.username;
            this._b = new BigInteger(secret2_buf);
            if ("verifier" in identity) {
                this._v = new BigInteger(identity.verifier);
            }
            else {
                this._v = new BigInteger(SRP.computeVerifier(params, identity.salt, username, typeof identity.password === "string" ? Buffer.from(identity.password) : identity.password));
            }
            this._I = username;
            this._s = identity.salt;
        }
        this._B = getB(params, this._k, this._v, this._b);
    }
    /**
     * Returns the server's public key (B).
     *
     * @return {Buffer}
     */
    computeB() {
        return this._B;
    }
    /**
     * Sets the client's public key (A).
     *
     * @param {Buffer} A The client's public key
     */
    setA(A) {
        const u_num = getu(this._params, A, this._B);
        const S_buf = server_getS(this._params, this._v, new BigInteger(A), this._b, u_num);
        this._K = getK(this._params, S_buf);
        this._u = u_num; // only for tests
        this._S = S_buf; // only for tests
        if (this._I && this._s) {
            this._M1 = getM1(this._params, this._I, this._s, A, this._B, this._K);
        }
        else {
            this._M1 = getM1(this._params, A, this._B, this._S);
        }
        this._M2 = getM2(this._params, A, this._M1, this._K);
    }
    /**
     * Checks the client was able to calculate M1.
     *
     * @param {Buffer} M1 The client's M1 value
     */
    checkM1(M1) {
        if (this._M1 === undefined) {
            throw new Error("incomplete protocol");
        }
        if (!equal(this._M1, M1)) {
            throw new Error("client did not use the same password");
        }
    }
    /**
     * Returns the shared session key.
     *
     * @return {Buffer}
     */
    computeK() {
        if (this._K === undefined) {
            throw new Error("incomplete protocol");
        }
        return this._K;
    }
    /**
     * Gets the M2 value.
     * This requires setting the client's public key {@see Server.setA}.
     *
     * @return {Buffer}
     */
    computeM2() {
        if (this._M2 === undefined) {
            throw new Error("incomplete protocol");
        }
        return this._M2;
    }
}
exports.SrpServer = SrpServer;
//# sourceMappingURL=srp.js.map