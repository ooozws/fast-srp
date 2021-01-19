"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
/* eslint-disable @typescript-eslint/ban-ts-comment */
// @ts-ignore
const vows_1 = __importDefault(require("vows"));
const assert_1 = __importDefault(require("assert"));
const srp_1 = require("../srp");
const BigInteger = require("../../jsbn/jsbn");
// eslint-disable-next-line @typescript-eslint/no-unused-vars
const hap_test_data_1 = require("./hap_test_data");
const params = srp_1.SRP.params.hap;
const inputs = {
    I: Buffer.from(hap_test_data_1.I, "ascii"),
    P: Buffer.from(hap_test_data_1.p, "ascii"),
    salt: hap_test_data_1.s.toBuffer(true),
    // a and b are usually random. For testing, we force them to specific values.
    a: hap_test_data_1.a.toBuffer(true),
    b: hap_test_data_1.b.toBuffer(true),
};
const expected = {
    // 'k' encodes the group (N and g), used in SRP-6a
    k: Buffer.from("a9c2e2559bf0ebb53f0cbbf62282906bede7f2182f00678211fbd5bde5b285033a4993503b87397f9be5ec02080fedbc0835587ad039060879b8621e8c3659e0", "hex"),
    // 'x' is derived from the salt and password
    x: Buffer.from("b149ecb0946b0b206d77e73d95deb7c41bd12e86a5e2eea3893d5416591a002ff94bfea384dc0e1c550f7ed4d5a9d2ad1f1526f01c56b5c10577730cc4a4d709", "hex"),
    // 'v' is the SRP verifier
    v: hap_test_data_1.v.toBuffer(true),
    // 'B' is the server's public message
    B: hap_test_data_1.B.toBuffer(true),
    // 'A' is the client's public message
    A: hap_test_data_1.A.toBuffer(true),
    // 'u' combines the two public messages
    u: hap_test_data_1.u.toBuffer(true),
    // 'S' is the shared secret
    S: hap_test_data_1.S.toBuffer(true),
    // 'K' is the shared derived key
    K: hap_test_data_1.K.toBuffer(true),
    // 'M1' is the client's proof that it knows the shared key
    M1: Buffer.from("5f7c14ab57ed0e94fd1d78c6b4dd09ed7e340b7e05d419a9fd760f6b35e523d1310777a1ae1d2826f596f3a85116cc457c7c964d4f44ded5559da818c88b617f", "hex"),
};
function hexequal(a, b, msg) {
    assert_1.default.strictEqual(a.length, b.length, msg);
    assert_1.default.strictEqual(a.toString("hex"), b.toString("hex"), msg);
}
function numequal(a, b, msg) {
    assert_1.default(a.compareTo(b) === 0, msg);
}
function checkVectors(params, inputs, expected, useVerifier = true) {
    hexequal(inputs.I, Buffer.from("616c696365", "hex"), "I");
    hexequal(srp_1.SRP.computeVerifier(params, inputs.salt, inputs.I, inputs.P), expected.v, "v");
    const client = new srp_1.SrpClient(params, inputs.I, inputs.a, undefined, inputs.salt, inputs.P, true);
    const server = useVerifier ?
        new srp_1.SrpServer(params, { username: inputs.I, salt: inputs.salt, verifier: expected.v }, inputs.b) :
        new srp_1.SrpServer(params, inputs.salt, inputs.I, inputs.P, inputs.b);
    // @ts-ignore
    numequal(client._k, new BigInteger(expected.k.toString("hex"), 16), "k");
    // @ts-ignore
    numequal(client._x, new BigInteger(expected.x.toString("hex"), 16), "x");
    hexequal(client.computeA(), expected.A);
    hexequal(server.computeB(), expected.B);
    assert_1.default.throws(() => client.computeM1(), /incomplete protocol/);
    assert_1.default.throws(() => client.computeK(), /incomplete protocol/);
    assert_1.default.throws(() => server.checkM1(expected.M1), /incomplete protocol/);
    assert_1.default.throws(() => server.computeK(), /incomplete protocol/);
    assert_1.default.throws(() => server.computeM2(), /incomplete protocol/);
    client.setB(expected.B);
    // @ts-ignore
    numequal(client._u, new BigInteger(expected.u.toString("hex"), 16));
    // @ts-ignore
    hexequal(client._S, expected.S);
    hexequal(client.computeM1(), expected.M1);
    hexequal(client.computeK(), expected.K);
    server.setA(expected.A);
    // @ts-ignore
    numequal(server._u, new BigInteger(expected.u.toString("hex"), 16));
    // @ts-ignore
    hexequal(server._S, expected.S);
    assert_1.default.throws(() => server.checkM1(Buffer.from("notM1")), /client did not use the same password/);
    server.checkM1(expected.M1); // happy, not throwy
    hexequal(server.computeK(), expected.K);
}
vows_1.default.describe("HomeKit vectors").addBatch({
    "with verifier": () => checkVectors(params, inputs, expected),
    "with password": () => checkVectors(params, inputs, expected, false),
}).export(module);
//# sourceMappingURL=test_hap_vectors.js.map