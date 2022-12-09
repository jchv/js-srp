import { Srp, Mode, Hash } from "./index.js";
import { fromHex, bigintFromBytes, bytesFromBigint, constantTimeCompare } from "./util.js";

const encoder = new TextEncoder();

async function testClientSrpTools() {
  // Test vectors from https://github.com/secure-remote-password/test-vectors/blob/master/srptools.json.
  const test = {
    I: encoder.encode("alice"),
    P: encoder.encode("password123"),
    s: fromHex("beb25379d1a8581eb5a727673a2441ee"),
    v: fromHex("7e273de8696ffc4f4e337d05b4b375beb0dde1569e8fa00a9886d8129bada1f1822223ca1a605b530e379ba4729fdc59f105b4787e5186f5c671085a1447b52a48cf1970b4fb6f8400bbf4cebfbb168152e08ab5ea53d15c1aff87b2b9da6e04e058ad51cc72bfc9033b564e26480d78e955a5e29e7ab245db2be315e2099afb"),
    a: fromHex("60975527035cf2ad1989806f0407210bc81edc04e2762a56afd529ddda2d4393"),
    A: fromHex("61d5e490f6f1b79547b0704c436f523dd0e560f0c64115bb72557ec44352e8903211c04692272d8b2d1a5358a2cf1b6e0bfcf99f921530ec8e39356179eae45e42ba92aeaced825171e1e8b9af6d9c03e1327f44be087ef06530e69f66615261eef54073ca11cf5858f0edfdfe15efeab349ef5d76988a3672fac47b0769447b"),
    B: fromHex("bd0c61512c692c0cb6d041fa01bb152d4916a1e77af46ae105393011baf38964dc46a0670dd125b95a981652236f99d9b681cbf87837ec996c6da04453728610d0c6ddb58b318885d7d82c7f8deb75ce7bd4fbaa37089e6f9c6059f388838e7a00030b331eb76840910440b1b27aaeaeeb4012b7d7665238a8e3fb004b117b58"),
    K: fromHex("017eefa1cefc5c2e626e21598987f31e0f1b11bb"),
    M1: fromHex("3f3bc67169ea71302599cf1b0f5d408b7b65d347"),
  } as const;

  const srp = new Srp(Mode.SRPTools, Hash.SHA1, 1024);

  const verifier = await srp.verifier(test.I, test.P, test.s);

  if (!constantTimeCompare(verifier.v, test.v)) {
    throw new Error("Verifier does not match; expected:\n" + test.v + "got:\n" + verifier.v);
  }

  const client = await srp.newClient(test.I, test.P, bigintFromBytes(test.a));
  if (!constantTimeCompare(bytesFromBigint(client.A), test.A)) {
    throw new Error("A value does not match; expected:\n" + test.A + "got:\n" + client.A);
  }

  const M1 = await client.generate(test.s, test.B);
  if (!constantTimeCompare(fromHex(M1), test.M1)) {
    throw new Error("A value does not match; expected:\n" + test.A + "got:\n" + client.A);
  }

  if (!constantTimeCompare(client.K, test.K)) {
    throw new Error("A value does not match; expected:\n" + test.A + "got:\n" + client.A);
  }
}

testClientSrpTools().catch(e => {
  console.error(e);
  process.exit(1);
});
