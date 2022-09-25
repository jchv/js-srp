/**
 * A simple SRP-6a implementation with some tweaks.
 *
 * In addition to SRP-6a:
 * - The identity I is hashed prior to calculating the verifier.
 * - The passphrase p is hashed prior to calculating the verifier.
 * - The hash function is configurable, but only supports WebCrypto-compatible algorithms.
 * 
 * This library is designed to be compatible with
 * https://github.com/opencoff/go-srp.
 * 
 * --
 * 
 * This code is licensed under the terms of the ISC license.
 * 
 * Copyright © 2022, John Chadwick <john@jchw.io>
 * 
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

// This should give us the WebCrypto API in both browsers and Node.js.
let webcrypto: Crypto;
if (typeof self === 'undefined') {
  // @ts-ignore - prefer to not include node types only for this
  webcrypto = require('node:crypto').webcrypto as Crypto;
} else {
  webcrypto = self.crypto;
}

/**
 * Prime fields used for cryptographic operations.
 */
 interface PrimeField {
  g: bigint;
  N: bigint;
  n: number;
}

/**
 * Enumeration of hash types. This is a subset of the Go hash enumeration, with
 * only algorithms supported by WebCrypto.
 */
export enum Hash {
  SHA1 = 3,
  SHA256 = 5,
  SHA384 = 6,
  SHA512 = 7,
}

/** Known-safe prime fields. */
const knownPrimeFields = new Map<number, PrimeField>([
  [1024, { g: 2n, N: 0xeeaf0ab9adb38dd69c33f80afa8fc5e86072618775ff3c0b9ea2314c9c256576d674df7496ea81d3383b4813d692c6e0e0d5d8e250b98be48e495c1d6089dad15dc7d7b46154d6b6ce8ef4ad69b15d4982559b297bcf1885c529f566660e57ec68edbc3c05726cc02fd4cbf4976eaa9afd5138fe8376435b9fc61d2fc0eb06e3n, n: 128 }],
  [1536, { g: 2n, N: 0x9def3cafb939277ab1f12a8617a47bbbdba51df499ac4c80beeea9614b19cc4d5f4f5f556e27cbde51c6a94be4607a291558903ba0d0f84380b655bb9a22e8dcdf028a7cec67f0d08134b1c8b97989149b609e0be3bab63d47548381dbc5b1fc764e3f4b53dd9da1158bfd3e2b9c8cf56edf019539349627db2fd53d24b7c48665772e437d6c7f8ce442734af7ccb7ae837c264ae3a9beb87f8a2fe9b8b5292e5a021fff5e91479e8ce7a28c2442c6f315180f93499a234dcf76e3fed135f9bbn, n: 192 }],
  [2048, { g: 2n, N: 0xac6bdb41324a9a9bf166de5e1389582faf72b6651987ee07fc3192943db56050a37329cbb4a099ed8193e0757767a13dd52312ab4b03310dcd7f48a9da04fd50e8083969edb767b0cf6095179a163ab3661a05fbd5faaae82918a9962f0b93b855f97993ec975eeaa80d740adbf4ff747359d041d5c33ea71d281e446b14773bca97b43a23fb801676bd207a436c6481f1d2b9078717461a5b9d32e688f87748544523b524b0d57d5ea77a2775d2ecfa032cfbdbf52fb3786160279004e57ae6af874e7303ce53299ccc041c7bc308d82a5698f3a8d0c38271ae35f8e9dbfbb694b5c803d89f7ae435de236d525f54759b65e372fcd68ef20fa7111f9e4aff73n, n: 256 }],
  [3072, { g: 5n, N: 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a93ad2caffffffffffffffffn, n: 384 }],
  [4096, { g: 5n, N: 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a92108011a723c12a787e6d788719a10bdba5b2699c327186af4e23c1a946834b6150bda2583e9ca2ad44ce8dbbbc2db04de8ef92e8efc141fbecaa6287c59474e6bc05d99b2964fa090c3a2233ba186515be7ed1f612970cee2d7afb81bdd762170481cd0069127d5b05aa993b4ea988d8fddc186ffb7dc90a6c08f4df435c934063199ffffffffffffffffn, n: 512 }],
  [6144, { g: 5n, N: 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a92108011a723c12a787e6d788719a10bdba5b2699c327186af4e23c1a946834b6150bda2583e9ca2ad44ce8dbbbc2db04de8ef92e8efc141fbecaa6287c59474e6bc05d99b2964fa090c3a2233ba186515be7ed1f612970cee2d7afb81bdd762170481cd0069127d5b05aa993b4ea988d8fddc186ffb7dc90a6c08f4df435c93402849236c3fab4d27c7026c1d4dcb2602646dec9751e763dba37bdf8ff9406ad9e530ee5db382f413001aeb06a53ed9027d831179727b0865a8918da3edbebcf9b14ed44ce6cbaced4bb1bdb7f1447e6cc254b332051512bd7af426fb8f401378cd2bf5983ca01c64b92ecf032ea15d1721d03f482d7ce6e74fef6d55e702f46980c82b5a84031900b1c9e59e7c97fbec7e8f323a97a7e36cc88be0f1d45b7ff585ac54bd407b22b4154aacc8f6d7ebf48e1d814cc5ed20f8037e0a79715eef29be32806a1d58bb7c5da76f550aa3d8a1fbff0eb19ccb1a313d55cda56c9ec2ef29632387fe8d76e3c0468043e8f663f4860ee12bf2d5b0b7474d6e694f91e6dcc4024ffffffffffffffffn, n: 768 }],
  [8192, { g: 19n, N: 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a92108011a723c12a787e6d788719a10bdba5b2699c327186af4e23c1a946834b6150bda2583e9ca2ad44ce8dbbbc2db04de8ef92e8efc141fbecaa6287c59474e6bc05d99b2964fa090c3a2233ba186515be7ed1f612970cee2d7afb81bdd762170481cd0069127d5b05aa993b4ea988d8fddc186ffb7dc90a6c08f4df435c93402849236c3fab4d27c7026c1d4dcb2602646dec9751e763dba37bdf8ff9406ad9e530ee5db382f413001aeb06a53ed9027d831179727b0865a8918da3edbebcf9b14ed44ce6cbaced4bb1bdb7f1447e6cc254b332051512bd7af426fb8f401378cd2bf5983ca01c64b92ecf032ea15d1721d03f482d7ce6e74fef6d55e702f46980c82b5a84031900b1c9e59e7c97fbec7e8f323a97a7e36cc88be0f1d45b7ff585ac54bd407b22b4154aacc8f6d7ebf48e1d814cc5ed20f8037e0a79715eef29be32806a1d58bb7c5da76f550aa3d8a1fbff0eb19ccb1a313d55cda56c9ec2ef29632387fe8d76e3c0468043e8f663f4860ee12bf2d5b0b7474d6e694f91e6dbe115974a3926f12fee5e438777cb6a932df8cd8bec4d073b931ba3bc832b68d9dd300741fa7bf8afc47ed2576f6936ba424663aab639c5ae4f5683423b4742bf1c978238f16cbe39d652de3fdb8befc848ad922222e04a4037c0713eb57a81a23f0c73473fc646cea306b4bcbc8862f8385ddfa9d4b7fa2c087e879683303ed5bdd3a062b3cf5b3a278a66d2a13f83f44f82ddf310ee074ab6a364597e899a0255dc164f31cc50846851df9ab48195ded7ea1b1d510bd7ee74d73faf36bc31ecfa268359046f4eb879f924009438b481c6cd7889a002ed5ee382bc9190da6fc026e479558e4475677e9aa9e3050e2765694dfc81f56e880b96e7160c980dd98edd3dfffffffffffffffffn, n: 1024 }],
]);

/**
 * Returns the length of the bigint in bits.
 *
 * @param {bigint} n bigint to check
 * @return {number} count of bits needed to store bigint
 */
function bitLength(n: bigint): number {
  return n.toString(2).length;
}

/**
 * Returns the length of the bigint in bytes. Rounds up to the nearest byte.
 *
 * @param {bigint} n bigint to check
 * @return {number} count of bytes needed to store bigint
 */
function byteLength(n: bigint): number {
  return ((bitLength(n) + 7) / 8) | 0;
}

/**
 * Deserializes a buffer of bytes into a bigint.
 *
 * @param {Uint8Array} buf buffer containing a serialized bigint
 * @return {bigint} deserialized value parsed from buf
 */
function bigintFromBytes(buf: Uint8Array): bigint {
  let ret = 0n;
  for (const i of buf.values()) {
    ret = (ret << 8n) + BigInt(i);
  }
  return ret;
}

/**
 * Serializes a bigint into a buffer of bytes.
 *
 * @param {bigint} v value to serialize
 * @return {Uint8Array} serialized form of v
 */
function bytesFromBigint(v: bigint): Uint8Array {
  const bytes = new Uint8Array(byteLength(v));
  for (let i = bytes.length - 1; v > 0; i--, v >>= 8n) {
    bytes[i] = Number(v & 0xffn);
  }
  return bytes;
}

/**
 * Returns cryptographically-safe random bytes into a buffer.
 *
 * @param {number} numBytes number of bytes
 * @return {Uint8Array} buffer containing random bytes
 */
 function randomBytes(numBytes: number): Uint8Array {
  if (numBytes < 1) {
    throw new RangeError("numBytes must be >= 1");
  }

  const bytes = new Uint8Array(numBytes);
  webcrypto.getRandomValues(bytes);
  return bytes;
}

/**
 * Returns the smallest positive value in the multiplicative group of integers
 * modulo n that is congruent to a.
 *
 * @param {bigint} a value to find congruent value of
 * @param {bigint} n modulo of multiplicative group
 * @return {bigint} smallest positive congruent value of a in integers modulo n
 */
function toZn(a: bigint, n: bigint): bigint {
  if (n < 1n) {
    throw new RangeError("n must be > 0");
  }

  const aZn = a % n;
  return aZn < 0n ? aZn + n : aZn;
}

/**
 * Solves for values g, x, y, such that g = gcd(a, b) and g = ax + by.
 *
 * @param {bigint} a
 * @param {bigint} b
 * @return {{g: bigint, x: bigint, y: bigint }}
 */
function eGcd(
  a: bigint,
  b: bigint
): {
  g: bigint;
  x: bigint;
  y: bigint;
} {
  if (a < 1n || b < 1n) {
    throw new RangeError("a and b must be > 0");
  }

  let x = 0n;
  let y = 1n;
  let u = 1n;
  let v = 0n;

  while (a !== 0n) {
    const q = b / a;
    const r = b % a;
    const m = x - u * q;
    const n = y - v * q;
    b = a;
    a = r;
    x = u;
    y = v;
    u = m;
    v = n;
  }

  return { g: b, x, y };
}

/**
 * Calculates the modular inverse of a in the multiplicative group of integers
 * modulo n.
 *
 * @param {bigint} a
 * @param {bigint} n
 * @return {bigint}
 */
function modInv(a: bigint, n: bigint): bigint {
  const egcd = eGcd(toZn(a, n), n);
  if (egcd.g !== 1n) {
    throw new RangeError();
  } else {
    return toZn(egcd.x, n);
  }
}

/**
 * Calculates the value of x ^ y % m efficiently.
 *
 * @param {bigint} x
 * @param {bigint} y
 * @param {bigint} m
 * @return {bigint}
 */
function modPow(x: bigint, y: bigint, m: bigint): bigint {
  if (m < 1n) {
    throw new RangeError("n must be > 0");
  } else if (m === 1n) {
    return 0n;
  }

  x = toZn(x, m);

  if (y < 0n) {
    return modInv(modPow(x, y >= 0 ? y : -y, m), m);
  }

  let r = 1n;
  while (y > 0) {
    if (y % 2n === 1n) {
      r = (r * x) % m;
    }
    y = y / 2n;
    x = x ** 2n % m;
  }
  return r;
}

/**
 * Concatenates multiple buffers into one new buffer.
 *
 * @param {Uint8Array[]} a buffers to concatenate
 * @return {Uint8Array} a new buffer containing the concatenated contents
 */
function concatBytes(...a: Uint8Array[]): Uint8Array {
  let length = 0;
  for (const b of a) {
    length += b.byteLength;
  }
  const buf = new Uint8Array(length);
  let offset = 0;
  for (const b of a) {
    buf.set(b, offset);
    offset += b.byteLength;
  }
  return buf;
}

/**
 * Encodes a buffer into a hexadecimal string.
 *
 * @param {Uint8Array} buffer buffer to encode
 * @return {string} hex-encoded form of buffer
 */
function toHex(buffer: Uint8Array): string {
  return [...buffer].map((x) => x.toString(16).padStart(2, "0")).join("");
}

/**
 * Decodes a hexadecimal string into a new buffer.
 *
 * @param {string} str hexadecimal string to decode
 * @return {Uint8Array} buffer of bytes decoded from str
 */
function fromHex(str: string): Uint8Array {
  return Uint8Array.from(
    str.match(/.{2}/g)?.map((byte) => parseInt(byte, 16)) ?? []
  );
}

/**
 * Compares two buffers with constant-time execution.
 *
 * @param {Uint8Array} a first buffer to compare
 * @param {Uint8Array} b second buffer to compare
 * @return {boolean} true if a == b, otherwise false
 */
function constantTimeCompare(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }

  const len = a.length;
  let out = 0;

  for (let i = 0; i < len; i++) {
    out |= a[i]! ^ b[i]!;
  }

  return out === 0;
}

/**
 * Returns the result of applying a hash to the given buffer.
 *
 * @param {Hash} hash algorithm to use
 * @param {BufferSource} data data to hash
 * @return {Promise<ArrayBuffer>} digest
 */
function hash(hash: Hash, data: BufferSource): Promise<ArrayBuffer> {
  switch (hash) {
    case Hash.SHA1:
      return webcrypto.subtle.digest("SHA-1", data);
    case Hash.SHA256:
      return webcrypto.subtle.digest("SHA-256", data);
    case Hash.SHA384:
      return webcrypto.subtle.digest("SHA-384", data);
    case Hash.SHA512:
      return webcrypto.subtle.digest("SHA-512", data);
  }
}

/**
 * Find a known-safe prime field for a given number of bits.
 *
 * @param {number} bits
 * @return {PrimeField}
 */
function findPrimeField(bits: number = 0): PrimeField {
  if (bits === 0) bits = 2048;

  const primeField = knownPrimeFields.get(bits);

  if (!primeField) {
    throw new Error(`Invalid prime field size ${bits}`);
  }

  return primeField;
}

/**
 * Returns a serialized bigint with padding to ensure it is at least n bytes.
 *
 * @param {bigint} x number to serialize
 * @param {number} n minimum number of bytes to return
 * @return {Uint8Array} buffer containing padded output
 */
function pad(x: bigint, n: number): Uint8Array {
  const b = bytesFromBigint(x);
  if (b.length >= n) {
    return b;
  }
  const z = n - b.length;
  const p = new Uint8Array(n);
  for (let i = 0; i < z; i++) {
    p[i] = 0;
  }
  p.set(b, z);
  return p;
}

/**
 * Performs basic SRP operations with a given prime field.
 */
export class Srp {
  readonly pf: PrimeField;

  constructor(readonly h: Hash, bits: number = 0) {
    this.pf = findPrimeField(bits);
  }

  /**
   * Calculates the hash of a buffer and returns it as a bigint.
   */
  async hashInt(buf: Uint8Array): Promise<bigint> {
    return bigintFromBytes(new Uint8Array(await hash(this.h, buf)));
  }

  /**
   * Calculate a verifier for the given identity + passphrase.
   *
   * @param {Uint8Array} I raw identity value
   * @param {Uint8Array} p raw passphrase value
   * @param {Uint8Array?} salt optional salt value; otherwise random
   * @return {Verifier}
   */
  async verifier(
    I: Uint8Array,
    p: Uint8Array,
    salt?: Uint8Array
  ): Promise<Verifier> {
    const ih = new Uint8Array(await hash(this.h, I));
    const ph = new Uint8Array(await hash(this.h, p));
    const pf = this.pf;
    if (!salt) salt = randomBytes(pf.n);
    const x = await this.hashInt(concatBytes(ih, ph, salt));
    const r = modPow(pf.g, x, pf.N);

    return new Verifier({
      i: ih,
      s: salt,
      v: bytesFromBigint(r),
      h: this.h,
      pf: pf,
    });
  }

  /**
   * Initialize SRP client operations.
   *
   * @param {Uint8Array} I raw identity value
   * @param {Uint8Array} p raw passphrase value
   * @param {bigint?} a optional; private value a to use
   * @return {Promise<Client>}
   */
  async newClient(I: Uint8Array, p: Uint8Array, a?: bigint): Promise<Client> {
    const pf = this.pf;

    if (!a) {
      a = bigintFromBytes(randomBytes(pf.n));
    }

    return new Client({
      s: this,
      i: new Uint8Array(await hash(this.h, I)),
      p: new Uint8Array(await hash(this.h, p)),
      a,
      xA: modPow(pf.g, a, pf.N),
      k: await this.hashInt(
        concatBytes(bytesFromBigint(pf.N), pad(pf.g, Number(pf.n)))
      ),
      xK: new Uint8Array(),
      xM: new Uint8Array(),
    });
  }
}

/**
 * Contains SRP verifier parameters.
 */
export class Verifier {
  private readonly i: Uint8Array;
  private readonly s: Uint8Array;
  private readonly v: Uint8Array;
  private readonly h: Hash;
  private readonly pf: PrimeField;

  constructor(fields: {
    i: Uint8Array;
    s: Uint8Array;
    v: Uint8Array;
    h: Hash;
    pf: PrimeField;
  }) {
    this.i = fields.i;
    this.s = fields.s;
    this.v = fields.v;
    this.h = fields.h;
    this.pf = fields.pf;
  }

  /**
   * Encodes the verifier to a string.
   *
   * @returns {[string, string]} tuple of hashed identity and verifier string
   */
  encode(): [string, string] {
    const ih = toHex(this.i);
    const b = [
      this.pf.n.toString(10),
      this.pf.N.toString(16),
      this.pf.g.toString(16),
      this.h.toString(10),
      ih,
      toHex(this.s),
      toHex(this.v),
    ].join(":");
    return [ih, b];
  }
}

/**
 * Performs SRP client operations.
 */
export class Client {
  private readonly s: Srp;
  private readonly i: Uint8Array;
  private readonly p: Uint8Array;
  private readonly a: bigint;
  private readonly xA: bigint;
  private readonly k: bigint;
  private xK: Uint8Array;
  private xM: Uint8Array;

  constructor(fields: {
    s: Srp;
    i: Uint8Array;
    p: Uint8Array;
    a: bigint;
    xA: bigint;
    k: bigint;
    xK: Uint8Array;
    xM: Uint8Array;
  }) {
    this.s = fields.s;
    this.i = fields.i;
    this.p = fields.p;
    this.a = fields.a;
    this.xA = fields.xA;
    this.k = fields.k;
    this.xK = fields.xK;
    this.xM = fields.xM;
  }

  /**
   * Returns credentials to pass to the server.
   *
   * @returns {string} serialized credentials
   */
  credentials(): string {
    return [toHex(this.i), toHex(bytesFromBigint(this.xA))].join(":");
  }

  /**
   * Generates an authenticator, given server credentials.
   *
   * @param {string} srv server credentials
   * @return {Promise<string>} authenticator to send to server
   */
  async generate(srv: string): Promise<string> {
    const v = srv.split(":");
    if (!v[0] || !v[1]) {
      throw new Error("Invalid server public key");
    }

    const salt = fromHex(v[0]);

    const B = bigintFromBytes(fromHex(v[1]));

    const pf = this.s.pf;
    if (B % pf.N === 0n) {
      throw new Error("Invalid server public key");
    }

    const u = await this.s.hashInt(
      concatBytes(pad(this.xA, pf.n), pad(B, pf.n))
    );
    if (u === 0n) {
      throw new Error("Invalid server public key");
    }

    const x = await this.s.hashInt(concatBytes(this.i, this.p, salt));
    const t0 = modPow(pf.g, x, pf.N) * this.k;

    const t1 = B - t0;
    const t2 = this.a + u * x;
    const S = modPow(t1, t2, pf.N);

    this.xK = new Uint8Array(await hash(this.s.h, bytesFromBigint(S)));
    this.xM = new Uint8Array(
      await hash(
        this.s.h,
        concatBytes(
          this.xK,
          bytesFromBigint(this.xA),
          bytesFromBigint(B),
          this.i,
          salt,
          bytesFromBigint(pf.N),
          bytesFromBigint(pf.g)
        )
      )
    );

    return toHex(this.xM);
  }

  /**
   * Validates the proof returned by the server.
   *
   * @param {string} proof proof returned by the server
   * @returns {Promise<boolean>} true if valid, otherwise false
   */
  async serverOk(proof: string): Promise<boolean> {
    const enc = new TextEncoder();
    const h = enc.encode(
      toHex(new Uint8Array(await hash(this.s.h, concatBytes(this.xK, this.xM))))
    );
    const proofBin = enc.encode(proof);
    return constantTimeCompare(h, proofBin);
  }
}
