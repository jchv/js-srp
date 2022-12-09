import type { webcrypto } from "crypto";

export const crypto = require('node:crypto').webcrypto as webcrypto.Crypto;
