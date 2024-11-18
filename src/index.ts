import { pbkdf2Sync, randomBytes, timingSafeEqual } from "crypto";

/** Defines type of HMAC digest algorythm. */
type HmacDigest =
  | "RSA-MD5"
  | "RSA-RIPEMD160"
  | "RSA-SHA1"
  | "RSA-SHA1-2"
  | "RSA-SHA224"
  | "RSA-SHA256"
  | "RSA-SHA3-224"
  | "RSA-SHA3-256"
  | "RSA-SHA3-384"
  | "RSA-SHA3-512"
  | "RSA-SHA384"
  | "RSA-SHA512"
  | "RSA-SHA512/224"
  | "RSA-SHA512/256"
  | "RSA-SM3"
  | "blake2b512"
  | "blake2s256"
  | "id-rsassa-pkcs1-v1_5-with-sha3-224"
  | "id-rsassa-pkcs1-v1_5-with-sha3-256"
  | "id-rsassa-pkcs1-v1_5-with-sha3-384"
  | "id-rsassa-pkcs1-v1_5-with-sha3-512"
  | "md5"
  | "md5-sha1"
  | "md5WithRSAEncryption"
  | "ripemd"
  | "ripemd160"
  | "ripemd160WithRSA"
  | "rmd160"
  | "sha1"
  | "sha1WithRSAEncryption"
  | "sha224"
  | "sha224WithRSAEncryption"
  | "sha256"
  | "sha256WithRSAEncryption"
  | "sha3-224"
  | "sha3-256"
  | "sha3-384"
  | "sha3-512"
  | "sha384"
  | "sha384WithRSAEncryption"
  | "sha512"
  | "sha512-224"
  | "sha512-224WithRSAEncryption"
  | "sha512-256"
  | "sha512-256WithRSAEncryption"
  | "sha512WithRSAEncryption"
  | "shake128"
  | "shake256"
  | "sm3"
  | "sm3WithRSAEncryption"
  | "ssl3-md5"
  | "ssl3-sha1";

/** Represents hashing error. */
export class StringHashError extends Error {
  /** Gets inner error. */
  public inner?: Error;

  /**
   * Initializes a new instance of `StringHashError` class.
   * @param message Error message.
   * @param inner Inner error.
   */
  constructor(message?: string, inner?: Error) {
    super(message);

    this.inner = inner;
  }
}

/** Defines properties of hashing options. */
export type StringHashOptions = {
  /** Gets hash signature (prefix). */
  signature?: string;

  /** Gets the HMAC digest algorythm. */
  algorythm?: HmacDigest;

  /** Gets salt length. */
  saltLength?: number;

  /** Gets hash length. */
  hashLength?: number;

  /** Gets the number of iteration. */
  iterations?: number;
};

/** Defines properties and methods of `StringHasher`. */
interface IStringHasher {
  /** Gets hash signature (prefix). */
  signature: string;

  /** Gets algorythm */
  algorythm: HmacDigest;

  /** Gets salt length. */
  saltLength: number;

  /** Gets hash length. */
  hashLength: number;

  /** Gets buffer length (`saltLength` - `hashLength` - `signatureLength`). */
  buffLength: number;

  /** Gets iterations count. */
  iterations: number;

  /**
   * Generates hash of the `value` string.
   * @param value String to generate hash of.
   * @returns Hash, generated of given string with following structure: `{signature}{hashBuff}{saltBuff}`.
   */
  generate(value: string): string;

  /**
   * Compares a plain-text `value` string to a hashed one.
   * @param value Value string.
   * @param hash Hash string.
   * @returns `true` is hashes converge; `false` otherwise.
   */
  validate(value: string, hash: string): boolean;
}

/** Represents string hasher. */
export class StringHasher implements IStringHasher {
  public readonly signature: string = "sha512";
  public readonly algorythm: HmacDigest = "sha512";
  public readonly saltLength: number = 32;
  public readonly hashLength: number = 128;
  public readonly buffLength: number = 90;
  public readonly iterations: number = 100000;

  /**
   * Initializes a new instance of `StringHasher` class.
   * @param options Hashing options.
   */
  constructor(options?: StringHashOptions) {
    if (!options) return;

    // Change field values if options present.
    if (options.signature) this.signature = options.signature.trim();
    if (options.algorythm) this.algorythm = options.algorythm;
    if (options.saltLength) this.saltLength = options.saltLength;
    if (options.hashLength) this.hashLength = options.hashLength;
    if (options.iterations) this.iterations = options.iterations;

    // Validating values.
    if (this.saltLength <= 0) throw new StringHashError("Salt length cannot be less than or equals zero.");
    if (this.hashLength <= 0) throw new StringHashError("Hash length cannot be less than or equals zero.");
    if (this.iterations < 1000) throw new StringHashError("Iterations count cannot be less than 1000.");
    if (this.hashLength / 2 < this.saltLength)
      throw new StringHashError("Salt length cannot be less than half of hash length.");
    if ((this.hashLength / 3) * 2 < this.saltLength + this.signature.length)
      throw new StringHashError("Salt length combined with signature length cannot be more than 2/3 of hash length.");

    // Calculating raw hash buffer length.
    this.buffLength = this.hashLength - this.saltLength - this.signature.length;
  }

  private generateSalt(): Buffer {
    try {
      return randomBytes(this.saltLength / 2);
    } catch (e) {
      throw new StringHashError("Unable to generate salt.", e as Error);
    }
  }

  private generateHash(value: string, salt: Buffer): Buffer {
    try {
      return pbkdf2Sync(value, salt, this.iterations, this.buffLength / 2, this.algorythm);
    } catch (e) {
      throw new StringHashError("Unable to generate hash.", e as Error);
    }
  }

  public generate(value: string): string {
    const salt = this.generateSalt();
    const hash = this.generateHash(value, salt);

    return `${this.signature}${Buffer.concat([hash, salt]).toString("hex")}`;
  }

  public validate(value: string, hash: string): boolean {
    if (value.length == 0 || hash.length != this.hashLength) return false;
    if (this.signature != hash.substring(0, this.signature.length)) return false;

    const hashStr = hash.substring(this.signature.length, this.hashLength - this.saltLength);
    const saltStr = hash.substring(this.signature.length + this.buffLength);

    const saltBuff = Buffer.from(saltStr, "hex");
    const hashBuff = Buffer.from(hashStr, "hex");
    const testBuff = this.generateHash(value, saltBuff);

    return timingSafeEqual(hashBuff, testBuff);
  }
}
