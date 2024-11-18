# @redexinus/string-hash

- [About](#about)
- [StringHashOptions](#stringhashoptions)
- [Getting started](#getting-started)
  - [Installation](#installation)
  - [Import](#import)
- [How to use](#how-to-use)
  - [generate() function](#generate-function)
  - [validate() function](#validate-function)
- [Full example](#full-example)

## About

`string-hash` is the simplest, `zero dependency` hashing library based on `crypto:pbkdf2`.

## StringHashOptions

All options are optional and wrapped into `StringHashOptions` interface.

There are some validation rules must be followed:

- Salt and hash lengths cannot be less than or equal zero.
- Salt length cannot be greater than half of hash length.
- Salt length combined with signature length cannot be more than 2/3 of hash length.
- The number of iterations cannot be less than 1000\*.

\* _For security reasons this value should be as large as possible. Note: the larger iterations count the longer hashing will take_.

If one of the rules violated, `StringHashError` will be thrown.

If no options were provided, default options will be used:

```ts
{
    signature: "",
    algorythm: "sha512",
    saltLength: 32,
    hashLength: 128,
    iterations: 100000,
}
```

Although `HmacDigest` type contains `sha1` algorythm, it is not recomended due to it\`s deemed unsafe. Do your own research to undestand what algorythms are safe to use in cryptographic context or use one of the following values:

```ts
"sha256" | "sha384" | "sha512";
```

## Getting started

Library exports several objects:

- StringHashError - hashing error object;
- StringHashOptions - interface that holds hashing options;
- StringHasher - a class that provides `generate` and `validate` functions.

### Installation

The package is hosted on `Github`\`s `npm` registry.

To install it, you should add `.npmrc` file to your project with next line:

```npmrc
@redexinus:registry=https://npm.pkg.github.com
```

After this you can install the package with this command:

```bash
npm i @redexinus/string-hash
```

### Import

Depending on language used in a project, there are two methods to import this lib:

`Javascript`:

```js
const { StringHasher } = require("@redexinus/string-hash");
```

`ES`:

```ts
import { StringHasher } from "@redexinus/string-hash";
```

Optionaly, you might import `StringHashOptions` for type safety, in case you\`ll need to define default hashing options object.

After import, you should initialize `StringHasher` class:

```ts
const options: StringHasherOptions = {
  signature: "hash512",
  algorythm: "sha512",
  saltLength: 32,
  hashLength: 128,
  iterations: 100000,
};

const hasher = new StringHasher(options);
```

## How to use

### generate() function

Generates hash of the `value` string.

It accepts following argument:

- `value`: String to generate hash of.

This function will generate salt buffer using `crypto:randomBytes()` and than use this salt and provided `value` to generate hash buffer using `crypto:pbkdf2Sync()`.

The function returns hash, generated of given string with following structure\*:

```ts
`${signature}${hashBuff}${saltBuff}`;
```

\* _Note: All buffers are converted to `HEX` string_.

Example:

```ts
const hash = hasher.generate("value");
console.log(hash); // "hash512...f949d3"
```

### validate() function

Compares a plain-text `value` string to a hashed one.

It accepts following arguments:

- `value`: Value string;
- `hash`: Hash string.

This function extracts `signature`, `hashStr` and `saltStr` from given `hash` string and generates new `hash` buffer using `value` and extracted `salt`. Than it\`s compares two buffers using `crypto:timingSafeEqual()`.

The function returns `true` if hashes converge; `false` otherwise.

Example:

```ts
const conv = hasher.validate("value", "hash512...f949d3");
console.log(conv); // true | false
```

## Full example

```ts
import { StringHashOptions, StringHasher } from "@redexinus/string-hash";

const options: StringHasherOptions = {
  signature: "hash512",
  algorythm: "sha512",
  saltLength: 32,
  hashLength: 128,
  iterations: 100000,
};

const hasher = new StringHasher(options);

const value = "qwe123asd456!@#";

const hash = hasher.generate(value);
console.log(hash); // "hash512...f949d3"

const conv = hasher.validate(value, hash);
console.log(conv); // true
```
