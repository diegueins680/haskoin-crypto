# haskoin-crypto

Implementation of the Bitcoin cryptographic primitives in Haskell

Project Status: **Experimental**

## Description

haskoin-crypto is a component of **haskoin**, an ecosystem of haskell libraries
implementing the various parts of the bitcoin protocol. Specifically,
haskoin-crypto provides the elliptic curve cryptography required for creating
and validating bitcoin transactions. Only operations on the bitcoin-specific
SECP256k1 curve are available in this package. haskoin-crypto also implements
the SHA-256 and RIPEMP-160 digest algorithms.

The philosophy behind haskoin-crypto is to provide a sound implementation of
the elliptic curve cryptography by favouring elegance and safety over
performance. We do, however, consider performance as an important goal to
achieve when it doesn't conflict with code safety. Instead of hiding behind
abstractions, we implement the elliptic curve cryptography in pure Haskell
which provides the following advantages:

- Provide an alternative to openssl for the cloud of bitcoin nodes
- Describe precisely the canonical crypto formats used in bitcoin
- Reduce trust on third party code

## Synopsis

```haskell
    -- seed is an Integer with at least 256 bits of entropy
    main :: IO ()
    main = withECDSA seed $ do
        sig <- signMessage (hash256 msg) privateKey
```
## Usage

### Keys

```haskell
    data PublicKey = PublicKey Point | PublicKeyU Point
    data PrivateKey = PrivateKey FieldN | PrivateKeyU FieldN
```

Public and private keys each have an associated data type. They each have two
data constructors corresponding to either the compressed or uncompressed
versions of the keys. The default format used across this library is the
compressed format, so uncompressed versions are usually explicitly postfixed
with an upper-case U. The data constructors are mainly used internally for
serialization and are not exported by the library.

`PublicKey` type is an instance of `Data.Binary` so it can be serialized to its
compressed or uncompressed form:

```haskell
    import Data.Binary (get, put)
    import Data.Binary.Get (runGet)
    import Data.Binary.Put (runPut)
    import qualified Data.ByteString as BS (ByteString)

    toBS :: PublicKey -> BS.ByteString
    toBS = runPut . put
    
    fromBS :: BS.ByteString -> PublicKey
    fromBS bs = runGet get bs
```

An uncompressed public key will store both *x* and *y* components of a point
and will start with an *0x04* byte. Compressed public keys are more space
efficient as they only store the *x* component and one additional byte *0x02*
if *y* is even or *0x03* if *y* is odd. You don't loose any security by using
compressed keys. In fact, the *y* component can be fully deduced from the
elliptic curve equation if you know the *x* component of the point and the
parity of *y*.

To create a private key from an Integer, you can use either:

```haskell
    makePrivateKey  :: Integer -> PrivateKey -- Compressed format
    makePrivateKeyU :: Integer -> PrivateKey -- Uncompressed format
```

Note that the Integer is your secret for the private key and it needs to be
drawn from a random source containing at least 256 bits of entropy. We can not
be held accountable if you are using a bad random number generator. You have
been warned. 

You can derive a `PublicKey` from a `PrivateKey`:

```haskell
    derivePublicKey :: PrivateKey -> PublicKey
```

If you need to test whether you are dealing with a compressed or uncompressed key:

```haskell
    isCompressed :: PublicKey -> Bool
    isPrivateKeyCompressed :: PrivateKey -> Bool
```

You can also test if a `PublicKey` is valid. This will check that the elliptic
curve point associated with the public key is not the point at infinity and
that the *x* and *y* coordinates of the point lie on the SECP256k1 curve.

```haskell
    validatePublicKey :: PublicKey -> Bool
``` 

To derive a base58 Bitcoin address from a public key (like
176CwMCWMq1y9CxFZWk7Vfoka5PoaNzxRq):

```haskell
    publicKeyAddress :: PublicKey -> Data.ByteString
```

You can also import and export private keys to the WIF (Wallet Import Format)
format which is compatible with the reference Satoshi client:

```haskell
    -- fromWIF returns Nothing if the ByteString format is bad
    fromWIF :: Data.ByteString -> Maybe PrivateKey
    toWIF :: PrivateKey -> Data.ByteString
```

### ECDSA

```haskell
    newtype ECDSA m a = ECDSA StateT Nonce m a
```

The ECDSA monad provides a safe context in which to call `signMessage` for
signature creations. `signMessage` calls within the ECDSA monad are guaranteed
not to re-use the same *k* value. The ECDSA monad has an internal state
containing the current *k* value. Whenever you ask for this value, it is hashed
with SHA-256 and a new value is stored inside the ECDSA monad by hashing it a
second time with SHA-256. This guarantees that the *k* value you are going to
use for you signature is not stored anywhere and can not accidentally be
re-used.

```haskell
    withECDSA :: Monad m => Integer -> ECDSA m a -> m a
```

Runs an ECDSA monad by seeding it with the initial *k* value used for signature
creation. This library doesn't provide the random number generator (RNG) for
seeding the initial *k* value. You need to make sure you provide an Integer
drawn from a random pool of at least 256 bits of entropy. 

```haskell
    data Signature = Signature FieldN FieldN
```

Data type describing an ECDSA signature as a tuple (r,s), two Integers modulo
the curve order N.

```haskell
    signMessage :: Monad m => Hash256 -> PrivateKey -> ECDSA m Signature
```

You can call signMessage inside the ECDSA monad to safely sign a hashed message.

## Installing

```sh
    git clone https://github.com/plaprade/haskoin-crypto.git
    cabal install
```

For running the test suites

```sh
    cabal configure --enable-test
    cabal build
    cabal test
```

For running the benchmarks

```sh
    cabal configure --enable-benchmark
    cabal build
    cabal bench
```

## Benchmarks

## Bugs

Please report any bugs in the projects bug tracker:

[http://github.com/plaprade/haskoin-crypto/issues](http://github.com/plaprade/haskoin-crypto/issues)

## Contributing

We're glad you want to contribute! It's simple:

- Fork haskoin-crypto
- Create a branch `git checkout -b my_branch`
- Commit your changes `git commit -am 'comments'`
- Push the branch `git push origin my_branch`
- Open a pull request

## Supporting

You can support the project by donating in [Bitcoins](http://www.bitcoin.org)
to:

**176CwMCWMq1y9CxFZWk7Vfoka5PoaNzxRq**
