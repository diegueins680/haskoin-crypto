# haskoin-crypto

Implementation of the Bitcoin cryptographic primitives in Haskell

Project Status: **Experimental**

## Description

**haskoin-crypto** is a component of **haskoin**, an ecosystem of haskell
libraries implementing the various parts of the bitcoin protocol. Specifically,
haskoin-crypto provides the elliptic curve cryptography required for creating
and validating bitcoin transactions. Only operations on the bitcoin-specific
SECP256k1 curve are available in this package. haskoin-crypto also implements
the SHA-256 and RIPEMD-160 digest algorithms.

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
    import Control.Applicative ((<$>))
    import Control.Monad.Trans (liftIO)

    import Data.Maybe (fromJust)

    -- For serializing/de-serializing interface
    import Data.Binary (encode, decodeOrFail)
    import qualified Data.ByteString as BS

    import Haskoin.Crypto
    import Haskoin.Util (bsToInteger)

    main :: IO ()
    main = do

        -- Build an Integer from a random source
        rnd <- bsToInteger <$> (devURandom 32)

        -- Test if Integer rnd is in the range [1, N-1]
        let vld  = isValidPrvKey rnd
            -- Build a private key from a random Integer
            -- Will fail if rnd is not in the range [1, N-1]
            prv  = fromJust $ makePrvKey rnd
            -- Derive the public key from a private key
            pub  = derivePubKey prv
            -- Compute the bitcoin address from the public key
            addr = addrToBase58 $ pubKeyAddr pub
            -- Serialize the private key to WIF format
            wif  = toWIF prv
            -- Deserialize a private key from WIF format
            prv' = fromWIF wif

        -- Serialize and de-serialize a public key
        -- See Data.Binary for more details
        let pubBin = encode pub
            pub'   = case decodeOrFail pubBin of
                (Left  (_, _, err)) -> error err
                (Right (_, _, res)) -> res :: PubKey

        -- Create a message in ByteString format
        let msg  = BS.pack [1,3,3,7]
            -- Compute two rounds of SHA-256
            hash = doubleHash256 msg
            -- Deterministically sign messages. Both signatures here are equal
            dSig1 = detSignMsg hash prv
            dSig2 = detSignMsg hash prv
            -- Verify a signature
            dVer  = verifySig hash dSig1 pub

        -- Initialize a PRNG environment for creating signatures
        withSource devURandom $ do 

            -- Generate private keys derived from the internal PRNG
            prv1 <- genPrvKey
            prv2 <- genPrvKey

            -- Signatures are signed with nonces derived from the internal PRNG
            sig1 <- signMsg hash prv
            sig2 <- signMsg hash prv

            -- Verify signatures
            let ver1 = verifySig hash sig1 pub
                ver2 = verifySig hash sig2 pub

            -- Serialize and de-serialize a signature
            -- See Data.Binary for more details
            let sigBin = encode sig1
                -- Deserialize a signature
                sig1'  = case decodeOrFail sigBin of
                    (Left  (_, _, err)) -> error err
                    (Right (_, _, res)) -> res :: Signature

            -- Print some results
            liftIO $ do
                print $ "Deterministic Signature 1: " ++ (show dSig1)
                print $ "Deterministic Signature 2: " ++ (show dSig2)
                print $ "Random Signature 1: " ++ (show sig1)
                print $ "Random Signature 2: " ++ (show sig2)
                print $ "Signature verification: " 
                    ++ (show dVer) ++" " ++ (show ver1) ++ " " ++ (show ver2)
```

## Usage

All the types and functions in this section are exported by `Haskoin.Crypto`

```haskell
    import Haskoin.Crypto
```

### Keys

```haskell
    data PubKey = PubKey Point | PubKeyU Point

    data PrvKey = PrvKey FieldN | PrvKeyU FieldN
```

Public and private keys each have an associated data type. They each have two
data constructors corresponding to either the compressed or uncompressed
versions of the keys. The default format used across this library is the
compressed format, so uncompressed versions are usually explicitly postfixed
with an upper-case U. The data constructors are mainly used internally for
serialization and are not exported by the library.

The `PubKey` type is an instance of `Data.Binary` so it can be serialized
and de-serialized through the `encode` and `decodeOrFail` functions. Below is a
sample code describing how to use the serialization interface.

```haskell
    import Data.Binary (encode, decodeOrFail)
    import Data.ByteString.Lazy (ByteString)
    import Haskoin.Crypto 

    -- toByteString and fromByteString are only example functions
    -- They are not exported by Haskoin.Crypto
    toByteString :: PubKey -> ByteString
    toByteString key = encode key
    
    fromByteString :: ByteString -> PubKey
    fromByteString bs = case decodeOrFail bs of
        (Left  (_, _, err)) -> error err
        (Right (_, _, res)) -> res 
```

An uncompressed public key will store both **x** and **y** components of a
point and will start with an `0x04` byte. Compressed public keys are more space
efficient as they only store the **x** component and one additional byte `0x02`
if **y** is even or `0x03` if **y** is odd. You don't loose any security by
using compressed keys. In fact, the **y** component can be fully deduced from
the elliptic curve equation knowing the **x** component of the point and the
parity of **y**.

To create a private key from an Integer, you can use either:

```haskell
    makePrvKey  :: Integer -> Maybe PrvKey -- Compressed format
    makePrvKeyU :: Integer -> Maybe PrvKey -- Uncompressed format
```

These functions can return `Nothing` if the Integer is <= 0 or >= than the
curve order N.

Note that the Integer is your secret for the private key and it needs to be
drawn from a random source containing at least 128 bits of entropy.

To recover the secret (as `Integer`) in a `PrvKey`:

```haskell
    fromPrvKey :: PrvKey -> Integer
```

To test if an Integer would make a valid `PrvKey` (i > 0 && i < N):

```haskell
    isValidPrvKey :: Integer -> Bool
```

You can derive a `PubKey` from a `PrvKey`:

```haskell
    derivePubKey :: PrvKey -> PubKey
```

If you need to test whether you are dealing with the uncompressed alternatives
of the keys:

```haskell
    isPubKeyU :: PubKey -> Bool
    isPrvKeyU :: PrvKey -> Bool
```

You can also test if a `PubKey` is valid. This will check that the elliptic
curve point associated with the public key is not the point at infinity and
that the **x** and **y** coordinates of the point lie on the SECP256k1 curve.

```haskell
    isPubKeyValid :: PubKey -> Bool
``` 

You can serialize/de-serialize a `PrvKey` in the `Get` and `Put` monad as a
fixed-sized 32 byte Integer in big endian format (same as for `Hash256`):

```haskell
    -- Check Data.Binary for more details  
    putPrvKey  :: PrvKey -> Put
    getPrvKey  :: Get PrvKey
    -- De-serialize as an uncompressed private key
    getPrvKeyU :: Get PrvKey
```

You can also import and export private keys to/from the WIF (Wallet Import
Format) format which is compatible with the reference Satoshi client:

```haskell
    -- fromWIF returns Nothing if the ByteString format is bad
    fromWIF :: Data.ByteString -> Maybe PrvKey
    toWIF :: PrvKey -> Data.ByteString
```

For more details on the WIF format, check out:

[en.bitcoin.it/wiki/Wallet_import_format](http://en.bitcoin.it/wiki/Wallet_import_format)

### ECDSA

```haskell
    type SecretT m a = S.StateT (SecretState m) m a
```

`SecretT` is essentially a monad wrapping a HMAC DRBG SHA-256. `SecretT`
provides a safe context for signing messages with `signMsg` as this will
not re-use the same **k** nonce. Remember that re-using the same **k** nonce
for two signatures will expose your private key.

```haskell
    withSource :: MonadIO m => (Int -> m BS.ByteString) -> SecretT m a -> m a
```

`withSource` runs a `SecretT` monad. You need to pass it a function that can
get new bytes of entropy when required. The `SecretT` monad will call this
function upon initialization and when a reseeding of the HMAC DRBG is required
(about every 10000 calls). We provide two default sources of entropy:
`devRandom` and `devURandom` if they are available on your machine. Otherwise
you can provide your own.

```haskell
    -- /dev/urandom on machines that support it
    devURandom :: Int -> IO BS.ByteString

    -- /dev/random on machines that support it
    devRandom :: Int -> IO BS.ByteString
```

The `Int` parameter defines how many random bytes you want to get from your
source. You can use them like this:

```haskell
    withSource devRandom $ do
        sig <- signMsg msg key
        k   <- genPrvKey
```

```haskell
    data Signature = Signature FieldN FieldN
```

Data type describing an ECDSA signature.

```haskell
    signMsg :: Monad m => Hash256 -> PrvKey -> SecretT m Signature
```

`signMsg` should be called withing the `SecretT` monad to safely sign the
hash of a message.

We also provide an implementation of deterministic signatures as defined in
[RFC 6979](http://tools.ietf.org/html/rfc6979). It is called *deterministic*
signing because the secret **k** nonce is computed in a deterministic way from
a hash of the message and private key.

```haskell
    detSignMsg :: Hash256 -> PrvKey -> Signature
```

Deterministic signing is useful to validate an implementation against known
test vectors. It is much harder to verify the correctness of an implementation
when **k** nonces are produced randomly. This property comes in handy to verify
untrusted hardware wallets. 

A `Signature` is an instance of `Data.Binary` and can be
serialized/de-serialized using the `encode` and `decodeOrFail` functions. Below
is an example describing how to use the serialization interface.

```haskell
    import Data.Binary (encode, decodeOrFail)
    import Data.ByteString.Lazy (ByteString)
    import Haskoin.Crypto 

    -- toByteString and fromByteString are only example functions
    -- They are not exported by Haskoin.Crypto
    toByteString :: Signature -> ByteString
    toByteString sig = encode sig
    
    fromByteString :: ByteString -> Signature
    fromByteString bs = case decodeOrFail bs of
        (Left  (_, _, err)) -> error err
        (Right (_, _, res)) -> res 
```

To verify a `Signature`:

```haskell
    verifySig :: Hash256 -> Signature -> PubKey -> Bool
```

### Digests

The `Hash256` and `Hash160` data types represent hashes of either 256 or 160
bits. They are essentially unsigned integers modulo 2^256 or modulo 2^160. They
behave the same way as the `Word8`, `Word16`, `Word32` and `Word64` types of
the `Data.Word` package, except with 160 and 256 bits. We use these types as
opposed to Integers to convey the information that we are dealing with hashes
produced by digest functions rather than arbitrary integers. 

The `Hash512` type is also supported for its use in the implementation of
hierarchical deterministic wallets (HDW) although it's not directly used in the
Bitcoin protocol itself.

```haskell
    type Hash512 = Ring Mod512
    type Hash256 = Ring Mod256
    type Hash160 = Ring Mod160
```

The following message digest functions are exported by the library

```haskell
    -- Single round of SHA-512
    hash512   :: Data.ByteString -> Hash512
    hash512BS :: Data.ByteString -> Data.ByteString

    -- Single round of SHA-256
    hash256   :: Data.ByteString -> Hash256
    hash256BS :: Data.ByteString -> Data.ByteString

    -- Single round of RIPEMD-160
    hash160   :: Data.ByteString -> Hash160
    hash160BS :: Data.ByteString -> Data.ByteString

    -- Double round of SHA-256
    doubleHash256   :: Data.ByteString -> Hash256
    doubleHash256BS :: Data.ByteString -> Data.ByteString
```

And the following hash-based message authentication codes (HMAC) functions
are exported:

```haskell
    hmac512 :: BS.ByteString -> BS.ByteString -> Hash512
    hmac256 :: BS.ByteString -> BS.ByteString -> Hash256
```

A 32 bit checksum is represented as a `CheckSum32` data type

```haskell
    newtype CheckSum32 = CheckSum32 Word32
```

It is an instance of `Data.Binary` so you can serialize/de-serialize it easily.
To compute a `CheckSum32`, use:

```haskell
    chksum32 :: BS.ByteString -> CheckSum32
```

### Bitcoin Addresses and Base58

We have a data type called `Address` to represent addresses to which people can
send bitcoins to. Today, we have regular public key addresses or script hash
addresses. The former is computed from the hash of a public key while the later
is computed from the hash of a script.

```haskell
    data Address = PubKeyAddress Hash160 | ScriptAddress Hash160
```

To compute an `Address` from a `PubKey`:

```haskell
    pubKeyAddr :: PubKey -> Address
```

You can compute the Base58 representation of an address using the following
functions:

```haskell
    addrToBase58   :: Address -> BS.ByteString
    addrFromBase58 :: BS.ByteString -> Maybe Address
```

This will yield addresses with the following formats:

- PubKeyAddress: 176CwMCWMq1y9CxFZWk7Vfoka5PoaNzxRq (leading 0x00 on prodnet)
- ScriptAddress: 3QJmV3qfvL9SuYo34YihAf3sRCW3qSinyC (leading 0x05 on prodnet)

If you need access to the raw base58 encoding functions, use:

```haskell
    encodeBase58      :: BS.ByteString -> BS.ByteString
    decodeBase58      :: BS.ByteString -> Maybe BS.ByteString
    encodeBase58Check :: BS.ByteString -> BS.ByteString
    decodeBase58Check :: BS.ByteString -> Maybe BS.ByteString
```

The decoding functions may return `Nothing` if the input contains invalid
Base58 data or if the checksum doesn't match in the case of
`decodeBase58Check`.

## Dependencies

- Cabal package manager

```sh
    # in Ubuntu
    apt-get install cabal-install
```

- haskoin-util

```sh
    # haskoin-util is not on Hackage (yet) 
    git clone https://github.com/plaprade/haskoin-util.git
    cd haskoin-util
    cabal install
```

## Installing

```sh
    # haskoin-crypto is not on Hackage (yet) 
    git clone https://github.com/plaprade/haskoin-crypto.git
    cd haskoin-crypto
    cabal install
```

### Tests

If you are missing the test dependencies:

```sh
    cabal install --enable-tests
    cabal test
```

If you have the test dependencies, you can build without installing:

```sh
    cabal configure --enable-tests
    cabal build
    cabal test
```

The tests can take a few minutes to run.

### Benchmarks

```sh
    cabal configure --enable-benchmarks
    cabal build
    cabal bench
```

## Benchmarks

Here are the results of some benchmarks running on a single core I7:

```sh
    Ring multiplication (mod n) (10000000 samples)
    Total time: 1.868806s
    Op/sec    : 5351010.217218908757s
    ----------------------------
    Ring inversion (mod n) (100000 samples)
    Total time: 7.244239s
    Op/sec    : 13804.072449846008s
    ----------------------------
    Point multiplications (2000 samples)
    Total time: 4.372304s
    Op/sec    : 457.424735334048s
    ----------------------------
    Point additions (100000 samples)
    Total time: 0.684761s
    Op/sec    : 146036.354290036961s
    ----------------------------
    Point doubling (100000 samples)
    Total time: 0.455613s
    Op/sec    : 219484.518659476353s
    ----------------------------
    Shamirs trick (2000 samples)
    Total time: 4.366215s
    Op/sec    : 458.062646937908s
    ----------------------------
    Signature creations (2000 samples)
    Total time: 4.786426s
    Op/sec    : 417.848306857768s
    ----------------------------
    Signature verifications (2000 samples)
    Total time: 5.70411s
    Op/sec    : 350.624374354632s
```

## Bugs

Please report any bugs in the projects bug tracker:

[github.com/plaprade/haskoin-crypto/issues](http://github.com/plaprade/haskoin-crypto/issues)

## Contributing

We're glad you want to contribute! It's simple:

- Fork haskoin-crypto
- Create a branch `git checkout -b my_branch`
- Commit your changes `git commit -am 'comments'`
- Push the branch `git push origin my_branch`
- Open a pull request

Code guidelines:

- 80 columns.
- 4 space indentation. No tabs.
- Follow the general style of the code, whenever it makes sense.

## Supporting

You can support the project by donating in [Bitcoins](http://www.bitcoin.org)
to:

**176CwMCWMq1y9CxFZWk7Vfoka5PoaNzxRq**

