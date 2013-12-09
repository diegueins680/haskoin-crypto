{-|
  This package provides the elliptic curve cryptography required for creating
  and validating bitcoin transactions. It also provides SHA-256 and RIPEMD-160
  hashing functions.
-}
module Network.Haskoin.Crypto
( 
  -- *Elliptic Curve Keys
  -- **Public Keys
  PubKey(..)
, isValidPubKey
, isPubKeyU
, derivePubKey
, pubKeyAddr
, addPubKeys
  -- **Private Keys
, PrvKey(..)
, isValidPrvKey
, makePrvKey
, makePrvKeyU
, fromPrvKey
, isPrvKeyU
, addPrvKeys
, putPrvKey
, getPrvKey
, getPrvKeyU
, fromWIF
, toWIF

  -- *ECDSA
, SecretT
, Signature
, withSource
, devURandom
, devRandom
, signMsg
, detSignMsg
, verifySig
, genPrvKey
, isCanonicalHalfOrder

  -- *Hash functions
, Hash512
, Hash256
, Hash160
, CheckSum32
, hash512
, hash512BS
, hash256
, hash256BS
, hash160
, hash160BS
, doubleHash256
, doubleHash256BS
, chksum32
, hmac512
, split512
, join512

-- *Base58 and Addresses
, Address(..)
, base58ToAddr
, addrToBase58
, encodeBase58
, decodeBase58
, encodeBase58Check
, decodeBase58Check

) where

import Network.Haskoin.Crypto.ECDSA
import Network.Haskoin.Crypto.Keys
import Network.Haskoin.Crypto.Hash
import Network.Haskoin.Crypto.Base58

