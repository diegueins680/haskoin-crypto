module Haskoin.Crypto.Keys.Tests (tests) where

import Test.QuickCheck.Property hiding ((.&.))
import Test.Framework
import Test.Framework.Providers.QuickCheck2

import Data.Maybe
import Data.Word
import Data.Bits
import Data.Binary
import Data.Binary.Get
import Data.Binary.Put
import qualified Data.ByteString as BS

import QuickCheckUtils

import Haskoin.Crypto.Keys
import Haskoin.Crypto.Point
import Haskoin.Crypto.Ring
import Haskoin.Util

tests :: [Test]
tests = 
    [ testGroup "PublicKey Binary"
        [ testProperty "get( put(PublicKey) ) = PublicKey" getPutPoint
        , testProperty "size( put(Point) ) = 33 or 65" putPointSize
        , testProperty "makeKey( toKey(k) ) = k" makeToKey
        , testProperty "makeKeyU( toKey(k) ) = k" makeToKeyU
        ],
      testGroup "Key formats"
        [ testProperty "fromWIF( toWIF(i) ) = i" fromToWIF
        ],
      testGroup "Key compression"
        [ testProperty "Compressed public key" testCompressed
        , testProperty "Uncompressed public key" testUnCompressed
        , testProperty "Compressed private key" testPrivateCompressed
        , testProperty "Uncompressed private key" testPrivateUnCompressed
        ],
      testGroup "Public Key"
        [ testProperty "Derived public key valid" testDerivedPublicKey
        ]
    ]

{- Public Key Binary -}

getPutPoint :: PublicKey -> Bool
getPutPoint p = p == runGet get (runPut $ put p)

putPointSize :: PublicKey -> Bool
putPointSize p = case p of
    (PublicKey  InfPoint) -> BS.length s == 1
    (PublicKey  _)        -> BS.length s == 33
    (PublicKeyU InfPoint) -> BS.length s == 1
    (PublicKeyU _)        -> BS.length s == 65
    where s = toStrictBS $ runPut $ put p

makeToKey :: FieldN -> Property
makeToKey i = i /= 0 ==> 
    (fromPrivateKey $ makeKey (fromIntegral i)) == (fromIntegral i)
    where makeKey = fromJust . makePrivateKey

makeToKeyU :: FieldN -> Property
makeToKeyU i = i /= 0 ==> 
    (fromPrivateKey $ makeKey (fromIntegral i)) == (fromIntegral i)
    where makeKey = fromJust . makePrivateKeyU

{- Key formats -}

fromToWIF :: PrivateKey -> Property
fromToWIF pk = i > 0 ==> pk == (fromJust $ fromWIF $ toWIF pk)
    where i = runPrivateKey pk

{- Key Compression -}

testCompressed :: FieldN -> Property
testCompressed n = n > 0 ==> 
    isCompressed $ derivePublicKey $ makeKey (fromIntegral n)
    where makeKey = fromJust . makePrivateKey

testUnCompressed :: FieldN -> Property
testUnCompressed n = n > 0 ==> 
    not $ isCompressed $ derivePublicKey $ makeKey (fromIntegral n)
    where makeKey = fromJust . makePrivateKeyU

testPrivateCompressed :: FieldN -> Property
testPrivateCompressed n = n > 0 ==> 
    isPrivateKeyCompressed $ makeKey (fromIntegral n)
    where makeKey = fromJust . makePrivateKey

testPrivateUnCompressed :: FieldN -> Property
testPrivateUnCompressed n = n > 0 ==> 
    not $ isPrivateKeyCompressed $ makeKey (fromIntegral n)
    where makeKey = fromJust . makePrivateKeyU

testDerivedPublicKey :: PrivateKey -> Bool
testDerivedPublicKey k = validatePublicKey $ derivePublicKey k

