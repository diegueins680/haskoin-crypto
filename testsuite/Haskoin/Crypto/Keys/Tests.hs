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
    [ testGroup "PubKey Binary"
        [ testProperty "get( put(PubKey) ) = PubKey" getPutPubKey
        , testProperty "size( put(Point) ) = 33 or 65" putPubKeySize
        , testProperty "makeKey( toKey(k) ) = k" makeToKey
        , testProperty "makeKeyU( toKey(k) ) = k" makeToKeyU
        ],
      testGroup "Key formats"
        [ testProperty "fromWIF( toWIF(i) ) = i" fromToWIF
        , testProperty "get( put(PrvKey) )" getPutPrv
        ],
      testGroup "Key compression"
        [ testProperty "Compressed public key" testCompressed
        , testProperty "Uncompressed public key" testUnCompressed
        , testProperty "Compressed private key" testPrivateCompressed
        , testProperty "Uncompressed private key" testPrivateUnCompressed
        ],
      testGroup "Public Key"
        [ testProperty "Derived public key valid" testDerivedPubKey
        ],
      testGroup "Key properties"
        [ testProperty "PubKey addition" testAddPubKeyC
        , testProperty "PubKeyU addition" testAddPubKeyU
        , testProperty "PrvKey addition" testAddPrvKeyC
        , testProperty "PrvKeyU addition" testAddPrvKeyU
        ]
    ]

{- Public Key Binary -}

getPutPubKey :: PubKey -> Bool
getPutPubKey p = p == (decode' $ encode' p)

putPubKeySize :: PubKey -> Bool
putPubKeySize p = case p of
    (PubKey  InfPoint) -> BS.length bs == 1
    (PubKey  _)        -> BS.length bs == 33
    (PubKeyU InfPoint) -> BS.length bs == 1
    (PubKeyU _)        -> BS.length bs == 65
    where bs = encode' p

makeToKey :: FieldN -> Property
makeToKey i = i /= 0 ==> 
    (fromPrvKey $ makeKey (fromIntegral i)) == (fromIntegral i)
    where makeKey = fromJust . makePrvKey

makeToKeyU :: FieldN -> Property
makeToKeyU i = i /= 0 ==> 
    (fromPrvKey $ makeKey (fromIntegral i)) == (fromIntegral i)
    where makeKey = fromJust . makePrvKeyU

{- Key formats -}

fromToWIF :: PrvKey -> Property
fromToWIF pk = i > 0 ==> pk == (fromJust $ fromWIF $ toWIF pk)
    where i = runPrvKey pk

getPutPrv :: PrvKey -> Property
getPutPrv k@(PrvKey  i) = i > 0 ==> 
    k == runGet getPrvKey  (runPut $ putPrvKey k)
getPutPrv k@(PrvKeyU i) = i > 0 ==> 
    k == runGet getPrvKeyU (runPut $ putPrvKey k)

{- Key Compression -}

testCompressed :: FieldN -> Property
testCompressed n = n > 0 ==> 
    not $ isPubKeyU $ derivePubKey $ fromJust $ makePrvKey $ fromIntegral n

testUnCompressed :: FieldN -> Property
testUnCompressed n = n > 0 ==> 
    isPubKeyU $ derivePubKey $ fromJust $ makePrvKeyU $ fromIntegral n

testPrivateCompressed :: FieldN -> Property
testPrivateCompressed n = n > 0 ==> 
    not $ isPrvKeyU $ fromJust $ makePrvKey $ fromIntegral n

testPrivateUnCompressed :: FieldN -> Property
testPrivateUnCompressed n = n > 0 ==> 
    isPrvKeyU $ fromJust $ makePrvKeyU $ fromIntegral n

testDerivedPubKey :: PrvKey -> Bool
testDerivedPubKey k = isValidPubKey $ derivePubKey k

{- Key properties -}

testAddPubKeyC :: TestPrvKeyC -> TestPrvKeyC -> Bool
testAddPubKeyC (TestPrvKeyC k1) (TestPrvKeyC k2)
    | model == InfPoint = isNothing res
    | otherwise         = PubKey model == fromJust res
    where p1    = derivePubKey k1
          p2    = derivePubKey k2
          model = addPoint (runPubKey p1) (runPubKey p2)
          res   = addPubKeys p1 p2

testAddPubKeyU :: TestPrvKeyU -> TestPrvKeyU -> Bool
testAddPubKeyU (TestPrvKeyU k1) (TestPrvKeyU k2)
    | model == InfPoint = isNothing res
    | otherwise         = PubKeyU model == fromJust res
    where p1    = derivePubKey k1
          p2    = derivePubKey k2
          model = addPoint (runPubKey p1) (runPubKey p2)
          res   = addPubKeys p1 p2

testAddPrvKeyC :: TestPrvKeyC -> TestPrvKeyC -> Bool
testAddPrvKeyC (TestPrvKeyC k1) (TestPrvKeyC k2)
    | model == 0 = isNothing res
    | otherwise  = PrvKey model == fromJust res
    where model = (runPrvKey k1) + (runPrvKey k2)
          res   = addPrvKeys k1 k2

testAddPrvKeyU :: TestPrvKeyU -> TestPrvKeyU -> Bool
testAddPrvKeyU (TestPrvKeyU k1) (TestPrvKeyU k2)
    | model == 0 = isNothing res
    | otherwise  = PrvKeyU model == fromJust res
    where model = (runPrvKey k1) + (runPrvKey k2)
          res   = addPrvKeys k1 k2


