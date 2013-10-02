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
import Haskoin.Crypto.Arbitrary

import Haskoin.Crypto.Keys
import Haskoin.Crypto.Point
import Haskoin.Crypto.Ring
import Haskoin.Util

tests :: [Test]
tests = 
    [ testGroup "PubKey Binary"
        [ testProperty "get( put(PubKey) ) = PubKey" getPutPubKey
        , testProperty "is public key canonical" isCanonicalPubKey
        , testProperty "makeKey( toKey(k) ) = k" makeToKey
        , testProperty "makeKeyU( toKey(k) ) = k" makeToKeyU
        , testProperty "decoded PubKey is always valid" decodePubKey
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
        , testProperty "Derived public key from Integer valid" deriveFromInt
        ],
      testGroup "Key properties"
        [ testProperty "PubKey addition" testAddPubKey
        , testProperty "PrvKey addition" testAddPrvKey
        ]
    ]

{- Public Key Binary -}

getPutPubKey :: PubKey -> Bool
getPutPubKey p = p == (decode' $ encode' p)

-- github.com/bitcoin/bitcoin/blob/master/src/script.cpp
-- from function IsCanonicalPubKey
isCanonicalPubKey :: PubKey -> Bool
isCanonicalPubKey p = not $
    -- Non-canonical public key: too short
    (BS.length bs < 33) ||
    -- Non-canonical public key: invalid length for uncompressed key
    (BS.index bs 0 == 4 && BS.length bs /= 65) ||
    -- Non-canonical public key: invalid length for compressed key
    (BS.index bs 0 `elem` [2,3] && BS.length bs /= 33) ||
    -- Non-canonical public key: compressed nor uncompressed
    (not $ BS.index bs 0 `elem` [2,3,4])
    where bs = encode' p

makeToKey :: FieldN -> Property
makeToKey i = i /= 0 ==> 
    (fromPrvKey $ makeKey (fromIntegral i)) == (fromIntegral i)
    where makeKey = fromJust . makePrvKey

makeToKeyU :: FieldN -> Property
makeToKeyU i = i /= 0 ==> 
    (fromPrvKey $ makeKey (fromIntegral i)) == (fromIntegral i)
    where makeKey = fromJust . makePrvKeyU

decodePubKey :: BS.ByteString -> Bool
decodePubKey bs = either (const True) (isValidPubKey . lst) $ decodeOrFail' bs
    where lst (a,b,c) = c

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

deriveFromInt :: Integer -> Bool
deriveFromInt i = maybe True (isValidPubKey . derivePubKey) $ makePrvKey i

{- Key properties -}

testAddPubKey :: TestPrvKeyC -> Hash256 -> Bool
testAddPubKey (TestPrvKeyC key) i 
    | toInteger i >= curveN = isNothing res
    | model == InfPoint     = isNothing res
    | otherwise             = PubKey model == fromJust res
    where pub   = derivePubKey key
          pt    = mulPoint (toFieldN i) curveG
          model = addPoint (runPubKey pub) pt
          res   = addPubKeys pub i

testAddPrvKey :: TestPrvKeyC -> Hash256 -> Bool
testAddPrvKey (TestPrvKeyC key) i
    | toInteger i >= curveN = isNothing res
    | model == 0  = isNothing res
    | otherwise   = PrvKey model == fromJust res
    where model = (runPrvKey key) + (toFieldN i)
          res   = addPrvKeys key i

