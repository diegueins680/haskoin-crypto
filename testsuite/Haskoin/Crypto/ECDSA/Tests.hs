module Haskoin.Crypto.ECDSA.Tests (tests) where

import Test.QuickCheck.Property hiding ((.&.))
import Test.Framework
import Test.Framework.Providers.QuickCheck2

import Control.Monad.Identity
import Data.Maybe
import Data.Word
import Data.Bits
import Data.Binary
import Data.Binary.Get
import Data.Binary.Put
import qualified Data.ByteString as BS

import QuickCheckUtils
import Haskoin.Crypto.Arbitrary

import Haskoin.Crypto.ECDSA
import Haskoin.Crypto.Point
import Haskoin.Crypto.Ring
import Haskoin.Crypto.NumberTheory
import Haskoin.Crypto.Keys
import Haskoin.Util

tests :: [Test]
tests = 
    [ testGroup "ECDSA signatures"
        [ testProperty "verify( sign(msg) ) = True" signAndVerify
        , testProperty "verify( detSign(msg) ) = True" signAndVerifyD
        , testProperty "S component <= order/2" halfOrderSig
        ],
      testGroup "ECDSA Binary"
        [ testProperty "get( put(Sig) ) = Sig" getPutSig
        , testProperty "Encoded signature is canonical" testIsCanonical
        ]
    ]

{- ECDSA Signatures -}

signAndVerify :: Hash256 -> FieldN -> FieldN -> Property
signAndVerify msg k n = k > 0 && n > 0 ==> case sM of
    (Just s) -> verifySig msg s (PubKey kP)
    Nothing  -> True -- very bad luck
    where kP = mulPoint k curveG
          nP = mulPoint n curveG
          sM = unsafeSignMsg msg k (n,nP)

signAndVerifyD :: Hash256 -> TestPrvKeyC -> Bool
signAndVerifyD msg (TestPrvKeyC k) = verifySig msg (detSignMsg msg k) p
    where p = derivePubKey k
           
halfOrderSig :: Signature -> Bool
halfOrderSig sig@(Signature _ (Ring s)) = 
    s <= (curveN `div` 2) && isCanonicalHalfOrder sig

{- ECDSA Binary -}

getPutSig :: Signature -> Bool
getPutSig sig@(Signature r s) = sig == (decode' $ encode' sig)

-- github.com/bitcoin/bitcoin/blob/master/src/script.cpp
-- from function IsCanonicalSignature
testIsCanonical :: Signature -> Bool
testIsCanonical sig@(Signature r s) = not $
    -- Non-canonical signature: too short
    (len < 8) ||
    -- Non-canonical signature: too long
    (len > 72) ||
    -- Non-canonical signature: wrong type
    (BS.index s 0 /= 0x30) ||
    -- Non-canonical signature: wrong length marker
    (BS.index s 1 /= len - 2) ||
    -- Non-canonical signature: S length misplaced
    (5 + rlen >= len) || 
    -- Non-canonical signature: R+S length mismatch
    (rlen + slen + 6 /= len) ||
    -- Non-canonical signature: R value type mismatch
    (BS.index s 2 /= 0x02) ||
    -- Non-canonical signature: R length is zero
    (rlen == 0) ||
    -- Non-canonical signature: R value negative
    (testBit (BS.index s 4) 7) ||
    -- Non-canonical signature: R value excessively padded
    (  rlen > 1 
    && BS.index s 4 == 0 
    && not (testBit (BS.index s 5) 7)
    ) ||
    -- Non-canonical signature: S value type mismatch
    (BS.index s (fromIntegral rlen+4) /= 0x02) ||
    -- Non-canonical signature: S length is zero
    (slen == 0) ||
    -- Non-canonical signature: S value negative
    (testBit (BS.index s (fromIntegral rlen+6)) 7) ||
    -- Non-canonical signature: S value excessively padded
    (  slen > 1
    && BS.index s (fromIntegral rlen+6) == 0 
    && not (testBit (BS.index s (fromIntegral rlen+7)) 7)
    ) 
    where s = encode' sig
          len = fromIntegral $ BS.length s
          rlen = BS.index s 3
          slen = BS.index s (fromIntegral rlen + 5)

