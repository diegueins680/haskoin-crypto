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
        , testProperty "S component of a signature is even" evenSig
        ],
      testGroup "ECDSA Binary"
        [ testProperty "get( put(Sig) ) = Sig" getPutSig
        , testProperty "Verify DER of put(Sig)" putSigSize
        ]
    ]

{- ECDSA Signatures -}

signAndVerify :: Hash256 -> FieldN -> FieldN -> Property
signAndVerify msg k n = k > 0 && n > 0 ==> case sM of
    (Just s) -> verifySignature msg s (PubKey kP)
    Nothing  -> True -- very bad luck
    where kP = mulPoint k curveG
          nP = mulPoint n curveG
          sM = unsafeSignMessage msg k (n,nP)
           
evenSig :: Signature -> Bool
evenSig (Signature _ (Ring s)) = s `mod` 2 == 0

{- ECDSA Binary -}

getPutSig :: Signature -> Property
getPutSig sig@(Signature r s) = r > 0 && s > 0 ==> 
    sig == runGet get (runPut $ put sig)

putSigSize :: Signature -> Property
putSigSize sig@(Signature r s) = r > 0 && s > 0 ==>
   (  a == fromIntegral 0x30    -- DER type is Sequence
   && b <= fromIntegral 70      -- Maximum length is 35 + 35
   && l == fromIntegral (b + 2) -- Advertised length matches
   )
   where bs = toStrictBS $ runPut $ put sig
         a  = BS.index bs 0
         b  = BS.index bs 1
         l  = BS.length bs

