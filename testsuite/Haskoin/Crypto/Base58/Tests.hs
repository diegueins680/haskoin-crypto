module Haskoin.Crypto.Base58.Tests (tests) where

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
import Haskoin.Util.Arbitrary

import Haskoin.Util
import Haskoin.Crypto.Base58

tests :: [Test]
tests = 
    [ testGroup "Address and Base58"
        [ testProperty "decode58( encode58(i) ) = i" decodeEncode58
        , testProperty "decode58Chk( encode58Chk(i) ) = i" decodeEncode58Check
        , testProperty "decode58( encode58(address) ) = address" decEncAddr
        ]
    ]

decodeEncode58 :: BS.ByteString -> Bool
decodeEncode58 bs = (fromJust $ decodeBase58 $ encodeBase58 bs) == bs

decodeEncode58Check :: BS.ByteString -> Bool
decodeEncode58Check bs = 
    (fromJust $ decodeBase58Check $ encodeBase58Check bs) == bs

decEncAddr :: Address -> Bool
decEncAddr a = (fromJust $ base58ToAddr $ addrToBase58 a) == a

