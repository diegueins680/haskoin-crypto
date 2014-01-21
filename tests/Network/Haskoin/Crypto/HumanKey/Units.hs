module Network.Haskoin.Crypto.HumanKey.Units (tests) where

import qualified Data.ByteString.Lazy.Char8 as C
import Data.Binary

import Test.HUnit ((@=?))
import Test.Framework (Test, testGroup)
import Test.Framework.Providers.HUnit (testCase)

import Data.Maybe

import Network.Haskoin.Crypto.HumanKey
import Network.Haskoin.Util

tests :: [Test]
tests =
    [ testGroup "Encode keys in RFC-1751" . map encodeTest $ zip [1..] vectors
    , testGroup "Decode keys in RFC-1751" . map decodeTest $ zip [1..] vectors
    ]

type TestVector = (C.ByteString, HumanKey)

hex2lbs :: String -> C.ByteString
hex2lbs = toLazyBS . fromJust . hexToBS . filter (/=' ')

vectors :: [TestVector]
vectors =
  [ ( hex2lbs "CCAC 2AED 5910 56BE 4F90 FD44 1C53 4766"
    , HumanKey "RASH BUSH MILK LOOK BAD BRIM AVID GAFF BAIT ROT POD LOVE"
    )
  , ( hex2lbs "EFF8 1F9B FBC6 5350 920C DD74 16DE 8009"
    , HumanKey "TROD MUTE TAIL WARM CHAR KONG HAAG CITY BORE O TEAL AWL"
    )
  ]

encodeTest :: (Int, TestVector) -> Test
encodeTest (i, (bs, hk)) = testCase ("Encode #" ++ show i) (bs @=? encode hk)

decodeTest :: (Int, TestVector) -> Test
decodeTest (i, (bs, hk)) = testCase ("Decode #" ++ show i) (hk @=? decode bs)
