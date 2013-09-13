module Haskoin.Crypto.Hash.Units (tests) where

import Test.HUnit
import Test.Framework
import Test.Framework.Providers.HUnit

import Data.Maybe
import Data.List
import qualified Data.ByteString as BS

import Haskoin.Crypto.Hash
import Haskoin.Util

-- Test vectors from NIST
-- http://csrc.nist.gov/groups/STM/cavp/documents/drbg/drbgtestvectors.zip

tests =
    [ testGroup "bitcoind /src/test/key_tests.cpp" 
        [ testCase "HMAC DRBG Vector 1" (testDRBG (t1v1 !! 0))
        ] 
    ]

t1v1 :: [[BS.ByteString]]
t1v1 = 
    [
    -- Vector 1
    [ integerToBS 0xca851911349384bffe89de1cbdc46e6831e44d34a4fb935ee285dd14b71a7488
    , integerToBS 0x659ba96c601dc69fc902940805ec0ca8
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0xe528e9abf2dece54d47c7e75e5fe302149f817ea9fb4bee6f4199697d04d5b89d54fbb978a15b5c443c9ec21036d2460b6f73ebad0dc2aba6e624abf07745bc107694bb7547bb0995f70de25d6b29e2d3011bb19d27676c07162c8b5ccde0668961df86803482cb37ed6d5c0bb8d50cf1f50d476aa0458bdaba806f48be9dcb8
    ]
    ]

testDRBG :: [BS.ByteString] -> Assertion
testDRBG v = do
    let w1     = hmacDRBGNew (v !! 0) (v !! 1) (v !! 2)
        (w2,_) = hmacDRBGGen w1 128 (v !! 3)
        (_,r)  = hmacDRBGGen w2 128 (v !! 4)
    assertBool "Test1" $ fromJust r == (v !! 5)


