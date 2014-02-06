module Network.Haskoin.Crypto.Hash.Tests (tests) where

import Test.Framework (Test, testGroup)
import Test.Framework.Providers.QuickCheck2 (testProperty)

import Data.Word (Word32)

import Network.Haskoin.Crypto.Hash
import Network.Haskoin.Crypto.Arbitrary()

tests :: [Test]
tests = 
    [ testGroup "Hash tests" 
        [ testProperty "join512( split512(h) ) == h" joinSplit512
        , testProperty "decodeCompact . encodeCompact i == i" decEncCompact
        ]
    ]

joinSplit512 :: Hash512 -> Bool
joinSplit512 h = (join512 $ split512 h) == h

-- After encoding and decoding, we may loose precision so the new result is >=
-- to the old one.
decEncCompact :: Integer -> Bool
decEncCompact i 
    -- Integer completely fits inside the mantisse
    | (abs i) <= 0x007fffff = (decodeCompact $ encodeCompact i) == i
    -- Otherwise precision will be lost and the decoded result will
    -- be smaller than the original number
    | i >= 0                = (decodeCompact $ encodeCompact i) < i
    | otherwise             = (decodeCompact $ encodeCompact i) > i

