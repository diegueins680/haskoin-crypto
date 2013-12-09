module Network.Haskoin.Crypto.Hash.Tests (tests) where

import Test.QuickCheck.Property hiding ((.&.))
import Test.Framework
import Test.Framework.Providers.QuickCheck2

import qualified Data.ByteString as BS

import QuickCheckUtils
import Network.Haskoin.Crypto.Arbitrary

import Network.Haskoin.Crypto.Hash
import Network.Haskoin.Util

tests :: [Test]
tests = 
    [ testGroup "Hash tests" 
        [ testProperty "join512( split512(h) ) == h" joinSplit512
        ]
    ]

joinSplit512 :: Hash512 -> Bool
joinSplit512 h = (join512 $ split512 h) == h

