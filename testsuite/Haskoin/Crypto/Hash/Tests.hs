module Haskoin.Crypto.Hash.Tests (tests) where

import Test.QuickCheck.Property hiding ((.&.))
import Test.Framework
import Test.Framework.Providers.QuickCheck2

import qualified Data.ByteString as BS

import QuickCheckUtils

import Haskoin.Crypto.Hash
import Haskoin.Util

tests :: [Test]
tests = 
    [ testGroup "Hash tests" 
        [ testProperty "join512( split512(h) ) == h" joinSplit512
        ]
    ]

joinSplit512 :: Hash512 -> Bool
joinSplit512 h = (join512 $ split512 h) == h

