module Network.Haskoin.Crypto.HumanKey.Tests (tests) where

import Data.Binary
import qualified Data.ByteString.Lazy.Char8 as C
import Network.Haskoin.Crypto.Arbitrary()
import Network.Haskoin.Crypto.HumanKey
import Test.Framework
import Test.Framework.Providers.QuickCheck2

tests :: [Test]
tests =
    [ testGroup "RFC-1751"
        [ testProperty "Encode/Decode RFC-1751 keys" decodeEncode
        , testProperty "Double 64-bit key" doubleWord64
        ]
    ]

decodeEncode :: (Word64, Word64) -> Bool
decodeEncode (w1, w2) = bs == bs'
    where bs = encode w1 `C.append` encode w2
          hk = decode bs :: HumanKey
          bs' = encode hk

doubleWord64 :: Word64 -> Bool
doubleWord64 w = ws1 == ws2
    where bs = encode w `C.append` encode w
          HumanKey ws = decode bs :: HumanKey
          (ws1, ws2) = splitAt 6 $ words ws
