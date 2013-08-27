module Haskoin.Crypto.Util
( integerToBS
, bsToInteger
) where

import Data.Word (Word8)
import qualified Data.ByteString as BS 
    ( ByteString
    , pack, unpack
    )
import Data.Bits ((.|.), shiftL, shiftR)
import Data.List (unfoldr)

bsToInteger :: BS.ByteString -> Integer
bsToInteger = (foldr f 0) . reverse . BS.unpack
    where f w n = (toInteger w) .|. shiftL n 8

integerToBS :: Integer -> BS.ByteString
integerToBS 0 = BS.pack [0]
integerToBS i 
    | i > 0    = BS.pack $ reverse $ unfoldr f i
    | otherwise = error "integerToBS not defined for negative values"
    where f 0 = Nothing
          f x = Just $ (fromInteger x :: Word8, x `shiftR` 8)

