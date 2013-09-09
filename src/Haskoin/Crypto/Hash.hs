module Haskoin.Crypto.Hash
( Hash512
, Hash256
, Hash160
, CheckSum32
, hash512
, hash256
, hash160
, hash512BS
, hash256BS
, hash160BS
, doubleHash256
, doubleHash256BS
, chksum32
, hmac512
, hmac256
, split512
, join512
) where

import Data.Word (Word32)
import Crypto.Hash 
    ( Digest 
    , SHA512
    , SHA256
    , RIPEMD160
    , hash
    , digestToByteString
    )
import Crypto.MAC.HMAC (hmac)
import Data.Binary.Get (runGet)
import Data.Binary (Binary, get, put)
import Data.Bits (shiftL, shiftR)
import Control.Applicative ((<$>))

import qualified Data.ByteString as BS (ByteString)

import Haskoin.Util (toLazyBS, decode')
import Haskoin.Crypto.Ring 
    ( Hash512
    , Hash256
    , Hash160
    , toMod512
    )

newtype CheckSum32 = CheckSum32 { runCheckSum32 :: Word32 }
    deriving (Show, Eq)

instance Binary CheckSum32 where
    get = CheckSum32 <$> get
    put (CheckSum32 w) = put w

run512 :: BS.ByteString -> BS.ByteString
run512 = (digestToByteString :: Digest SHA512 -> BS.ByteString) . hash

run256 :: BS.ByteString -> BS.ByteString
run256 = (digestToByteString :: Digest SHA256 -> BS.ByteString) . hash

run160 :: BS.ByteString -> BS.ByteString
run160 = (digestToByteString :: Digest RIPEMD160 -> BS.ByteString) . hash

hash512 :: BS.ByteString -> Hash512
hash512 bs = runGet get (toLazyBS $ run512 bs)

hash512BS :: BS.ByteString -> BS.ByteString
hash512BS bs = run512 bs

hash256 :: BS.ByteString -> Hash256
hash256 bs = runGet get (toLazyBS $ run256 bs)

hash256BS :: BS.ByteString -> BS.ByteString
hash256BS bs = run256 bs

hash160 :: BS.ByteString -> Hash160
hash160 bs = runGet get (toLazyBS $ run160 bs)

hash160BS :: BS.ByteString -> BS.ByteString
hash160BS bs = run160 bs

doubleHash256 :: BS.ByteString -> Hash256
doubleHash256 bs = runGet get (toLazyBS $ run256 $ run256 bs)

doubleHash256BS :: BS.ByteString -> BS.ByteString
doubleHash256BS bs = run256 $ run256 bs

{- CheckSum -}

chksum32 :: BS.ByteString -> CheckSum32
chksum32 bs = CheckSum32 $ fromIntegral $ (doubleHash256 bs) `shiftR` 224

{- HMAC -}

hmac512 :: BS.ByteString -> BS.ByteString -> Hash512
hmac512 key msg = decode' $ hmac hash512BS 128 key msg

hmac256 :: BS.ByteString -> BS.ByteString -> Hash256
hmac256 key msg = decode' $ hmac hash256BS 64 key msg

split512 :: Hash512 -> (Hash256, Hash256)
split512 i = (fromIntegral $ i `shiftR` 256, fromIntegral i)

join512 :: (Hash256, Hash256) -> Hash512
join512 (a,b) = ((toMod512 a) `shiftL` 256) + (toMod512 b)

