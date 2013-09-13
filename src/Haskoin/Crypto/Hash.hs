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
, hmacDRBGNew
, hmacDRBGUpd
, hmacDRBGRsd
, hmacDRBGGen
, split512
, join512
) where

import Data.Word (Word32, Word64)
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

import qualified Data.ByteString as BS 
    ( ByteString
    , null
    , append
    , cons
    , concat
    , take
    , empty
    , length
    , replicate
    )

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

hmac512BS :: BS.ByteString -> BS.ByteString -> BS.ByteString
hmac512BS key msg = hmac hash512BS 128 key msg

hmac256BS :: BS.ByteString -> BS.ByteString -> BS.ByteString
hmac256BS key msg = hmac hash256BS 64 key msg

hmac512 :: BS.ByteString -> BS.ByteString -> Hash512
hmac512 key = decode' . (hmac512BS key)

hmac256 :: BS.ByteString -> BS.ByteString -> Hash256
hmac256 key = decode' . (hmac256BS key)

split512 :: Hash512 -> (Hash256, Hash256)
split512 i = (fromIntegral $ i `shiftR` 256, fromIntegral i)

join512 :: (Hash256, Hash256) -> Hash512
join512 (a,b) = ((toMod512 a) `shiftL` 256) + (toMod512 b)


{- 10.1.2 HMAC_DRBG with HMAC-SHA256
   http://csrc.nist.gov/publications/nistpubs/800-90A/SP800-90A.pdf 
-}

type WorkingState    = (BS.ByteString, BS.ByteString, Word64)
type AdditionalInput = BS.ByteString
type ProvidedData    = BS.ByteString
type EntropyInput    = BS.ByteString
type PersString      = BS.ByteString
type Nonce           = BS.ByteString

-- 10.1.2.2 HMAC DRBG Update FUnction
hmacDRBGUpd :: ProvidedData -> BS.ByteString -> BS.ByteString
               -> (BS.ByteString, BS.ByteString)
hmacDRBGUpd info k0 v0 
    | BS.null info = (k1,v1) -- 10.1.2.2.3
    | otherwise    = (k2,v2) -- 10.1.2.2.6
    where k1 = hmac256BS k0 $ v0 `BS.append` (0 `BS.cons` info) -- 10.1.2.2.1
          v1 = hmac256BS k1 v0                                  -- 10.1.2.2.2
          k2 = hmac256BS k1 $ v1 `BS.append` (1 `BS.cons` info) -- 10.1.2.2.4
          v2 = hmac256BS k2 v1                                  -- 10.1.2.2.5

-- 10.1.2.3 HMAC DRBG Instantiation
hmacDRBGNew :: EntropyInput -> Nonce -> PersString -> WorkingState
hmacDRBGNew seed nonce info = (k1, v1, 1)          -- 10.1.2.3.6
    where s        = BS.concat [seed, nonce, info] -- 10.1.2.3.1
          k0       = BS.replicate 32 0             -- 10.1.2.3.2
          v0       = BS.replicate 32 1             -- 10.1.2.3.3
          (k1,v1) = hmacDRBGUpd s k0 v0            -- 10.1.2.3.4

-- 10.1.2.4 HMAC DRBG Reseeding
hmacDRBGRsd :: WorkingState -> EntropyInput -> AdditionalInput -> WorkingState
hmacDRBGRsd (k,v,_) xseed info = (k0,v0,1)  -- 10.1.2.4.4
    where s        = xseed `BS.append` info -- 10.1.2.4.1
          (k0, v0) = hmacDRBGUpd s k v      -- 10.1.2.4.2

-- 10.1.2.5 HMAC DRBG Generation
hmacDRBGGen :: WorkingState -> Word64 -> AdditionalInput
            -> (WorkingState, Maybe BS.ByteString)
hmacDRBGGen (k0,v0,c0) bytes info 
    -- 10.1 Table 2 (reseed interval)
    | c0 > 2^48 = ((k0,v0,c0), Nothing)  -- 10.1.2.5.1
    | otherwise = ((k2,v3,c1), Just res) -- 10.1.2.5.8
    where (k1,v1) | BS.null info = (k0,v0) 
                  | otherwise    = hmacDRBGUpd info k0 v0   -- 10.1.2.5.2
          (tmp,v2) = go (fromIntegral bytes) k1 v1 BS.empty -- 10.1.2.5.3/4
          res      = BS.take (fromIntegral bytes) tmp       -- 10.1.2.5.5
          (k2,v3)  = hmacDRBGUpd info k1 v2                 -- 10.1.2.5.6
          c1       = c0 + 1                                 -- 10.1.2.5.7
          go l k v acc | BS.length acc >= l = (acc,v)
                       | otherwise = let vn = hmac256BS k v 
                                         in go l k vn (acc `BS.append` vn)
          


