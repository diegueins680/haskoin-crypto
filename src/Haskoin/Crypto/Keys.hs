module Haskoin.Crypto.Keys
( PubKey(..)
, isValidPubKey
, isPubKeyU
, derivePubKey
, pubKeyAddr
, addPubKeys
, PrvKey(..)
, isValidPrvKey
, makePrvKey
, makePrvKeyU
, fromPrvKey
, isPrvKeyU
, addPrvKeys
, putPrvKey
, getPrvKey
, getPrvKeyU
, fromWIF
, toWIF
, curveG
) where

import Data.Binary (Binary, get, put)
import Data.Binary.Get (Get, getWord8)
import Data.Binary.Put (Put, putWord8, runPut)

import Control.Monad (when, unless, guard)
import Control.Applicative ((<$>),(<*>))
import Data.Maybe (isJust, fromJust)

import qualified Data.ByteString as BS 
    ( ByteString
    , head, tail
    , last, init
    , cons, snoc
    , length
    )
import Haskoin.Crypto.Ring 
    ( FieldN, FieldP
    , isIntegerValidKey
    , quadraticResidue
    , toMod256
    )
import Haskoin.Crypto.Point 
    ( Point( InfPoint )
    , makePoint
    , mulPoint 
    , addPoint
    , getAffine
    , curveB
    , validatePoint
    )
import Haskoin.Crypto.Base58 
    ( Address(..)
    , encodeBase58Check
    , decodeBase58Check
    )
import Haskoin.Crypto.Hash 
    ( Hash256
    , hash160
    , hash256BS
    )
import Haskoin.Util 
    ( toStrictBS
    , bsToInteger
    , encode'
    )

curveG :: Point
curveG = fromJust $ makePoint
        0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798       
        0X483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8 

{- Public Keys -}

data PubKey =
        PubKey  { runPubKey :: !Point } | -- default is Compressed
        PubKeyU { runPubKey :: !Point }   -- Uncompressed is explicit
        deriving Show

instance Eq PubKey where
    -- Compression does not matter for InfPoint
    (PubKey  InfPoint) == (PubKeyU InfPoint) = True
    (PubKeyU InfPoint) == (PubKey  InfPoint) = True
    (PubKey  a)        == (PubKey  b)        = a == b
    (PubKeyU a)        == (PubKeyU b)        = a == b
    _                  == _                  = False

isValidPubKey :: PubKey -> Bool
isValidPubKey = validatePoint . runPubKey

-- Adding public keys together. Provides support for HDW (BIP32)
addPubKeys :: PubKey -> PubKey -> Maybe PubKey
addPubKeys (PubKey p1) (PubKey p2) = case addPoint p1 p2 of
    InfPoint -> Nothing
    p3       -> Just $ PubKey p3
addPubKeys (PubKeyU p1) (PubKeyU p2) = case addPoint p1 p2 of
    InfPoint -> Nothing
    p3       -> Just $ PubKeyU p3
addPubKeys _ _ = error "Adding incompatible public keys"

isPubKeyU :: PubKey -> Bool
isPubKeyU (PubKey  _) = False
isPubKeyU (PubKeyU _) = True

derivePubKey :: PrvKey -> PubKey
derivePubKey k = case k of
    (PrvKey  d) -> PubKey  $ mulPoint d curveG
    (PrvKeyU d) -> PubKeyU $ mulPoint d curveG

instance Binary PubKey where

    -- Section 2.3.4 http://www.secg.org/download/aid-780/sec1-v2.pdf
    get = go =<< getWord8
              -- 2.3.4.1 InfPoint if input is 0x00
        where go 0 = return $ PubKey InfPoint
              -- 2.3.4.3 Uncompressed format
              go 4 = getUncompressed
              -- 2.3.4.2 Compressed format
              -- 2 means pY is even, 3 means pY is odd
              go y | y == 2 || y == 3 = getCompressed (even y)
                   | otherwise = fail "Get: Invalid public key encoding"

    -- Section 2.3.3 http://www.secg.org/download/aid-780/sec1-v2.pdf
    put pk = case getAffine (runPubKey pk) of
        -- 2.3.3.1
        Nothing -> putWord8 0x00
        (Just (x,y)) -> case pk of
            -- Compressed
            (PubKey  p) -> putWord8 (if even y then 2 else 3) >> put x
            -- Uncompressed
            (PubKeyU p) -> putWord8 4 >> put x >> put y

getUncompressed :: Get PubKey
getUncompressed = do
    p <- makePoint <$> get <*> get
    unless (isJust p) (fail "Get: Point not on the curve")
    return $ PubKeyU $ fromJust $ p

getCompressed :: Bool -> Get PubKey
getCompressed e = do
    -- 2.1 
    x <- get :: Get FieldP
    -- 2.4.1 (deriving yP)
    let a  = x ^ (3 :: Integer) + curveB
        ys = filter matchSign (quadraticResidue a)
    -- We found no square root (mod p)
    when (null ys) (fail $ "No ECC point for x = " ++ (show x))
    let p = makePoint x (head ys)
    -- Additionally, check that the point is on the curve
    unless (isJust p) (fail "Get: Point not on the curve")
    return $ PubKey $ fromJust $ p
    where matchSign a = (even a) == e

pubKeyAddr :: PubKey -> Address
pubKeyAddr = PubKeyAddress . hash160 . hash256BS . encode'

{- Private Keys -}

data PrvKey =
        PrvKey  { runPrvKey :: !FieldN } | -- default is Compressed
        PrvKeyU { runPrvKey :: !FieldN }   -- Uncompressed is explicit
        deriving (Eq, Show)

isValidPrvKey :: Integer -> Bool
isValidPrvKey = isIntegerValidKey

-- Integer needs to be a random number with at least 128 bits of entropy
makePrvKey :: Integer -> Maybe PrvKey
makePrvKey i
    | isValidPrvKey i = Just $ PrvKey $ fromInteger i
    | otherwise       = Nothing

-- Integer needs to be a random number with at least 128 bits of entropy
makePrvKeyU :: Integer -> Maybe PrvKey
makePrvKeyU i
    | isValidPrvKey i = Just $ PrvKeyU $ fromInteger i
    | otherwise       = Nothing

fromPrvKey :: PrvKey -> Integer
fromPrvKey = fromIntegral . runPrvKey

-- Adding private keys together. Provides support for HDW (BIP32)
addPrvKeys :: PrvKey -> PrvKey -> Maybe PrvKey
addPrvKeys (PrvKey  r1) (PrvKey  r2) = makePrvKey  $ toInteger $ r1 + r2
addPrvKeys (PrvKeyU r1) (PrvKeyU r2) = makePrvKeyU $ toInteger $ r1 + r2
addPrvKeys _ _ = error "Adding incompatible private keys"

isPrvKeyU :: PrvKey -> Bool
isPrvKeyU (PrvKey  _) = False
isPrvKeyU (PrvKeyU _) = True

-- Serialize private key to 32 byte big endian bytestring
putPrvKey :: PrvKey -> Put
putPrvKey k | runPrvKey k == 0 = error "Put: 0 is an invalid private key"
            | otherwise        = put $ toMod256 $ runPrvKey k

getPrvKey :: Get PrvKey
getPrvKey = do
        i <- get :: Get Hash256
        let res = makePrvKey $ fromIntegral i
        unless (isJust res) $ fail "Get: PrivateKey is invalid"
        return $ fromJust res

getPrvKeyU :: Get PrvKey
getPrvKeyU = do
        i <- get :: Get Hash256
        let res = makePrvKeyU $ fromIntegral i
        unless (isJust res) $ fail "Get: PrivateKey is invalid"
        return $ fromJust res

fromWIF :: BS.ByteString -> Maybe PrvKey
fromWIF bs = do
    b <- decodeBase58Check bs
    guard (BS.head b == 0x80)  -- Check that this is a private key
    case BS.length b of
        33 -> do               -- Uncompressed format
            let i = bsToInteger (BS.tail b)
            makePrvKeyU i
        34 -> do               -- Compressed format
            guard (BS.last b == 0x01) 
            let i = bsToInteger $ BS.tail $ BS.init b
            makePrvKey i
        _  -> Nothing          -- Bad length

toWIF :: PrvKey -> BS.ByteString
toWIF k = encodeBase58Check $ BS.cons 0x80 enc
    where enc | isPrvKeyU k = bs
              | otherwise   = BS.snoc bs 0x01
          bs = toStrictBS $ runPut $ putPrvKey k

