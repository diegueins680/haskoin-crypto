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
, fromTestWIF
, toTestWIF
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
import Haskoin.Crypto.Curve (pairG, curveN)
import Haskoin.Crypto.Ring 
    ( FieldN, FieldP
    , isIntegerValidKey
    , quadraticResidue
    , toMod256
    , toFieldN
    )
import Haskoin.Crypto.Point 
    ( Point( InfPoint )
    , makePoint
    , mulPoint 
    , addPoint
    , getAffine
    , validatePoint
    , isInfPoint
    , curveA, curveB
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
    ( runPut'
    , bsToInteger
    , encode'
    , stringToBS
    , bsToString
    )

curveG :: Point
curveG = fromJust $ makePoint (fromInteger $ fst pairG) 
                              (fromInteger $ snd pairG)

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
addPubKeys :: PubKey -> Hash256 -> Maybe PubKey
addPubKeys pub i
    | isPubKeyU pub = error "Add: HDW only supports compressed formats"
    | toInteger i < curveN =
        let pt1 = mulPoint (toFieldN i) curveG
            pt2 = addPoint (runPubKey pub) pt1
            in if isInfPoint pt2 then Nothing
                                 else Just $ PubKey pt2
    | otherwise = Nothing

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
              -- skip 2.3.4.1 and fail. InfPoint is an invalid public key
        where go 0 = fail "InfPoint is not a valid public key"
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
    let a  = x ^ (3 :: Integer) + (curveA * x) + curveB
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
addPrvKeys :: PrvKey -> Hash256 -> Maybe PrvKey
addPrvKeys key i
    | isPrvKeyU key = error "Add: HDW only supports compressed formats"
    | toInteger i < curveN =
        let r = (runPrvKey key) + (toFieldN i) 
            in makePrvKey $ toInteger r
    | otherwise = Nothing

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

fromWIF :: String -> Maybe PrvKey
fromWIF str = do
    bs <- decodeBase58Check $ stringToBS str
    guard (BS.head bs == 128)  -- Check that this is a prodnet private key
    decodeWIF bs

fromTestWIF :: String -> Maybe PrvKey
fromTestWIF str = do
    bs <- decodeBase58Check $ stringToBS str
    guard (BS.head bs == 239)  -- Check that this is a testnet private key
    decodeWIF bs

decodeWIF :: BS.ByteString -> Maybe PrvKey
decodeWIF bs = case BS.length bs of
    33 -> do               -- Uncompressed format
        let i = bsToInteger (BS.tail bs)
        makePrvKeyU i
    34 -> do               -- Compressed format
        guard (BS.last bs == 0x01) 
        let i = bsToInteger $ BS.tail $ BS.init bs
        makePrvKey i
    _  -> Nothing          -- Bad length

toWIF :: PrvKey -> String
toWIF k = bsToString $ encodeBase58Check $ BS.cons 128 enc
    where enc | isPrvKeyU k = bs
              | otherwise   = BS.snoc bs 0x01
          bs = runPut' $ putPrvKey k

toTestWIF :: PrvKey -> String
toTestWIF k = bsToString $ encodeBase58Check $ BS.cons 239 enc
    where enc | isPrvKeyU k = bs
              | otherwise   = BS.snoc bs 0x01
          bs = runPut' $ putPrvKey k

