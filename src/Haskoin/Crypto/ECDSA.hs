module Haskoin.Crypto.ECDSA
( SecretT
, Signature(..)
, withSource
, devURandom
, devRandom
, signMsg
, detSignMsg
, unsafeSignMsg
, verifySig
, genPrvKey
) where

import System.IO

import Control.Monad (liftM, guard, unless)
import Control.Monad.Trans (MonadTrans, MonadIO, lift)
import Control.Applicative (Applicative, (<*>), (<$>), pure)
import qualified Control.Monad.State as S
    ( StateT
    , evalStateT
    , get, put
    )

import Data.Word (Word32)
import Data.Maybe (fromJust)
import Data.Bits (testBit)
import Data.Binary (Binary, get, put)
import Data.Binary.Put (putWord8, putByteString, runPut)
import Data.Binary.Get (getWord8)

import qualified Data.ByteString as BS 
    ( ByteString
    , length
    , cons
    , append
    , splitAt
    , hGet
    , empty
    , index
    )
  
import Haskoin.Util 
    ( toStrictBS
    , stringToBS
    , isolate
    , integerToBS
    , bsToInteger
    , encode'
    )
import Haskoin.Crypto.Hash 
    ( hash256
    , hmac512
    , split512
    , WorkingState
    , hmacDRBGNew
    , hmacDRBGGen
    , hmacDRBGRsd
    )
import Haskoin.Crypto.Keys 
    ( PrvKey(..)
    , PubKey(..)
    , curveG
    , makePrvKey
    , putPrvKey
    )
import Haskoin.Crypto.Point 
    ( Point
    , getAffine, makePoint
    , mulPoint, shamirsTrick
    )
import Haskoin.Crypto.Ring 
    ( Hash256
    , FieldN
    , toFieldN
    , toMod256
    , inverseN
    , isIntegerValidKey
    , curveN
    )

type Nonce = FieldN

data Signature = Signature { sigR :: !FieldN, sigS :: !FieldN }
    deriving (Show, Eq)

type SecretState m = (WorkingState, (Int -> m BS.ByteString))

-- HMAC DRBG with SHA-256
type SecretT m a = S.StateT (SecretState m) m a

-- /dev/urandom on machines that support it
devURandom :: Int -> IO BS.ByteString
devURandom i = withBinaryFile "/dev/urandom" ReadMode $ flip BS.hGet i

-- /dev/random on machines that support it
devRandom :: Int -> IO BS.ByteString
devRandom i = withBinaryFile "/dev/random" ReadMode $ flip BS.hGet i

-- You have to supply a function that can generate random bits
withSource :: MonadIO m => (Int -> m BS.ByteString) -> SecretT m a -> m a
withSource f m = do
    seed  <- f 32 -- Read 256 bits from the random source
    nonce <- f 16 -- Read 128 bits from the random source
    let ws = hmacDRBGNew seed nonce (stringToBS "/haskoin:0.1.1/")
    S.evalStateT m (ws,f)

-- Prime subkey derivation function (from BIP32) with 32 bit counter
nextSecret :: MonadIO m => SecretT m FieldN
nextSecret = do
    (ws,f) <- S.get
    let (ws',randM) = hmacDRBGGen ws 32 (stringToBS "/haskoin:0.1.1/")
    case randM of
        (Just rand) -> do
            S.put (ws',f)
            let randI = bsToInteger rand
            if isIntegerValidKey randI
                then return $ fromInteger randI
                else nextSecret
        Nothing -> do
            seed <- lift $ f 32 -- Read 256 bits to re-seed the PRNG
            let ws0 = hmacDRBGRsd ws' seed (stringToBS "/haskoin:0.1.1/")
            S.put (ws0,f)
            nextSecret

genPrvKey :: MonadIO m => SecretT m PrvKey
genPrvKey = liftM (fromJust . makePrvKey . toInteger) nextSecret
        
-- Build a private/public key pair from the SecretT monad
-- Section 3.2.1 http://www.secg.org/download/aid-780/sec1-v2.pdf
genKeyPair :: MonadIO m => SecretT m (FieldN, Point)
genKeyPair = do
    -- 3.2.1.1 
    d <- nextSecret
    -- 3.2.1.2
    let q = mulPoint d curveG
    -- 3.2.1.3
    return (d,q)

-- Safely sign a message inside the SecretT monad
-- SecretT monad will generate a new nonce for each signature
-- Section 4.1.3 http://www.secg.org/download/aid-780/sec1-v2.pdf
signMsg :: MonadIO m => Hash256 -> PrvKey -> SecretT m Signature
signMsg _ (PrvKey  0) = error "Integer 0 is an invalid private key"
signMsg _ (PrvKeyU 0) = error "Integer 0 is an invalid private key"
signMsg h d = do
    -- 4.1.3.1
    (k,p) <- genKeyPair
    case unsafeSignMsg h (runPrvKey d) (k,p) of
        (Just sig) -> return sig
        -- If signing failed, retry with a new nonce
        Nothing    -> signMsg h d

-- RFC 6979 (http://tools.ietf.org/html/rfc6979)
-- ECDSA deterministic signatures
detSignMsg :: Hash256 -> PrvKey -> Signature
detSignMsg _ (PrvKey  0) = error "Integer 0 is an invalid private key"
detSignMsg _ (PrvKeyU 0) = error "Integer 0 is an invalid private key"
detSignMsg h d = go ws
    where ws = hmacDRBGNew d' (encode' h) BS.empty
          d' = toStrictBS $ runPut $ putPrvKey d -- encode to 32 bytes 
          go ws0 = case hmacDRBGGen ws0 32 BS.empty of
              (ws1, Just k) -> 
                  let kI = bsToInteger k
                      k' = fromIntegral kI
                      p  = mulPoint k' curveG
                      d' = runPrvKey d
                      in if isIntegerValidKey kI
                            then case unsafeSignMsg h d' (k',p) of
                                (Just sig) -> sig
                                Nothing    -> go ws1
                            else go ws1
                   -- If this happens to you, you should be playing the lottery
              _ -> error $ "Impossible to generate a deterministic signature"
          
-- Signs a message by providing the nonce
-- Re-using the same nonce twice will expose the private keys
-- Use signMsg within the SecretT monad or detSignMsg instead
-- Section 4.1.3 http://www.secg.org/download/aid-780/sec1-v2.pdf
unsafeSignMsg :: Hash256 -> FieldN -> (FieldN, Point) -> Maybe Signature
unsafeSignMsg _ 0 _ = Nothing
unsafeSignMsg h d (k,p) = do
    -- 4.1.3.1 (4.1.3.2 not required)
    (x,_) <- getAffine p
    -- 4.1.3.3
    let r = toFieldN x
    guard (r /= 0)
    -- 4.1.3.4 / 4.1.3.5
    let e = toFieldN h
    -- 4.1.3.6
    let s' = (e + r*d)/k
        -- Only create signatures with even s
        s  = if even s' then s' else (-s')
    guard (s /= 0)
    -- 4.1.3.7
    return $ Signature r s

-- Section 4.1.4 http://www.secg.org/download/aid-780/sec1-v2.pdf
verifySig :: Hash256 -> Signature -> PubKey -> Bool
-- 4.1.4.1 (r and s can not be zero)
verifySig _ (Signature 0 _) _ = False
verifySig _ (Signature _ 0) _ = False
verifySig h (Signature r s) q = 
    case getAffine p of
        Nothing      -> False
        -- 4.1.4.7 / 4.1.4.8
        (Just (x,_)) -> (toFieldN x) == r
    where 
        -- 4.1.4.2 / 4.1.4.3
        e  = toFieldN h
        -- 4.1.4.4
        s' = inverseN s
        u1 = e*s'
        u2 = r*s'
        -- 4.1.4.5 (u1*G + u2*q)
        p  = shamirsTrick u1 curveG u2 (runPubKey q)

instance Binary Signature where
    get = do
        t <- getWord8
        -- 0x30 is DER sequence type
        unless (t == 0x30) (fail $ 
            "Bad DER identifier byte " ++ (show t) ++ ". Expecting 0x30")
        l <- getWord8
        -- Length = (33 + 1 identifier byte + 1 length byte) * 2
        unless (l <= 70) (fail $
            "Bad DER length " ++ (show t) ++ ". Expecting length <= 70")
        isolate (fromIntegral l) $ do
            Signature <$> get <*> get

    put (Signature 0 s) = error "0 is an invalid r value in a Signature"
    put (Signature r 0) = error "0 is an invalid s value in a Signature"
    put (Signature r s) = do
        putWord8 0x30
        let c = toStrictBS $ runPut $ put r >> put s
        putWord8 (fromIntegral $ BS.length c)
        putByteString c

