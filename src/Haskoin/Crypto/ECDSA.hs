module Haskoin.Crypto.ECDSA
( SecretT
, Signature(..)
, withSecret
, signMessage
, verifySignature
, genPrvKey
) where

import Control.Monad (liftM, guard, unless)
import Control.Monad.Trans (MonadTrans, lift)
import Control.Applicative (Applicative, (<*>), (<$>), pure)
import qualified Control.Monad.State as S
    ( StateT
    , evalStateT
    , get, put
    )

import Data.Word (Word32)
import Data.Maybe (fromJust)
import Data.Binary (Binary, get, put)
import Data.Binary.Put (putWord8, putByteString, runPut)
import Data.Binary.Get (getWord8)

import qualified Data.ByteString as BS 
    ( ByteString
    , length
    , cons
    , append
    )
  
import Haskoin.Util 
    ( toStrictBS
    , stringToBS
    , isolate
    , integerToBS
    , encode'
    )
import Haskoin.Crypto.Hash 
    ( hash256
    , hmac512
    , split512
    )
import Haskoin.Crypto.Keys 
    ( PrvKey(..)
    , PubKey(..)
    , curveG
    , makePrvKey
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

type SecretState = (FieldN, Hash256, Word32)

-- PRNG over hmac-512
type SecretT m a = S.StateT SecretState m a

-- The input ByteString must have an entropy of at least 128 bits
withSecret :: Monad m => BS.ByteString -> SecretT m a -> m a
withSecret bs m = S.evalStateT m (s,k,0)
    where (s,k) = go (stringToBS "Secret seed")
          go key | isIntegerValidKey $ toInteger l = (toFieldN l,r)
                 | otherwise = go (BS.cons 0 key)
              where (l,r) = split512 $ hmac512 key bs 

-- Prime subkey derivation function (from BIP32) with 32 bit counter
nextSecret :: Monad m => SecretT m FieldN
nextSecret = do
    (s,k,c) <- S.get
    let msg   = BS.append (encode' $ toMod256 s) (encode' c)
        (l,r) = split512 $ hmac512 (encode' k) msg
        res   = s + (toFieldN l)
    S.put (s,k,c+1)
    if (toInteger l) < curveN && res > 0
        then return res
        else nextSecret

genPrvKey :: Monad m => SecretT m PrvKey
genPrvKey = liftM (fromJust . makePrvKey . toInteger) nextSecret
        
-- Build a private/public key pair from the SecretT monad
-- Section 3.2.1 http://www.secg.org/download/aid-780/sec1-v2.pdf
genKeyPair :: Monad m => SecretT m (FieldN, Point)
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
signMessage :: Monad m => Hash256 -> PrvKey -> SecretT m Signature
signMessage _ (PrvKey  0) = error "Integer 0 is an invalid private key"
signMessage _ (PrvKeyU 0) = error "Integer 0 is an invalid private key"
signMessage h d = do
    -- 4.1.3.1
    (k,p) <- genKeyPair
    case unsafeSignMessage h (runPrvKey d) (k,p) of
        (Just sig) -> return sig
        -- If signing failed, retry with a new nonce
        Nothing    -> signMessage h d

-- Signs a message by providing the nonce
-- Re-using the same nonce twice will expose the private keys
-- Use signMessage within the SecretT monad instead
-- Section 4.1.3 http://www.secg.org/download/aid-780/sec1-v2.pdf
unsafeSignMessage :: Hash256 -> FieldN -> (FieldN, Point) -> Maybe Signature
unsafeSignMessage _ 0 _ = Nothing
unsafeSignMessage h d (k,p) = do
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
verifySignature :: Hash256 -> Signature -> PubKey -> Bool
-- 4.1.4.1 (r and s can not be zero)
verifySignature _ (Signature 0 _) _ = False
verifySignature _ (Signature _ 0) _ = False
verifySignature h (Signature r s) q = 
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

