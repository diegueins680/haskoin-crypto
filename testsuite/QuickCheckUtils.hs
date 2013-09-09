{-# LANGUAGE EmptyDataDecls #-}
module QuickCheckUtils where

import Test.QuickCheck

import Control.Monad.Identity
import Control.Applicative ((<$>),(<*>))

import qualified Data.ByteString as BS

import Haskoin.Crypto.Point
import Haskoin.Crypto.Ring
import Haskoin.Crypto.ECDSA
import Haskoin.Crypto.Keys
import Haskoin.Crypto.Base58

data Mod32
type Test32  = Ring Mod32

newtype TestPrvKeyC = TestPrvKeyC { runTestPrvKeyC :: PrvKey }
    deriving (Eq, Show)

newtype TestPrvKeyU = TestPrvKeyU { runTestPrvKeyU :: PrvKey }
    deriving (Eq, Show)

instance RingMod Mod32 where
    rFromInteger i = Ring $ i `mod` 2 ^ (32 :: Integer)
    rBitSize     _ = 32

instance RingMod n => Arbitrary (Ring n) where
    arbitrary = fromInteger <$> (arbitrary :: Gen Integer)

instance Arbitrary Point where
    arbitrary = frequency
        [ (1, return makeInfPoint)
        , (9, (flip mulPoint $ curveG) <$> (arbitrary :: Gen FieldN))
        ]

instance Arbitrary TestPrvKeyC where
    arbitrary = do
        i <- fromInteger <$> choose (1, curveN-1)
        return $ TestPrvKeyC $ PrvKey i

instance Arbitrary TestPrvKeyU where
    arbitrary = do
        i <- fromInteger <$> choose (1, curveN-1)
        return $ TestPrvKeyU $ PrvKeyU i

instance Arbitrary PrvKey where
    arbitrary = oneof
        [ runTestPrvKeyC <$> (arbitrary :: Gen TestPrvKeyC)
        , runTestPrvKeyU <$> (arbitrary :: Gen TestPrvKeyU)
        ]

instance Arbitrary PubKey where
    arbitrary = derivePubKey <$> (arbitrary :: Gen PrvKey)

instance Arbitrary Address where
    arbitrary = do
        i <- choose (1,2^160-1) :: Gen Integer
        elements [ PubKeyAddress $ fromInteger i
                 , ScriptAddress $ fromInteger i
                 ]

instance Arbitrary Signature where
    arbitrary = do
        bs <- arbitrary :: Gen BS.ByteString
        d  <- arbitrary :: Gen PrvKey
        h  <- arbitrary :: Gen Hash256
        return $ runIdentity $ withSecret bs (signMessage h d)

-- from Data.ByteString project
instance Arbitrary BS.ByteString where
    arbitrary = do
        bs <- BS.pack `fmap` arbitrary
        n <- choose (0, 2)
        return (BS.drop n bs) -- to give us some with non-0 offset

