module Haskoin.Crypto.Arbitrary 
( genPrvKeyC
, genPrvKeyU
)  where

import Test.QuickCheck
import Haskoin.Util.Arbitrary

import Control.Monad.Identity
import Control.Applicative ((<$>),(<*>))

import Data.Maybe

import Haskoin.Crypto.Point
import Haskoin.Crypto.Hash
import Haskoin.Crypto.Ring
import Haskoin.Crypto.ECDSA
import Haskoin.Crypto.Keys
import Haskoin.Crypto.Base58
import Haskoin.Crypto.Curve

instance RingMod n => Arbitrary (Ring n) where
    arbitrary = fromInteger <$> arbitrary

instance Arbitrary CheckSum32 where
    arbitrary = chksum32 <$> arbitrary

instance Arbitrary Point where
    arbitrary = frequency
        [ (1, return makeInfPoint)
        , (9, (flip mulPoint $ curveG) <$> (arbitrary :: Gen FieldN))
        ]

genPrvKeyC :: Gen PrvKey
genPrvKeyC = do
    i <- fromInteger <$> choose (1, curveN-1)
    return $ fromJust $ makePrvKey i

genPrvKeyU :: Gen PrvKey
genPrvKeyU = do
    i <- fromInteger <$> choose (1, curveN-1)
    return $ fromJust $ makePrvKeyU i

instance Arbitrary PrvKey where
    arbitrary = oneof [genPrvKeyC, genPrvKeyU]

instance Arbitrary PubKey where
    arbitrary = derivePubKey <$> arbitrary

instance Arbitrary Address where
    arbitrary = do
        i <- fromInteger <$> choose (1,2^160-1)
        elements [ PubKeyAddress i
                 , ScriptAddress i
                 , TestPubKeyAddress i
                 , TestScriptAddress i
                 ]

instance Arbitrary Signature where
    arbitrary = do
        msg <- arbitrary
        prv <- runPrvKey <$> arbitrary
        non <- runPrvKey <$> arbitrary
        let pub  = mulPoint non curveG
        case unsafeSignMsg msg prv (non,pub) of
            (Just sig) -> return sig
            Nothing    -> arbitrary 

