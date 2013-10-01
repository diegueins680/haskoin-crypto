module Haskoin.Crypto.Arbitrary () where

import Test.QuickCheck

import Control.Monad.Identity
import Control.Applicative ((<$>),(<*>))

import Data.Maybe

import Haskoin.Crypto.Point
import Haskoin.Crypto.Ring
import Haskoin.Crypto.ECDSA
import Haskoin.Crypto.Keys
import Haskoin.Crypto.Base58

instance RingMod n => Arbitrary (Ring n) where
    arbitrary = fromInteger <$> (arbitrary :: Gen Integer)

instance Arbitrary Point where
    arbitrary = frequency
        [ (1, return makeInfPoint)
        , (9, (flip mulPoint $ curveG) <$> (arbitrary :: Gen FieldN))
        ]

instance Arbitrary PrvKey where
    arbitrary = do
        i <- fromInteger <$> choose (1, curveN-1)
        fromJust <$> elements [makePrvKey i, makePrvKeyU i]

instance Arbitrary PubKey where
    arbitrary = derivePubKey <$> arbitrary

instance Arbitrary Address where
    arbitrary = do
        i <- choose (1,2^160-1) :: Gen Integer
        elements [ PubKeyAddress $ fromInteger i
                 , ScriptAddress $ fromInteger i
                 ]

instance Arbitrary Signature where
    arbitrary = do
        msg <- arbitrary
        prv <- runPrvKey <$> (arbitrary :: Gen PrvKey)
        non <- runPrvKey <$> (arbitrary :: Gen PrvKey)
        let pub  = mulPoint non curveG
        case unsafeSignMsg msg prv (non,pub) of
            (Just sig) -> return sig
            Nothing    -> arbitrary 

