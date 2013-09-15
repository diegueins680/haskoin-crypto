module Units (tests) where

import Test.HUnit
import Test.Framework
import Test.Framework.Providers.HUnit

import Control.Monad (replicateM_)
import Control.Monad.Trans (liftIO)

import Data.Maybe
import qualified Data.ByteString as BS

import Haskoin.Crypto.Keys
import Haskoin.Crypto.Ring
import Haskoin.Crypto.Point
import Haskoin.Crypto.ECDSA
import Haskoin.Crypto.Hash
import Haskoin.Crypto.Base58
import Haskoin.Util

-- Unit tests copied from bitcoind implementation
-- https://github.com/bitcoin/bitcoin/blob/master/src/test/key_tests.cpp

strSecret1  = stringToBS "5HxWvvfubhXpYYpS3tJkw6fq9jE9j18THftkZjHHfmFiWtmAbrj"
strSecret2  = stringToBS "5KC4ejrDjv152FGwP386VD1i2NYc5KkfSMyv1nGy1VGDxGHqVY3"
strSecret1C = stringToBS "Kwr371tjA9u2rFSMZjTNun2PXXP3WPZu2afRHTcta6KxEUdm1vEw"
strSecret2C = stringToBS "L3Hq7a8FEQwJkW1M2GNKDW28546Vp5miewcCzSqUD9kCAXrJdS3g"

addr1  = stringToBS "1QFqqMUD55ZV3PJEJZtaKCsQmjLT6JkjvJ"
addr2  = stringToBS "1F5y5E5FMc5YzdJtB9hLaUe43GDxEKXENJ"
addr1C = stringToBS "1NoJrossxPBKfCHuJXT4HadJrXRE9Fxiqs"
addr2C = stringToBS "1CRj2HyM1CXWzHAXLQtiGLyggNT9WQqsDs"

strAddressBad = stringToBS "1HV9Lc3sNHZxwj4Zk6fB38tEmBryq2cBiF"

sigMsg = [("Very secret message " ++ (show i) ++ ": 11") | i <- [0..15]]

sec1  = fromJust $ fromWIF strSecret1
sec2  = fromJust $ fromWIF strSecret2
sec1C = fromJust $ fromWIF strSecret1C
sec2C = fromJust $ fromWIF strSecret2C
pub1  = derivePubKey sec1
pub2  = derivePubKey sec2
pub1C = derivePubKey sec1C
pub2C = derivePubKey sec2C

tests =
    [ testGroup "ECDSA PRNG unit tests"
        [ testCase "signMsg produces unique sigantures" uniqueSigs
        , testCase "genPrvKey produces unique keys" uniqueKeys
        ] 
    , testGroup "bitcoind /src/test/key_tests.cpp" $
        [ testCase "Decode Valid WIF" checkPrivkey
        , testCase "Decode Invalid WIF" checkInvalidKey
        , testCase "Check private key compression" checkPrvKeyCompressed
        , testCase "Check public key compression" checkKeyCompressed
        , testCase "Check matching address" checkMatchingAddress
        ] ++ 
        ( map (\x -> (testCase ("Check sig: " ++ (show x)) 
                (checkSignatures $ doubleHash256 $ stringToBS x))) sigMsg )
    ]

uniqueSigs :: Assertion
uniqueSigs = do
    let msg = hash256 $ BS.pack [0..19]
        prv = fromJust $ makePrvKey 0x987654321
    ((r1,s1),(r2,s2),(r3,s3)) <- liftIO $ withSource devURandom $ do
        (Signature a b) <- signMsg msg prv
        (Signature c d) <- signMsg msg prv
        replicateM_ 20 $ signMsg msg prv
        (Signature e f) <- signMsg msg prv
        return $ ((a,b),(c,d),(e,f))
    assertBool "DiffSig" $ 
        r1 /= r2 && r1 /= r3 && r2 /= r3 &&
        s1 /= s2 && s1 /= s3 && s2 /= s3

uniqueKeys :: Assertion
uniqueKeys = do
    (k1,k2,k3) <- liftIO $ withSource devURandom $ do
        a <- genPrvKey
        b <- genPrvKey
        replicateM_ 20 genPrvKey
        c <- genPrvKey
        return (a,b,c)
    assertBool "DiffKey" $ k1 /= k2 && k1 /= k3 && k2 /= k3

checkPrivkey = do
    assertBool "Key 1"  $ isJust $ fromWIF strSecret1
    assertBool "Key 2"  $ isJust $ fromWIF strSecret2
    assertBool "Key 1C" $ isJust $ fromWIF strSecret1C
    assertBool "Key 2C" $ isJust $ fromWIF strSecret2C

checkInvalidKey = 
    assertBool "Bad key" $ isNothing $ fromWIF strAddressBad

checkPrvKeyCompressed = do
    assertBool "Key 1"  $ isPrvKeyU sec1
    assertBool "Key 2"  $ isPrvKeyU sec2
    assertBool "Key 1C" $ not $ isPrvKeyU sec1C
    assertBool "Key 2C" $ not $ isPrvKeyU sec2C

checkKeyCompressed = do
    assertBool "Key 1"  $ isPubKeyU pub1
    assertBool "Key 2"  $ isPubKeyU pub2
    assertBool "Key 1C" $ not $ isPubKeyU pub1C
    assertBool "Key 2C" $ not $ isPubKeyU pub2C

checkMatchingAddress = do
    assertBool "Key 1"  $ addr1  == (addrToBase58 $ pubKeyAddr pub1)
    assertBool "Key 2"  $ addr2  == (addrToBase58 $ pubKeyAddr pub2)
    assertBool "Key 1C" $ addr1C == (addrToBase58 $ pubKeyAddr pub1C)
    assertBool "Key 2C" $ addr2C == (addrToBase58 $ pubKeyAddr pub2C)
    
checkSignatures h = do
    (sign1, sign2, sign1C, sign2C) <- liftIO $ withSource devURandom $ do
        a <- signMsg h sec1
        b <- signMsg h sec2
        c <- signMsg h sec1C
        d <- signMsg h sec2C
        return (a,b,c,d)
    assertBool "Key 1, Sign1"   $ verifySig h sign1 pub1
    assertBool "Key 1, Sign2"   $ not $ verifySig h sign2 pub1
    assertBool "Key 1, Sign1C"  $ verifySig h sign1C pub1
    assertBool "Key 1, Sign2C"  $ not $ verifySig h sign2C pub1
    assertBool "Key 2, Sign1"   $ not $ verifySig h sign1 pub2
    assertBool "Key 2, Sign2"   $ verifySig h sign2 pub2
    assertBool "Key 2, Sign1C"  $ not $ verifySig h sign1C pub2
    assertBool "Key 2, Sign2C"  $ verifySig h sign2C pub2
    assertBool "Key 1C, Sign1"  $ verifySig h sign1 pub1C
    assertBool "Key 1C, Sign2"  $ not $ verifySig h sign2 pub1C
    assertBool "Key 1C, Sign1C" $ verifySig h sign1C pub1C
    assertBool "Key 1C, Sign2C" $ not $ verifySig h sign2C pub1C
    assertBool "Key 2C, Sign1"  $ not $ verifySig h sign1 pub2C
    assertBool "Key 2C, Sign2"  $ verifySig h sign2 pub2C
    assertBool "Key 2C, Sign1C" $ not $ verifySig h sign1C pub2C
    assertBool "Key 2C, Sign2C" $ verifySig h sign2C pub2C


