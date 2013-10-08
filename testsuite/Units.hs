module Units (tests) where

import Test.HUnit
import Test.Framework
import Test.Framework.Providers.HUnit

import Control.Monad (replicateM_, liftM2)
import Control.Monad.Trans (liftIO)

import Data.Maybe
import Data.Binary
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

strSecret1  = "5HxWvvfubhXpYYpS3tJkw6fq9jE9j18THftkZjHHfmFiWtmAbrj"
strSecret2  = "5KC4ejrDjv152FGwP386VD1i2NYc5KkfSMyv1nGy1VGDxGHqVY3"
strSecret1C = "Kwr371tjA9u2rFSMZjTNun2PXXP3WPZu2afRHTcta6KxEUdm1vEw"
strSecret2C = "L3Hq7a8FEQwJkW1M2GNKDW28546Vp5miewcCzSqUD9kCAXrJdS3g"

addr1  = "1QFqqMUD55ZV3PJEJZtaKCsQmjLT6JkjvJ"
addr2  = "1F5y5E5FMc5YzdJtB9hLaUe43GDxEKXENJ"
addr1C = "1NoJrossxPBKfCHuJXT4HadJrXRE9Fxiqs"
addr2C = "1CRj2HyM1CXWzHAXLQtiGLyggNT9WQqsDs"

strAddressBad = "1HV9Lc3sNHZxwj4Zk6fB38tEmBryq2cBiF"

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
    , testGroup "Trezor RFC 6979 Test Vectors"
        [ testCase "RFC 6979 Test Vector 1" (testDetSigning $ detVec !! 0)
        , testCase "RFC 6979 Test Vector 2" (testDetSigning $ detVec !! 1)
        , testCase "RFC 6979 Test Vector 3" (testDetSigning $ detVec !! 2)
        , testCase "RFC 6979 Test Vector 4" (testDetSigning $ detVec !! 3)
        , testCase "RFC 6979 Test Vector 5" (testDetSigning $ detVec !! 4)
        ] 
    ]

{- ECDSA PRNG unit tests -}

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

{- bitcoind /src/test/key_tests.cpp -}

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


{- Trezor RFC 6979 Test Vectors -}
-- github.com/trezor/python-ecdsa/blob/master/ecdsa/test_pyecdsa.py

detVec :: [(Integer,String,String)]
detVec = 
    [ 
      ( 0x1
      , "Satoshi Nakamoto"
      , "934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d82442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5"
      )
    , ( 0x1
      , "All those moments will be lost in time, like tears in rain. Time to die..."
      , "8600dbd41e348fe5c9465ab92d23e3db8b98b873beecd930736488696438cb6b547fe64427496db33bf66019dacbf0039c04199abb0122918601db38a72cfc21"
      )
    , ( 0Xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140
      , "Satoshi Nakamoto"
      , "fd567d121db66e382991534ada77a6bd3106f0a1098c231e47993447cd6af2d06b39cd0eb1bc8603e159ef5c20a5c8ad685a45b06ce9bebed3f153d10d93bed5"
      )
    , ( 0xf8b8af8ce3c7cca5e300d33939540c10d45ce001b8f252bfbc57ba0342904181
      , "Alan Turing"
      , "7063ae83e7f62bbb171798131b4a0564b956930092b33b07b395615d9ec7e15c58dfcc1e00a35e1572f366ffe34ba0fc47db1e7189759b9fb233c5b05ab388ea"
      )
    , ( 0xe91671c46231f833a6406ccbea0e3e392c76c167bac1cb013f6f1013980455c2
      , "There is a computer disease that anybody who works with computers knows about. It's a very serious disease and it interferes completely with the work. The trouble with computers is that you 'play' with them!"
      , "b552edd27580141f3b2a5463048cb7cd3e047b97c9f98076c32dbdf85a68718b279fa72dd19bfae05577e06c7c0c1900c371fcd5893f7e1d56a37d30174671f6"
      )
    ]

testDetSigning (prv,msg,bs) = do
    assertBool "RFC 6979 Vector" $ res == (fromJust $ hexToBS $ stringToBS bs)
    where (Signature r s) = detSignMsg msg' prv'
          msg' = hash256 $ stringToBS msg
          prv' = fromJust $ makePrvKey prv
          res = runPut' $ put (fromIntegral r :: Hash256) >> 
                          put (fromIntegral s :: Hash256)


