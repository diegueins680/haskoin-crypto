{-# LANGUAGE BangPatterns #-}
module Main where

import Control.Monad
import Control.Applicative

import System.Random

import Data.Maybe
import Data.Time.Clock

import Network.Haskoin.Crypto.ECDSA
import Network.Haskoin.Crypto.Keys
import Network.Haskoin.Crypto.Point
import Network.Haskoin.Crypto.Ring
import Network.Haskoin.Crypto.Curve


bench :: Int -> String -> IO a -> IO a
bench n s f = do
    start <- getCurrentTime
    !r <- f
    end <- getCurrentTime
    let t = (diffUTCTime end start)
    putStrLn $ "----------------------------"
    putStrLn $ s ++ " (" ++ (show n) ++ " samples)"
    putStrLn $ "Total time: " ++ (show t)
    putStrLn $ "Op/sec    : " ++ (show $ (fromIntegral n)/t)
    seq r $ return r

main :: IO ()
main = do

    _ <- bench (10^(7 :: Int)) "Ring multiplication (mod n)" 
        (return $ testRing $ 10^(7 :: Int))
        
    _ <- bench (10^(5 :: Int)) "Ring inversion (mod n)" 
        (return $ invRing $ 10^(5 :: Int))

    let elems = 2000
        msg   = fromInteger $ curveN - 10

    !priv <- replicateM elems $
                (fromJust . makePrvKey) <$> 
                getStdRandom (randomR (1, curveN))

    !pub <- bench elems "Point multiplications" $ forM priv $ \x -> 
        return $! derivePubKey x

    _ <- bench 100000 "Point additions" $ 
        forM (take 100000 $ cycle pub) $ \x -> do
            let !a = runPubKey x
            return $! addPoint a a

    _ <- bench 100000 "Point doubling" $ 
        forM (take 100000 $ cycle pub) $ \x -> do
            let !a = runPubKey x
            return $! doublePoint a

    _ <- bench elems "Shamirs trick" $ 
        forM (priv `zip` pub) $ \(d,q) -> do
            let !a = runPrvKey d
                !b = runPubKey q
            return $! shamirsTrick a b a b

    !sigs <- bench elems "Signature creations" $ 
        withSource devURandom $! forM priv (signMsg msg) 
        
    _ <- bench elems "Signature verifications" $ 
        forM (sigs `zip` pub) $ \(s,q) -> 
            return $! verifySig msg s q

    return ()

testRing :: Int -> FieldN
testRing maxVal = go 2 0
  where 
    go i n
        | n < maxVal = go (i*i) (n + 1)
        | otherwise = i

invRing :: Int -> FieldN
invRing maxVal = go 1 0
  where 
    go i n
        | n < maxVal = go ((inverseN i) + 1) (n + 1)
        | otherwise = i

