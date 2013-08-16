module Haskoin.Crypto.Point
( Point( InfPoint )
, makePoint
, makeInfPoint
, getAffine, getX, getY
, validatePoint
, isInfPoint
, addPoint
, doublePoint
, mulPoint
, shamirsTrick
, curveB
) where

import Data.Maybe (isJust, fromJust)

import Data.Bits (testBit, shiftR, bitSize)
import Control.Applicative ((<$>), (<*>))
import Control.Monad (unless, when)

import Haskoin.Crypto.Ring (FieldP, FieldN, quadraticResidue)

curveB :: FieldP
curveB = fromInteger 0x07

{- 
    Elliptic curves of the form y^2 = x^3 + 7 (mod p)
    Point on the elliptic curve in transformed Jacobian coordinates 
    (X,Y,Z) such that (x,y) = (X/Z^2, Y/Z^3)
    InfPoint is the point at infinity
-}

data Point = Point FieldP FieldP FieldP | InfPoint
    deriving Show

instance Eq Point where
    InfPoint         == InfPoint         = True
    (Point x1 y1 z1) == (Point x2 y2 z2) = a == b && c == d
        where a = x1*z2 ^ (2 :: Integer)
              b = x2*z1 ^ (2 :: Integer)
              c = y1*z2 ^ (3 :: Integer)
              d = y2*z1 ^ (3 :: Integer)
    _                == _                = False

-- Create a new point from (x,y) coordinates.
-- Returns Nothing if the point doesn't lie on the curve
makePoint :: FieldP -> FieldP -> Maybe Point
makePoint x y
    | validatePoint point = Just point
    | otherwise = Nothing
    where point = Point x y 1

makeInfPoint :: Point
makeInfPoint = InfPoint

-- Get the original (x,y) coordinates from the Jacobian triple (X,Y,Z)
getAffine :: Point -> Maybe (FieldP, FieldP)
getAffine point = case point of
    InfPoint      -> Nothing
    (Point _ _ 0) -> Nothing
    (Point x y z) -> Just (x/z ^ (2 :: Integer), y/z ^ (3 :: Integer))

getX :: Point -> Maybe FieldP
getX point = fst <$> (getAffine point)

getY :: Point -> Maybe FieldP
getY point = snd <$> (getAffine point)

-- Section 3.2.2.1 http://www.secg.org/download/aid-780/sec1-v2.pdf
-- point 3.2.2.1.4 is not necessary as h=1
validatePoint :: Point -> Bool
validatePoint point = case getAffine point of
    -- 3.2.2.1.1 (check that point not equal to InfPoint)
    Nothing    -> False 
    -- 3.2.2.1.2 (check that the point lies on the curve)
    Just (x,y) -> y ^ (2 :: Integer) == x ^ (3 :: Integer) + curveB

isInfPoint :: Point -> Bool
isInfPoint InfPoint      = True
isInfPoint (Point _ _ 0) = True
isInfPoint _             = False

-- Elliptic curve point addition
addPoint :: Point -> Point -> Point
addPoint InfPoint point = point
addPoint point InfPoint = point
addPoint p1@(Point x1 y1 z1) (Point x2 y2 z2)
    | u1 == u2 = if s1 == s2 then doublePoint p1 else InfPoint
    | otherwise = Point x3 y3 z3
    where u1 = x1*z2 ^ (2 :: Integer)
          u2 = x2*z1 ^ (2 :: Integer)
          s1 = y1*z2 ^ (3 :: Integer)
          s2 = y2*z1 ^ (3 :: Integer)
          h  = u2 - u1
          r  = s2 - s1
          x3 = r ^ (2 :: Integer) - h ^ (3 :: Integer) - 2*u1*h ^ (2 :: Integer) 
          y3 = r*(u1 * h ^ (2 :: Integer) - x3) - s1 * h ^ (3 :: Integer)
          z3 = h * z1 * z2

-- Elliptic curve point doubling 
doublePoint :: Point -> Point
doublePoint InfPoint = InfPoint
doublePoint (Point x y z)
    | y == 0 = InfPoint
    | otherwise = Point x' y' z'
    where s  = 4*x*y ^ (2 :: Integer)
          m  = 3*x ^ (2 :: Integer) 
          x' = m ^ (2 :: Integer) - 2*s
          y' = m*(s - x') - 8*y ^ (4 :: Integer)
          z' = 2*y*z

-- Elliptic curve point multiplication using Montgomery ladder
-- Todo: Check if Haskell lazy evaluation opens up side channel attacks
mulPoint :: FieldN -> Point -> Point
mulPoint 0 _        = InfPoint
mulPoint 1 p        = p
mulPoint _ InfPoint = InfPoint
mulPoint n p = go InfPoint p ((bitSize n) - 1)
    where go r0 r1 i
            | i < 0       = r0
            | testBit n i = go (addPoint r0 r1) (doublePoint r1) (i - 1)
            | otherwise   = go (doublePoint r0) (addPoint r0 r1) (i - 1)

-- Efficiently compute n1*p1 + n2*p2
shamirsTrick :: FieldN -> Point -> FieldN -> Point -> Point
shamirsTrick r1 p1 r2 p2 = go r1 r2
    where q      = addPoint p1 p2
          go 0 0 = InfPoint
          go a b | ea && eb  = b2
                 | ea        = addPoint b2 p2
                 | eb        = addPoint b2 p1
                 | otherwise = addPoint b2 q
             where b2 = doublePoint $ go (a `shiftR` 1) (b `shiftR` 1)
                   ea = even a
                   eb = even b

