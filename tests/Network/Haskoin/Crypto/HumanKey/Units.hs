module Network.Haskoin.Crypto.HumanKey.Units (tests) where

import qualified Data.ByteString.Lazy.Char8 as C
import Data.Binary

import Test.HUnit ((@=?))
import Test.Framework (Test, testGroup)
import Test.Framework.Providers.HUnit (testCase)

import Data.Maybe

import Network.Haskoin.Crypto.HumanKey
import Network.Haskoin.Util

tests :: [Test]
tests =
    [ testGroup "RFC-1751 unit tests"
        [ testGroup "Encode keys in RFC-1751"
            . map encodeTest  $ zip [1..] vectors
        , testGroup "Decode keys in RFC-1751"
            . map decodeTest  $ zip [1..] vectors
        , testGroup "Encode keys in RFC-1751 (lowercase)"
            . map encodeTest  $ zip [1..] vectorsLc
        , testGroup "Decode keys in RFC-1751 (lowercase)"
            . map decodeTest  $ zip [1..] vectorsLc
        , testGroup "Bad checksums"
            . map badChecksum $ zip [1..] badChecksumVectors
        , testGroup "Bad checksums (lowercase)"
            . map badChecksum $ zip [1..] badChecksumVectorsLc
        , testGroup "Not in dictionary"
            . map notDict $ zip [1..] notDictVectors
        , testGroup "Not in dictionary (lowercase)"
            . map notDict $ zip [1..] notDictVectorsLc
        ]
    ]

type TestVector = (C.ByteString, HumanKey)

badChecksumVectors :: [String]
badChecksumVectors =
    [ "RASH BUSH MILK LOOK BAD A AVID GAFF BAIT ROT POD LOVE"
    , "TAB BORE DUNK SURE COVE NORM PRY IF JOE MYRA GWEN TENT"
    , "BORN ROLL LOVE BEAR AGEE IFFY CUTS MASK MOOD FOWL ROME MIT"
    ]

badChecksumVectorsLc :: [String]
badChecksumVectorsLc =
    [ "rash bush milk look bad a avid gaff bait rot pod love"
    , "tab bore dunk sure cove norm pry if joe myra gwen tent"
    , "born roll love bear agee iffy cuts mask mood fowl rome mit"
    ]

badChecksum :: (Int, String) -> Test
badChecksum (i, s) = testCase ("Bad checksum #" ++ show i)
                              (Left "Checksum failed." @=? humanKey s)

notDictVectors :: [String]
notDictVectors =
    [ "PHON MEMO HOP NELL RET DEAF HURT YAWN FLAG MILE LEO LESK"
    , "JAG SUCH PER HASH FULL PHON DAN THEY CAIN BOND LEFT COCA"
    , "TENT TIER LIEU ROD URGE BOWL PATK HOOK FLEW ELY MAN OAK"
    , "TIE OLDY FEEL DOCK EWE PA EMIT HAVE HIS TOTE SWAN KTUH"
    ]

notDictVectorsLc :: [String]
notDictVectorsLc =
    [ "phon memo hop nell ret deaf hurt yawn flag mile leo lesk"
    , "jag such per hash full phon dan they cain bond left coca"
    , "tent tier lieu rod urge bowl patk hook flew ely man oak"
    , "tie oldy feel dock ewe pa emit have his tote swan ktuh"
    ]

notDict :: (Int, String) -> Test
notDict (i, s) = testCase ("Not in dictionary #" ++ show i)
                          (Left "Unknown word." @=? humanKey s)

hex2lbs :: String -> C.ByteString
hex2lbs = toLazyBS . fromJust . hexToBS . filter (/=' ')

vectors :: [TestVector]
vectors =
  [ ( hex2lbs "CCAC 2AED 5910 56BE 4F90 FD44 1C53 4766"
    , fromRight $
      humanKey "RASH BUSH MILK LOOK BAD BRIM AVID GAFF BAIT ROT POD LOVE"
    )
  , ( hex2lbs "EFF8 1F9B FBC6 5350 920C DD74 16DE 8009"
    , fromRight $
      humanKey "TROD MUTE TAIL WARM CHAR KONG HAAG CITY BORE O TEAL AWL"
    )
  ]

vectorsLc :: [TestVector]
vectorsLc =
  [ ( hex2lbs "ccac 2aed 5910 56be 4f90 fd44 1c53 4766"
    , fromRight $
      humanKey "rash bush milk look bad brim avid gaff bait rot pod love"
    )
  , ( hex2lbs "eff8 1f9b fbc6 5350 920c dd74 16de 8009"
    , fromRight $
      humanKey "trod mute tail warm char kong haag city bore o teal awl"
    )
  ]

encodeTest :: (Int, TestVector) -> Test
encodeTest (i, (bs, hk)) = testCase ("Encode #" ++ show i) (bs @=? encode hk)

decodeTest :: (Int, TestVector) -> Test
decodeTest (i, (bs, hk)) = testCase ("Decode #" ++ show i) (hk @=? decode bs)
