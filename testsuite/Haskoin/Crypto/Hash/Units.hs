module Haskoin.Crypto.Hash.Units (tests) where

import Test.HUnit
import Test.Framework
import Test.Framework.Providers.HUnit

import Data.Maybe
import Data.List
import qualified Data.ByteString as BS

import Haskoin.Crypto.Hash
import Haskoin.Util

-- Test vectors from NIST
-- http://csrc.nist.gov/groups/STM/cavp/documents/drbg/drbgtestvectors.zip
-- About 1/3 of HMAC DRBG SHA-256 test vectors are tested here

tests =
    [ testGroup "HMAC DRBG Suite 1" 
        [ testCase "HMAC DRBG Vector 0"  (testDRBG (t1 !! 0))
        , testCase "HMAC DRBG Vector 1"  (testDRBG (t1 !! 1))
        , testCase "HMAC DRBG Vector 2"  (testDRBG (t1 !! 2))
        , testCase "HMAC DRBG Vector 3"  (testDRBG (t1 !! 3))
        , testCase "HMAC DRBG Vector 4"  (testDRBG (t1 !! 4))
        , testCase "HMAC DRBG Vector 5"  (testDRBG (t1 !! 5))
        , testCase "HMAC DRBG Vector 6"  (testDRBG (t1 !! 6))
        , testCase "HMAC DRBG Vector 7"  (testDRBG (t1 !! 7))
        , testCase "HMAC DRBG Vector 8"  (testDRBG (t1 !! 8))
        , testCase "HMAC DRBG Vector 9"  (testDRBG (t1 !! 9))
        , testCase "HMAC DRBG Vector 10" (testDRBG (t1 !! 10))
        , testCase "HMAC DRBG Vector 11" (testDRBG (t1 !! 11))
        , testCase "HMAC DRBG Vector 12" (testDRBG (t1 !! 12))
        , testCase "HMAC DRBG Vector 13" (testDRBG (t1 !! 13))
        , testCase "HMAC DRBG Vector 14" (testDRBG (t1 !! 14))
        ] 
    , testGroup "HMAC DRBG Suite 2" 
        [ testCase "HMAC DRBG Vector 0"  (testDRBG (t2 !! 0))
        , testCase "HMAC DRBG Vector 1"  (testDRBG (t2 !! 1))
        , testCase "HMAC DRBG Vector 2"  (testDRBG (t2 !! 2))
        , testCase "HMAC DRBG Vector 3"  (testDRBG (t2 !! 3))
        , testCase "HMAC DRBG Vector 4"  (testDRBG (t2 !! 4))
        , testCase "HMAC DRBG Vector 5"  (testDRBG (t2 !! 5))
        , testCase "HMAC DRBG Vector 6"  (testDRBG (t2 !! 6))
        , testCase "HMAC DRBG Vector 7"  (testDRBG (t2 !! 7))
        , testCase "HMAC DRBG Vector 8"  (testDRBG (t2 !! 8))
        , testCase "HMAC DRBG Vector 9"  (testDRBG (t2 !! 9))
        , testCase "HMAC DRBG Vector 10" (testDRBG (t2 !! 10))
        , testCase "HMAC DRBG Vector 11" (testDRBG (t2 !! 11))
        , testCase "HMAC DRBG Vector 12" (testDRBG (t2 !! 12))
        , testCase "HMAC DRBG Vector 13" (testDRBG (t2 !! 13))
        , testCase "HMAC DRBG Vector 14" (testDRBG (t2 !! 14))
        ] 
    , testGroup "HMAC DRBG Suite 3" 
        [ testCase "HMAC DRBG Vector 0"  (testDRBG (t3 !! 0))
        , testCase "HMAC DRBG Vector 1"  (testDRBG (t3 !! 1))
        , testCase "HMAC DRBG Vector 2"  (testDRBG (t3 !! 2))
        , testCase "HMAC DRBG Vector 3"  (testDRBG (t3 !! 3))
        , testCase "HMAC DRBG Vector 4"  (testDRBG (t3 !! 4))
        , testCase "HMAC DRBG Vector 5"  (testDRBG (t3 !! 5))
        , testCase "HMAC DRBG Vector 6"  (testDRBG (t3 !! 6))
        , testCase "HMAC DRBG Vector 7"  (testDRBG (t3 !! 7))
        , testCase "HMAC DRBG Vector 8"  (testDRBG (t3 !! 8))
        , testCase "HMAC DRBG Vector 9"  (testDRBG (t3 !! 9))
        , testCase "HMAC DRBG Vector 10" (testDRBG (t3 !! 10))
        , testCase "HMAC DRBG Vector 11" (testDRBG (t3 !! 11))
        , testCase "HMAC DRBG Vector 12" (testDRBG (t3 !! 12))
        , testCase "HMAC DRBG Vector 13" (testDRBG (t3 !! 13))
        , testCase "HMAC DRBG Vector 14" (testDRBG (t3 !! 14))
        ] 
    , testGroup "HMAC DRBG Suite 4" 
        [ testCase "HMAC DRBG Vector 0"  (testDRBG (t4 !! 0))
        , testCase "HMAC DRBG Vector 1"  (testDRBG (t4 !! 1))
        , testCase "HMAC DRBG Vector 2"  (testDRBG (t4 !! 2))
        , testCase "HMAC DRBG Vector 3"  (testDRBG (t4 !! 3))
        , testCase "HMAC DRBG Vector 4"  (testDRBG (t4 !! 4))
        , testCase "HMAC DRBG Vector 5"  (testDRBG (t4 !! 5))
        , testCase "HMAC DRBG Vector 6"  (testDRBG (t4 !! 6))
        , testCase "HMAC DRBG Vector 7"  (testDRBG (t4 !! 7))
        , testCase "HMAC DRBG Vector 8"  (testDRBG (t4 !! 8))
        , testCase "HMAC DRBG Vector 9"  (testDRBG (t4 !! 9))
        , testCase "HMAC DRBG Vector 10" (testDRBG (t4 !! 10))
        , testCase "HMAC DRBG Vector 11" (testDRBG (t4 !! 11))
        , testCase "HMAC DRBG Vector 12" (testDRBG (t4 !! 12))
        , testCase "HMAC DRBG Vector 13" (testDRBG (t4 !! 13))
        , testCase "HMAC DRBG Vector 14" (testDRBG (t4 !! 14))
        ] 
    , testGroup "HMAC DRBG Suite 5 (Reseed)" 
        [ testCase "HMAC DRBG Vector 0"  (testDRBGRsd (r1 !! 0))
        , testCase "HMAC DRBG Vector 1"  (testDRBGRsd (r1 !! 1))
        , testCase "HMAC DRBG Vector 2"  (testDRBGRsd (r1 !! 2))
        , testCase "HMAC DRBG Vector 3"  (testDRBGRsd (r1 !! 3))
        , testCase "HMAC DRBG Vector 4"  (testDRBGRsd (r1 !! 4))
        , testCase "HMAC DRBG Vector 5"  (testDRBGRsd (r1 !! 5))
        , testCase "HMAC DRBG Vector 6"  (testDRBGRsd (r1 !! 6))
        , testCase "HMAC DRBG Vector 7"  (testDRBGRsd (r1 !! 7))
        , testCase "HMAC DRBG Vector 8"  (testDRBGRsd (r1 !! 8))
        , testCase "HMAC DRBG Vector 9"  (testDRBGRsd (r1 !! 9))
        , testCase "HMAC DRBG Vector 10" (testDRBGRsd (r1 !! 10))
        , testCase "HMAC DRBG Vector 11" (testDRBGRsd (r1 !! 11))
        , testCase "HMAC DRBG Vector 12" (testDRBGRsd (r1 !! 12))
        , testCase "HMAC DRBG Vector 13" (testDRBGRsd (r1 !! 13))
        , testCase "HMAC DRBG Vector 14" (testDRBGRsd (r1 !! 14))
        ] 
    , testGroup "HMAC DRBG Suite 6 (Reseed)" 
        [ testCase "HMAC DRBG Vector 0"  (testDRBGRsd (r2 !! 0))
        , testCase "HMAC DRBG Vector 1"  (testDRBGRsd (r2 !! 1))
        , testCase "HMAC DRBG Vector 2"  (testDRBGRsd (r2 !! 2))
        , testCase "HMAC DRBG Vector 3"  (testDRBGRsd (r2 !! 3))
        , testCase "HMAC DRBG Vector 4"  (testDRBGRsd (r2 !! 4))
        , testCase "HMAC DRBG Vector 5"  (testDRBGRsd (r2 !! 5))
        , testCase "HMAC DRBG Vector 6"  (testDRBGRsd (r2 !! 6))
        , testCase "HMAC DRBG Vector 7"  (testDRBGRsd (r2 !! 7))
        , testCase "HMAC DRBG Vector 8"  (testDRBGRsd (r2 !! 8))
        , testCase "HMAC DRBG Vector 9"  (testDRBGRsd (r2 !! 9))
        , testCase "HMAC DRBG Vector 10" (testDRBGRsd (r2 !! 10))
        , testCase "HMAC DRBG Vector 11" (testDRBGRsd (r2 !! 11))
        , testCase "HMAC DRBG Vector 12" (testDRBGRsd (r2 !! 12))
        , testCase "HMAC DRBG Vector 13" (testDRBGRsd (r2 !! 13))
        , testCase "HMAC DRBG Vector 14" (testDRBGRsd (r2 !! 14))
        ] 
    , testGroup "HMAC DRBG Suite 7 (Reseed)" 
        [ testCase "HMAC DRBG Vector 0"  (testDRBGRsd (r3 !! 0))
        , testCase "HMAC DRBG Vector 1"  (testDRBGRsd (r3 !! 1))
        , testCase "HMAC DRBG Vector 2"  (testDRBGRsd (r3 !! 2))
        , testCase "HMAC DRBG Vector 3"  (testDRBGRsd (r3 !! 3))
        , testCase "HMAC DRBG Vector 4"  (testDRBGRsd (r3 !! 4))
        , testCase "HMAC DRBG Vector 5"  (testDRBGRsd (r3 !! 5))
        , testCase "HMAC DRBG Vector 6"  (testDRBGRsd (r3 !! 6))
        , testCase "HMAC DRBG Vector 7"  (testDRBGRsd (r3 !! 7))
        , testCase "HMAC DRBG Vector 8"  (testDRBGRsd (r3 !! 8))
        , testCase "HMAC DRBG Vector 9"  (testDRBGRsd (r3 !! 9))
        , testCase "HMAC DRBG Vector 10" (testDRBGRsd (r3 !! 10))
        , testCase "HMAC DRBG Vector 11" (testDRBGRsd (r3 !! 11))
        , testCase "HMAC DRBG Vector 12" (testDRBGRsd (r3 !! 12))
        , testCase "HMAC DRBG Vector 13" (testDRBGRsd (r3 !! 13))
        , testCase "HMAC DRBG Vector 14" (testDRBGRsd (r3 !! 14))
        ] 
    , testGroup "HMAC DRBG Suite 8 (Reseed)" 
        [ testCase "HMAC DRBG Vector 0"  (testDRBGRsd (r4 !! 0))
        , testCase "HMAC DRBG Vector 1"  (testDRBGRsd (r4 !! 1))
        , testCase "HMAC DRBG Vector 2"  (testDRBGRsd (r4 !! 2))
        , testCase "HMAC DRBG Vector 3"  (testDRBGRsd (r4 !! 3))
        , testCase "HMAC DRBG Vector 4"  (testDRBGRsd (r4 !! 4))
        , testCase "HMAC DRBG Vector 5"  (testDRBGRsd (r4 !! 5))
        , testCase "HMAC DRBG Vector 6"  (testDRBGRsd (r4 !! 6))
        , testCase "HMAC DRBG Vector 7"  (testDRBGRsd (r4 !! 7))
        , testCase "HMAC DRBG Vector 8"  (testDRBGRsd (r4 !! 8))
        , testCase "HMAC DRBG Vector 9"  (testDRBGRsd (r4 !! 9))
        , testCase "HMAC DRBG Vector 10" (testDRBGRsd (r4 !! 10))
        , testCase "HMAC DRBG Vector 11" (testDRBGRsd (r4 !! 11))
        , testCase "HMAC DRBG Vector 12" (testDRBGRsd (r4 !! 12))
        , testCase "HMAC DRBG Vector 13" (testDRBGRsd (r4 !! 13))
        , testCase "HMAC DRBG Vector 14" (testDRBGRsd (r4 !! 14))
        ] 
    ]

testDRBG :: [BS.ByteString] -> Assertion
testDRBG v = do
    let w1     = hmacDRBGNew (v !! 0) (v !! 1) (v !! 2)
        (w2,_) = hmacDRBGGen w1 128 (v !! 3)
        (_,r)  = hmacDRBGGen w2 128 (v !! 4)
    assertBool "HMAC DRBG" $ fromJust r == (v !! 5)

testDRBGRsd :: [BS.ByteString] -> Assertion
testDRBGRsd v = do
    let w1 = hmacDRBGNew (v !! 0) (v !! 1) (v !! 2)
        w2 = hmacDRBGRsd w1 (v !! 3) (v !! 4)
        (w3,_) = hmacDRBGGen w2 128 (v !! 5)
        (_,r)  = hmacDRBGGen w3 128 (v !! 6)
    assertBool "HMAC DRBG" $ fromJust r == (v !! 7)

{- 
    [SHA-256]
    [PredictionResistance = False]
    [EntropyInputLen = 256]
    [NonceLen = 128]
    [PersonalizationStringLen = 0]
    [AdditionalInputLen = 0]
    [ReturnedBitsLen = 1024]
-}

t1 :: [[BS.ByteString]]
t1 = 
    [
    -- COUNT = 0
    [ integerToBS 0xca851911349384bffe89de1cbdc46e6831e44d34a4fb935ee285dd14b71a7488
    , integerToBS 0x659ba96c601dc69fc902940805ec0ca8
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0xe528e9abf2dece54d47c7e75e5fe302149f817ea9fb4bee6f4199697d04d5b89d54fbb978a15b5c443c9ec21036d2460b6f73ebad0dc2aba6e624abf07745bc107694bb7547bb0995f70de25d6b29e2d3011bb19d27676c07162c8b5ccde0668961df86803482cb37ed6d5c0bb8d50cf1f50d476aa0458bdaba806f48be9dcb8
    ],
    -- COUNT = 1
    [ integerToBS 0x79737479ba4e7642a221fcfd1b820b134e9e3540a35bb48ffae29c20f5418ea3
    , integerToBS 0x3593259c092bef4129bc2c6c9e19f343
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0xcf5ad5984f9e43917aa9087380dac46e410ddc8a7731859c84e9d0f31bd43655b924159413e2293b17610f211e09f770f172b8fb693a35b85d3b9e5e63b1dc252ac0e115002e9bedfb4b5b6fd43f33b8e0eafb2d072e1a6fee1f159df9b51e6c8da737e60d5032dd30544ec51558c6f080bdbdab1de8a939e961e06b5f1aca37
    ],
    -- COUNT = 2
    [ integerToBS 0xb340907445b97a8b589264de4a17c0bea11bb53ad72f9f33297f05d2879d898d
    , integerToBS 0x65cb27735d83c0708f72684ea58f7ee5
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0x75183aaaf3574bc68003352ad655d0e9ce9dd17552723b47fab0e84ef903694a32987eeddbdc48efd24195dbdac8a46ba2d972f5808f23a869e71343140361f58b243e62722088fe10a98e43372d252b144e00c89c215a76a121734bdc485486f65c0b16b8963524a3a70e6f38f169c12f6cbdd169dd48fe4421a235847a23ff
    ],
    -- COUNT = 3
    [ integerToBS 0x8e159f60060a7d6a7e6fe7c9f769c30b98acb1240b25e7ee33f1da834c0858e7
    , integerToBS 0xc39d35052201bdcce4e127a04f04d644
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0x62910a77213967ea93d6457e255af51fc79d49629af2fccd81840cdfbb4910991f50a477cbd29edd8a47c4fec9d141f50dfde7c4d8fcab473eff3cc2ee9e7cc90871f180777a97841597b0dd7e779eff9784b9cc33689fd7d48c0dcd341515ac8fecf5c55a6327aea8d58f97220b7462373e84e3b7417a57e80ce946d6120db5
    ],
    -- COUNT = 4
    [ integerToBS 0x74755f196305f7fb6689b2fe6835dc1d81484fc481a6b8087f649a1952f4df6a
    , integerToBS 0xc36387a544a5f2b78007651a7b74b749
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0xb2896f3af4375dab67e8062d82c1a005ef4ed119d13a9f18371b1b873774418684805fd659bfd69964f83a5cfe08667ddad672cafd16befffa9faed49865214f703951b443e6dca22edb636f3308380144b9333de4bcb0735710e4d9266786342fc53babe7bdbe3c01a3addb7f23c63ce2834729fabbd419b47beceb4a460236
    ],
    -- COUNT = 5
    [ integerToBS 0x4b222718f56a3260b3c2625a4cf80950b7d6c1250f170bd5c28b118abdf23b2f
    , integerToBS 0x7aed52d0016fcaef0b6492bc40bbe0e9
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0xa6da029b3665cd39fd50a54c553f99fed3626f4902ffe322dc51f0670dfe8742ed48415cf04bbad5ed3b23b18b7892d170a7dcf3ef8052d5717cb0c1a8b3010d9a9ea5de70ae5356249c0e098946030c46d9d3d209864539444374d8fbcae068e1d6548fa59e6562e6b2d1acbda8da0318c23752ebc9be0c1c1c5b3cf66dd967
    ],
    -- COUNT = 6
    [ integerToBS 0xb512633f27fb182a076917e39888ba3ff35d23c3742eb8f3c635a044163768e0
    , integerToBS 0xe2c39b84629a3de5c301db5643af1c21
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0xfb931d0d0194a97b48d5d4c231fdad5c61aedf1c3a55ac24983ecbf38487b1c93396c6b86ff3920cfa8c77e0146de835ea5809676e702dee6a78100da9aa43d8ec0bf5720befa71f82193205ac2ea403e8d7e0e6270b366dc4200be26afd9f63b7e79286a35c688c57cbff55ac747d4c28bb80a2b2097b3b62ea439950d75dff
    ],
    -- COUNT = 7
    [ integerToBS 0xaae3ffc8605a975befefcea0a7a286642bc3b95fb37bd0eb0585a4cabf8b3d1e
    , integerToBS 0x9504c3c0c4310c1c0746a036c91d9034
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0x2819bd3b0d216dad59ddd6c354c4518153a2b04374b07c49e64a8e4d055575dfbc9a8fcde68bd257ff1ba5c6000564b46d6dd7ecd9c5d684fd757df62d85211575d3562d7814008ab5c8bc00e7b5a649eae2318665b55d762de36eba00c2906c0e0ec8706edb493e51ca5eb4b9f015dc932f262f52a86b11c41e9a6d5b3bd431
    ],
    -- COUNT = 8
    [ integerToBS 0xb9475210b79b87180e746df704b3cbc7bf8424750e416a7fbb5ce3ef25a82cc6
    , integerToBS 0x24baf03599c10df6ef44065d715a93f7
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0xae12d784f796183c50db5a1a283aa35ed9a2b685dacea97c596ff8c294906d1b1305ba1f80254eb062b874a8dfffa3378c809ab2869aa51a4e6a489692284a25038908a347342175c38401193b8afc498077e10522bec5c70882b7f760ea5946870bd9fc72961eedbe8bff4fd58c7cc1589bb4f369ed0d3bf26c5bbc62e0b2b2
    ],
    -- COUNT = 9
    [ integerToBS 0x27838eb44ceccb4e36210703ebf38f659bc39dd3277cd76b7a9bcd6bc964b628
    , integerToBS 0x39cfe0210db2e7b0eb52a387476e7ea1
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0xe5e72a53605d2aaa67832f97536445ab774dd9bff7f13a0d11fd27bf6593bfb52309f2d4f09d147192199ea584503181de87002f4ee085c7dc18bf32ce5315647a3708e6f404d6588c92b2dda599c131aa350d18c747b33dc8eda15cf40e95263d1231e1b4b68f8d829f86054d49cfdb1b8d96ab0465110569c8583a424a099a
    ],
    -- COUNT = 10
    [ integerToBS 0xd7129e4f47008ad60c9b5d081ff4ca8eb821a6e4deb91608bf4e2647835373a5
    , integerToBS 0xa72882773f78c2fc4878295840a53012
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0x0cbf48585c5de9183b7ff76557f8fc9ebcfdfde07e588a8641156f61b7952725bbee954f87e9b937513b16bba0f2e523d095114658e00f0f3772175acfcb3240a01de631c19c5a834c94cc58d04a6837f0d2782fa53d2f9f65178ee9c837222494c799e64c60406069bd319549b889fa00a0032dd7ba5b1cc9edbf58de82bfcd
    ],
    -- COUNT = 11
    [ integerToBS 0x67fe5e300c513371976c80de4b20d4473889c9f1214bce718bc32d1da3ab7532
    , integerToBS 0xe256d88497738a33923aa003a8d7845c
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0xb44660d64ef7bcebc7a1ab71f8407a02285c7592d755ae6766059e894f694373ed9c776c0cfc8594413eefb400ed427e158d687e28da3ecc205e0f7370fb089676bbb0fa591ec8d916c3d5f18a3eb4a417120705f3e2198154cd60648dbfcfc901242e15711cacd501b2c2826abe870ba32da785ed6f1fdc68f203d1ab43a64f
    ],
    -- COUNT = 12
    [ integerToBS 0xde8142541255c46d66efc6173b0fe3ffaf5936c897a3ce2e9d5835616aafa2cb
    , integerToBS 0xd01f9002c407127bc3297a561d89b81d
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0x64d1020929d74716446d8a4e17205d0756b5264867811aa24d0d0da8644db25d5cde474143c57d12482f6bf0f31d10af9d1da4eb6d701bdd605a8db74fb4e77f79aaa9e450afda50b18d19fae68f03db1d7b5f1738d2fdce9ad3ee9461b58ee242daf7a1d72c45c9213eca34e14810a9fca5208d5c56d8066bab1586f1513de7
    ],
    -- COUNT = 13
    [ integerToBS 0x4a8e0bd90bdb12f7748ad5f147b115d7385bb1b06aee7d8b76136a25d779bcb7
    , integerToBS 0x7f3cce4af8c8ce3c45bdf23c6b181a00
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0x320c7ca4bbeb7af977bc054f604b5086a3f237aa5501658112f3e7a33d2231f5536d2c85c1dad9d9b0bf7f619c81be4854661626839c8c10ae7fdc0c0b571be34b58d66da553676167b00e7d8e49f416aacb2926c6eb2c66ec98bffae20864cf92496db15e3b09e530b7b9648be8d3916b3c20a3a779bec7d66da63396849aaf
    ],
    -- COUNT = 14
    [ integerToBS 0x451ed024bc4b95f1025b14ec3616f5e42e80824541dc795a2f07500f92adc665
    , integerToBS 0x2f28e6ee8de5879db1eccd58c994e5f0
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0x3fb637085ab75f4e95655faae95885166a5fbb423bb03dbf0543be063bcd48799c4f05d4e522634d9275fe02e1edd920e26d9accd43709cb0d8f6e50aa54a5f3bdd618be23cf73ef736ed0ef7524b0d14d5bef8c8aec1cf1ed3e1c38a808b35e61a44078127c7cb3a8fd7addfa50fcf3ff3bc6d6bc355d5436fe9b71eb44f7fd
    ]
    ]

{-
    [SHA-256]
    [PredictionResistance = False]
    [EntropyInputLen = 256]
    [NonceLen = 128]
    [PersonalizationStringLen = 0]
    [AdditionalInputLen = 256]
    [ReturnedBitsLen = 1024]
-}

t2 :: [[BS.ByteString]]
t2 = 
    [
    -- COUNT = 0
    [ integerToBS 0xd3cc4d1acf3dde0c4bd2290d262337042dc632948223d3a2eaab87da44295fbd
    , integerToBS 0x0109b0e729f457328aa18569a9224921
    , BS.empty
    , integerToBS 0x3c311848183c9a212a26f27f8c6647e40375e466a0857cc39c4e47575d53f1f6
    , integerToBS 0xfcb9abd19ccfbccef88c9c39bfb3dd7b1c12266c9808992e305bc3cff566e4e4
    , integerToBS 0x9c7b758b212cd0fcecd5daa489821712e3cdea4467b560ef5ddc24ab47749a1f1ffdbbb118f4e62fcfca3371b8fbfc5b0646b83e06bfbbab5fac30ea09ea2bc76f1ea568c9be0444b2cc90517b20ca825f2d0eccd88e7175538b85d90ab390183ca6395535d34473af6b5a5b88f5a59ee7561573337ea819da0dcc3573a22974
    ],
    -- COUNT = 1
    [ integerToBS 0xf97a3cfd91faa046b9e61b9493d436c4931f604b22f1081521b3419151e8ff06
    , integerToBS 0x11f3a7d43595357d58120bd1e2dd8aed
    , BS.empty
    , integerToBS 0x517289afe444a0fe5ed1a41dbbb5eb17150079bdd31e29cf2ff30034d8268e3b
    , integerToBS 0x88028d29ef80b4e6f0fe12f91d7449fe75062682e89c571440c0c9b52c42a6e0
    , integerToBS 0xc6871cff0824fe55ea7689a52229886730450e5d362da5bf590dcf9acd67fed4cb32107df5d03969a66b1f6494fdf5d63d5b4d0d34ea7399a07d0116126d0d518c7c55ba46e12f62efc8fe28a51c9d428e6d371d7397ab319fc73ded4722e5b4f30004032a6128df5e7497ecf82ca7b0a50e867ef6728a4f509a8c859087039c
    ],
    -- COUNT = 2
    [ integerToBS 0x0f2f23d64f481cabec7abb01db3aabf125c3173a044b9bf26844300b69dcac8b
    , integerToBS 0x9a5ae13232b43aa19cfe8d7958b4b590
    , BS.empty
    , integerToBS 0xec4c7a62acab73385f567da10e892ff395a0929f959231a5628188ce0c26e818
    , integerToBS 0x6b97b8c6b6bb8935e676c410c17caa8042aa3145f856d0a32b641e4ae5298648
    , integerToBS 0x7480a361058bd9afa3db82c9d7586e42269102013f6ec5c269b6d05f17987847748684766b44918fd4b65e1648622fc0e0954178b0279dfc9fa99b66c6f53e51c4860131e9e0644287a4afe4ca8e480417e070db68008a97c3397e4b320b5d1a1d7e1d18a95cfedd7d1e74997052bf649d132deb9ec53aae7dafdab55e6dae93
    ],
    -- COUNT = 3
    [ integerToBS 0x53c56660c78481be9c63284e005fcc14fbc7fb27732c9bf1366d01a426765a31
    , integerToBS 0xdc7a14d0eb5b0b3534e717a0b3c64614
    , BS.empty
    , integerToBS 0x3aa848706ecb877f5bedf4ffc332d57c22e08747a47e75cff6f0fd1316861c95
    , integerToBS 0x9a401afa739b8f752fddacd291e0b854f5eff4a55b515e20cb319852189d3722
    , integerToBS 0x5c0eb420e0bf41ce9323e815310e4e8303cd677a8a8b023f31f0d79f0ca15aeb636099a369fd074d69889865eac1b72ab3cbfebdb8cf460b00072802e2ec648b1349a5303be4ccaadd729f1a9ea17482fd026aaeb93f1602bc1404b9853adde40d6c34b844cf148bc088941ecfc1642c8c0b9778e45f3b07e06e21ee2c9e0300
    ],
    -- COUNT = 4
    [ integerToBS 0xf63c804404902db334c54bb298fc271a21d7acd9f770278e089775710bf4fdd7
    , integerToBS 0x3e45009ea9cb2a36ba1aa4bf39178200
    , BS.empty
    , integerToBS 0xd165a13dc8cc43f3f0952c3f5d3de4136954d983683d4a3e6d2dc4c89bf23423
    , integerToBS 0x75106bc86d0336df85097f6af8e80e2da59046a03fa65b06706b8bbc7ffc6785
    , integerToBS 0x6363139bba32c22a0f5cd23ca6d437b5669b7d432f786b8af445471bee0b2d24c9d5f2f93717cbe00d1f010cc3b9c515fc9f7336d53d4d26ba5c0d76a90186663c8582eb739c7b6578a3328bf68dc2cec2cd89b3a90201f6993adcc854df0f5c6974d0f5570765a15fe03dbce28942dd2fd16ba2027e68abac83926969349af8
    ],
    -- COUNT = 5
    [ integerToBS 0x2aaca9147da66c176615726b69e3e851cc3537f5f279fe7344233d8e44cfc99d
    , integerToBS 0x4e171f080af9a6081bee9f183ac9e340
    , BS.empty
    , integerToBS 0xd75a2a6eb66c3833e50f5ec3d2e434cf791448d618026d0c360806d120ded669
    , integerToBS 0xb643b74c15b37612e6577ed7ca2a4c67a78d560af9eb50a4108fca742e87b8d6
    , integerToBS 0x501dcdc977f4ba856f24eaa4968b374bebb3166b280334cb510232c31ebffde10fa47b7840ef3fe3b77725c2272d3a1d4219baf23e0290c622271edcced58838cf428f0517425d2e19e0d8c89377eecfc378245f283236fafa466c914b99672ceafab369e8889a0c866d8bd639db9fb797254262c6fd44cfa9045ad6340a60ef
    ],
    -- COUNT = 6
    [ integerToBS 0xa2e4cd48a5cf918d6f55942d95fcb4e8465cdc4f77b7c52b6fae5b16a25ca306
    , integerToBS 0xbef036716440db6e6d333d9d760b7ca8
    , BS.empty
    , integerToBS 0xbfa591c7287f3f931168f95e38869441d1f9a11035ad8ea625bb61b9ea17591c
    , integerToBS 0xc00c735463bca215adc372cb892b05e939bf669583341c06d4e31d0e5b363a37
    , integerToBS 0xe7d136af69926a5421d4266ee0420fd729f2a4f7c295d3c966bdfa05268180b508b8a2852d1b3a06fd2ab3e13c54005123ef319f42d0c6d3a575e6e7e1496cb28aacadbcf83740fba8f35fcee04bb2ed8a51db3d3362b01094a62fb57e33c99a432f29fce6676cffbbcc05107e794e75e44a02d5e6d9d748c5fbff00a0178d65
    ],
    -- COUNT = 7
    [ integerToBS 0x95a67771cba69011a79776e713145d309edae56fad5fd6d41d83eaff89df6e5e
    , integerToBS 0xbe5b5164e31ecc51ba6f7c3c5199eb33
    , BS.empty
    , integerToBS 0x065f693b229a7c4fd373cd15b3807552dd9bf98c5485cef361949d4e7d774b53
    , integerToBS 0x9afb62406f0e812c4f156d58b19a656c904813c1b4a45a0029ae7f50731f8014
    , integerToBS 0xf61b61a6e79a41183e8ed6647899d2dc85cdaf5c3abf5c7f3bf37685946dc28f4923dc842f2d4326bd6ce0d50a84cb3ba869d72a36e246910eba6512ba36cd7ed3a5437c9245b00a344308c792b668b458d3c3e16dee2fbec41867da31084d46d8ec168de2148ef64fc5b72069abf5a6ada1ead2b7146bb793ff1c9c3690fa56
    ],
    -- COUNT = 8
    [ integerToBS 0xa459e1815cbca4514ec8094d5ab2414a557ba6fe10e613c345338d0521e4bf90
    , integerToBS 0x62221392e2552e76cd0d36df6e6068eb
    , BS.empty
    , integerToBS 0x0a3642b02b23b3ef62c701a63401124022f5b896de86dab6e6c7451497aa1dcc
    , integerToBS 0xc80514865901371c45ba92d9f95d50bb7c9dd1768cb3dfbc45b968da94965c6e
    , integerToBS 0x464e6977b8adaef307c9623e41c357013249c9ffd77f405f3925cebb69f151ce8fbb6a277164002aee7858fc224f6499042aa1e6322deee9a5d133c31d640e12a7487c731ba03ad866a24675badb1d79220c40be689f79c2a0be93cb4dada3e0eac4ab140cb91998b6f11953e68f2319b050c40f71c34de9905ae41b2de1c2f6
    ],
    -- COUNT = 9
    [ integerToBS 0x252c2cad613e002478162861880979ee4e323025eebb6fb2e0aa9f200e28e0a1
    , integerToBS 0xd001bc9a8f2c8c242e4369df0c191989
    , BS.empty
    , integerToBS 0x9bcfc61cb2bc000034bb3db980eb47c76fb5ecdd40553eff113368d639b947fd
    , integerToBS 0x8b0565c767c2610ee0014582e9fbecb96e173005b60e9581503a6dca5637a26e
    , integerToBS 0xe96c15fe8a60692b0a7d67171e0195ff6e1c87aab844221e71700d1bbee75feea695f6a740c9760bbe0e812ecf4061d8f0955bc0195e18c4fd1516ebca50ba6a6db86881737dbab8321707675479b87611db6af2c97ea361a5484555ead454defb1a64335de964fc803d40f3a6f057893d2afc25725754f4f00abc51920743dc
    ],
    -- COUNT = 10
    [ integerToBS 0x8be0ca6adc8b3870c9d69d6021bc1f1d8eb9e649073d35ee6c5aa0b7e56ad8a5
    , integerToBS 0x9d1265f7d51fdb65377f1e6edd6ae0e4
    , BS.empty
    , integerToBS 0xda86167ac997c406bb7979f423986a84ec6614d6caa7afc10aff0699a9b2cf7f
    , integerToBS 0xe4baa3c555950b53e2bfdba480cb4c94b59381bac1e33947e0c22e838a9534cf
    , integerToBS 0x64384ecc4ea6b458efc227ca697eac5510092265520c0a0d8a0ccf9ed3ca9d58074671188c6a7ad16d0b050cdc072c125d7298d3a31d9f044a9ee40da0089a84fea28cc7f05f1716db952fad29a0e779635cb7a912a959be67be2f0a4170aace2981802e2ff6467e5b46f0ffbff3b42ba5935fd553c82482ac266acf1cd247d7
    ],
    -- COUNT = 11
    [ integerToBS 0xd43a75b6adf26d60322284cb12ac38327792442aa8f040f60a2f331b33ac4a8f
    , integerToBS 0x0682f8b091f811afacaacaec9b04d279
    , BS.empty
    , integerToBS 0x7fd3b8f512940da7de5d80199d9a7b42670c04a945775a3dba869546cbb9bc65
    , integerToBS 0x2575db20bc7aafc2a90a5dabab760db851d754777bc9f05616af1858b24ff3da
    , integerToBS 0x0da7a8dc73c163014bf0841913d3067806456bbca6d5de92b85534c6545467313648d71ef17c923d090dc92cff8d4d1a9a2bb63e001dc2e8ab1a597999be3d6cf70ff63fee9985801395fbd4f4990430c4259fcae4fa1fcd73dc3187ccc102d04af7c07532885e5a226fc42809c48f22eecf4f6ab996ae4fcb144786957d9f41
    ],
    -- COUNT = 12
    [ integerToBS 0x64352f236af5d32067a529a8fd05ba00a338c9de306371a0b00c36e610a48d18
    , integerToBS 0xdf99ed2c7608c870624b962a5dc68acd
    , BS.empty
    , integerToBS 0xda416335e7aaf60cf3d06fb438735ce796aad09034f8969c8f8c3f81e32fef24
    , integerToBS 0xa28c07c21a2297311adf172c19e83ca0a87731bdffb80548978d2d1cd82cf8a3
    , integerToBS 0x132b9f25868729e3853d3c51f99a3b5fae6d4204bea70890daf62e042b776a526c8fb831b80a6d5d3f153237df1fd39b6fd9137963f5516d9cdd4e3f9195c46e9972c15d3edc6606e3368bde1594977fb88d0ca6e6f5f3d057ccadc7d7dab77dfc42658a1e972aa446b20d418286386a52dfc1c714d2ac548713268b0b709729
    ],
    -- COUNT = 13
    [ integerToBS 0x282f4d2e05a2cd30e9087f5633089389449f04bac11df718c90bb351cd3653a5
    , integerToBS 0x90a7daf3c0de9ea286081efc4a684dfb
    , BS.empty
    , integerToBS 0x2630b4ccc7271cc379cb580b0aaede3d3aa8c1c7ba002cf791f0752c3d739007
    , integerToBS 0xc31d69de499f1017be44e3d4fa77ecebc6a9b9934749fcf136f267b29115d2cc
    , integerToBS 0xc899094520e0197c37b91dd50778e20a5b950decfb308d39f1db709447ae48f6101d9abe63a783fbb830eec1d359a5f61a2013728966d349213ee96382614aa4135058a967627183810c6622a2158cababe3b8ab99169c89e362108bf5955b4ffc47440f87e4bad0d36bc738e737e072e64d8842e7619f1be0af1141f05afe2d
    ],
    -- COUNT = 14
    [ integerToBS 0x13c752b9e745ce77bbc7c0dbda982313d3fe66f903e83ebd8dbe4ff0c11380e9
    , integerToBS 0xf1a533095d6174164bd7c82532464ae7
    , BS.empty
    , integerToBS 0x4f53db89b9ba7fc00767bc751fb8f3c103fe0f76acd6d5c7891ab15b2b7cf67c
    , integerToBS 0x582c2a7d34679088cca6bd28723c99aac07db46c332dc0153d1673256903b446
    , integerToBS 0x6311f4c0c4cd1f86bd48349abb9eb930d4f63df5e5f7217d1d1b91a71d8a6938b0ad2b3e897bd7e3d8703db125fab30e03464fad41e5ddf5bf9aeeb5161b244468cfb26a9d956931a5412c97d64188b0da1bd907819c686f39af82e91cfeef0cbffb5d1e229e383bed26d06412988640706815a6e820796876f416653e464961
    ]
    ]

{-
    [SHA-256]
    [PredictionResistance = False]
    [EntropyInputLen = 256]
    [NonceLen = 128]
    [PersonalizationStringLen = 256]
    [AdditionalInputLen = 0]
    [ReturnedBitsLen = 1024]
-}

t3 :: [[BS.ByteString]]
t3 = 
    [
    -- COUNT = 0
    [ integerToBS 0x5cacc68165a2e2ee20812f35ec73a79dbf30fd475476ac0c44fc6174cdac2b55
    , integerToBS 0x6f885496c1e63af620becd9e71ecb824
    , integerToBS 0xe72dd8590d4ed5295515c35ed6199e9d211b8f069b3058caa6670b96ef1208d0
    , BS.empty
    , BS.empty
    , integerToBS 0xf1012cf543f94533df27fedfbf58e5b79a3dc517a9c402bdbfc9a0c0f721f9d53faf4aafdc4b8f7a1b580fcaa52338d4bd95f58966a243cdcd3f446ed4bc546d9f607b190dd69954450d16cd0e2d6437067d8b44d19a6af7a7cfa8794e5fbd728e8fb2f2e8db5dd4ff1aa275f35886098e80ff844886060da8b1e7137846b23b
    ],
    -- COUNT = 1
    [ integerToBS 0x8df013b4d103523073917ddf6a869793059e9943fc8654549e7ab22f7c29f122
    , integerToBS 0xda2625af2ddd4abcce3cf4fa4659d84e
    , integerToBS 0xb571e66d7c338bc07b76ad3757bb2f9452bf7e07437ae8581ce7bc7c3ac651a9
    , BS.empty
    , BS.empty
    , integerToBS 0xb91cba4cc84fa25df8610b81b641402768a2097234932e37d590b1154cbd23f97452e310e291c45146147f0da2d81761fe90fba64f94419c0f662b28c1ed94da487bb7e73eec798fbcf981b791d1be4f177a8907aa3c401643a5b62b87b89d66b3a60e40d4a8e4e9d82af6d2700e6f535cdb51f75c321729103741030ccc3a56
    ],
    -- COUNT = 2
    [ integerToBS 0x565b2b77937ba46536b0f693b3d5e4a8a24563f9ef1f676e8b5b2ef17823832f
    , integerToBS 0x4ef3064ec29f5b7f9686d75a23d170e3
    , integerToBS 0x3b722433226c9dba745087270ab3af2c909425ba6d39f5ce46f07256068319d9
    , BS.empty
    , BS.empty
    , integerToBS 0xd144ee7f8363d128872f82c15663fe658413cd42651098e0a7c51a970de75287ec943f9061e902280a5a9e183a7817a44222d198fbfab184881431b4adf35d3d1019da5a90b3696b2349c8fba15a56d0f9d010a88e3f9eeedb67a69bcaa71281b41afa11af576b765e66858f0eb2e4ec4081609ec81da81df0a0eb06787340ea
    ],
    -- COUNT = 3
    [ integerToBS 0xfc3832a91b1dcdcaa944f2d93cbceb85c267c491b7b59d017cde4add79a836b6
    , integerToBS 0xd5e76ce9eabafed06e33a913e395c5e0
    , integerToBS 0xffc5f6eefd51da64a0f67b5f0cf60d7ab43fc7836bca650022a0cee57a43c148
    , BS.empty
    , BS.empty
    , integerToBS 0x0e713c6cc9a4dbd4249201d12b7bf5c69c3e18eb504bf3252db2f43675e17d99b6a908400cea304011c2e54166dae1f20260008efe4e06a87e0ce525ca482bca223a902a14adcf2374a739a5dfeaf14cadd72efa4d55d15154c974d9521535bcb70658c5b6c944020afb04a87b223b4b8e5d89821704a9985bb010405ba8f3d4
    ],
    -- COUNT = 4
    [ integerToBS 0x8009eb2cb49fdf16403bcdfd4a9f952191062acb9cc111eca019f957fb9f4451
    , integerToBS 0x355598866952394b1eddd85d59f81c9d
    , integerToBS 0x09ff1d4b97d83b223d002e05f754be480d13ba968e5aac306d71cc9fc49cc2dd
    , BS.empty
    , BS.empty
    , integerToBS 0x9550903c2f02cf77c8f9c9a37041d0040ee1e3ef65ba1a1fbbcf44fb7a2172bd6b3aaabe850281c3a1778277bacd09614dfefececac64338ae24a1bf150cbf9d9541173a82ecba08aa19b75abb779eb10efa4257d5252e8afcac414bc3bb5d3006b6f36fb9daea4c8c359ef6cdbeff27c1068571dd3c89dc87eda9190086888d
    ],
    -- COUNT = 5
    [ integerToBS 0xa6e4c9a8bd6da23b9c2b10a7748fd08c4f782fadbac7ea501c17efdc6f6087bd
    , integerToBS 0xacdc47edf1d3b21d0aec7631abb6d7d5
    , integerToBS 0xc16ee0908a5886dccf332fbc61de9ec7b7972d2c4c83c477409ce8a15c623294
    , BS.empty
    , BS.empty
    , integerToBS 0xa52f93ccb363e2bdf0903622c3caedb7cffd04b726052b8d455744c71b76dee1b71db9880dc3c21850489cb29e412d7d80849cfa9151a151dcbf32a32b4a54cac01d3200200ed66a3a5e5c131a49655ffbf1a8824ff7f265690dffb4054df46a707b9213924c631c5bce379944c856c4f7846e281ac89c64fad3a49909dfb92b
    ],
    -- COUNT = 6
    [ integerToBS 0x59d6307460a9bdd392dfc0904973991d585696010a71e52d590a5039b4849fa4
    , integerToBS 0x34a0aafb95917cbf8c38fc5548373c05
    , integerToBS 0x0407b7c57bc11361747c3d67526c36e228028a5d0b145d66ab9a2fe4b07507a0
    , BS.empty
    , BS.empty
    , integerToBS 0x299aba0661315211b09d2861855d0b4b125ab24649461341af6abd903ed6f025223b3299f2126fcad44c675166d800619cf49540946b12138989417904324b0ddad121327211a297f11259c9c34ce4c70c322a653675f78d385e4e2443f8058d141195e17e0bd1b9d44bf3e48c376e6eb44ef020b11cf03eb141c46ecb43cf3d
    ],
    -- COUNT = 7
    [ integerToBS 0x9ae3506aadbc8358696ba1ba17e876e1157b7048235921503d36d9211b430342
    , integerToBS 0x9abf7d66afee5d2b811cba358bbc527d
    , integerToBS 0x0d645f6238e9ceb038e4af9772426ca110c5be052f8673b8b5a65c4e53d2f519
    , BS.empty
    , BS.empty
    , integerToBS 0x5f032c7fec6320fe423b6f38085cbad59d826085afe915247b3d546c4c6b174554dd4877c0d671de9554b505393a44e71f209b70f991ac8aa6e08f983fff2a4c817b0cd26c12b2c929378506489a75b2025b358cb5d0400821e7e252ac6376cd94a40c911a7ed8b6087e3de5fa39fa6b314c3ba1c593b864ce4ff281a97c325b
    ],
    -- COUNT = 8
    [ integerToBS 0x96ae3b8775b36da2a29b889ad878941f43c7d51295d47440cd0e3c4999193109
    , integerToBS 0x1fe022a6fc0237b055d4d6a7036b18d5
    , integerToBS 0x1e40e97362d0a823d3964c26b81ab53825c56446c5261689011886f19b08e5c2
    , BS.empty
    , BS.empty
    , integerToBS 0xe707cd14b06ce1e6dbcceaedbf08d88891b03f44ad6a797bd12fdeb557d0151df9346a028dec004844ca46adec3051dafb345895fa9f4604d8a13c8ff66ae093fa63c4d9c0816d55a0066d31e8404c841e87b6b2c7b5ae9d7afb6840c2f7b441bf2d3d8bd3f40349c1c014347c1979213c76103e0bece26ad7720601eff42275
    ],
    -- COUNT = 9
    [ integerToBS 0x33f5120396336e51ee3b0b619b5f873db05ca57cda86aeae2964f51480d14992
    , integerToBS 0x6f1f6e9807ba5393edcf3cb4e4bb6113
    , integerToBS 0x3709605af44d90196867c927512aa8ba31837063337b4879408d91a05c8efa9f
    , BS.empty
    , BS.empty
    , integerToBS 0x8b8291126ded9acef12516025c99ccce225d844308b584b872c903c7bc6467599a1cead003dc4c70f6d519f5b51ce0da57f53da90dbe8f666a1a1dde297727fee2d44cebd1301fc1ca75956a3fcae0d374e0df6009b668fd21638d2b733e6902d22d5bfb4af1b455975e08eef0ebe4dc87705801e7776583c8de11672729f723
    ],
    -- COUNT = 10
    [ integerToBS 0xad300b799005f290fee7f930eebce158b98fb6cb449987fe433f955456b35300
    , integerToBS 0x06aa2514e4bd114edf7ac105cfef2772
    , integerToBS 0x87ada711465e4169da2a74c931afb9b5a5b190d07b7af342aa99570401c3ee8a
    , BS.empty
    , BS.empty
    , integerToBS 0x80d7c606ff49415a3a92ba1f2943235c01339c8f9cd0b0511fbfdf3ef23c42ffff008524193faaa4b7f2f2eb0cfa221d9df89bd373fe4e158ec06fad3ecf1eb48b8239b0bb826ee69d773883a3e8edac66254610ff70b6609836860e39ea1f3bfa04596fee1f2baca6cebb244774c6c3eb4af1f02899eba8f4188f91776de16f
    ],
    -- COUNT = 11
    [ integerToBS 0x130b044e2c15ab89375e54b72e7baae6d4cad734b013a090f4df057e634f6ff0
    , integerToBS 0x65fd6ac602cd44107d705dbc066e52b6
    , integerToBS 0xf374aba16f34d54aae5e494505b67d3818ef1c08ea24967a76876d4361379aec
    , BS.empty
    , BS.empty
    , integerToBS 0x5d179534fb0dba3526993ed8e27ec9f915183d967336bb24352c67f4ab5d7935d3168e57008da851515efbaecb69904b6d899d3bfa6e9805659aef2942c4903875b8fcbc0d1d24d1c075f0ff667c1fc240d8b410dff582fa71fa30878955ce2ed786ef32ef852706e62439b69921f26e84e0f54f62b938f04905f05fcd7c2204
    ],
    -- COUNT = 12
    [ integerToBS 0x716430e999964b35459c17921fe5f60e09bd9ab234cb8f4ba4932bec4a60a1d5
    , integerToBS 0x9533b711e061b07d505da707cafbca03
    , integerToBS 0x372ae616d1a1fc45c5aecad0939c49b9e01c93bfb40c835eebd837af747f079d
    , BS.empty
    , BS.empty
    , integerToBS 0xa80d6a1b2d0ce01fe0d26e70fb73da20d45841cf01bfbd50b90d2751a46114c0e758cb787d281a0a9cf62f5c8ce2ee7ca74fefff330efe74926acca6d6f0646e4e3c1a1e52fce1d57b88beda4a5815896f25f38a652cc240deb582921c8b1d03a1da966dd04c2e7eee274df2cd1837096b9f7a0d89a82434076bc30173229a60
    ],
    -- COUNT = 13
    [ integerToBS 0x7679f154296e6d580854826539003a82d1c54e2e062c619d00da6c6ac820789b
    , integerToBS 0x55d12941b0896462e7d888e5322a99a3
    , integerToBS 0xba4d1ed696f58ef64596c76cee87cc1ca83069a79e7982b9a06f9d62f4209faf
    , BS.empty
    , BS.empty
    , integerToBS 0x10dc7cd2bb68c2c28f76d1b04ae2aa287071e04c3b688e1986b05cc1209f691daa55868ebb05b633c75a40a32b49663185fe5bb8f906008347ef51590530948b87613920014802e5864e0758f012e1eae31f0c4c031ef823aecfb2f8a73aaa946fc507037f9050b277bdeaa023123f9d22da1606e82cb7e56de34bf009eccb46
    ],
    -- COUNT = 14
    [ integerToBS 0x8ca4a964e1ff68753db86753d09222e09b888b500be46f2a3830afa9172a1d6d
    , integerToBS 0xa59394e0af764e2f21cf751f623ffa6c
    , integerToBS 0xeb8164b3bf6c1750a8de8528af16cffdf400856d82260acd5958894a98afeed5
    , BS.empty
    , BS.empty
    , integerToBS 0xfc5701b508f0264f4fdb88414768e1afb0a5b445400dcfdeddd0eba67b4fea8c056d79a69fd050759fb3d626b29adb8438326fd583f1ba0475ce7707bd294ab01743d077605866425b1cbd0f6c7bba972b30fbe9fce0a719b044fcc1394354895a9f8304a2b5101909808ddfdf66df6237142b6566588e4e1e8949b90c27fc1f
    ]
    ]

{-
    [SHA-256]
    [PredictionResistance = False]
    [EntropyInputLen = 256]
    [NonceLen = 128]
    [PersonalizationStringLen = 256]
    [AdditionalInputLen = 256]
    [ReturnedBitsLen = 1024]
-}

t4 :: [[BS.ByteString]]
t4 = 
    [
    -- COUNT = 0
    [ integerToBS 0x5d3286bc53a258a53ba781e2c4dcd79a790e43bbe0e89fb3eed39086be34174b
    , integerToBS 0xc5422294b7318952ace7055ab7570abf
    , integerToBS 0x2dba094d008e150d51c4135bb2f03dcde9cbf3468a12908a1b025c120c985b9d
    , integerToBS 0x793a7ef8f6f0482beac542bb785c10f8b7b406a4de92667ab168ecc2cf7573c6
    , integerToBS 0x2238cdb4e23d629fe0c2a83dd8d5144ce1a6229ef41dabe2a99ff722e510b530
    , integerToBS 0xd04678198ae7e1aeb435b45291458ffde0891560748b43330eaf866b5a6385e74c6fa5a5a44bdb284d436e98d244018d6acedcdfa2e9f499d8089e4db86ae89a6ab2d19cb705e2f048f97fb597f04106a1fa6a1416ad3d859118e079a0c319eb95686f4cbcce3b5101c7a0b010ef029c4ef6d06cdfac97efb9773891688c37cf
    ],
    -- COUNT = 1
    [ integerToBS 0xc2a566a9a1817b15c5c3b778177ac87c24e797be0a845f11c2fe399dd37732f2
    , integerToBS 0xcb1894eb2b97b3c56e628329516f86ec
    , integerToBS 0x13ce4d8dd2db9796f94156c8e8f0769b0aa1c82c1323b61536603bca37c9ee29
    , integerToBS 0x413dd83fe56835abd478cb9693d67635901c40239a266462d3133b83e49c820b
    , integerToBS 0xd5c4a71f9d6d95a1bedf0bd2247c277d1f84a4e57a4a8825b82a2d097de63ef1
    , integerToBS 0xb3a3698d777699a0dd9fa3f0a9fa57832d3cefac5df24437c6d73a0fe41040f1729038aef1e926352ea59de120bfb7b073183a34106efed6278ff8ad844ba0448115dfddf3319a82de6bb11d80bd871a9acd35c73645e1270fb9fe4fa88ec0e465409ea0cba809fe2f45e04943a2e396bbb7dd2f4e0795303524cc9cc5ea54a1
    ],
    -- COUNT = 2
    [ integerToBS 0xa33288a96f41dd54b945e060c8bd0c094f1e28267cc1dcbba52063c1a9d54c4d
    , integerToBS 0x36918c977e1a7276a2bb475591c367b7
    , integerToBS 0x6aa528c940962638dc2201738850fd1fe6f5d0eb9f687ff1af39d9c7b36830d9
    , integerToBS 0x37ee633a635e43af59abdb1762c7ea45bfe060ec1d9077ecd2a43a658673f3c7
    , integerToBS 0x2eb96f2e28fa9f674bb03ade703b8f791ee5356e2ee85c7ed5bda96325256c61
    , integerToBS 0xdb2f91932767eb846961ce5321c7003431870508e8c6f8d432ca1f9cee5cdc1aed6e0f133d317eb6990c4b3b0a360cdfb5b43a6e712bd46bca04c414868fab22c6a49c4b89c812697c3a7fbfc8ddf10c8aa5ebf13a09fd114eb2a02a07f69786f3ce7fd30231f22779bc8db103b13fa546dbc45a89a86275281172761683d384
    ],
    -- COUNT = 3
    [ integerToBS 0x5f37b6e47e1776e735adc03d4b999879477ff4a206231924033d94c0114f911b
    , integerToBS 0x7d12d62c79c9f6234ae0314156947459
    , integerToBS 0x92d4d9fab5f8bf5119f2663a9df7334f50dcde74fb9d7732f7eba56501e60d54
    , integerToBS 0xc9aef0d7a9ba7345d08b6d5b5ce5645c7495b8685e6b93846ffcf470f5abd40d
    , integerToBS 0x50d9d1f5074f7d9f1a24a9c63aa47b94da5ba78db1b0f18e4d4fe45c6875813c
    , integerToBS 0x20d942bbd7d98700faa37e94d53bf74f2d6bd1d8c95c0b88d842c4857797d59e7c8788aeeac29740122f208f703bf35dc32b0035db0648384feb6aa17a3274bc09b2d2b746c5a06fd82f4469fb86131a49482cb7be7d9b4b95042394cfb18b13f333ec0fe5c227bf1d8f33ecb2e42e358b6c3e034cb585331bd1d27f638029b9
    ],
    -- COUNT = 4
    [ integerToBS 0x2311c5afd64c584484b2729e84db80c0b4063fe9ca7edc83350488d7e67264a0
    , integerToBS 0x6a6dfd975a0dc7b72df1f107c4b3b3a6
    , integerToBS 0x2abd870ec5fe26ed14dfa57a3309f920131b70580c3639af2645cd1af93db1b1
    , integerToBS 0xc6e532a3b25653b6002aed5269cc2118749306e736bde039d4d569d4f967773f
    , integerToBS 0x5e7d26c4da769c373092b2b4f72b109fe34bdb7d169ea38f78ebae5df4a15759
    , integerToBS 0xcacaeb1b4ac2305d8714eb50cbe1c67c5a2c0bbc7938fdfdcafef7c85fc40becbf777a4cfb6f14c6eee320943a493d2b0a744a6eb3c256ee9a3763037437df9adce3e2260f0c35e958af0edb5a81debd8bdaf2b8bb2b98b9186e5a222a21609ff58df4cbe1d4898d10d6e7c46f31f5cb1041bfd83a5fb27d5c56c961e91403fc
    ],
    -- COUNT = 5
    [ integerToBS 0x362ece9d330e1172a8f9e50258476d0c79c3ee50346524ba12d970ee3a6ef8c5
    , integerToBS 0xcf11bcb4d9d51311ceacfca8705e833f
    , integerToBS 0xabb5a8edde02e526449284ecc31bc713383df3ed085f752e3b6a32f305861eed
    , integerToBS 0x746302ab1f4a86b17546bea762e929360f2e95c7788a63545a264ef997c8c65e
    , integerToBS 0xb907c5b2a8833a48e56e819228ce9a050b41b3309f5ca37bed720311d92b33af
    , integerToBS 0x73c7131a558350590053580873ef956ff952f2aa6ff1bea452e013d1bc2afddea2311756dbe756e63ba6258480c48f3f6c1319b5f572f67ca530af09e39413d1d432bea8f89206619618cb0e7c88e9f2033639d0eb0efc20616b64f940da99b88231984c3fb23f19e890576f555fde394dbd4351f17a7ffd5c369379001bda03
    ],
    -- COUNT = 6
    [ integerToBS 0xcf614bc29946bc0095f415e8bdeda10aab05392f9cc9187a86ea6ec95ee422e1
    , integerToBS 0x77fb5ec22dc0432cc13f4693e2e3bd9a
    , integerToBS 0xe4ce77914ffbc5fddf1fb51edfafdc196109139b84c741354135ec8d314c7c43
    , integerToBS 0xe1e83ee1205acaf6164dc287aec08e5b32789e5be818078db39e53cad589db51
    , integerToBS 0x4e20c0226d5e1e7e805679f03f72452b5bea2d0ba41e0c12329bf60eb3016dd1
    , integerToBS 0x838fdf1418a746aa52ae4005d90c3fd301f648c5770ffef2a9f3912e37a93850cc4b8bfcce910aead0cb75958823b1a62e283901c5e4a3980e4ea36257458e2e4953555819b8852a26489b1d74821f80c9908469b43f124ff7ea62497c36159a47353098a1b9ec32e54800d6704371cc37f357ad74aacc203e9b6db97f94d0c4
    ],
    -- COUNT = 7
    [ integerToBS 0xa8da1d3e233f393fd44d204c200202f7d01896e72c5ac652940cfd15b5d4b0bd
    , integerToBS 0x0a112b4cb0890af0a495e0f49fcf6874
    , integerToBS 0xd2e32799bc822b8d033299bdf63dc35774f7649e935d25be5b10512c430d1bda
    , integerToBS 0x920a82d76fcd2cd106ada64bba232b7b2344f3afe6b1d1d20ee8795144571009
    , integerToBS 0xeeaac5878275372025f8231febed64db6a11273c3c00d625fc80a95f18ad7d3f
    , integerToBS 0x5f6dae489b53d89027b2cc333c700f090152d77b3eaf01d47f56ce6eca9893ef877b4cb560fab0fbdb34e3d1c6cd8480b33c053d2661a10aa531df4961b97d659c7492584236582b3fe701055efa59c328194cd1e07fcffd910d9ee01b7b9e8c8fda7f7ac01a8e203b8b26eb8078a9b9a5021562c44af24089e3ef84c1d5a6bd
    ],
    -- COUNT = 8
    [ integerToBS 0xa77b1ed4ecaa650374e1052c405f1d88881c25c87d13dbe1334d8c1a847fa76b
    , integerToBS 0x05c143e2f145db216fe7be9ed23635d0
    , integerToBS 0xb5c750968ff09ed251d4a1c05342ac843db5246b19045728a634fa4f6e752e54
    , integerToBS 0xff5937bcd01a363696bf8e40adc8e4ab3e56dbf7e7d09451c99e538785fe6697
    , integerToBS 0x4acb34eea8266badcf8f6557a0eecf3eb4d7a295c876d6175598cb66a388efb8
    , integerToBS 0xec13eadfcc84e77d2a2efa1a2cd8b1355587cb27feb3d19d75b37f0446333ddb8236e751c63b7a6e595ec24a25051a696dbe8c062dd8896d1446db228a2f10e8094ee07e7ee648ed6bebb2f5ec5aae24c9c640665c28355cc11c116795ecc070790f7fdfc4398900311b6695d5da0175091ed1828d2731085bfb4a20bd86cce0
    ],
    -- COUNT = 9
    [ integerToBS 0x491686c781e83eb4e21d9989e8d718100b0d21a2c56295888baef1a65f219651
    , integerToBS 0x499085296d21065feabf3106101c8d6f
    , integerToBS 0xd208a72f9ae34f0817669fb04f49239dd31700f3dc9a93db8d75fb79f9b686c1
    , integerToBS 0x9ffc61893a293a864008fdd56d3292600d9e2ec8a1ea8f34ac5931e968905a23
    , integerToBS 0x4ff3a397dfdae0912032a302a5e7a07dceca8d9013a21545689319b7c024cd07
    , integerToBS 0x3c258ebf2203fca3b322ad1b016e21c7f5c148425f81e4fb0a0e462dce9dfa569c37a006527768297a5b68461b08912642a341b88c85597e30e7561206886098c4e2d861f11513f0ffdbbc78d3a2dd60c105abbb33c5e05ae27081b690fb8b3610917aa9bf1a4ad74481b5ff8334f14e5ad6a6a1eb2259476078076fb7e3a992
    ],
    -- COUNT = 10
    [ integerToBS 0x36a5267eeeb5a1a7d46de0f8f9281f73cd9611f01198fdaa78c5315205e5a177
    , integerToBS 0xb66b5337970df36219321badacc624eb
    , integerToBS 0xc2a7b164949da102bece44a423197682ff97627d1fe9654266b8527f64e5b386
    , integerToBS 0xa977e2d8637b019c74063d163bb25387dc56f4eb40e502cefc5ae6ad26a6abdc
    , integerToBS 0xc5c9819557b1e7d8a86fa8c60be42993edc3ef539c13d9a51fb64b0de06e145e
    , integerToBS 0xb471711a4fc7ab7247e65d2c2fe49a50169187187b7978cd2fdb0f8318be3ec55fc68ed4577ad9b42cbb57100b5d35ac86c244c4c93a5b28c1a11c2dfe905d608ec7804dec5bb15cf8d79695534d5e13a6a7e18a887ec9cf184da0cbbc6267f3a952a769403bafcdbb559401be0d8b3300ea7258b4026fc892175efd55ba1a67
    ],
    -- COUNT = 11
    [ integerToBS 0xa76b0366df89e4073a6b6b9c04da1d6817ce26f1c4825cad4097bdf4d7b9445e
    , integerToBS 0x773d3cc3290176773847869be528d1a4
    , integerToBS 0x1bfd3bcfb9287a5ad055d1b2b8615fa81c94ac24bc1c219a0f8de58789e0404a
    , integerToBS 0xedd879fa56f21d93029da875b683ce50f6fdc4c0da41da051d000eed2afefefa
    , integerToBS 0xf528ffd29160039260133ed9654589ce60e39e7f667c34f82cda65ddcf5fff14
    , integerToBS 0x39d1ff8848e74dd2cdc6b818ad69823878062116fdf1679942f892c7e191be1c4b6ea268ecdff001b22af0d510f30c2c25b90fc34927f46e3f45d36b0e1848b3a5d54c36c7c65ee7287d325dfbb51b56a438feb6650ce13df88bf06b87ac4a35d2a199ea888629fb0d83f82f0ea160dc79ed220d8ef195b9e80c542f60c2d320
    ],
    -- COUNT = 12
    [ integerToBS 0x46571e1df43e5e141235e2a9ec85bb0faf1dc0566031e14d41a2fbd0315653ec
    , integerToBS 0xb60ef6a3347967519aabeaf748e4e991
    , integerToBS 0x759fd8593e3688b23c4a003b655311770d670789878570eb3b155a8e6c2d8c45
    , integerToBS 0x033128460b449e1accb0e9c54508759ddc2538bc64b51e6277553f0c60a02723
    , integerToBS 0xa5e4a717240bdeac18a0c0e231a11dc04a47d7550f342fa9a7a5ff334eb9327d
    , integerToBS 0x9d222df1d530ea7f8f2297a0c79d637da570b48042ecddded75956bba0f0e70b271ffa3c9a53bada6ee1b8a4203c22bfde82a5e2eb1b150f54c6483458569422c1a34a8997d42cc09750167a78bf52a0bd158397af9f83caabe689185c099bf0a9a4853dd3cf8b8e89efebb6a27dba873e65e9927741b22968f2875789b44e01
    ],
    -- COUNT = 13
    [ integerToBS 0xd63980e63bbe4ac08d2ac5646bf085b82c75995e3fdfc23bb9cc734cd85ca7d2
    , integerToBS 0xd33ed1dcae13fb634ba08272d6697590
    , integerToBS 0xacd0da070072a5340c4f5f4395568e1a36374e074196ae87f3692ee40487e1df
    , integerToBS 0xf567677b5e12e26f3544be3da9314c88fc475bf84804a89a51f12b191392c02b
    , integerToBS 0xc01cc7873e93c86e2bfb8fc984cfc2eab5cc58eeef018fedb5cba5aedd386156
    , integerToBS 0xb133446f633bcb40724bbf9fa187c39a44b9c094a0a0d40e98977e5466dc2c9adf62a5f4551eeb6406a14658de8a0ed7487c3bf6277e811101284a941745ce16176acc875f1435e14161772fa84609e8123c53dd03cbb868030835c0d11d8d6aa04a1b6f908248b028997737f54735ec4ed7a81fc868199ffb61a779d9340334
    ],
    -- COUNT = 14
    [ integerToBS 0x3d99f9b7ac3a2fbe9cf15d960bf41f5588fc4db1e0d2a5c9c0fe9059f03593fb
    , integerToBS 0x411f504bb63a9b3afa7ffa1357bb48be
    , integerToBS 0x0bb5ebd55981a25ba69164da49fa92f2871fd3fc65eb30d0f0d0b8d798a4f8f2
    , integerToBS 0x288e948a551284eb3cb23e26299955c2fb8f063c132a92683c1615ecaed80f30
    , integerToBS 0xd975b22f79e34acf5db25a2a167ef60a10682dd9964e15533d75f7fa9efc5dcb
    , integerToBS 0xee8d707eea9bc7080d58768c8c64a991606bb808600cafab834db8bc884f866941b4a7eb8d0334d876c0f1151bccc7ce8970593dad0c1809075ce6dbca54c4d4667227331eeac97f83ccb76901762f153c5e8562a8ccf12c8a1f2f480ec6f1975ac097a49770219107d4edea54fb5ee23a8403874929d073d7ef0526a647011a
    ]
    ]

{- Reseed test vectors -}

{-
    [SHA-256]
    [PredictionResistance = False]
    [EntropyInputLen = 256]
    [NonceLen = 128]
    [PersonalizationStringLen = 0]
    [AdditionalInputLen = 0]
    [ReturnedBitsLen = 1024]
-}

r1 :: [[BS.ByteString]]
r1 = 
    [
    -- COUNT = 0
    [ integerToBS 0x06032cd5eed33f39265f49ecb142c511da9aff2af71203bffaf34a9ca5bd9c0d
    , integerToBS 0x0e66f71edc43e42a45ad3c6fc6cdc4df
    , BS.empty
    , integerToBS 0x01920a4e669ed3a85ae8a33b35a74ad7fb2a6bb4cf395ce00334a9c9a5a5d552
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0x76fc79fe9b50beccc991a11b5635783a83536add03c157fb30645e611c2898bb2b1bc215000209208cd506cb28da2a51bdb03826aaf2bd2335d576d519160842e7158ad0949d1a9ec3e66ea1b1a064b005de914eac2e9d4f2d72a8616a80225422918250ff66a41bd2f864a6a38cc5b6499dc43f7f2bd09e1e0f8f5885935124
    ],
    -- COUNT = 1
    [ integerToBS 0xaadcf337788bb8ac01976640726bc51635d417777fe6939eded9ccc8a378c76a
    , integerToBS 0x9ccc9d80c89ac55a8cfe0f99942f5a4d
    , BS.empty
    , integerToBS 0x03a57792547e0c98ea1776e4ba80c007346296a56a270a35fd9ea2845c7e81e2
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0x17d09f40a43771f4a2f0db327df637dea972bfff30c98ebc8842dc7a9e3d681c61902f71bffaf5093607fbfba9674a70d048e562ee88f027f630a78522ec6f706bb44ae130e05c8d7eac668bf6980d99b4c0242946452399cb032cc6f9fd96284709bd2fa565b9eb9f2004be6c9ea9ff9128c3f93b60dc30c5fc8587a10de68c
    ],
    -- COUNT = 2
    [ integerToBS 0x62cda441dd802c7652c00b99cac3652a64fc75388dc9adcf763530ac31df9214
    , integerToBS 0x5fdc897a0c1c482204ef07e0805c014b
    , BS.empty
    , integerToBS 0xbd9bbf717467bf4b5db2aa344dd0d90997c8201b2265f4451270128f5ac05a1a
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0x7e41f9647a5e6750eb8acf13a02f23f3be77611e51992cedb6602c314531aff2a6e4c557da0777d4e85faefcb143f1a92e0dbac8de8b885ced62a124f0b10620f1409ae87e228994b830eca638ccdceedd3fcd07d024b646704f44d5d9c4c3a7b705f37104b45b9cfc2d933ae43c12f53e3e6f798c51be5f640115d45cf919a4
    ],
    -- COUNT = 3
    [ integerToBS 0x6bdc6ca8eef0e3533abd02580ebbc8a92f382c5b1c8e3eaa12566ecfb90389a3
    , integerToBS 0x8f8481cc7735827477e0e4acb7f4a0fa
    , BS.empty
    , integerToBS 0x72eca6f1560720e6bd1ff0152c12eeff1f959462fd62c72b7dde96abcb7f79fb
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0xd5a2e2f254b5ae65590d4fd1ff5c758e425be4bacdeede7989669f0a22d34274fdfc2bf87135e30abdae2691629c2f6f425bd4e119904d4785ecd9328f15259563e5a71f915ec0c02b66655471067b01016fdf934a47b017e07c21332641400bbe5719050dba22c020b9b2d2cdb933dbc70f76fec4b1d83980fd1a13c4565836
    ],
    -- COUNT = 4
    [ integerToBS 0x096ef37294d369face1add3eb8b425895e921626495705c5a03ee566b34158ec
    , integerToBS 0x6e2e0825534d2989715cc85956e0148d
    , BS.empty
    , integerToBS 0x1b4f7125f472c253837fa787d5acf0382a3b89c3f41c211d263052402dcc62c5
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0x4541f24f759b5f2ac2b57b51125077cc740b3859a719a9bab1196e6c0ca2bd057af9d3892386a1813fc8875d8d364f15e7fd69d1cc6659470415278164df656295ba9cfcee79f6cbe26ee136e6b45ec224ad379c6079b10a2e0cb5f7f785ef0ab7a7c3fcd9cb6506054d20e2f3ec610cbba9b045a248af56e4f6d3f0c8d96a23
    ],
    -- COUNT = 5
    [ integerToBS 0xa7dccdd431ae5726b83585b54eae4108f7b7a25c70187c0acbb94c96cc277aa8
    , integerToBS 0x94c8f4b8e195a47356a89a50d1389ab5
    , BS.empty
    , integerToBS 0x51733eee2e922f4055e53939e222e71fae730eb037443db2c7679708abb86a65
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0x99ba2691a622afecc9472418e6a8f9f1cdc1e3583c3bc7a2a650a1ab79dcbccbd656636c573179276e782569420c97438c06be898867f628b1c01eb570263d2c0f09c7aab536f6fba7df6aad19e05c236b645674667c03d1b6a04d7fc11177fe78933b309679f5bf26a4632b9a13e314c4bf4532428d3d95c689002b6dc1fbb1
    ],
    -- COUNT = 6
    [ integerToBS 0xc286425ecf543a49bcc9196b0db1a80bc54e4948adba6f41712a350a02891fa6
    , integerToBS 0x957a659a4ec2e0b7ad185483c220fd61
    , BS.empty
    , integerToBS 0x08c2129813eea0776fba72788fdf2718759cc3c4207fa20a5fe23ac6e32cc28e
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0x8e1020a4fd84c99e0fc7e3f7ce48de5ed9ec9a5c2ccd624dbe6f30e2f688a31dc55957630357a5d48ca2a456241a28bfb16d8bb000877697a7ce24d9ad4d22b0c15117996f1f270b94f46d7a9bdfa7608fa1dd849177a9b8049e51b6b7a2742623854a1fddb5efc447eed1ea1aed6f02b4b2754ecf71ea0509da2e54f524a7e7
    ],
    -- COUNT = 7
    [ integerToBS 0x02818bd7c1ec456ace55beeba99f646a6d3aa0ea78356ea726b763ff0dd2d656
    , integerToBS 0xc482687d508c9b5c2a75f7ce390014e8
    , BS.empty
    , integerToBS 0xcf319bfa63980e3cb997fd28771bb5614e3acb1149ba45c133ffbbab17433193
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0x19a231ff26c1865ce75d7a7185c30dd0b333126433d0c8cbf1be0d2b384d4eb3a8aff03540fbfa5f5496521a4e4a64071b44c78bd0b7e68fac9e5695c5c13fd3b9dbe7f7739781a4c8f0b980f1b17d99bce17ceb52b56866ae02456ffef83399c8cf7826f3c45c8a19315890919d20f40fc4e18d07e9c8ccd16c3327b5988f71
    ],
    -- COUNT = 8
    [ integerToBS 0x77a5c86d99be7bc2502870f4025f9f7563e9174ec67c5f481f21fcf2b41cae4b
    , integerToBS 0xed044ad72ee822506a6d0b1211502967
    , BS.empty
    , integerToBS 0x778100749f01a4d35c3b4a958aafe296877e0acafd089f50bc7797a42a33ab71
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0x831a4da566f46289904893ef1cc1cd4ad19ee48f3857e2b69e936d10afbdc29822e85d02663d346ef3e09a848b1d9cc04f4c4c6e3b3b0e56a034e2334d34ca08f8097be307ba41d020bc94f8c1937fe85644eeb5592c2b5a2138f7ded9a5b44b200c8b5beb27597c790f94d660eb61e8248391edc3ae2d77656cbe8354275b13
    ],
    -- COUNT = 9
    [ integerToBS 0x0ea458cff8bfd1dd8b1addcba9c01317d53039e533104e32f96e7d342e6c7b9b
    , integerToBS 0x935a4b66fc74c2a48757a99c399e64e3
    , BS.empty
    , integerToBS 0x6c5f3708e7b714c4ed139b4fa9e8c763af01773484005109a85e33653bb0ce98
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0x373a37af84fddec13645a9768d6a785ae5a2589d64cd9b37980dde2541499210c4f408335de1d585349064f3f53a2b4c5ec6dc2a09591f99ad9fad528ac83474164b45497bf167f81e66fa08463ffea917f6891e48f149fafc20622bb1172f34886feb45c26fd446a4a4e2891b4bc594186896141aaaeeb301b49e7c1a26fec7
    ],
    -- COUNT = 10
    [ integerToBS 0xbfb68be4ce1756d25bdfad5e0c2f8bec29360901cc4da51d423d1591cc57e1ba
    , integerToBS 0x98afe4bd194c143e099680c504cceaab
    , BS.empty
    , integerToBS 0xb97caf210e82498c3408790d41c320dd4a72007778389b44b7bc3c1c4b8c53f8
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0x409e0aa949fb3b38231bf8732e7959e943a338ea399026b744df15cbfeff8d71b3da023dcce059a88cf0d4b7475f628e4764c8bef13c70cfbbbb6da2a18aabcad919db09d04fc59765edb165147c88dd473a0f3c5ee19237ca955697e001ba654c5ee0bd26761b49333154426bc63286298a8be634fe0d72cfdeef0f3fc48eca
    ],
    -- COUNT = 11
    [ integerToBS 0x4f6880a64610004463031d67d7924fa446c39138d4d41007e8df3d65691a9367
    , integerToBS 0x6b33b2c13600f4b1df6ca3d1960e8dd4
    , BS.empty
    , integerToBS 0x57b87b8c8f48312b5333d43b367730c0a5ad4725a16778fcb53fe136d136cbfd
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0x73d0f324ed186e2ad06bd1800e262bdbda79ba54e626761bd60f74f43e3bb62958ec1e2f1d940af163e1cadc124e7ebaba2f72e67efd746c7f6d0cad53ef03d859d93cff778a32ee5be172fe7fdbdc232ded360d704a6fa0f70bebe942e56478345492f49dc5c6fc346b88a58947ad250e688e8c626fe1efe7624620e571976e
    ],
    -- COUNT = 12
    [ integerToBS 0xaae352e111843219cae8f70e7b8f6eb9bb53d246cbec1e4f07d42757143295b4
    , integerToBS 0xb84485dccd1bf93210e322eafcbebcd9
    , BS.empty
    , integerToBS 0xf9237f00d744d8fbff21b9d0043c258e8731817e6a5fb7b4bf5011680e5bc642
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0xcfb28b93522c7d61d8d3ce3f080e435e4c83c7e13a9dab788db8fef0407267a14fbc9324e090e24df5491fedfa81116869983938d4d4d7324a310c3af33a6f7938f602c5e4e63f1771cdaabdab0782b5affb54eb53047c109a9606739dd0065bd21eca33132986554878354f5f9f852e674dd690163b0ff74c7a25e6bae8ce39
    ],
    -- COUNT = 13
    [ integerToBS 0x589e79e339b7d2a1b879f0b0e1a7d1ad2474eaa8025b070f1ffa877b7124d4ff
    , integerToBS 0x0961ed64dbd62065d96e75de6d2ff9d6
    , BS.empty
    , integerToBS 0xe928388d3af48c2968527a4d2f9c2626fbc3f3f5a5d84e0583ab6f78e7f8b081
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0xfce6ced1ecf474d181ab331f79c3d2cc8a768ec2818de5b3fc7cf418322716d6a6853733561a497c0c25cb288d2c9fcfbca891bafd5a834c85f3603f402acf1a7b1ea92db847ed5c252a862ad4ab5e259715f1fc81da67f5230bf8be50ee8069758095f7d0e559e03f2c6072290e61794458437609e473eb66580cddaad19b71
    ],
    -- COUNT = 14
    [ integerToBS 0x714277d408ad87fde317f0a94732fce62f1352bdc90936673b4f1daa0925aa26
    , integerToBS 0xd16582a99f23010b4248b88d86485419
    , BS.empty
    , integerToBS 0xbd9fc7cb2fd5063b2c3c0c4f346ad2e3879371a9c805e59b9f2cd2cc2a40894f
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0x62ef7a431288252e0d736c1d4e36cc9ac37107dcd0d0e971a22444a4adae73a41eff0b11c8625e118dbc9226142fd0a6aa10ac9b190919bda44e7248d6c88874612abd77fb3716ea515a2d563237c446e2a282e7c3b0a3aef27d3427cc7d0a7d38714659c3401dbc91d3595159318ebca01ae7d7fd1c89f6ad6b604173b0c744
    ]
    ]

{-
    [SHA-256]
    [PredictionResistance = False]
    [EntropyInputLen = 256]
    [NonceLen = 128]
    [PersonalizationStringLen = 0]
    [AdditionalInputLen = 256]
    [ReturnedBitsLen = 1024]
-}

r2 :: [[BS.ByteString]]
r2 = 
    [
    -- COUNT = 0
    [ integerToBS 0x05ac9fc4c62a02e3f90840da5616218c6de5743d66b8e0fbf833759c5928b53d
    , integerToBS 0x2b89a17904922ed8f017a63044848545
    , BS.empty
    , integerToBS 0x2791126b8b52ee1fd9392a0a13e0083bed4186dc649b739607ac70ec8dcecf9b
    , integerToBS 0x43bac13bae715092cf7eb280a2e10a962faf7233c41412f69bc74a35a584e54c
    , integerToBS 0x3f2fed4b68d506ecefa21f3f5bb907beb0f17dbc30f6ffbba5e5861408c53a1e
    , integerToBS 0x529030df50f410985fde068df82b935ec23d839cb4b269414c0ede6cffea5b68
    , integerToBS 0x02ddff5173da2fcffa10215b030d660d61179e61ecc22609b1151a75f1cbcbb4363c3a89299b4b63aca5e581e73c860491010aa35de3337cc6c09ebec8c91a6287586f3a74d9694b462d2720ea2e11bbd02af33adefb4a16e6b370fa0effd57d607547bdcfbb7831f54de7073ad2a7da987a0016a82fa958779a168674b56524
    ],
    -- COUNT = 1
    [ integerToBS 0x1bea3296f24e9242b96ed00648ac6255007c91f7c1a5088b2482c28c834942bf
    , integerToBS 0x71073136a5cc1eb5b5fa09e1790a0bed
    , BS.empty
    , integerToBS 0xd714329f3fbea1df9d0b0b0d88dfe3774beb63d011935923d048e521b710dc6f
    , integerToBS 0x4ef872fd211a426ea1085ab39eb220cc698fdfeabe49b8835d620ab7885de7a4
    , integerToBS 0xd74d1669e89875852d9ccbf11c20fe3c13a621ebcb3f7edeea39a2b3379fdcf5
    , integerToBS 0x0c8aa67ca310bd8e58c16aba35880f747266dbf624e88ec8f9ee9be5d08fdeb1
    , integerToBS 0xce95b98f13adcdf7a32aa34709d6e02f658ae498d2ab01ce920f69e7e42c4be1d005acf0ca6b17891dfafc620dd4cd3894f8492a5c846089b9b452483eb0b91f3649ec0b6f98d1aaabc2e42cd39c2b25081b85ab50cb723007a0fd83550f32c210b7c4150b5a6bb3b0c9e3c971a09d43acb48e410a77f824b957092aa8ef98bc
    ],
    -- COUNT = 2
    [ integerToBS 0xa7ea449b49db48601fc3a3d5d77081fab092b8d420ed1b266f704f94352dd726
    , integerToBS 0xd11a159b60af8d20a0e37d27e6c74aa3
    , BS.empty
    , integerToBS 0x50916ab47e8cb5dc843f9fba80639103711f86be8e3aa94f8a64a3fe0e6e5b35
    , integerToBS 0xe2bb6768120555e7b9e0d573537a82f8f32f54560e1050b6abb1588fb3441e66
    , integerToBS 0xa50cec9d1ecddb2c163d24019e81c31a2b350ccd3ad8181fd31bb8d1f64fa50e
    , integerToBS 0x591dbbd48b51abced67f9c6269cf0133cd3dcbb5cfafcb6ef758569c555a5773
    , integerToBS 0x0a464abcc8685158372d544635b953fcb1d3821c30aaa93982f9b788935f00f88115aad61d5cee003b3d1cb50f3e961a501e2dd0fc7e1724778b184a4bdf9f64e110dda7446e5544a30bd49a400ea1a5411800e1edfeea349323618afc5dc5782dc4b71d2da4d6a4785f8dd346feb9c8740ffd26bf644e3e4323ff24c30b9f10
    ],
    -- COUNT = 3
    [ integerToBS 0x14683ec508a29d7812e0f04a3e9d87897000dc07b4fbcfda58eb7cdabc492e58
    , integerToBS 0xb2243e744eb980b3ece25ce76383fd46
    , BS.empty
    , integerToBS 0x18590e0ef4ee2bdae462f76d9324b3002559f74c370cfccf96a571d6955703a7
    , integerToBS 0x9ea3ccca1e8d791d22fcda621fc4d51b882df32d94ea8f20ee449313e6909b78
    , integerToBS 0x16366a578b5ea4d0cb547790ef5b4fd45d7cd845bc8a7c45e99419c8737debb4
    , integerToBS 0xa68caa29a53f1ba857e484d095805dc319fe6963e4c4daaf355f722eba746b92
    , integerToBS 0xc4e7532ee816789c2d3da9ff9f4b37139a8515dbf8f9e1d0bf00c12addd79ebbd76236f75f2aa705a09f7955038ebff0d566911c5ea13214e2c2eeb46d23ad86a33b60f7b9448d63eec3e1d59f48b39552857447dc5d7944667a230e3dbfa30ca322f6eacaf7536a286706a627c5083c32de0658b9073857c30fb1d86eb8ad1b
    ],
    -- COUNT = 4
    [ integerToBS 0xfa261fb230e2822458532ca2d5c39758750e6819a6fcebef10579ba995096959
    , integerToBS 0x564e1c9fbcb12878df2bd49202cbf821
    , BS.empty
    , integerToBS 0xbf7de29e99e7f0e1b9f96f3b1902fb4049c8c6234d20de8316ebe66d97725457
    , integerToBS 0x8b7326621f6afbd44a726de48d03bcc5331f7306026c229ea9523497fbeaa88d
    , integerToBS 0x33b00b31623d6160c4c6740363a96481be14b19bc47be95641227284c366922a
    , integerToBS 0x2d812c8203575790ad6b6f2ed91a49d57460de779a3e881bef3be12e8766dc91
    , integerToBS 0x5574e0b4efc17e8ce136e592beabfe32551072bddd740929e698467b40b3991f028a22c760f7034853cc53007e3793e3c4a600d9e9d94528f8dc09aeba86146cdde2b7f71255ae0efc529b49be2205979dba6525bfe155e8819e8e2aeeaa285704242da90b4c4535101cc47d94b0e388a1b2e63ad0cbe158b9e1bbae9cc0007c
    ],
    -- COUNT = 5
    [ integerToBS 0x61f1471ced56aa04c57e1b512307d4cb92497d9592d7e9e35356e99d585cab1b
    , integerToBS 0x84714e960c403a4fac06b2828cc564d9
    , BS.empty
    , integerToBS 0x7bf97db3c102edc81596d4757045fe6bdc008f35792fc6290b77d889c09c33a8
    , integerToBS 0x5b8bdc41f76d98cfa71ed976ea3994706375c8841adb8b6b3b6418e3132e8832
    , integerToBS 0x94c8a8fdf38a6ccb8571c89420d899adab169214bb0dfcd43a04622e289935b2
    , integerToBS 0x8a4b46e0a7a55907365f82d4ab9376509bd44728cab8cbafb0da901012ad8dcd
    , integerToBS 0x933eb159a6af7455b60e40586c064f05f1970f564281b1ebc4662701ac1f299e4eb908c4afcb2e065191281ab576f684aefedd6904bad04d96bd93c0516c62a496c3073a0cda0676a11cc08866b0cc74f62cb9d3db48673b2c3fbeada69f922b4b795ccba22df12ef7125909381f7d681f6b9caba02fb913c5437b98c040c576
    ],
    -- COUNT = 6
    [ integerToBS 0xa1d5bb7d70621dee6b668b28c56d5610c2f8ced30284cc3e0e48de331af05062
    , integerToBS 0x88a49e3e54c5ea54c98b95de81bcc807
    , BS.empty
    , integerToBS 0xb4e2426e98f6eed97a6cdf690a89ee109e84c3dca16c883c26fa4ac671638d8d
    , integerToBS 0x5bd1e086ed228cfd8b55c1731fea40c3a63d022599ca2da4bb23118f4821ba62
    , integerToBS 0xb754b53ac226e8ebe47a3d31496ec822de06fca2e7ef5bf1dec6c83d05368ec3
    , integerToBS 0xfa7e76b2805d90b3d89fff545010d84f67aa3a2c9eb2ba232e75f4d53267dac3
    , integerToBS 0xdf6b2460688fa537df3ddfe5575fca5eb8abad56cbc4e5a618a2b4a7daf6e215c3a497974c502f9d0ec35de3fc2ea5d4f10de9b2aee66dcc7e7ae6357983095959b817f0383e3030771bd2ed97406acf78a1a4a5f30fa0992289c9202e69e3eb1eabe227c11409ff430f6dfca1a923a8b17bc4b87e908007f5e9759c41482b01
    ],
    -- COUNT = 7
    [ integerToBS 0x68f21d14525d56233c7e263482d344c388a840103a77fb20ac60ce463cabdc79
    , integerToBS 0x59fa80ae570f3e0c60ac7e2578cec3cb
    , BS.empty
    , integerToBS 0x7584b4166530442f06e241dd904f562167e2fdae3247ab853a4a9d4884a5fa46
    , integerToBS 0xf6a5482f139045c5389c9246d772c782c4ebf79c3a84b5cf779f458a69a52914
    , integerToBS 0x9d37b1ce99f8079993ddf0bd54bab218016685b22655a678ce4300105f3a45b7
    , integerToBS 0x4c97c67026ff43c2ee730e7b2ce8cce4794fd0588deb16185fa6792ddd0d46de
    , integerToBS 0xe5f8874be0a8345aabf2f829a7c06bb40e60869508c2bdef071d73692c0265f6a5bf9ca6cf47d75cbd9df88b9cb236cdfce37d2fd4913f177dbd41887dae116edfbdad4fd6e4c1a51aad9f9d6afe7fcafced45a4913d742a7ec00fd6170d63a68f986d8c2357765e4d38835d3fea301afab43a50bd9edd2dec6a979732b25292
    ],
    -- COUNT = 8
    [ integerToBS 0x7988146cbf9598d74cf88dc314af6b25c3f7de96ae9892fb0756318cea01987e
    , integerToBS 0x280bc1ae9bfdf8a73c2df07b82a32c9c
    , BS.empty
    , integerToBS 0x2bbc607085232e5e12ccf7c0c19a5dc80e45eb4b3d4a147fe941fa6c13333474
    , integerToBS 0xf3f5c1bb5da59252861753c4980c23f72be1732f899fdea7183b5c024c858a12
    , integerToBS 0x44d0cfc4f56ab38fa465a659151b3461b65b2462d1ad6b3463b5cf96ad9dc577
    , integerToBS 0x34fb9a3cdacc834ff6241474c4f6e73ed6f5d9ea0337ab2b7468f01ad8a26e93
    , integerToBS 0x4caec9e760c4d468e47613fe50de4a366ae20ba76793744a4e14433ea4de79dc188601eb86c803b094641ab2337b99d459d37decc7d27473057be45ba848868ee0fb5f1cf303d2fcd0b3e0c36f65a65f81b3fee8778a1f22302e25dfe34e6d587fa8864e621121880f7cd55f350531c4ce0530099eec2d0059706dcd657708d9
    ],
    -- COUNT = 9
    [ integerToBS 0x1c974c953fa2a057c9fc9409a6843f6f839aa544bca4fa11e48afd77931d4656
    , integerToBS 0xed7c08285464af7a5dbdc10b944a1270
    , BS.empty
    , integerToBS 0x78146ad135acb836360d36afc50653dcc36c21662da2a6f6ae05222e75f34000
    , integerToBS 0x263c4984c238ded333c86472866353817379502157172cfa51371d82b1efd7b5
    , integerToBS 0x79b591529f9a26a0d7c8f8fd64e354b0c134ef1f757e43f9463b3dbb7a3da1ab
    , integerToBS 0x7d8f7204b0b5401ddce9e88dcf5facb9a44660a9f5f1c862748e7269c29f7964
    , integerToBS 0x72e2ca257b9edaf59b50e05a144f56fb517832fb9ad3489b1e664e3d5412cbf6b2883e891703b2e73aff9ab56da1009fcdef010ab4cdab996795c8f7c47fb1192bb160353997ad39d7d5fd0e2efc9103a7c3f158246afd53fe53ca6782f809698ef5f1f0d85536780a3fd6a8bafa475891c09213088bd1a3dc169257c34a517a
    ],
    -- COUNT = 10
    [ integerToBS 0x56216d71984a77154569122c777ce57e1d101a6025b28163a25971d39c1c5d0f
    , integerToBS 0x5cd148ba7e54f4975ac8e3e0f9b5d06a
    , BS.empty
    , integerToBS 0x3580f8ca974626c77259c6e37383cb8150b4d0ab0b30e377bed0dc9d1ff1a1bf
    , integerToBS 0x15633e3a62b21594d49d3d26c4c3509f96011d4dbb9d48bbbea1b61c453f6abe
    , integerToBS 0x6068eaca85c14165b101bb3e8c387c41d3f298918c7f3da2a28786ab0738a6fc
    , integerToBS 0xe34f92d2b6aeeeea4ff49bfe7e4b1f462eabb853f0e86fbae0e8b3d51409ce49
    , integerToBS 0x587fdb856abc19ede9078797ecb44099e07aadcd83acdcb2b090601d653f4a14c68ab2ebdda63578c5633a825bae4c0c818f89aac58d30fd7b0b5d459a0f3d86fcad78f4bb14dfff08ad81e4ea9f487cb426e91d6e80dfed436ba38fce8d6f21ca2151c92dd5c323b077d6139c66395558f0537026c4a028affa271ef4e7ea23
    ],
    -- COUNT = 11
    [ integerToBS 0x83eb48bedc1e9294866ab8e5322ef83f6f271f8188e8fdabe5817788bd31570d
    , integerToBS 0xd6ed90bc692237f132441ede857a6629
    , BS.empty
    , integerToBS 0xa4e5e127f992bd5ca79ee56bb8a9bccf74c21814bfaf97ffd052211e802e12e4
    , integerToBS 0x84136e403d9ed7f4515c188213abcfaca35715fa55de6d734aec63c4606a68f1
    , integerToBS 0xfe9d8ef26e2d2e94b99943148392b2b33a581b4b97a8d7a0ecd41660a61dd10b
    , integerToBS 0x594dad642183ce2cdc9494d6bcb358e0e7b767c5a0fa33e456971b8754a9abd5
    , integerToBS 0x86715d43ba95fbbca9b7193ea977a820f4b61ba1b7e3b8d161b6c51b09dfd5040d94c04338b14d97ed25af577186b36ae7251a486c8a2d24a35e84a95c89d669d49e307b4a368b72164135ac54d020a970a180dfbed135d2c86f01270846d5301bd73db2c431a8aa10a0a3d03d146e5fafb9a2aa0b4efc80edab06ff3b532236
    ],
    -- COUNT = 12
    [ integerToBS 0xba2c94203dab2e6499d8c50dca7b5c34a6b4764834f9816631aa21b9f9c37361
    , integerToBS 0x67db133bdefb25e395085bceee5a0afc
    , BS.empty
    , integerToBS 0xfa8984d16d35302cda35a3a355ab9242ec96fec0652d39282d4a0abf0a80df87
    , integerToBS 0xb6fed10255a3fea6772ae1ae6d9f6cbb9bfaa34804e58a5b786f9bc60b348ccd
    , integerToBS 0x445e072244edc716d3528f0e0a20ff0cd8f819c0d031736c8da122748f24d6c6
    , integerToBS 0x1f856e403c4fa035bac9aa81a20e347c7d8b213aab699d69d9d6186a06ac45c1
    , integerToBS 0x79f33fc36b3b47d9ac805bdbbe699909a8d0beb689a8b2723c291bd5bf7f3ce61343d4722a14e4add36312dbb0594910c8828aff1abc159915d498106f9ffb31147478d8c9ef75d1536ba5036506b313f6e85033f8f6fea2a4de817c867a59378c53c70a2f108275daedd415c05b61c4fd5d48c54be9adb9dea6c40a2ec99ee0
    ],
    -- COUNT = 13
    [ integerToBS 0x0db4c51492db4fe973b4bb1c52a1e873b58fc6bb37a3a4bfc252b03b994495d1
    , integerToBS 0xa2a3900f169bba3f78a42526c700de62
    , BS.empty
    , integerToBS 0x29d5aab356876447e3a20d81c7e3fc6975e2b984180a91493044442999e1ca3a
    , integerToBS 0x40b34183b4e72cdff5952b317b3d45943d0fdcfa0527f3563055f7c73ae8f892
    , integerToBS 0xdc94220c99ffb595c7c4d6de8de5a6bb4b38847169e24a557ef6d879ad84149d
    , integerToBS 0xb2376626fd2f5218b3ed4a5609b43aa24d371cd2176ea017c2b99cf868060021
    , integerToBS 0xf0bd6bc4c506d9427a09352d9c1970b146360732841a6323f4cb602c87dedfb5ff7e6964b9144933af3c5c83017ccd6a94bdca467a504564aaa7b452591a16ff6a1e7e94ddc98f9a58016cdcb8caaed6c80671ba48cc81a832d341093dda1d4e5001ec6bf66348b21e3692a13df92538ad572bb2023822072fc95f9590293ffc
    ],
    --  COUNT = 14
    [ integerToBS 0x593845f0adfeffa7c169f8a610147ae8a08c0072fc0c14c3977d3de0d00b55af
    , integerToBS 0x9e0eb2507342ee01c02beadee7d077bd
    , BS.empty
    , integerToBS 0xaefe591697eab678c52e20013aa424b95cfd217b259757fbe17335563f5b5706
    , integerToBS 0xcbb5be0ef9bf0555ee58955c4d971fb9baa6d6070c3f7244a4eb88b48f0793bf
    , integerToBS 0x6dd878394abdc0402146ba07005327c55f4d821bfebca08d04e66824e3760ab4
    , integerToBS 0xba86a691d6cbf452b1e2fd1dfb5d31ef9ea5b8be92c4988dc5f560733b371f69
    , 0 `BS.cons` (integerToBS 0x00735cbfafac5df82e5cb28fc619b01e2ba9571dc0023d26f09c37fb37d0e809066165a97e532bf86fa7d148078e865fe1a09e27a6889be1533b459cd9cd229494b5cf4d2abf28c38180278d47281f13820276ec85effb8d45284eb9eef5d179ab4880023ab2bd08ee3f766f990286bf32430c042f5521bbfd0c7ee09e2254d7)
    ]
    ]

{-
    [SHA-256]
    [PredictionResistance = False]
    [EntropyInputLen = 256]
    [NonceLen = 128]
    [PersonalizationStringLen = 256]
    [AdditionalInputLen = 0]
    [ReturnedBitsLen = 1024]
-}

r3 :: [[BS.ByteString]]
r3 =
    [
    -- COUNT = 0
    [ integerToBS 0xfa0ee1fe39c7c390aa94159d0de97564342b591777f3e5f6a4ba2aea342ec840
    , integerToBS 0xdd0820655cb2ffdb0da9e9310a67c9e5
    , integerToBS 0xf2e58fe60a3afc59dad37595415ffd318ccf69d67780f6fa0797dc9aa43e144c
    , integerToBS 0xe0629b6d7975ddfa96a399648740e60f1f9557dc58b3d7415f9ba9d4dbb501f6
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0xf92d4cf99a535b20222a52a68db04c5af6f5ffc7b66a473a37a256bd8d298f9b4aa4af7e8d181e02367903f93bdb744c6c2f3f3472626b40ce9bd6a70e7b8f93992a16a76fab6b5f162568e08ee6c3e804aefd952ddd3acb791c50f2ad69e9a04028a06a9c01d3a62aca2aaf6efe69ed97a016213a2dd642b4886764072d9cbe
    ],
    -- COUNT = 1
    [ integerToBS 0xcff72f345115376a57f4db8a5c9f64053e7379171a5a1e81e82aad3448d17d44
    , integerToBS 0xd1e971ec795d098b3dae14ffcbeecfd9
    , integerToBS 0x6ec0c798c240f22740cad7e27b41f5e42dccaf66def3b7f341c4d827294f83c9
    , integerToBS 0x45ec80f0c00cad0ff0b7616d2a930af3f5cf23cd61be7fbf7c65be0031e93e38
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0x17a7901e2550de088f472518d377cc4cc6979f4a64f4975c74344215e4807a1234eefef99f64cb8abc3fb86209f6fc7ddd03e94f83746c5abe5360cdde4f2525ccf7167e6f0befae05b38fd6089a2ab83719874ce8f670480d5f3ed9bf40538a15aaad112db1618a58b10687b68875f00f139a72bdf043f736e4a320c06efd2c
    ],
    -- COUNT = 2
    [ integerToBS 0xb7099b06fc7a8a74c58219729db6b0f780d7b4fa307bc3d3f9f22bfb763596a3
    , integerToBS 0xb8772059a135a6b61da72f375411de26
    , integerToBS 0x2ac1bfb24e0b8c6ac2803e89261822b7f72a0320df2b199171b79bcbdb40b719
    , integerToBS 0x9aec4f56ec5e96fbd96048b9a63ac8d047aedbbeea7712e241133b1a357ecfc4
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0x0e1f2bfef778f5e5be671ecb4971624ec784ed2732abc4fbb98a8b482fb68737df91fd15acfad2951403ac77c5ca3edffc1e03398ae6cf6ac24a91678db5c7290abc3fa001aa02d50399326f85d2b8942199a1575f6746364740a5910552c639804d7530c0d41339345a58ff0080eccf1711895192a3817a8dc3f00f28cc10cc
    ],
    -- COUNT = 3
    [ integerToBS 0x7ba02a734c8744b15ef8b4074fe639b32e4431762ab5b7cd4d5df675ea90672b
    , integerToBS 0x8a424f32108607c8f1f45d97f500ee12
    , integerToBS 0x3ad627433f465187c48141e30c2678106091e7a680229a534b851b8d46feb957
    , integerToBS 0xd8f02b59b6a3dd276bc69cba68efcf11ab83ead1397afd9841786bd1bb5da97a
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0x1fb91186ba4b4459d994b4b9f4ca252c7be6294d6cdb5fe56f8ff784d4b190a1c6456e0a41223bbbdf83ed8e7cfbfa765d9d8bc7ea5f4d79ea7eccb4928081a21de4cca36620d6267f55d9a352b76fc0a57375884112c31f65ff28e76d315698c29e6c4c05cb58b0a07ae66143b4abc78b9d25c78b4121e1e45bef1a6c1793e2
    ],
    -- COUNT = 4
    [ integerToBS 0x9a8865dfe053ae77cb6a9365b88f34eec17ea5cbfb0b1f04d1459e7fa9c4f3cb
    , integerToBS 0x180c0a74da3ec464df11fac172d1c632
    , integerToBS 0x336372ec82d0d68befad83691966ef6ffc65105388eb2d6eed826c2285037c77
    , integerToBS 0x75b95108eff1fabe83613e1c4de575e72a5cdc4bb9311dd006f971a052386692
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0x3c683f6d4f8f5a4018d01633dfee74266aaa68ed6fc649e81b64dfdf5f75e75d5c058d66cf5fd01a4f143a6ff695517a4a43bd3adfd1fb2c28ba9a41063140bedbffdb4d21b1ace1550d59209ec61f1e2dbacb2a9116a79cb1410bf2deca5218080aacd9c68e1d6557721a8913e23f617e30f2e594f61267d5ed81464ee730b2
    ],
    -- COUNT = 5
    [ integerToBS 0x22c1af2f2a4c885f06988567da9fc90f34f80f6dd5101c281beef497a6a1b2f8
    , integerToBS 0x3fafdecf79a4174801f133131629037b
    , integerToBS 0x80327dac486111b8a8b2c8e8381fb2d713a67695c2e660b2b0d4af696cc3e1de
    , integerToBS 0xf95a0e4bd24f0e2e9e444f511b7632868ead0d5bb3846771264e03f8ab8ed074
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0x77a7fea2f35a188f6d1bfdd49b569d8c45e2dd431d35a18c6f432c724f1e33ae92cb89a9cf91519e50705a53199f5b572dc85c1aef8f28fb52dc7986228f66954d54eda84a86962cf25cf765bd9949876349291b1aae5f88fcf4b376912d205add4f53b2770c657946c0d824281f441509153f48356d9d43f8a927e0693db8fc
    ],
    -- COUNT = 6
    [ integerToBS 0xd0840e3a8d629d5b883d33e053a341b21c674e67e1999f068c497ecfaabfd6f6
    , integerToBS 0x071de7244ecb2fdf7ab27f2d84aa7b7a
    , integerToBS 0x90d609527fad96ffe64ab153860346f3d237c8940555ae17b47842d82d3b0943
    , integerToBS 0x1dd1a8b59856c49a388f594c5f42cc2e4a56b3ccb8a65e7066e44c12f4344d50
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0x7ab28a9b2d3ae999195553e6550cced4c2daccbe7ec9dcbb0d467fabba185b727fbfd9830242cd098f4db3cf4a85e8bf8e8d5974b62b28550922b32ed5bfc1a522b6605cf93bf8d90bdec1c5b9e59c6fc37a817d437068a87254be1f7c4618ada46fbc3a2efb02e44524e21d91be7534cf05fbfd858304b706d6a91ea1cc6ad5
    ],
    -- COUNT = 7
    [ integerToBS 0x2e2dd56869104492767a59778652831919e1c8b970f84e824ae4116597a0ab7f
    , integerToBS 0x01c42a7e983641de46c82fd09b4f2f76
    , integerToBS 0xbcd9e1508fcc22820a8be07180fea5045367333b569e111b011cd57dc1858765
    , integerToBS 0x7306507cd3ca7eec667e640d270cfbb033063d97520b6b7e38ff3cea0e79d12b
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0xb915726c7b8c5dc3975f1a334684b973abf6a9495d930088cf5d071548e4fd29a67b55cc561ed6949ad28150a9fb4307c1fa5f783a7ea872e8d7c7e67ff0c2906081ee915737d813c25be5c30b952a36f393e6baa56ab01adc2b4776ad7b5d036a53659877c7a4e5220a897d6c0799af37beeed91173fbe9c613c3b6b9bb28e5
    ],
    -- COUNT = 8
    [ integerToBS 0xd1aab0f16bd47a5ccd67c22e094daa3735eae21aa57f0bcd9e053d9d0d545cb8
    , integerToBS 0x199310dfe1b01265b8c0d2b46d6c7c9f
    , integerToBS 0x625b4b8f4de72ea9cb6f70556322dc2a19d6b2b32de623f557e419a084ba60fd
    , integerToBS 0xf50cabae4e060f3971096b78e550cda2837a26a693d905db2d992d589b268f44
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0x987e1fdfe004c619cf1e9034576707eccd849400e19c87a1fef5b0179ec51c42a2f8c45d7942d0023a023c89f188b2634362703985695369863322f58619c50a7385a2dc91fc78f94b59f0131dc2b56a0d7c699d427285da1c104b0ad1739da10d8071c23993787045dc21f0070e1e9aa1658fc8e3add73dac7262e80e0aa2ee
    ],
    -- COUNT = 9
    [ integerToBS 0x449480eaa100aff6f48dc6286a5a81b9728b084864f78a9da98f606a00a6a41f
    , integerToBS 0xe53c6c5ac3da9f4726389a03f97bb640
    , integerToBS 0x6b8fedc084d8e28d333aef6db3702b6351f0d24e30908cccb63794282655886b
    , integerToBS 0x73a6d64e1966ae324388dc12c14544e9dc5ae4fcb331e99d350c456ff16f9aa0
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0xa06912d362da7eb25598857f6d65344c3e23ec3deb80c6e43158845b95eaeca241c0bbbd67ac385e24693444455cc1c2c08c1134d956b8bc93b28be9c2d3322b3e09252979dfb8d39d04c94f81bebda5c73110605a237b561216bda9ee9bdee1cc0c7728bcc8304682334ca944e467a27a85313fa5395a9c790e35defd2edb12
    ],
    -- COUNT = 10
    [ integerToBS 0x9a6174166e97aa4981ddf580bc01c96754b9f0ba042750aabfda1cffe56e8581
    , integerToBS 0xd7512ff6b7db7ce141b2bb01dcd0425e
    , integerToBS 0xed75288f23275f9422444da5d3b53ccb3c4ac8acfb659a1e9b7655c2db52f879
    , integerToBS 0x6888b9277e57dc57663d402eba8d03cf56a070dc868e6a128b18040002baf690
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0x03519dfb2ff88cc2b53eecc48ae2a18ddcf91a5d69d5aefcdda8444e6df790a5240e67b2a4de75b4bb8a31f0f8aeb5e785ffb7a1341bb52fe00a05ee66fa2d44ea9956e055f9ffa6647c3bfe851ab364ade71a0d356de710ddafb7622b1da1bc53fd4d3210407289c68d8aeb346bf15806dbe787e781b94f63da3e1f61b5ac60
    ],
    -- COUNT = 11
    [ integerToBS 0x9c6ae1002ee1b0add0be563ce50f899da936e13efa620d08c2688c192514763a
    , integerToBS 0xfde7db5160c73044be73e9d4c1b22d86
    , integerToBS 0x8fdaaeffd64e53f7b4374d902d441209964e12b65d29afec258e65db6de167ca
    , integerToBS 0xbcc28fd58e397f53f494ad8132df82c5d8c4c22ea0b7139bd81eeba65667bb69
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0x021d938c9b4db780c7d8134aeff1053e5b8843370b8ae9a6749fca7199d809810f1bc8dfa49426470c30c3616f903e35fbacb23420a32f1bee567cc32300f704246ddc0217f236ef52c3ec9e2433ca66f05c25721f7661c43f22c1a125ed5db531bd0836eb435c27eefc7424ce9d845e1d4cc4c503097b4ffca788e674a5cb53
    ],
    -- COUNT = 12
    [ integerToBS 0xfe96a85b69d46b540918927bb609dc57642eeaefd46bb5da2163a0bc60294b58
    , integerToBS 0x22195a410d24db45589448dfe979d3fd
    , integerToBS 0x20f698833a4472fd7b78fb9b0c4eb68604f166a2694c4af48dac2b2376790e1e
    , integerToBS 0x09cb870879d3f734214f6a4bd2e08c62a2a954bebe559416d8c3551aafe71d6a
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0xd3e96dbe29e1fcb8ed83b19dbfb240e6f41679fbe83853aa71446617e63e5af78cf98b331d15bccb8c673c4e5d5dcec467a1fe26a6cd1696d0c9bc49f78139d051287df7f3ae0dbb4bbf581cb8211931063c3f4612ced53f59d1b4ebb875729139f5d2a7d60642e8f2835eed888b7e3e49c0dffd012cd746abfa3e1c5c2308c6
    ],
    -- COUNT = 13
    [ integerToBS 0xa4fd693ff0a8af24bcec352d3196549fd0da5ee5d99ca58416ca03ce4c50f38e
    , integerToBS 0x8cd67f2bf71d4366ce61396642531ff5
    , integerToBS 0x368969c15a4849d7593be8b162113b9298a535c148ff668a9e8b147fb3af4eba
    , integerToBS 0x83d2be9a0d74e6a42159ae630acebf4e15271ef7f14f3de14752be0e0e822b11
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0xe9188fc0eaec74b2608e21e3a40be94aaf4ae08eb684de8f8bba2d5fd3b073aa5531c938c0fc628da65725c54b5c68bb91d7d326565e96685e0a4e7b220c50e0caf1628edba5bd755b31894f8cb90afa76e88c5eb9e61b4932444c1397dee3e32241a3fb70a3929e49f6da02eea54812abb3d6b5cee18f03af1e0b4958430ab3
    ],
    -- COUNT = 14
    [ integerToBS 0x254ff5687a6dad3f1d237dc762f58d24ef2e2c084d0a48d26a3dc81e5490cda3
    , integerToBS 0xf2ec392acca491e03ce47b95963a49fc
    , integerToBS 0xf806b9b4a56682c61b55cb6a334caf87ffe135adfea6d0c3fc22b39898fbd078
    , integerToBS 0xb8494b1c1f1752fb6f80d732a89b08115857f7cc96e7dff05ebb822706889917
    , BS.empty
    , BS.empty
    , BS.empty
    , integerToBS 0x0e527e00494d55564f9d9b28e7110f9a61ce36c883b5be2dcb055444164cdddd1a9f2731716f22d6ff476ce413c77abfc0e946871d5481345c2e97b4bfdd12ac03df606fc56bdb99ac7b71a69b5b9160373bbec3e9dde477180af454e7acc6bc58dc0afb4281c0de4354c1bf599054e3800c6d60d892858865b5361f50bfca9b
    ]
    ]

{-
    [SHA-256]
    [PredictionResistance = False]
    [EntropyInputLen = 256]
    [NonceLen = 128]
    [PersonalizationStringLen = 256]
    [AdditionalInputLen = 256]
    [ReturnedBitsLen = 1024]
-}

r4 :: [[BS.ByteString]]
r4 =
    [
    -- COUNT = 0
    [ integerToBS 0xcdb0d9117cc6dbc9ef9dcb06a97579841d72dc18b2d46a1cb61e314012bdf416
    , integerToBS 0xd0c0d01d156016d0eb6b7e9c7c3c8da8
    , integerToBS 0x6f0fb9eab3f9ea7ab0a719bfa879bf0aaed683307fda0c6d73ce018b6e34faaa
    , integerToBS 0x8ec6f7d5a8e2e88f43986f70b86e050d07c84b931bcf18e601c5a3eee3064c82
    , integerToBS 0x1ab4ca9014fa98a55938316de8ba5a68c629b0741bdd058c4d70c91cda5099b3
    , integerToBS 0x16e2d0721b58d839a122852abd3bf2c942a31c84d82fca74211871880d7162ff
    , integerToBS 0x53686f042a7b087d5d2eca0d2a96de131f275ed7151189f7ca52deaa78b79fb2
    , integerToBS 0xdda04a2ca7b8147af1548f5d086591ca4fd951a345ce52b3cd49d47e84aa31a183e31fbc42a1ff1d95afec7143c8008c97bc2a9c091df0a763848391f68cb4a366ad89857ac725a53b303ddea767be8dc5f605b1b95f6d24c9f06be65a973a089320b3cc42569dcfd4b92b62a993785b0301b3fc452445656fce22664827b88f
    ],
    -- COUNT = 1
    [ integerToBS 0x3e42348bf76c0559cce9a44704308c85d9c205b676af0ac6ba377a5da12d3244
    , integerToBS 0x9af783973c632a490f03dbb4b4852b1e
    , integerToBS 0x2e51c7a8ac70adc37fc7e40d59a8e5bf8dfd8f7b027c77e6ec648bd0c41a78de
    , integerToBS 0x45718ac567fd2660b91c8f5f1f8f186c58c6284b6968eadc9810b7beeca148a1
    , integerToBS 0x63a107246a2070739aa4bed6746439d8c2ce678a54fc887c5aba29c502da7ba9
    , integerToBS 0xe4576291b1cde51c5044fdc5375624cebf63333c58c7457ca7490da037a9556e
    , integerToBS 0xb5a3fbd57784b15fd875e0b0c5e59ec5f089829fac51620aa998fff003534d6f
    , integerToBS 0xc624d26087ffb8f39836c067ba37217f1977c47172d5dcb7d40193a1cfe20158b774558cbee8eb6f9c62d629e1bcf70a1439e46c5709ba4c94a006ba94994796e10660d6cb1e150a243f7ba5d35c8572fd96f43c08490131797e86d3ed8467b692f92f668631b1d32862c3dc43bfba686fe72fdd947db2792463e920522eb4bc
    ],
    -- COUNT = 2
    [ integerToBS 0xb63fdd83c674699ba473faab9c358434771c5fa0348ca0faf7ebd7cf5891826b
    , integerToBS 0x5fd204e2598d9626edab4158a8cfd95f
    , integerToBS 0x2a5dfad8494306d9d4648a805c4602216a746ae3493492693a50a86d1ba05c64
    , integerToBS 0xadea5ba92f8010bb1a6a4b6fae2caa0b384165adf721253afd635d6021f764af
    , integerToBS 0x07c69d8d2b8aa1454c5c48083dd41477fda6bfcf0385638379933a60ed2e0a77
    , integerToBS 0xa14e902247a3d6493d3fbc8519518b71a660e5502cf7ecfc796cfaa5b4ee4baa
    , integerToBS 0x60e690e4a1eba14aec5187112a383e9991347fab7bac7cb2a40a52579a0d2718
    , integerToBS 0x792b47b6ed221623bb187d63e3f039c6983d94efd5771dc9b4c40bee65924513485a6332baeda6a96f9bb431f592d73462b61d9d914a72b56fa9d87597426fb246424ebcd7abd51b2eefec8f5b839c0b3c34015342ace296b5f2218fa194b50aea1c89663460292c92c45f112ddbf6b9406f6e7ccee9c47ed2d90a27be5dd73e
    ],
    -- COUNT = 3
    [ integerToBS 0xdab85f98eaf0cfba013b97de4d9c264ca6fe120366cb83e8b3113c68b34e39d5
    , integerToBS 0xd05108e1028ae67b4ea63bdc6d75eb88
    , integerToBS 0x09fed3822f6f5e5b9e575d31dc215de1607b0dfc927412618c2d8f79166dbaba
    , integerToBS 0x1794885a64470744198b7d0bc24472ffe8daf3c7eb219df6ddf180e484fe0aa5
    , integerToBS 0x8d74d01b582f70b92f53b43468084e1586d9b36465d333d5faaf6911e62fe40e
    , integerToBS 0xef7f6b6eb479ab05b3f9ab6dd72eac8b1e86d887f1bcae363cae386d0275a06f
    , integerToBS 0x7442b2a792a6a29559bb8a515d56916ee18200580aa02e1237dd358619382d8f
    , integerToBS 0x49d2cbfa0897b7d961c293c1e572fb26f28e7b956e746f6eda90454c1370a29e25303ceadc7837514dc638553b487ef9487c977c10625409178ad6506d103c487a66655d08659d92a4d5994d1c8ddb28fe60f2e49577d6e80cae1478068c98268f45e6293c9326c7f726ec89601351c0a26fd3a6549f8a41c6f58692c86594c0
    ],
    -- COUNT = 4
    [ integerToBS 0x0f0aa84ef12e10ae2b279e799c683441862457b9bc25581c2cd3d5b58a5b3246
    , integerToBS 0xf74f4230c2427a52f01f39e825d250ac
    , integerToBS 0xd02b2f53da48b923c2921e0f75bd7e6139d7030aead5aeebe46c20b9ca47a38a
    , integerToBS 0x5222b26e79f7c3b7066d581185b1a1f6376796f3d67f59d025dd2a7b1886d258
    , integerToBS 0xd11512457bf3b92d1b1c0923989911f58f74e136b1436f00bad440dd1d6f1209
    , integerToBS 0x54d9ea7d40b7255ef3d0ab16ea9fdf29b9a281920962b5c72d97b0e371b9d816
    , integerToBS 0x601cef261da8864f1e30196c827143e4c363d3fa865b808e9450b13e251d47fa
    , integerToBS 0xe9847cefea3b88062ea63f92dc9e96767ce9202a6e049c98dc1dcbc6d707687bd0e98ed2cc215780c454936292e44a7c6856d664581220b8c8ca1d413a2b81120380bfd0da5ff2bf737b602727709523745c2ced8daef6f47d1e93ef9bc141a135674cba23045e1f99aa78f8cead12eeffff20de2008878b1f806a2652db565a
    ],
    -- COUNT = 5
    [ integerToBS 0x6a868ce39a3adcd189bd704348ba732936628f083de8208640dbd42731447d4e
    , integerToBS 0xefdde4e22b376e5e7385e79024350699
    , integerToBS 0xf7285cd5647ff0e2c71a9b54b57f04392641a4bde4a4024fa11c859fecaad713
    , integerToBS 0x0174f7f456ac06c1d789facc071701f8b60e9accebced73a634a6ad0e1a697d4
    , integerToBS 0x5463bb2241d10c970b68c3abc356c0fe5ef87439fc6457c5ee94be0a3fb89834
    , integerToBS 0x3ab62cdbc638c1b2b50533d28f31b1758c3b8435fe24bb6d4740005a73e54ce6
    , integerToBS 0x2dbf4c9123e97177969139f5d06466c272f60d067fefadf326ccc47971115469
    , integerToBS 0x8afce49dccc4ff64c65a83d8c0638bd8e3b7c13c52c3c59d110a8198753e96da512c7e03aeed30918706f3ad3b819e6571cfa87369c179fb9c9bbc88110baa490032a9d41f9931434e80c40ae0051400b7498810d769fb42dddbc7aa19bdf79603172efe9c0f5d1a65372b463a31178cbae581fa287f39c4fbf8434051b7419f
    ],
    -- COUNT = 6
    [ integerToBS 0xbb6b339eae26072487084ec9e4b53f2f1d4267d205042e74c77fb9ca0591ba50
    , integerToBS 0xc0e7bf6eb07feccbc494af4098e59d30
    , integerToBS 0x34aeec7ed0cae83701b6477709c8654a1114212401dc91cbe7de39d71f0c06e1
    , integerToBS 0xf47fc60afbeb807236f7974d837335bc0b22288ef09ddfcb684e16b4c36a050b
    , integerToBS 0xe8071ccd84ac4527e5c6e85b0709ed867776f25ae0e04180dcb7105ecd3e3490
    , integerToBS 0xfbac45b5952200ad7c4232500f2417a1c14723bdd1cc078821bc2fe138b86597
    , integerToBS 0xc4292d7dbef3ba7c18bf46bcf26776add22ab8ee206d6c722665dec6576b1bc0
    , integerToBS 0x228aa2a314fcbfe63089ce953ac457093deaa39dd9ce2a4ece56a6028a476a98129be516d6979eff5587c032cdf4739d7ac712970f600fa781a8e542e399661183e34e4b90c59ec5dc5cad86f91083529d41c77b8f36c5a8e28ba1a548223a02eaed8426f6fe9f349ebec11bc743e767482e3472ec2799c1f530ebdc6c03bc4b
    ],
    -- COUNT = 7
    [ integerToBS 0xbe658e56f80436039e2a9c0a62952dd7d70842244b5ab10f3b8a87d36104e629
    , integerToBS 0x33c9627455dfde91865aee93e5071147
    , integerToBS 0xd3a6eb29b180b791984deb056d72c0608a2c9044237aecf100ccb03700064c5e
    , integerToBS 0xbef24dc9a5aa23003d3825f9b2b00e7dab571ea6ad86415dbd30c0bbdce7b972
    , integerToBS 0x047c29e4d1584fa70cb66e2aa148a2aa29837c5eee64dcac60fdba356cdf90bb
    , integerToBS 0x41c4792161b1b00d410cb79cd56bd311a714fb78dc3471c25bdd7479f2e9a952
    , integerToBS 0xcd4936d7bc3ea0e7201bcbefbc908215a97680ca6ce8672360aea600b6564308
    , integerToBS 0x2c25557f6db07db057f56ad5b6dc0427d1a0e825c48c19a526f9a65087c6d1ead7c78363a61616c84f1022653af65173a3f9ec3275f2b0a0d0bc750194673c0eaa6c623cd88abb0c8979baee4cd85bfce2e4a20bfebf2c3be61676563767dfe229e0b7be67ad6fcd116dd0b460708b1b0e5c3d60f3dd8138030404d197375d75
    ],
    -- COUNT = 8
    [ integerToBS 0xae537f31a28ca14500e759716bc207983bfeab60b25079fa30b77b8d41244cb9
    , integerToBS 0xfca9e27d8ab84cf9b9ce491ec5d8cb67
    , integerToBS 0x8c9cb2b19aa3abe83c8fe7da96e9c11648252653a29dcd5bf0ac334ac587f032
    , integerToBS 0x1eb52777be480f05115ae6370f30159a94d50ffcc64454678ab1d1ac6f166fa7
    , integerToBS 0x9cdf6f1a2bc07acd4b0f43b5f2b892a1153e2669f237d257923636094fb40b54
    , integerToBS 0x692d512722de6ba720fd23c8994ac63179b5f7e611addf9cfacd60e06e144a6a
    , integerToBS 0xbbeea7b2bea821f339f494947c0b4bae8056119db69a3cbef21914953729cdef
    , integerToBS 0xc0c4fb7080c0fbe425c1b756fb3a090cb0d08c7027d1bb82ed3b07613e2a757f83a78d42f9d8653954b489f800a5e058ebc4f5a1747526541d8448cb72e2232db20569dc96342c36672c4be625b363b4587f44557e58cedb4597cb57d006fda27e027818ae89e15b4c6382b9e7a4453290ea43163b4f9cae38b1023de6a47f7b
    ],
    -- COUNT = 9
    [ integerToBS 0x2f8994c949e08862db0204008f55d3561f3e0362df13b9d9a70fda39938f2d33
    , integerToBS 0x1bf3e94ea858160b832fe85d301256f5
    , integerToBS 0xb46671cf7fa142e7012ed261e1fe86714711c246c7d1c0330fa692141e86d5d1
    , integerToBS 0x5ecdb1e8fe12260b9bfe12d6e6f161474fa2311e12e39b0beb0fcd92a6737b73
    , integerToBS 0x3ce9a29f0207d079e6dc81fb830356e555f96a23ea71424972ea9308965786d3
    , integerToBS 0xdb950000c0776cc0e049929ce021020adc42d29cd9b5d8f7117fbe6bde3e594f
    , integerToBS 0xfc18ee6dd3dac2306774f0ac36cd789e33462d72a8c75df9057123db33e5f7bc
    , integerToBS 0x8546362cc8af9b78dd6e8eb2c37db96e70708852bfd9380abedc7f324575a167bea18f632f3e19d099cfbf310773f9719eec036d2e09f393a023add8ebdc4fb87af43b2fe6c7eaa4d39f8022ce247aa45fdc84d1b92cacce6eae8252a03ec2ec5330c01f56d113fd2ec3d0240af0afcf13ddde205bb5e7c2d912dcb4aee5dcf3
    ],
    -- COUNT = 10
    [ integerToBS 0x0c85e31487de1d7ba4a7b998ac56dc42c6dc0eae7bf5c8aaf1e4e78875f5fb47
    , integerToBS 0xde878f728f73f83dc2a2f550b96c8b97
    , integerToBS 0x9aac37bce1a6a81dc7934e23747991e3cf48c55ffe5a57781c41768a35220a01
    , integerToBS 0x2d5ca8af1a70cfdccd015ee3bf0665dd1941fc6a7317b9d0d06658f5744cfbd9
    , integerToBS 0xdb881e6d0dc3b62793d7da5fe5a18e33be9b93f4a63a00a878dfbecf0d383bd2
    , integerToBS 0xf743ce1b72f3de4c901369eed581c626ed3081ca707e6634fdaff46721ce0878
    , integerToBS 0xcd52da3ec8a839c537dacdea8506a3eeee879de388ff5e513322d6d1bb3ff694
    , integerToBS 0xa5bdd57cb8fde6298e7c5e563afcca60dd472eca484bd8c3cc17f3307be09b601744dd3ab9e8a44107c5868824575f850c0f399b280cf198006f83ede8c0b537e9be227fa140b65995ad9dfa1f2303d560c3b7f59bedd93c1282ea263924469411c2653f87fd814c74cb91c148430481d64bad0fec3cbb3dd1f39aa55c36f81b
    ],
    -- COUNT = 11
    [ integerToBS 0x93161b2dc08cb0fd50171141c865a841ca935cfdd2b5907d6ff8ab0348c4ceb0
    , integerToBS 0x5cb9f6e5912b90c3349a50ab881b35a1
    , integerToBS 0x0dceb4a36326c4df1685df43fddeecb5d0c76f00eb44826694f27e610290f6e1
    , integerToBS 0xd8e9be44b5f293482548d4787762ebfb03c73c40e45385e8b98907cd66f493dd
    , integerToBS 0x105a8f85d6959f3e043ef508cfea21d52123f03b7aea8034c4eec761eaba1fee
    , integerToBS 0xbf781f7e489d9b4b5aa5ee6d1796468af672a8d25f311edf3c4b4dbf433d703f
    , integerToBS 0xc81d6bcf1e5bf37e39dda1735c6f193df115b1a854a12e7cafe060afe4589335
    , integerToBS 0x4306628124d0100fade7eaaf5edf227d50771f9e5f2e1e983800eef9a39fde0b0c280e63c8728d836b5b93ea794a32c1c04cfc54bd5300e3febb5fe2e1023eded8d7cd180279a598f76823e8d5a7dffcc93a09deec5d1f80838e938fba4de9f47e94b99382ae55f116df9c3b3ddf7e50516e203645852a415796f03a86418107
    ],
    -- COUNT = 12
    [ integerToBS 0x1ae12a5e4e9a4a5bfa79da30a9e6c62ffc639572ef1254194d129a16eb53c716
    , integerToBS 0x5399b3481fdf24d373222267790a0fec
    , integerToBS 0x8280cfdcd7a575816e0199e115da0ea77cae9d30b49c891a6c225e9037ba67e2
    , integerToBS 0x681554ff702658122e91ba017450cfdfc8e3f4911153f7bcc428403e9c7b9d68
    , integerToBS 0x226732b7a457cf0ac0ef09fd4f81296573b49a68de5e7ac3070e148c95e8e323
    , integerToBS 0x45942b5e9a1a128e85e12c34596374ddc85fd7502e5633c7390fc6e6f1e5ef56
    , integerToBS 0x6fc59929b41e77072886aff45f737b449b105ed7eacbd74c7cbfedf533dbeaa1
    , integerToBS 0xb7547332e1509663fcfea2128f7f3a3df484cd8df034b00199157d35d61e35f1a9d481c7d2e81305616d70fc371ee459b0b2267d627e928590edcac3231898b24ef378aa9c3d381619f665379be76c7c1bd535505c563db3725f034786e35bdd90429305fd71d7bf680e8cdd6d4c348d97078f5cf5e89dee2dc410fad4f2a30f
    ],
    -- COUNT = 13
    [ integerToBS 0x29e20d724dfa459960df21c6ec76b1e6cabd23a9e9456d6c591d7e4529da0ef8
    , integerToBS 0x95df1f837eba47a1687aa5c4ddcf8aaf
    , integerToBS 0x3713b601e164b1a51dda1ca9242ff477514648e90d311a06e10ce5aa15da5d7f
    , integerToBS 0x2a2a312626ca3e20034fc4f28033c7d573f66ef61ab2ea0c7bf0411a9d247264
    , integerToBS 0xec68be33ac8ff3dd127e051604898c0f9a501271859376653a0516336180993d
    , integerToBS 0x9935499661d699a00c622a875441b4df5204958fe95892c8ce67f7dfb2be3e4a
    , integerToBS 0x256a4ba9e8f439d5487fa5eb45efcf1bc1120491724db3abe328d951f2739fc9
    , integerToBS 0x73114cb3624d687d4cd49a6e769dfc7a3f8901dc41f6ad1df4ce480536fa82e52ae958d0528640d92b8bb981b755058e32c4733682e5c4c0df41f3505a1643a0dd49cfdeaf7a18adffca88256c6d2cceb838af6c92a64bc21cb7a760a0391291bfe3575e014fc156323f8eb5e86518c669dad8d29ad5fd4ef6e296f4a0764c26
    ],
    -- COUNT = 14
    [ integerToBS 0x1353f3543eb1134980e061fc4382394975dbc74f1f1ea5ecc02780a813ac5ee6
    , integerToBS 0xcf584db2447afbe2c8fa0c15575ee391
    , integerToBS 0x345b0cc016f2765a8c33fc24f1dcfa182cbe29d7eacbcdc9bcda988521458fc2
    , integerToBS 0xba60219332a67b95d90ec9de6b8453d4c8af991ae9277461ff3af1b92fc985d3
    , integerToBS 0x6964b9b9842aec9c7ec2aad926d701f30eec76fe699265ae2a7765d716958069
    , integerToBS 0x6a03c28a9365c558c33d3fdc7e5ebf0b4d32caac70df71403fd70ced09757528
    , integerToBS 0xa58546c72a0b4d47c9bd6c19e7cf4ab73b2d7ba36c6c6dc08606f608795ebd29
    , integerToBS 0x5b029ef68b6799868b04dc28dbea26bc2fa9fcc8c2b2795aafeed0127b7297fa19a4ef2ba60c42ff8259d5a759f92bd90fdfb27145e82d798bb3ab7fd60bfaefb7aefb116ca2a4fa8b01d96a03c47c8d987fdd33c460e560b138891278313bb619d0c3c6f9d7c5a37e88fce83e94943705c6ff68e00484e74ad4097b0c9e5f10
    ]
    ]

