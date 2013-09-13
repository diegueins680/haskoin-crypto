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
    ]

testDRBG :: [BS.ByteString] -> Assertion
testDRBG v = do
    let w1     = hmacDRBGNew (v !! 0) (v !! 1) (v !! 2)
        (w2,_) = hmacDRBGGen w1 128 (v !! 3)
        (_,r)  = hmacDRBGGen w2 128 (v !! 4)
    assertBool "HMAC DRBG" $ fromJust r == (v !! 5)


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


