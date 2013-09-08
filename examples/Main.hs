import Haskoin.Crypto
import Haskoin.Util (bsToInteger)

-- For serializing/de-serializing interface
import Data.Binary (encode, decodeOrFail)

-- Access to /dev/random
import System.IO
import qualified Data.ByteString as BS

import Data.Maybe (fromJust)
import Control.Applicative ((<$>))

-- Generate a random Integer with 256 bits of entropy
random256 :: IO Integer
random256 = withBinaryFile "/dev/random" ReadMode $ \h -> do
    bs <- BS.hGet h 32 -- Read 32 bytes
    return $ bsToInteger bs

main :: IO ()
main = do

    -- Create a private key from a random source
    -- Will fail if random256 is not > 0 and < curve order N
    prv <- (fromJust . makePrvKey) <$> random256

        -- Derive the public key from a private key
    let pub   = derivePubKey prv
        -- Compute the bitcoin address from the public key
        addr  = addrToBase58 $ pubKeyAddr pub
        -- Serialize the private key to WIF format
        wif   = toWIF prv
        -- Deserialize a private key from WIF format
        prv' = fromWIF wif

        -- Serialize and de-serialize a public key
        -- See Data.Binary for more details
    let pubBin = encode pub
        pub'   = case decodeOrFail pubBin of
            (Left  (_, _, err)) -> error err
            (Right (_, _, res)) -> res :: PubKey

    -- Generate a random seed to create signature nonces
    seed <- random256
    -- Initialize a safe environment for creating signatures
    withECDSA seed $ do 
            -- Create a message in ByteString format
        let msg = BS.pack [1,3,3,7]
            -- Compute two rounds of SHA-256
            hash = doubleHash256 msg

        -- Signatures are guaranteed to use different nonces
        sig1 <- signMessage hash prv
        sig2 <- signMessage hash prv

        -- Verify signatures
        let ver1 = verifySignature hash sig1 pub
            ver2 = verifySignature hash sig2 pub

            -- Serialize and de-serialize a signature
            -- See Data.Binary for more details
        let sigBin = encode sig1
            -- Deserialize a signature
            sig1'  = case decodeOrFail sigBin of
                (Left  (_, _, err)) -> error err
                (Right (_, _, res)) -> res :: Signature

        return ()

    print $ (show prv)
    print $ (show seed)

