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
-- Using /dev/urandom in this example 
-- You should probably use /dev/random in production
random256 :: IO BS.ByteString
random256 = withBinaryFile "/dev/urandom" ReadMode $ flip BS.hGet 32

main :: IO ()
main = do

    -- Build an Integer from a random source
    rnd <- bsToInteger <$> random256

        -- Build a private key from a random Integer
        -- Will fail if random256 is not > 0 and < curve order N
    let prv = fromJust $ makePrvKey rnd
        -- Derive the public key from a private key
        pub  = derivePubKey prv
        -- Compute the bitcoin address from the public key
        addr = addrToBase58 $ pubKeyAddr pub
        -- Serialize the private key to WIF format
        wif  = toWIF prv
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
    withSecret seed $ do 

        -- Generate private keys derived from the internal PRNG
        prv1 <- genPrvKey
        prv2 <- genPrvKey

            -- Create a message in ByteString format
        let msg = BS.pack [1,3,3,7]
            -- Compute two rounds of SHA-256
            hash = doubleHash256 msg

        -- Signatures are signed with nonces derived from the internal PRNG
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

