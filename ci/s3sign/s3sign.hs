{-# LANGUAGE OverloadedStrings #-}

module S3sign where


import Data.ByteString.Char8 (pack)
import qualified Data.ByteString.Char8 as BS
import Network.S3 as S3
import System.Environment(getArgs)

main :: IO ()
main = do
    BS.putStrLn "s3sign public-key aws-secret upload/path.name local/file.name"
    args <- getArgs
    let public      = pack ( args !! 0 )
        secret      = pack ( args !! 1 )
        path        = pack ( args !! 2 )
        fname       = pack ( args !! 3 )
        credentials = S3.S3Keys public secret
        request     = S3.S3Request S3.S3PUT "application/octet-stream" "solana-build-artifacts" path (365*24*60*60)
    req  <- generateS3URL credentials request
    let
        url         = S3.signedRequest req
    BS.putStrLn $ BS.concat $ ["curl -X PUT -T ", fname, " \"", url, "\" -H \"Content-Type: application/octet-stream\" -H \"x-amz-acl: public-read\""]
