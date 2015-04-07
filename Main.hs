{-# LANGUAGE TupleSections #-}
import Control.Applicative
import Data.Maybe
import Data.Char
import Data.Word
import qualified Data.List as L
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.UTF8 as BU
import qualified Data.ByteString.Lazy.UTF8 as BLU
import Codec.Compression.Zlib as Zlib
import qualified Data.Digest.Pure.SHA as SHA
import System.Environment (getArgs)
import System.Directory
import Text.Printf

parseBlob :: BL.ByteString -> (String, Int, BL.ByteString)
parseBlob str = let (btype, tl') = BL.break (== 0x20) str ; (slen, tl) = BL.break (== 0) tl'
                in (BLU.toString btype, read $ BLU.toString slen, BL.tail tl)

parseTreeObject :: BL.ByteString -> [(String, String, String)]
parseTreeObject = L.unfoldr parseEntry . BL.unpack
  where parseEntry [] = Nothing
        parseEntry bl = let (hd, (_:tl)) = splitAt (fromJust $ L.findIndex (== 0) bl) bl in
            let (mode, (_:path)) = break (== 0x20) hd ; (hsh, tl') = splitAt 20 tl
            in Just ((BU.toString . B.pack $ mode, BU.toString . B.pack $ path, concatMap (printf "%02x" ) hsh), tl')

prettyTreeObject :: [(String, String, String)] -> String
prettyTreeObject = unlines . map (\(mode, path, hash) -> concat [mode, " blob ", hash, "    ", path])

main = do
    argv <- getArgs
    curdir <- getCurrentDirectory

    -- search for a .git directory:
    let cpath = filter (/= "/") $ L.groupBy (\a b -> a /= '/' && b /= '/') curdir
    let parents = map ((\d -> "/" ++ d ++ "/.git") . L.intercalate "/") . takeWhile (not.null) . iterate init $ cpath
    pardirsexist <- mapM (\d -> (,d) <$> doesDirectoryExist d) parents
    let gitdir = maybe (error ".git directory not found") snd . listToMaybe . filter fst $ pardirsexist

    case argv of
      ["cat-file", opt, hash] -> do
        let objpath = concat [gitdir, "/objects/", take 2 hash, "/", drop 2 hash]
        (blobtype, bloblen, blob) <- parseBlob <$> Zlib.decompress <$> BL.readFile objpath
        putStr $ maybe (error "Usage: omit cat-file [-t|-s|-p] <hash>") id $ lookup opt
          [("-t", blobtype ++ "\n"), ("-s", show bloblen ++ "\n"),
           ("-p", maybe (error "bad file") id $ lookup blobtype 
              [("blob", BLU.toString blob), ("commit", BLU.toString blob),
               ("tree", prettyTreeObject $ parseTreeObject blob)]),
           ("blob", BLU.toString blob), ("tree", prettyTreeObject $ parseTreeObject blob),
           ("commit", BLU.toString blob)]

      _ -> error "Usage: omit [cat-file|]"
