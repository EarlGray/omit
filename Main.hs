{-# LANGUAGE TupleSections #-}
import Control.Applicative
import Data.Maybe
import Data.Char
import Data.List (groupBy, intercalate)
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.UTF8 as BU
import qualified Data.ByteString.Lazy.UTF8 as BLU
import Codec.Compression.Zlib as Zlib
import qualified Data.Digest.Pure.SHA as SHA
import System.Environment (getArgs)
import System.Directory

main = do
    argv <- getArgs
    curdir <- getCurrentDirectory

    -- search for a .git directory:
    let cpath = filter (/= "/") $ groupBy (\a b -> a /= '/' && b /= '/') curdir
    let parents = map ((\d -> "/" ++ d ++ "/.git") . intercalate "/") . takeWhile (not.null) . iterate init $ cpath
    pardirsexist <- mapM (\d -> (,d) <$> doesDirectoryExist d) parents
    let gitdir = maybe (error ".git directory not found") snd . listToMaybe . filter fst $ pardirsexist

    case argv of
      ["cat-file", opt, hash] -> do
        let objpath = gitdir ++ "/objects/" ++ (take 2 hash) ++ "/" ++ (drop 2 hash)
        blob <- Zlib.decompress <$> BL.readFile objpath
        putStr $ ($ blob) $ maybe (error "Usage: omit cat-file [-t|-s|-p] <hash>") id $ lookup opt
          [("-t", (++ "\n") . BLU.toString . BL.takeWhile (/= (fromIntegral $ ord ' '))),
           ("-s", (++ "\n") . shhjow . BL.length), ("-p", BLU.toString . BL.dropWhile (/= 0))]

      _ -> error "Usage: omit [cat-file|]"
