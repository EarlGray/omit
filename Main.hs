{-# LANGUAGE TupleSections #-}
import Control.Applicative
import Control.Monad
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
import System.IO
import System.Time
import System.Directory
import System.Environment (getArgs)
import qualified System.Console.ANSI as TTY
import Text.Printf

maybeOr msg = maybe (error msg) id

objpathFor hash = concat ["/objects/", take 2 hash, "/", drop 2 hash]

getBlob gitdir hash = parseBlob <$> Zlib.decompress <$> BL.readFile (gitdir ++ objpathFor hash)

parseBlob :: BL.ByteString -> (String, Int, BL.ByteString)
parseBlob str = let (btype, tl') = BL.break (== 0x20) str ; (slen, tl) = BL.break (== 0) tl'
                in (BLU.toString btype, read $ BLU.toString slen, BL.tail tl)

parseTreeObject :: BL.ByteString -> [(String, String, String)] 
parseTreeObject = L.unfoldr parseEntry . BL.unpack -- [(mode::String, len::String, path::String)]
  where parseEntry [] = Nothing
        parseEntry bl = let (hd, (_:tl)) = splitAt (fromJust $ L.findIndex (== 0) bl) bl in
            let (mode, (_:path)) = break (== 0x20) hd ; (hsh, tl') = splitAt 20 tl
            in Just ((BU.toString . B.pack $ mode, BU.toString . B.pack $ path, concatMap (printf "%02x" ) hsh), tl')

prettyTreeObject :: [(String, String, String)] -> String
prettyTreeObject = unlines . map (\(mode, path, hash) -> concat [mode, " blob ", hash, "    ", path])

-- parseCommitObj :: 

main = do
    argv <- getArgs
    curdir <- getCurrentDirectory
    outtty <- hIsTerminalDevice stdout

    -- search for a .git directory:
    let cpath = filter (/= "/") $ L.groupBy (\a b -> a /= '/' && b /= '/') curdir
    let parents = map ((\d -> "/"++d++"/.git") . L.intercalate "/") . takeWhile (not.null) . iterate init $ cpath
    pardirsexist <- mapM (\d -> (,d) <$> doesDirectoryExist d) parents
    let gitdir = maybe (error ".git directory not found") snd . listToMaybe . filter fst $ pardirsexist

    case argv of
      ["cat-file", opt, hash] -> do
        (blobtype, bloblen, blob) <- getBlob gitdir hash
        putStr $ maybe (error "Usage: omit cat-file [-t|-s|-p] <hash>") id $ lookup opt
          [("-t", blobtype ++ "\n"), ("-s", show bloblen ++ "\n"),
           ("-p", maybe (error "bad file") id $ lookup blobtype 
              [("blob", BLU.toString blob), ("commit", BLU.toString blob),
               ("tree", prettyTreeObject $ parseTreeObject blob)]),
           ("blob", BLU.toString blob), ("tree", prettyTreeObject $ parseTreeObject blob),
           ("commit", BLU.toString blob)]

      ("log":[]) -> do
        let commitHeader hdr info = words <$> (listToMaybe $ filter (L.isPrefixOf $ hdr ++ " ") info)
        let printCommit commit = do
                ("commit", _, blob) <- getBlob gitdir commit
                let (commMeta, commMsg) = break null $ lines $ BLU.toString blob
                let (cmTZ : cmEpoch : cmAuthor) = reverse $ maybeOr "No commit author" $ commitHeader "author" commMeta
                putStrLn $ "commit " ++ commit
                putStrLn $ "Author:\t" ++ unwords (drop 1 . reverse $ cmAuthor)
                putStrLn $ "Date\t" ++ show (TOD (read cmEpoch) 0)
                mapM_ (putStrLn . ("    " ++)) commMsg
                putStrLn ""
                let cmPar = commitHeader "parent" commMeta
                when (isJust cmPar) $ let ["parent", parent] = fromJust cmPar in printCommit parent
                
        ("ref", (':':' ':path)) <- (break (== ':') . head . lines) <$> readFile (gitdir ++ "/HEAD")
        commit <- head <$> lines <$> readFile (gitdir ++ "/" ++ path)
        printCommit commit

      _ -> error "Usage: omit [cat-file|]"
