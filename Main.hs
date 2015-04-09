{-# LANGUAGE TupleSections, ScopedTypeVariables #-}
import Control.Applicative
import Control.Monad
import Control.Exception as Exc
import Data.Maybe
import Data.Char
import Data.Word
import Data.Bits
import qualified Data.List as L
import qualified Data.Map as M
import qualified Data.Set as S
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.UTF8 as BU
import qualified Data.ByteString.Lazy.UTF8 as BLU
import Data.Binary.Get as BinGet
import Codec.Compression.Zlib as Zlib
import qualified Data.Digest.Pure.SHA as SHA
import System.IO
import System.Time
import System.Directory
import System.Posix (fileSize, getFileStatus)
import System.Posix.Types
import System.Environment (getArgs)
import System.Console.ANSI as TTY
import System.Exit (exitFailure, exitSuccess)
import Numeric (readHex)
import Text.Printf

bool thenb elseb cond = if cond then thenb else elseb
maybeOr msg = maybe (error msg) id
splitBy num lst = L.unfoldr (\s -> if null s then Nothing else Just $ splitAt num s) lst

colorPutStrLn color msg = setSGR [SetColor Foreground Dull color] >> putStr msg >> setSGR [] >> putStrLn ""

type SHAHash = B.ByteString
showSHA = concatMap (printf "%02x" )
readSHA = B.pack . map (fst . head . readHex) . splitBy 2

type HashInfoMap = (M.Map SHAHash (Int, Int, Word32)) -- (packOffset, packSize, crc32)

objpathFor hash = concat ["/objects/", take 2 hash, "/", drop 2 hash]
changeFileExtension ext = reverse . (reverse ext ++) . tail . dropWhile (/= '.') . reverse

getBlob :: FilePath -> [(FilePath, M.Map SHAHash (Int, Int, Word32))] -> String
           -> IO (String {-type-}, Int {-len-}, BL.ByteString {-blob-})
getBlob gitdir idxmaps hash = do
    isobj <- doesFileExist (gitdir ++ objpathFor hash)
    if isobj then parseBlob <$> Zlib.decompress <$> BL.readFile (gitdir ++ objpathFor hash)
    else let (idxfile, idxmap) = head $ filter (((readSHA hash) `M.member`) . snd) idxmaps
             packfile = (gitdir ++ "/objects/pack/" ++ changeFileExtension ".pack" idxfile)
             skipblobinfo (t, n) = getWord8 >>= ((bool (skipblobinfo (t, n+1)) (return (t, n))) . (`testBit` 7))
             blobinfo = getWord8 >>= (\w -> (if w `testBit` 7 then skipblobinfo else return) (w, 1))
             getblob blobpos blobsz = do
                skip blobpos
                (ty, skipped) <- blobinfo
                zblob <- getByteString (blobsz - skipped)
                return (ty, BL.fromStrict zblob) 
         in do
             let Just (blobpos, blobsz, _) = M.lookup (readSHA hash) idxmap
             (ty, zblob) <- runGet (getblob blobpos blobsz) <$> BL.readFile packfile
             let blob = Zlib.decompress zblob
             let Just blobty = L.lookup (ty .&. 0x70) [(0x10,"commit"), (0x20,"tree"), (0x30,"blob")] 
             return (blobty, fromIntegral $ BL.length blob, blob)

parseBlob :: BL.ByteString -> (String, Int, BL.ByteString) -- blobtype, bloblen, blob
parseBlob str = let (btype, tl') = BL.break (== 0x20) str ; (slen, tl) = BL.break (== 0) tl'
                in (BLU.toString btype, read $ BLU.toString slen, BL.tail tl)

parseTreeObject :: BL.ByteString -> [(String, String, String)] 
parseTreeObject = L.unfoldr parseEntry . BL.unpack -- [(mode::String, len::String, path::String)]
  where parseEntry [] = Nothing
        parseEntry bl = let (hd, (_:tl)) = splitAt (fromJust $ L.findIndex (== 0) bl) bl in
            let (mode, (_:path)) = break (== 0x20) hd ; (hsh, tl') = splitAt 20 tl
            in Just ((BU.toString . B.pack $ mode, BU.toString . B.pack $ path, showSHA hsh), tl')

prettyTreeObject :: [(String, String, String)] -> String
prettyTreeObject = unlines . map (\(mode, path, hash) -> concat [mode, " blob ", hash, "    ", path])

getIdxFile_v2 :: Get (M.Map SHAHash (Int, Word32))
getIdxFile_v2 = do
    indv <- replicateM 0x100 getWord32be
    let lastind = fromIntegral $ last indv
    hashv <- replicateM lastind (getByteString 20)
    crc32v <- replicateM lastind getWord32be
    offv <- map fromIntegral <$> replicateM lastind getWord32be
    -- TODO: 8b offsets
    return $ M.fromAscList $ zip hashv $ zip offv crc32v

parseIdxFile_v2 :: FilePath -> IO HashInfoMap -- (offset, size, crc32)
parseIdxFile_v2 idxfile = do
    idxdata <- BL.readFile idxfile
    packlen <- fromIntegral <$> fileSize <$> getFileStatus (changeFileExtension ".pack" idxfile)
    let (idxbody, trail) = BL.splitAt (BL.length idxdata - 20) idxdata
    when ((show $ SHA.sha1 idxbody) /= (showSHA $ BL.unpack trail)) $ error "idxfile: idx hash invalid"
    let (0xff744f63, 2, idxmap') = runGet (liftM3 (,,) getWord32be getWord32be getIdxFile_v2) idxbody
    let offs' = S.fromList $ ((map fst $ M.elems idxmap') ++ [packlen - 20])
    return $ M.map (\(off, crc32) -> (off, (fromJust $ S.lookupGT off offs') - off, crc32)) idxmap'

parseIndex :: BL.ByteString -> [B.ByteString]
parseIndex dat = map (\([ctsec, ctusec, mtsec, mtusec, stdev, stino, stmode, stuid, stgid, fsize], sha, flags, fname) -> fname) idxdata
    -- read extensions
    -- verify SHA
  where
    ("DIRC", ver, nentries) = runGet (liftM3 (,,) (BU.toString <$> getByteString 4) getWord32be getWord32be) dat
    go nb bs = (B.break (== 0) <$> getByteString nb) >>= (\(d, z) -> (if B.null z then go 8 else return)(B.append bs d))
    getIdxEntry = liftM4 (,,,) (replicateM 10 getWord32be) (getByteString 20) getWord16be (go 2 B.empty)
    idxdata = runGet (replicateM (fromIntegral nentries) getIdxEntry) (BL.drop 12 dat)

main = do
    argv <- getArgs
    curdir <- getCurrentDirectory
    outtty <- hIsTerminalDevice stdout
    let colPutStrLn color = if outtty then colorPutStrLn color else putStrLn

    -- search for a .git directory:
    let cpath = filter (/= "/") $ L.groupBy (\a b -> a /= '/' && b /= '/') curdir
    let parents = map ((\d -> "/"++d++"/.git") . L.intercalate "/") . takeWhile (not.null) . iterate init $ cpath
    pardirsexist <- mapM (\d -> (,d) <$> doesDirectoryExist d) parents
    let gitdir = maybe (error ".git directory not found") snd . listToMaybe . filter fst $ pardirsexist

    -- find pack files and load them
    idxfiles <- filter (L.isSuffixOf ".idx") <$> getDirectoryContents (gitdir ++ "/objects/pack")
    idxmaps <- zip idxfiles <$> forM idxfiles (parseIdxFile_v2 . ((gitdir ++ "/objects/pack/") ++))

    case argv of
      ["cat-file", opt, hash] -> do
        (blobtype, bloblen, blob) <- getBlob gitdir idxmaps hash
        putStr $ maybe (error "Usage: omit cat-file [-t|-s|-p] <hash>") id $ lookup opt
          [("-t", blobtype ++ "\n"), ("-s", show bloblen ++ "\n"),
           ("-p", maybe (error "bad file") id $ lookup blobtype 
              [("blob", BLU.toString blob), ("commit", BLU.toString blob),
               ("tree", prettyTreeObject $ parseTreeObject blob)]),
           ("blob", BLU.toString blob), ("tree", prettyTreeObject $ parseTreeObject blob),
           ("commit", BLU.toString blob)]

      ("verify-pack":argv') -> do
        let (verbose, packfile) = ("-v" `elem` argv', last argv')
        let verifyPack = do
                offmap <- parseIdxFile_v2 $ changeFileExtension ".idx" packfile
                let printHash (hsh, (off, sz, crc32)) = putStrLn $ L.intercalate " " [showSHA (B.unpack hsh), show sz, show off]
                when verbose $ forM_ (M.toList offmap) printHash
                offmap `seq` return ()
        verifyPack `Exc.catch` (\(e :: Exc.SomeException) -> when verbose (hPrint stderr e) >> exitFailure)

      ("log":[]) -> do
        let commitHeader hdr info = words <$> (listToMaybe $ filter (L.isPrefixOf $ hdr ++ " ") info)
        let printCommit commit = do
                ("commit", _, blob) <- getBlob gitdir idxmaps commit
                let (commMeta, commMsg) = break null $ lines $ BLU.toString blob
                let (cmTZ : cmEpoch : cmAuthor) = reverse $ maybeOr "No commit author" $ commitHeader "author" commMeta
                colPutStrLn Yellow $ "commit " ++ commit
                putStrLn $ "Author:\t" ++ unwords (drop 1 . reverse $ cmAuthor)
                putStrLn $ "Date\t" ++ show (TOD (read cmEpoch) 0)
                mapM_ (putStrLn . ("    " ++)) commMsg
                putStrLn ""
                let cmPar = commitHeader "parent" commMeta
                when (isJust cmPar) $ let ["parent", parent] = fromJust cmPar in printCommit parent
                
        ("ref", (':':' ':path)) <- (break (== ':') . head . lines) <$> readFile (gitdir ++ "/HEAD")
        commit <- head <$> lines <$> readFile (gitdir ++ "/" ++ path)
        printCommit commit

      ["ls-files"] -> parseIndex <$> BL.readFile (gitdir ++ "/index") >>= mapM_ (putStrLn . BU.toString)

      _ -> error "Usage: omit [cat-file|verify-pack|log]"
