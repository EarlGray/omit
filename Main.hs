{-# LANGUAGE TupleSections, ScopedTypeVariables #-}
import Control.Applicative
import Control.Monad
import Control.Exception as Exc
import Data.Maybe
import Data.Char
import Data.Word
import Data.Bits
import qualified Data.List as L
import qualified Data.Set as S
import qualified Data.Map as M
import qualified Data.IntMap as IM
import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.UTF8 as BU
import qualified Data.ByteString.Lazy.UTF8 as BLU
import Data.Binary.Get as BinGet
import Data.Binary.Put as BinPut
import Data.Algorithm.Diff as Diff
import Codec.Compression.Zlib as Zlib
import qualified Data.Digest.Pure.SHA as SHA
import System.IO
import System.Time
import Data.Time.LocalTime
import System.Directory as Dir
import System.Posix as Posix
import System.FilePath.Posix ((</>))
import qualified System.FilePath.Posix as PF
import System.Process as Proc
import System.Environment (getArgs, lookupEnv)
import System.Console.ANSI as TTY
import System.Exit (exitFailure, exitSuccess)
import Numeric (readHex)
import Text.Printf

int :: (Num b, Integral a) => a -> b
int = fromIntegral

bool thenb elseb cond = if cond then thenb else elseb
on f g x y = f (g x) (g y)
maybeOr msg = maybe (error msg) id
splitBy num lst = L.unfoldr (\s -> if null s then Nothing else Just $ splitAt num s) lst

colorPutStrLn color msg = setSGR [SetColor Foreground Dull color] >> putStr msg >> setSGR [] >> putStrLn ""
todFromPosix etime = TOD (read ssec) psec
  where (ssec, (_:s')) = L.break (not . isDigit) (show etime)
        psec = case reads s' of { [] -> 0; [(nsec, _)] -> 1000 * nsec; }

timespecToTOD (tv_sec, tv_nsec) = TOD (toInteger tv_sec) (1000 * (toInteger tv_nsec))
timespecFromTOD (TOD sec psec) = (fromInteger sec, fromInteger (psec `div` 1000))

type SHAHash = B.ByteString
showSHA = concatMap (printf "%02x" ) . B.unpack
readSHA = B.pack . map (fst . head . readHex) . splitBy 2

hashobj :: BL.ByteString -> SHAHash
hashobj = BL.toStrict . SHA.bytestringDigest . SHA.sha1

type HashInfoMap = M.Map SHAHash (Int, Int, Word32) -- (packOffset, packSize, crc32)
type PackIndex = (FilePath, HashInfoMap)
data IndexEntry = IndexEntry { indCTime::ClockTime, indMTime::ClockTime, indDev::Word32, indIno::Word32,
        indMode::Word32, indUID::Word32, indGID::Word32, indFileSize::Word32, indSHA::SHAHash,
        indFl::Word16, indFName::FilePath } deriving (Show, Eq)

data BlobMode = FileBlob | ExecBlob | SymlinkBlob | GitlinkBlob | UnknownBlob String
instance Show BlobMode where
  show mod = case mod of { FileBlob->"100644"; ExecBlob->"100755"; SymlinkBlob->"120000"; GitlinkBlob->"160000"; UnknownBlob mod -> mod }
indmodeToBlobMode = flip L.lookup [(0o100644,FileBlob),(0o100755,ExecBlob),(0o120000,SymlinkBlob),(0o160000,GitlinkBlob)]

data GitTree = GitBlob BlobMode SHAHash FilePath | GitTree SHAHash FilePath [GitTree] deriving Show
data FSTree = FSDir FilePath [FSTree] | FSFile FilePath deriving Show

objpathFor (h1:h2:hash) = concat ["/objects/", (h1:h2:[]), "/", hash]

doesObjExist gitdir idxmaps sha = (any (M.member sha . snd) idxmaps || ) <$> doesFileExist (gitdir ++ objpathFor (showSHA sha))

getHeadRef gitdir = do
  ("ref", (':':' ':path)) <- (break (== ':') . head . lines) <$> readFile (gitdir ++ "/HEAD")
  return $ path
getHeadSHA gitdir = do
  reffile <- (gitdir </>) <$> getHeadRef gitdir
  head <$> lines <$> readFile reffile
getHeadTree gitdir idxmaps = do
  ("commit", _, blob) <- loadBlob gitdir idxmaps =<< (readSHA <$> getHeadSHA gitdir)
  return $ fromJust $ M.lookup "tree" $ fst $ parseCommitObject blob

blobify :: String -> BL.ByteString -> BL.ByteString
blobify blobty objdata = BL.append (BLU.fromString (blobty ++ " " ++ show (BL.length objdata) ++ "\0")) objdata

writeObject objpath obj = (createDirectoryIfMissing False $ PF.takeDirectory objpath) >> BL.writeFile objpath (Zlib.compress obj)

loadBlob :: FilePath -> [PackIndex] -> SHAHash -> IO (String {-type-}, Int {-len-}, BL.ByteString {-blob-})
loadBlob gitdir idxmaps hash = do
    isobj <- doesFileExist (gitdir ++ objpathFor (showSHA hash))
    if isobj then parseBlob <$> Zlib.decompress <$> BL.readFile (gitdir ++ objpathFor (showSHA hash))
    else let (idxfile, idxmap) = head $ filter ((hash `M.member`) . snd) idxmaps
             packfile = (gitdir ++ "/objects/pack/" ++ PF.replaceExtension idxfile "pack")
             skipblobinfo (t, n) = getWord8 >>= ((bool (skipblobinfo (t, n+1)) (return (t, n))) . (`testBit` 7))
             blobinfo = getWord8 >>= (\w -> (if w `testBit` 7 then skipblobinfo else return) (w, 1))
             getblob blobpos blobsz = do
                skip blobpos
                (ty, skipped) <- blobinfo
                zblob <- getByteString (blobsz - skipped)
                return (ty, BL.fromStrict zblob)
         in do
             let Just (blobpos, blobsz, _) = M.lookup hash idxmap
             (ty, zblob) <- runGet (getblob blobpos blobsz) <$> BL.readFile packfile
             let blob = Zlib.decompress zblob
             let Just blobty = L.lookup (ty .&. 0x70) [(0x10,"commit"), (0x20,"tree"), (0x30,"blob")]
             return (blobty, int $ BL.length blob, blob)

writeBlob :: FilePath -> [(FilePath, HashInfoMap)] -> String -> BL.ByteString -> IO SHAHash
writeBlob gitdir idxmaps blobty blob = do
  let obj = blobify blobty blob
  let sha = hashobj obj
  exists <- doesObjExist gitdir idxmaps sha
  unless exists $ do
    putStrLn $ "### writing : " ++ (gitdir ++ objpathFor (showSHA sha))
    writeObject (gitdir ++ objpathFor (showSHA sha)) obj
  return sha

parseBlob :: BL.ByteString -> (String, Int, BL.ByteString) -- blobtype, bloblen, blob
parseBlob str = let (btype, tl') = BL.break (== 0x20) str ; (slen, tl) = BL.break (== 0) tl'
                in (BLU.toString btype, read $ BLU.toString slen, BL.tail tl)

parseTreeObject :: BL.ByteString -> [(String, FilePath, SHAHash)]
parseTreeObject = L.unfoldr parseEntry . BL.unpack -- [(mode::String, name::FilePath, hash::SHAHash)]
  where parseEntry [] = Nothing
        parseEntry bl = let (hd, (_:tl)) = splitAt (fromJust $ L.findIndex (== 0) bl) bl in
            let (mode, (_:path)) = break (== 0x20) hd ; (hsh, tl') = splitAt 20 tl
            in Just ((BU.toString $ B.pack mode, BU.toString $ B.pack path, B.pack hsh), tl')

dumpTreeObject :: [(String, FilePath, SHAHash)] -> BL.ByteString
dumpTreeObject = runPut . void . mapM dumpTreeEntry . L.sortBy (compare `on` (\(_,e,_) -> BU.fromString e))
  where dumpTreeEntry (mod, name, sha) = putByteString (BU.fromString $ mod ++ " " ++ name) >> putWord8 0 >> putByteString sha

prettyTreeObject :: [(String, FilePath, SHAHash)] -> String
prettyTreeObject = unlines . map (\(mode, path, hash) -> concat [ty mode, " ", showSHA hash, "    ", path])
  where ty mod = maybeOr ("wrong tree entry type : " ++ mod) $ L.lookup mod blobtypes
        blobtypes = [("100644","100644 blob"), ("40000","040000 tree")]

parseCommitObject :: BL.ByteString -> (M.Map String String, [String])
parseCommitObject blob = (M.fromList $ map (\ln -> let (hdr:tl) = words ln in (hdr, unwords tl)) commMeta, commMsg)
  where (commMeta, commMsg) = break null $ lines $ BLU.toString blob

getIdxFile_v2 :: Get (M.Map SHAHash (Int, Word32))
getIdxFile_v2 = do
    indv <- replicateM 0x100 getWord32be
    let lastind = int $ last indv
    hashv <- replicateM lastind (getByteString 20)
    crc32v <- replicateM lastind getWord32be
    offv <- map int <$> replicateM lastind getWord32be
    -- TODO: 8b offsets
    return $ M.fromAscList $ zip hashv $ zip offv crc32v

parseIdxFile_v2 :: FilePath -> IO HashInfoMap -- (offset, size, crc32)
parseIdxFile_v2 idxfile = do
    idxdata <- BL.readFile idxfile
    packlen <- int <$> fileSize <$> getFileStatus (PF.replaceExtension idxfile "pack")
    let (idxbody, trail) = BL.splitAt (BL.length idxdata - 20) idxdata
    when ((show $ SHA.sha1 idxbody) /= (showSHA $ BL.toStrict trail)) $ error "idxfile: idx hash invalid"
    let (0xff744f63, 2, idxmap') = runGet (liftM3 (,,) getWord32be getWord32be getIdxFile_v2) idxbody
    let offs' = S.fromList $ ((map fst $ M.elems idxmap') ++ [packlen - 20])
    return $ M.map (\(off, crc32) -> (off, (fromJust $ S.lookupGT off offs') - off, crc32)) idxmap'

parseIndex :: BL.ByteString -> [IndexEntry]
parseIndex dat = map makeIdxentry idxdata
  where
    ("DIRC", ver, nentries) = runGet (liftM3 (,,) (BU.toString <$> getByteString 4) getWord32be getWord32be) dat
    go nb bs = (B.break (== 0) <$> getByteString nb) >>= (\(d, z) -> (if B.null z then go 8 else return)(B.append bs d))
    getIdxEntry = liftM4 (,,,) (replicateM 10 getWord32be) (getByteString 20) getWord16be (go 2 B.empty)
    idxdata = runGet (replicateM (int nentries) getIdxEntry) (BL.drop 12 dat)
    makeIdxentry ([ctsec, ctusec, mtsec, mtusec, stdev, stino, stmode, stuid, stgid, fsize], sha, flags, fname) =
      IndexEntry (timespecToTOD (ctsec, ctusec)) (timespecToTOD (mtsec, mtusec))
                 stdev stino stmode stuid stgid fsize sha flags (BU.toString fname)
    -- read extensions -- verify SHA

dumpIndex :: M.Map FilePath IndexEntry -> BL.ByteString
dumpIndex indmap = BL.append body trailer
  where body = runPut $ do
          putByteString (BU.fromString "DIRC") >> mapM putWord32be [2, int $ M.size indmap]
          mapM (putEntry . snd) . M.toAscList . M.mapKeys BU.fromString $ indmap
          return ()
        trailer = SHA.bytestringDigest $ SHA.sha1 body
        putEntry (IndexEntry ctime mtime dev ino mod uid gid fsize sha fl fname) = do
          let ((cts, ctns), (mts, mtns)) = (timespecFromTOD ctime, timespecFromTOD mtime)
              bname = BU.fromString fname
              zpadding = 8 - ((62 + B.length bname) `rem` 8)
          mapM_ putWord32be [int cts, int ctns, int mts, int mtns, dev, ino, mod, uid, gid, fsize]
          putByteString sha >> putWord16be fl >> putByteString bname >> replicateM zpadding (putWord8 0)

loadTree :: FilePath -> [(FilePath, HashInfoMap)] -> SHAHash -> FilePath -> IO GitTree
loadTree gitdir pathidx hash dirname = do
  ("tree", _, blob) <- loadBlob gitdir pathidx hash
  let loadSubtree (mod, name, sha) = if mod == "40000" || mod == "040000"
        then loadTree gitdir pathidx sha name
        else return $ GitBlob (fromMaybe (UnknownBlob mod) $ lookup mod
              [("100644",FileBlob), ("100755",ExecBlob), ("120000",SymlinkBlob), ("160000",GitlinkBlob)]) sha name
  GitTree hash dirname <$> forM (parseTreeObject blob) loadSubtree

writeTree :: FilePath -> [PackIndex] -> GitTree -> IO SHAHash
writeTree _ _ (GitBlob _ sha _) = return sha   -- a blob must have been written by `omit add` already
writeTree gitdir idxmaps (GitTree sha name entries) = do
  let mkinfo e = case e of { GitBlob mod sha name -> (show mod, name, sha); GitTree sha name _ -> ("40000", name, sha) }
  let treeblob = dumpTreeObject $ map mkinfo entries
  let obj = blobify "tree" treeblob
  let sha = hashobj obj
  exists <- doesObjExist gitdir idxmaps sha
  unless exists $ do
    mapM_ (writeTree gitdir idxmaps) entries
    writeObject (gitdir ++ objpathFor (showSHA sha)) obj
  return sha

commitTree :: FilePath -> [(String, String)] -> String -> IO SHAHash
commitTree gitdir meta msg = do
  let obj = blobify "commit" $ BLU.fromString $ unlines ((map (\(hdr, inf) -> unwords [hdr, inf]) meta) ++ [""] ++ lines msg)
  let sha = hashobj obj
  writeObject (gitdir ++ objpathFor (showSHA sha)) obj
  return sha

fsTreeFromList :: FilePath -> [[FilePath]] -> FSTree
fsTreeFromList dir fileparts = FSDir dir dirlst
  where grps' = L.groupBy ((==) `on` head) fileparts
        grps = map (\grp -> (head (head grp), map tail grp)) grps'
        dirlst = map (\(fname, subdirs) -> if null (head subdirs) then FSFile fname else (fsTreeFromList (PF.dropTrailingPathSeparator fname) subdirs)) grps

makeTreeFromIndex :: FilePath -> M.Map FilePath IndexEntry -> IO GitTree
makeTreeFromIndex root indexByPath = go root $ fsTreeFromList root $ map (PF.splitPath . indFName . snd) $ M.toAscList indexByPath
  where
    go workdir (FSDir dir entries) = do
      leaves <- forM entries $ \entry -> do
        case entry of
          FSFile fname -> do
            let ie = indexByPath M.! path
                path' = PF.makeRelative root workdir </> fname
                path = if "./" `L.isPrefixOf` path' then drop 2 path' else path'
            case indmodeToBlobMode (indMode ie)  of
              Nothing  -> error $ concat ["unknown mode ", show (indMode ie), " in index ", showSHA (indSHA ie)]
              Just mod -> return $ GitBlob mod (indSHA ie) fname
          FSDir subdir _ -> go (workdir </> subdir) entry
      let treeentrify (GitBlob mod sha fname) = (show mod, fname, sha)
          treeentrify (GitTree sha dir _) = ("40000",  dir, sha)
      -- mapM (\(mod, name, sha) -> putStrLn $ mod++" "++showSHA sha++": " ++name) $ map treeentrify leaves
      let sha = hashobj $ blobify "tree" $ dumpTreeObject $ map treeentrify leaves
      return $ GitTree sha dir leaves

groupByAscRange :: [(Int, a)] -> [[a]]
groupByAscRange = reverse . map reverse . snd . L.foldl' go (0, [[]])
  where go (n, grps@(hd:tl)) (k, v) = (k, if k == succ n then ((v : hd) : tl) else [v]:grps)

notFirst diffval = case diffval of { First _ -> False; _ -> True }
notSecond diffval = case diffval of { Second _ -> False; _ -> True }
isBoth diffval = case diffval of { Both _ _ -> True; _ -> False }

contextDiff :: Eq t => Int -> [Diff t] -> [[Diff (Int, t)]]
contextDiff nctx diff = groupByAscRange $ IM.toAscList ctxmap
  where annot (num1, num2, res) (Both ln1 ln2) = (succ num1, succ num2, Both (num1,ln1) (num2,ln2) : res)
        annot (num1, num2, res) (First ln)     = (succ num1, num2,      First (num1, ln) : res)
        annot (num1, num2, res) (Second ln)    = (num1,      succ num2, Second (num2, ln) : res)
        lnmap = IM.fromList $ zip [1..] $ reverse $ (\(_,_,e) -> e) $ L.foldl' annot (1,1,[]) diff
        isInContext num = not $ all isBoth $ catMaybes [ IM.lookup i lnmap | i <- [(num - nctx)..(num + nctx)] ]
        ctxmap = IM.foldlWithKey (\res n dv -> if isInContext n then IM.insert n dv res else res) IM.empty lnmap

printCtx [] = []
printCtx grp@((Both (n1,_) (n2,ln)):_) = (grpcaption ++ hdln):tllns
  where (len1, len2) = (length $ filter notSecond grp, length $ filter notFirst grp)
        diffln dv = case dv of { Both(_,ln) _ -> ' ':ln; First(_,ln) -> '-':ln; Second(_,ln) -> '+':ln }
        (hdln : tllns) = map diffln grp
        grpcaption = printf "@@ -%d,%d +%d,%d @@ " n1 len1 n2 len2

parseConfig dat = reverse $ snd $ L.foldl' iter ("",[]) $ map (words . trim '[' ']' . takeWhile (/= '#')) $ lines dat
  where trim fc lc str = if head str == fc && last str == lc then (init $ tail str) else str 
        iter s@(pre, res) [] = s
        iter (_, res)   [section] = (section, res)
        iter (pre, res) [section, subsect] = ((section ++ "." ++ trim '"' '"' subsect), res)
        iter (pre, res) (key:"=":val) = (pre, ((pre ++ "." ++ key, unwords val):res))
        iter _ ln = error $ "config parsing error at : " ++ unwords ln

lookupConfigs :: String -> [[(String, String)]] -> Maybe String
lookupConfigs key = listToMaybe . catMaybes . map (L.lookup key)

main = do
  argv <- getArgs
  curdir <- getCurrentDirectory
  let outtty = True
  -- outtty <- hIsTerminalDevice stdout
  let colPutStrLn color = if outtty then colorPutStrLn color else putStrLn

  -- search for a .git directory:
  let cpath = filter (/= "/") $ L.groupBy (\a b -> a /= '/' && b /= '/') curdir
  let parents = map ((\d -> "/"++d++"/.git") . L.intercalate "/") . takeWhile (not.null) . iterate init $ cpath
  pardirsexist <- mapM (\d -> (,d) <$> doesDirectoryExist d) parents
  let gitdir = maybe (error ".git directory not found") snd . listToMaybe . filter fst $ pardirsexist
  let workdir = PF.takeDirectory gitdir

  hasindex <- doesFileExist $ gitdir ++ "/index"
  index <- if hasindex then parseIndex <$> BL.readFile (gitdir ++ "/index") else return []
  let indexByPath = M.fromList $ map (\ie -> (indFName ie, ie)) index

  -- read configs
  localconf <- parseConfig <$> readFile (gitdir </> "config")
  userconf <- parseConfig <$> (readFile =<< ((</> ".gitconfig") <$> getHomeDirectory))

  -- find pack files and load them
  idxfiles <- filter (L.isSuffixOf ".idx") <$> getDirectoryContents (gitdir </> "objects" </> "pack")
  idxmaps <- zip idxfiles <$> forM idxfiles (parseIdxFile_v2 . ((gitdir ++ "/objects/pack/") ++))

  let lc = 7  -- longest collision, TODO

  case argv of
    ["cat-file", opt, hash] -> do
      (blobtype, bloblen, blob) <- loadBlob gitdir idxmaps (readSHA hash)
      putStr $ maybeOr "Usage: omit cat-file [-t|-s|-p] <hash>" $ lookup opt
        [("-t", blobtype ++ "\n"), ("-s", show bloblen ++ "\n"),
         ("-p", maybeOr "bad file" $ lookup blobtype
            [("blob", BLU.toString blob), ("commit", BLU.toString blob),
             ("tree", prettyTreeObject $ parseTreeObject blob)]),
         ("blob", BLU.toString blob), ("tree", prettyTreeObject $ parseTreeObject blob),
         ("commit", BLU.toString blob)]

    ("verify-pack":argv') -> do
      let (verbose, packfile) = ("-v" `elem` argv', last argv')
      let verifyPack = do
              offmap <- parseIdxFile_v2 $ PF.replaceExtension packfile "idx"
              let printHash (hsh, (off, sz, crc32)) =
                      putStrLn $ L.intercalate " " [showSHA hsh, show sz, show off]
              when verbose $ forM_ (M.toList offmap) printHash
              offmap `seq` return ()
      verifyPack `Exc.catch` (\(e :: Exc.SomeException) -> when verbose (hPrint stderr e) >> exitFailure)

    ("ls-files":argv') -> mapM_ (putStrLn . indFName) index

    ("config":argv') -> mapM_ (\(k, v) -> putStrLn $ k ++ "=" ++ v) localconf

    ("log":[]) -> do
      let printCommit commit = do
              ("commit", _, blob) <- loadBlob gitdir idxmaps (readSHA commit)
              let (commMeta, commMsg) = parseCommitObject blob
              let (cmTZ : cmEpoch : cmAuthor) =
                      reverse $ words $ maybeOr "No commit author" $ M.lookup "author" commMeta
              colPutStrLn Yellow $ "commit " ++ commit
              putStrLn $ "Author:\t" ++ unwords (reverse $ cmAuthor)
              putStrLn $ "Date:\t" ++ show (TOD (read cmEpoch) 0)
              mapM_ (putStrLn . ("    " ++)) commMsg
              putStrLn ""
              let cmPar = M.lookup "parent" commMeta
              when (isJust cmPar) $ let Just parent = cmPar in printCommit parent

      getHeadSHA gitdir >>= printCommit

    ("diff":argv') -> do
      case argv' of
        [] -> forM_ index $ \ie -> do
                let (fname, stageSHA) = (indFName ie, (showSHA $ indSHA ie))
                workdirBlob <- BL.readFile (workdir </> fname)
                let fileSHA = show (SHA.sha1 $ blobify "blob" workdirBlob)
                when (fileSHA /= stageSHA) $ do
                  let workdirLines = map BLU.toString $ BLU.lines workdirBlob
                  ("blob", _, stagedBlob) <- loadBlob gitdir idxmaps (readSHA stageSHA)
                  let stagedLines = map BLU.toString $ BLU.lines stagedBlob
                      diffcap = [ printf "diff --git a/%s b/%s" fname fname,
                          printf "index %s..%s %o" (take lc stageSHA) (take lc fileSHA) (indMode ie),
                          printf "--- a/%s\n+++ b/%s" fname fname ]
                      prettyDiff df = diffcap ++ (concat $ map printCtx $ contextDiff 3 df)
                  mapM_ putStrLn $ prettyDiff $ Diff.getDiff stagedLines workdirLines

        _ -> hPutStrLn stderr $ "Usage: omit diff"

    ("add":argv') -> do
      let iterargv pathidx rpath = do
            path <- Dir.canonicalizePath (curdir </> rpath)
            s <- getFileStatus path
            (blob, mod) <- case s of
              _ | isRegularFile s  -> (, bool 0o100755 0o100644 (fileMode s `testBit` 6)) <$> BL.readFile path
              _ | isSymbolicLink s -> (, 0o120000) <$> BLU.fromString <$> Posix.readSymbolicLink path
              _ -> error ("not a valid file to add: " ++ rpath)
            sha <- writeBlob gitdir idxmaps "blob" blob
            let fname = PF.makeRelative workdir path
                ie = IndexEntry (todFromPosix $ statusChangeTimeHiRes s) (todFromPosix $ modificationTimeHiRes s)
                      (int$deviceID s) (int$fileID s) mod (int$fileOwner s) (int$fileGroup s) (int $ fileSize s)
                      sha (0x7ff .&. int (B.length $ BU.fromString fname)) fname
            return $ M.insert fname ie pathidx

      pathidx <- foldM iterargv indexByPath argv'
      let (omit_index, indpath, indbackup) = (gitdir </> "omit_index", gitdir </> "index", gitdir </> "index.old")
      BL.writeFile omit_index $ dumpIndex pathidx
      doesFileExist indpath >>= (flip when (Dir.renameFile indpath indbackup))
      Dir.renameFile omit_index indpath

    ("write-tree":argv') -> do
      treesha <- writeTree gitdir idxmaps =<< makeTreeFromIndex workdir indexByPath
      putStrLn $ showSHA treesha

    ("commit":argv') -> do
      (prevcommit, reffile) <- (,) <$> getHeadSHA gitdir <*> getHeadRef gitdir
      prevtree <- getHeadTree gitdir idxmaps

      treesha <- writeTree gitdir idxmaps =<< makeTreeFromIndex workdir indexByPath
      when (treesha == readSHA prevtree) $ error "no changes to commit"

      let auth = maybeOr "No user.name configured" $ lookupConfigs "user.name" [localconf, userconf]
      let mail = maybeOr "No user.email configured" $ lookupConfigs "user.email" [localconf, userconf]
      TOD epoch _ <- getClockTime
      tzoffset <- timeZoneOffsetString <$> getCurrentTimeZone
      let cmAuthor = unwords [auth, "<" ++ mail ++ ">", show epoch, tzoffset]

      editor <- fromMaybe (fromMaybe "vi" $ lookupConfigs "core.editor" [localconf, userconf]) <$> lookupEnv "EDITOR"
      Proc.runCommand (editor ++ " " ++ (gitdir </> "COMMIT_EDITMSG")) >>= Proc.waitForProcess
      editmsg <- readFile (gitdir </> "COMMIT_EDITMSG")
      let commMsg = unlines $ filter (not.null) $ map (takeWhile (/= '#')) $ lines editmsg
      when (null commMsg) $ error "no commit message"

      let commMeta = [("tree", showSHA treesha),("parent", prevcommit),("author", cmAuthor),("committer", cmAuthor)]
      commit <- showSHA <$> commitTree gitdir commMeta commMsg
      writeFile (gitdir </> "omit_ref") commit
      Dir.renameFile (gitdir </> "omit_ref") (gitdir </> reffile)
      putStrLn commit

    _ -> error "Usage: omit [cat-file|verify-pack|ls-files|log|diff|add|commit]"
