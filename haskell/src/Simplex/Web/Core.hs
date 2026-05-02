{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE JavaScriptFFI #-}

module Simplex.Web.Core where

import Data.IORef (IORef, modifyIORef', newIORef, readIORef, writeIORef)
import Data.List (intercalate)
import GHC.Wasm.Prim (JSString (..), fromJSString, isJSFFIUsed, toJSString)
import System.IO.Unsafe (unsafePerformIO)

data Message = Message
  { messageSequence :: !Int
  , messageDirection :: !String
  , messageText :: !String
  , messageDeliveryStatus :: !String
  , messageCreatedAt :: !String
  }

data Upload = Upload
  { uploadId :: !Int
  , uploadName :: !String
  , uploadStatus :: !String
  , uploadProgress :: !Int
  }

data CoreState = CoreState
  { stateLoggedIn :: !Bool
  , stateHasSigner :: !Bool
  , stateDraftText :: !String
  , stateError :: !String
  , stateNextMessageSequence :: !Int
  , stateNextUploadId :: !Int
  , stateMessages :: ![Message]
  , stateUploads :: ![Upload]
  }

initialState :: CoreState
initialState =
  CoreState
    { stateLoggedIn = False
    , stateHasSigner = True
    , stateDraftText = ""
    , stateError = ""
    , stateNextMessageSequence = 1
    , stateNextUploadId = 1
    , stateMessages = []
    , stateUploads = []
    }

stateRef :: IORef CoreState
stateRef = unsafePerformIO (newIORef initialState)
{-# NOINLINE stateRef #-}

coreReset :: IO ()
coreReset = writeIORef stateRef initialState

coreLogin :: IO ()
coreLogin = modifyIORef' stateRef (\state -> state {stateLoggedIn = True, stateError = ""})

coreLogout :: IO ()
coreLogout =
  modifyIORef'
    stateRef
    ( \state ->
        state
          { stateLoggedIn = False
          , stateDraftText = ""
          , stateError = ""
          }
    )

coreSetDraft :: JSString -> IO ()
coreSetDraft draft =
  modifyIORef' stateRef (\state -> state {stateDraftText = fromJSString draft})

coreSetError :: JSString -> IO ()
coreSetError message =
  modifyIORef' stateRef (\state -> state {stateError = fromJSString message})

coreClearError :: IO ()
coreClearError = modifyIORef' stateRef (\state -> state {stateError = ""})

coreSendText :: JSString -> IO Int
coreSendText rawText = do
  let text = sanitizeText (fromJSString rawText)
  modifyIORef' stateRef (appendOutgoingMessage text)
  state <- readIORef stateRef
  pure (stateNextMessageSequence state - 1)

coreReceiveText :: JSString -> IO Int
coreReceiveText rawText = do
  let text = sanitizeText (fromJSString rawText)
  modifyIORef' stateRef (appendIncomingMessage text)
  state <- readIORef stateRef
  pure (stateNextMessageSequence state - 1)

coreSetDeliveryStatus :: Int -> JSString -> IO Bool
coreSetDeliveryStatus sequenceId rawStatus = do
  let nextStatus = fromJSString rawStatus
  modifyIORef' stateRef (\state -> state {stateMessages = map (updateMessage nextStatus) (stateMessages state)})
  state <- readIORef stateRef
  pure (any (\message -> messageSequence message == sequenceId && messageDeliveryStatus message == nextStatus) (stateMessages state))
  where
    updateMessage nextStatus message
      | messageSequence message == sequenceId = message {messageDeliveryStatus = nextStatus}
      | otherwise = message

coreAddUpload :: JSString -> IO Int
coreAddUpload rawName = do
  modifyIORef' stateRef appendUpload
  state <- readIORef stateRef
  pure (stateNextUploadId state - 1)
  where
    appendUpload state =
      let nextId = stateNextUploadId state
          nextUpload =
            Upload
              { uploadId = nextId
              , uploadName = sanitizeText (fromJSString rawName)
              , uploadStatus = "queued"
              , uploadProgress = 0
              }
       in state
            { stateNextUploadId = nextId + 1
            , stateUploads = stateUploads state ++ [nextUpload]
            }

coreUpdateUpload :: Int -> Int -> JSString -> IO Bool
coreUpdateUpload identifier rawProgress rawStatus = do
  let nextProgress = clampProgress rawProgress
      nextStatus = fromJSString rawStatus
  modifyIORef' stateRef (\state -> state {stateUploads = map (updateUpload nextProgress nextStatus) (stateUploads state)})
  state <- readIORef stateRef
  pure (any (matchesUpload nextProgress nextStatus) (stateUploads state))
  where
    updateUpload nextProgress nextStatus upload
      | uploadId upload == identifier = upload {uploadProgress = nextProgress, uploadStatus = nextStatus}
      | otherwise = upload
    matchesUpload nextProgress nextStatus upload =
      uploadId upload == identifier
        && uploadProgress upload == nextProgress
        && uploadStatus upload == nextStatus

coreSnapshotJson :: IO JSString
coreSnapshotJson = do
  state <- readIORef stateRef
  pure (toJSString (encodeState state))

coreMessageCount :: IO Int
coreMessageCount = length . stateMessages <$> readIORef stateRef

coreIsJSFFIUsed :: Int
coreIsJSFFIUsed =
  if isJSFFIUsed
    then 1
    else 0

appendOutgoingMessage :: String -> CoreState -> CoreState
appendOutgoingMessage text state =
  let nextSequence = stateNextMessageSequence state
      nextMessage =
        Message
          { messageSequence = nextSequence
          , messageDirection = "outgoing"
          , messageText = text
          , messageDeliveryStatus = "sent"
          , messageCreatedAt = sequenceStamp nextSequence
          }
   in state
        { stateDraftText = ""
        , stateNextMessageSequence = nextSequence + 1
        , stateMessages = stateMessages state ++ [nextMessage]
        , stateError = ""
        }

appendIncomingMessage :: String -> CoreState -> CoreState
appendIncomingMessage text state =
  let nextSequence = stateNextMessageSequence state
      nextMessage =
        Message
          { messageSequence = nextSequence
          , messageDirection = "incoming"
          , messageText = text
          , messageDeliveryStatus = "received"
          , messageCreatedAt = sequenceStamp nextSequence
          }
   in state
        { stateNextMessageSequence = nextSequence + 1
        , stateMessages = stateMessages state ++ [nextMessage]
        , stateError = ""
        }

sequenceStamp :: Int -> String
sequenceStamp sequenceId = "local-" ++ pad4 sequenceId

pad4 :: Int -> String
pad4 value =
  let digits = show value
      prefix = replicate (max 0 (4 - length digits)) '0'
   in prefix ++ digits

sanitizeText :: String -> String
sanitizeText = take 4000

clampProgress :: Int -> Int
clampProgress progress
  | progress < 0 = 0
  | progress > 100 = 100
  | otherwise = progress

encodeState :: CoreState -> String
encodeState state =
  "{"
    ++ intercalate
      ","
      [ jsonPair "loggedIn" (jsonBool (stateLoggedIn state))
      , jsonPair "hasSigner" (jsonBool (stateHasSigner state))
      , jsonPair "error" (jsonString (stateError state))
      , jsonPair "sending" "false"
      , jsonPair "draftText" (jsonString (stateDraftText state))
      , "\"service\":{\"transport_status\":\"local-haskell-core\",\"transport_error\":\"\"}"
      , jsonPair "messages" (jsonList (map encodeMessage (stateMessages state)))
      , jsonPair "uploads" (jsonList (map encodeUpload (stateUploads state)))
      , jsonPair "admin" "false"
      , jsonPair "adminMappings" "[]"
      ]
    ++ "}"

encodeMessage :: Message -> String
encodeMessage message =
  "{"
    ++ intercalate
      ","
      [ jsonPair "sequence" (show (messageSequence message))
      , jsonPair "direction" (jsonString (messageDirection message))
      , jsonPair "text" (jsonString (messageText message))
      , jsonPair "delivery_status" (jsonString (messageDeliveryStatus message))
      , jsonPair "created_at" (jsonString (messageCreatedAt message))
      ]
    ++ "}"

encodeUpload :: Upload -> String
encodeUpload upload =
  "{"
    ++ intercalate
      ","
      [ jsonPair "upload_id" (show (uploadId upload))
      , jsonPair "name" (jsonString (uploadName upload))
      , jsonPair "status" (jsonString (uploadStatus upload))
      , jsonPair "progress" (show (uploadProgress upload))
      ]
    ++ "}"

jsonPair :: String -> String -> String
jsonPair key value = jsonString key ++ ":" ++ value

jsonList :: [String] -> String
jsonList values = "[" ++ intercalate "," values ++ "]"

jsonBool :: Bool -> String
jsonBool True = "true"
jsonBool False = "false"

jsonString :: String -> String
jsonString value = "\"" ++ concatMap escapeChar value ++ "\""

escapeChar :: Char -> String
escapeChar '"' = "\\\""
escapeChar '\\' = "\\\\"
escapeChar '\b' = "\\b"
escapeChar '\f' = "\\f"
escapeChar '\n' = "\\n"
escapeChar '\r' = "\\r"
escapeChar '\t' = "\\t"
escapeChar ch
  | ch < ' ' = "\\u" ++ hex4 (fromEnum ch)
  | otherwise = [ch]

hex4 :: Int -> String
hex4 value =
  let digits = showHex value
      prefix = replicate (max 0 (4 - length digits)) '0'
   in prefix ++ digits

showHex :: Int -> String
showHex value
  | value < 16 = [hexDigit value]
  | otherwise =
      let (rest, finalDigit) = value `divMod` 16
       in showHex rest ++ [hexDigit finalDigit]

hexDigit :: Int -> Char
hexDigit value
  | value >= 0 && value <= 9 = toEnum (fromEnum '0' + value)
  | otherwise = toEnum (fromEnum 'a' + value - 10)

foreign export javascript "core_reset sync"
  coreReset :: IO ()

foreign export javascript "core_login sync"
  coreLogin :: IO ()

foreign export javascript "core_logout sync"
  coreLogout :: IO ()

foreign export javascript "core_set_draft sync"
  coreSetDraft :: JSString -> IO ()

foreign export javascript "core_set_error sync"
  coreSetError :: JSString -> IO ()

foreign export javascript "core_clear_error sync"
  coreClearError :: IO ()

foreign export javascript "core_send_text sync"
  coreSendText :: JSString -> IO Int

foreign export javascript "core_receive_text sync"
  coreReceiveText :: JSString -> IO Int

foreign export javascript "core_set_delivery_status sync"
  coreSetDeliveryStatus :: Int -> JSString -> IO Bool

foreign export javascript "core_add_upload sync"
  coreAddUpload :: JSString -> IO Int

foreign export javascript "core_update_upload sync"
  coreUpdateUpload :: Int -> Int -> JSString -> IO Bool

foreign export javascript "core_snapshot_json sync"
  coreSnapshotJson :: IO JSString

foreign export javascript "core_message_count sync"
  coreMessageCount :: IO Int

foreign export javascript "core_is_jsffi_used sync"
  coreIsJSFFIUsed :: Int
