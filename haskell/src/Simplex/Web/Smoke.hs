{-# LANGUAGE ForeignFunctionInterface #-}
{-# LANGUAGE JavaScriptFFI #-}

module Simplex.Web.Smoke where

import Data.Word (Word)

smokeAdd :: Word -> Word -> Word
smokeAdd left right = left + right

smokeFib :: Word -> Word
smokeFib n = go n 0 1
  where
    go 0 acc _ = acc
    go count acc next = go (count - 1) next (acc + next)

foreign export javascript "smoke_add sync"
  smokeAdd :: Word -> Word -> Word

foreign export javascript "smoke_fib sync"
  smokeFib :: Word -> Word
