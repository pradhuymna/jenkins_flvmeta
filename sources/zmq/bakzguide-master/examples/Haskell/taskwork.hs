-- |
-- Task worker (p.18)
-- Connects PULL socket to tcp://localhost:5557
-- Collects workloads from ventilator via that socket (see `taskvent.hs`)
-- Connects PUSH socket to tcp://localhost:5558
-- Sends results to sink via that socket (see `tasksink.hs`)
-- 

module Main where

import System.ZMQ4.Monadic 
import Control.Monad (forever)
import Data.ByteString.Char8 (unpack, empty)
import Control.Applicative ((<$>))
import System.IO (hSetBuffering, stdout, BufferMode(..))
import Control.Concurrent (threadDelay)


main :: IO ()
main = 
    runZMQ $ do
        -- connect a receiver to the ventilator
        receiver <- socket Pull
        connect receiver "tcp://localhost:5557"

        -- connect a sender to the sink
        sender <- socket Push
        connect sender "tcp://localhost:5558"
          
        liftIO $ hSetBuffering stdout NoBuffering
        forever $ do
            message <- unpack <$> receive receiver
            -- Simple progress indicator for the viewer
            liftIO $ putStr $ message ++ "."

            -- Do the "work"
            liftIO $ threadDelay (read message * 1000)
                   
            -- Send results to sink
            send sender [] empty
