package main

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/TRON-US/go-btfs-api/utils"
	"time"

	shell "github.com/TRON-US/go-btfs-api"

	"github.com/opentracing/opentracing-go/log"
)

func demoApp(demoState chan string){

	//defer close(demoState)

	localUrl := "http://localhost:5001"
	//localUrl := "http://demo9518058.mockable.io/"

	s := shell.NewShell(localUrl)

	mhash, _ := s.Add(bytes.NewBufferString(string(utils.RandString(15))), shell.Chunker("reed-solomon-1-1-256000"))

	sessionId, err := s.StorageUploadOffSign(mhash, shell.OfflineSignMode(true))
	if err != nil {
		log.Error(err)
	}

	LOOP:
	for {
		//pool for offline signing status
		time.Sleep(time.Second*10)
		uploadResp, statusError := s.StorageUploadStatus(sessionId)
		if statusError != nil {
			log.Error(statusError)
		}
		switch uploadResp.Status {
		case "uninitialized":
			demoState <- uploadResp.Status
			continue
		case "initSignReadyForEscrow", "initSignReadyForGuard":
			demoState <- uploadResp.Status
			batchContracts, errorUnsignedContracts := s.StorageUploadGetContractBatch(sessionId, mhash, uploadResp.Status)
			if errorUnsignedContracts != nil {
				log.Error(errorUnsignedContracts)
			}
			s.StorageUploadSignBatch(sessionId, mhash, batchContracts, uploadResp.Status)
			continue
		case "balanceSignReady", "payChannelSignReady", "payRequestSignReady", "guardSignReady":
			demoState <- uploadResp.Status
			unsignedData, errorUnsignedContracts := s.StorageUploadGetUnsignedData(sessionId, mhash, uploadResp.Status )
			if errorUnsignedContracts != nil {
				log.Error(errorUnsignedContracts)
			}
			switch unsignedData.Opcode{
			case "balance":
				s.StorageUploadSignBalance(sessionId, mhash, unsignedData, uploadResp.Status)
			case "paychannel":
				s.StorageUploadSignPayChannel(sessionId, mhash, unsignedData, uploadResp.Status, unsignedData.Price)
			case "payrequest":
				s.StorageUploadSignPayRequest(sessionId, mhash, unsignedData, uploadResp.Status)
			case "sign":
				s.StorageUploadSign(sessionId, mhash, unsignedData, uploadResp.Status)
			}
			continue
		case "retrySignReady":
			demoState <- uploadResp.Status
			batchContracts, errorUnsignedContracts := s.StorageUploadGetContractBatch(sessionId,mhash, uploadResp.Status)
			if errorUnsignedContracts != nil {
				log.Error(errorUnsignedContracts)
			}
			s.StorageUploadSignBatch(sessionId, mhash, batchContracts, uploadResp.Status)
			continue
		case "retrySignProcess":
			demoState <- uploadResp.Status
			continue
		case "init":
			demoState <- uploadResp.Status
			continue
		case "complete":
			demoState <- uploadResp.Status
			break LOOP
		case "error":
			demoState <- uploadResp.Status
			log.Error(errors.New("errStatus: session experienced an error. stopping app"))
			break LOOP
		}
	}
}
func main() {
	//need to call the add the file first to obtain the file hash
	demoState := make(chan string)
	fmt.Println("Starting offline signing demo ... ")
	go demoApp(demoState)
	for {
		select {
		case i := <- demoState:
			fmt.Println("Current status of offline signing demo: " + i)
		case <-time.After(20*time.Second): //simulates timeout
			fmt.Println("Time out: No news in 30 seconds")
		}
	}
	fmt.Println("Complete offline signing demo ... ")
}
