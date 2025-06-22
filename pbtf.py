
import time
import brotli
import asyncio
from cryptography.hazmat.backends.interfaces import PBKDF2HMACBackend
import requests

import random

from Packages.Serialization.Serialization import Serialization
from Packages.Serialization.keySerialization import keySerialization
from Packages.Structures.BlockChain.Parsers.BlockchainParser import BlockchainParser
from ..Structures.BlockChain.BlockChain import BlockChain
from ..Structures.BlockChain.Block import Block
from ..Verification.BlockVerification import BlockVerification
from ..FileIO.readLoadBlockChain import BlockChainReadWrite
from ..Client.TinyWebClient import TinyWebClient
from ..Verification.Signing import Signing, PrivateKeyMethods


import sys
nodeId = 0
if len(sys.argv) > 2:
    nodeId = int(sys.argv[2])

speedModifier = 1


class PBFTNode:
    node = None

    @staticmethod
    def runNode():
        blockChain = BlockChainReadWrite.readBlockChainFromFile(nodeId)

        if blockChain == None:
            blockChain = PBFTNode.configureBlockChainForFirstUse()        

        print({"last Block Index": blockChain.last_block().index})

        print({"nodeId": nodeId})

        node = PBFTNode(nodeId, blockChain)

        PBFTNode.node = node

        print({"in Node top, public Key": keySerialization.serializePublicKeyToString(PBFTNode.node.publicKey)})


        #BlockChainReadWrite.saveBlockChainToFile(node.blockChain)


        newPeerList = BlockchainParser.getMostRecentPeerList(node.blockChain)
        #print({"new Peer List, nodee":newPeerList})
        if newPeerList != None:
            newPeers = []
            for peer in newPeerList["peers"]:
                if not(peer in node.peers):
                    newPeers.append(peer)
            for i in range(len(newPeerList["peers"])):
                obj = {
                    "ip":newPeerList["peers"][i],
                    "id":newPeerList["ids"][i]
                }
                PBFTNode.node.fullPeerInfo[newPeerList["publicKeys"][i]] = obj
            print("Loaded peers from blockchain")
            if len(newPeers) != 0:  
                node.peers = node.peers + newPeers # adds new peers list to node.peers


        blockChainLength =  PBFTNode.node.blockChain.length

        blockChainHasProgressed = True

        counter = 1

        while True:
            #print({"check Length": blockChainLength })
            #print({"actualLength": PBFTNode.node.blockChain.length })
            #print({"blockChainHasProgressed": blockChainHasProgressed})

            blockChainHasProgressed = PBFTNode.node.blockChain.length != blockChainLength

            if counter % 10 == 0:
                #print({"allUsersInBlockChain": len(BlockchainParser.getAllUsers(PBFTNode.node.blockChain))})
                #print({"all Groups": len(BlockchainParser.getAllGroups(PBFTNode.node.blockChain))})
                #print({"blockChainHasProgressed": blockChainHasProgressed})
                newPeerList = BlockchainParser.getMostRecentPeerList(node.blockChain)
                #print({"new Peer List, nodee":newPeerList})
                if newPeerList != None:
                    newPeers = []
                    for peer in newPeerList["peers"]:
                        if not(peer in node.peers):
                            newPeers.append(peer)
                    for i in range(len(newPeerList["peers"])):
                        obj = {
                            "ip":newPeerList["peers"][i],
                            "id":newPeerList["ids"][i]
                        }
                        PBFTNode.node.fullPeerInfo[newPeerList["publicKeys"][i]] = obj
                    print("Loaded peers from blockchain")
                    if len(newPeers) != 0:  
                        node.peers = node.peers + newPeers # adds new peers list to node.peers
                        
                        longestChain = 0
                        peerWithLongestBlockChain = node.peers[0]
                        for peer in node.peers:
                            if peer != "http://127.0.0.1:" + str(5000 + nodeId) + "/":
                                #print("get all the lengths of the blockchains and select the longest one to query")
                                peerChainLength = node.getBlockChainLengthOfPeer(peer)
                                if  peerChainLength > longestChain:
                                    peerWithLongestBlockChain = peer
                                    longestChain = peerChainLength
                        
                        if longestChain > node.blockChain.length:
                            node.requestMissingBlocksFromPeer(peerWithLongestBlockChain)
                        else:
                            for peer in newPeers:
                                node.broadcastBlockChainToNewNode(peer)
                    
                elif len(node.peers) == 0:
                    print("Creating Block For Self")
                    node.SendBlockCreationSignalForSingularNode()

                #print({"peers": PBFTNode.node.peers})
                print({"proposerId": PBFTNode.node.calculateProposerId()})

            if counter % 3 == 0:
                blockChainLength = PBFTNode.node.blockChain.length
                if (not blockChainHasProgressed) and PBFTNode.node.calculateProposerId() == PBFTNode.node.id:
                    print("Proposing Block")
                    currentBlock = PBFTNode.node.createBlock("http://127.0.0.1:" + str(5000 + nodeId) + "/")

                    print({"current Transactions in proposing block":currentBlock.transactions})

                    currentBlock = BlockVerification.RemoveInvalidTransactionsFromBlock(currentBlock, PBFTNode.node)

                    if not BlockVerification.VerifyBlock(currentBlock, PBFTNode.node):
                        raise Exception("Block Verification Error")

                    blockHash = currentBlock.getHash()

                    if currentBlock.previous_hash != PBFTNode.node.blockChain.last_block().getHash():
                            raise Exception({"in Transaction, sync error detected":"Chains Out of sync while proposing block"})

                    #print({"Proposed Block previous hash":currentBlock.previous_hash})

                    #print({"Proposed Block blockchais Hashes":PBFTNode.node.blockChain.getListOfBlockHashes()})

                    PBFTNode.node.broadcastBlockToPeers(currentBlock, blockHash)
                    

            if counter % 21 == 0:
                #BlockchainParser.printAllMessages(PBFTNode.node.blockChain)

                print("------------------------------------------------------------------------------------")

                #BlockchainParser.printAllPermissionDescriptors(PBFTNode.node.blockChain)
                
                blockChainLength = PBFTNode.node.blockChain.length
                if (not blockChainHasProgressed) and len(PBFTNode.node.peers) != 0:
                    syncRes = PBFTNode.node.resyncWithLongestBlockChain()
                    proposerId = PBFTNode.node.calculateProposerId()
                    print({"sync Res":syncRes})
                    print({"proposerId": proposerId})
                    if syncRes < 0 and PBFTNode.node.id != proposerId:
                        PBFTNode.node.proposerOffset += 1
                        print({"idIpDict": PBFTNode.node.IdIpPeerDict})
                        print({"delinquints":PBFTNode.node.delinquentPeers})
                        

            if counter % 100 == 0:
                if len(PBFTNode.node.peers) != 0:
                    random.shuffle(PBFTNode.node.peers)
                    print({"shuffled Peers": PBFTNode.node.peers})
                print("Saving Blockchain every 100 seconds")
                BlockChainReadWrite.saveBlockChainToFile(node.blockChain, PBFTNode.node.id)

            time.sleep(speedModifier)
            counter += 1
            
            #print({"in Node, blockchain state":PBFTNode.node.blockChain.getListOfBlockHashes()})
           

    def __init__(self, id, blockChain):
        self.__privateKey = None
        self.publicKey = None

        self.id = id  # id represents the order in which nodes act as the proposer

        self.peers = []

        self.fullPeerInfo = {}

        self.delinquentPeers = {}

        self.IdIpPeerDict = {}

        self.PKeyIpDict = {}

        self.PKeyIdDict = {}

        self.ProposerId = 0

        self.blockChain = blockChain

        self.proposerOffset = 0

        self.initializeKeys()

    def initializeKeys(self):
        client = None
        try:
            self.__privateKey = PrivateKeyMethods.loadPrivateKeyNode(self.id)
            #print({"The private key":keySerialization.serializePrivateKey(self.__privateKey)})
            self.publicKey=PrivateKeyMethods.generatePublicKeyFromPrivate(self.__privateKey)
            print("Loaded Client: " + str(self.id))
        except:
            self.__privateKey = PrivateKeyMethods.generatePrivateKey()
            self.publicKey = PrivateKeyMethods.generatePublicKeyFromPrivate(self.__privateKey)
            PrivateKeyMethods.savePrivateKeyNode(self.__privateKey, self.id)
            print("Created New Node: " + str(self.id))

        return client

    def voteForMissingProposer(self, proposerId):
        signature = Signing.normalSigning(self.__privateKey, str(proposerId))
        data = {
            "proposerId": str(proposerId),
            "sender": keySerialization.serializePublicKeyToString(self.publicKey),
            "signature":signature
        }
        data = Serialization.serializeObjToJson(data)
        print({"missingProposerData":data})
        headers = {'Content-type': 'application/json',
                'Accept': 'text/plain'}

        for peer in self.peers:
            url = peer + "MissingProposer"
            try:
                r = requests.post(url, data= data, headers=headers)
                if r.status_code == requests.codes.ok:
                    data = Serialization.deserializeObjFromJsonR(r.text)
                    print(data)

            except:
                print("maybe it was the proposer?")
            
                

    def getLastBlockHashFromPeers(self):
        import requests
        hashes = {}
        for peer in self.peers:
            url = peer + "BlockChainLastHash"
            publicKeyString = keySerialization.serializePublicKeyToString(self.publicKey)
            signature = Signing.normalSigning(self.__privateKey, str(publicKeyString))
            data = {
                "sender": publicKeyString,
                "signature":signature
            }
            data = Serialization.serializeObjToJson(data)
            headers = {'Content-type': 'application/json',
                'Accept': 'text/plain'}
            r = requests.post(url, data= data, headers=headers)
            if r.status_code == requests.codes.ok:
                data = Serialization.deserializeObjFromJsonR(r.text)
                lastBlockHash = data['lastHash']

                if not(lastBlockHash in hashes):
                    hashes[lastBlockHash] = 1
                else:
                    hashes[lastBlockHash] += 1
        max = -1
        maxHash = ""

        for key in hashes:
            if hashes[key] > max:
                max = hashes[key]
                maxHash = key

        return maxHash

    def resyncWithLongestBlockChain(self):
        print("Resyncing blockchains")
        longestChain = 0
        peerWithLongestBlockChain = self.peers[0]
        for peer in self.peers:
            if peer != "http://127.0.0.1:" + str(5000 + nodeId) + "/":
                #print("get all the lengths of the blockchains and select the longest one to query")
                peerChainLength = self.getBlockChainLengthOfPeer(peer)
                print({"peerChainLength": peerChainLength})
                if  peerChainLength > longestChain:
                    peerWithLongestBlockChain = peer
                    longestChain = peerChainLength
        
        if longestChain > self.blockChain.length:
            self.requestMissingBlocksFromPeer(peerWithLongestBlockChain)
            return 0
        else:
            return -1 # returns -1 if chains are in sync and still no new blocks are proposed



    def getPendingTransactions(self, peer):
        url = peer + "GetPendingTransactions"

        publicKeyString = keySerialization.serializePublicKeyToString(self.publicKey)
        signature = Signing.normalSigning(self.__privateKey, str(publicKeyString))
        data = {
            "sender": publicKeyString,
            "signature":signature
        }
        
        headers = {'Content-type': 'application/json',
                'Accept': 'text/plain'}

        data = Serialization.serializeObjToJson(data)

        try:



            r = requests.post(url, data= data, headers=headers)

            if r.status_code == requests.codes.ok:

                data = Serialization.deserializeObjFromJsonR(r.text)

                transactions = data["pendingTransactions"]

                return transactions

        except:
            return {}
            


    def getBlockChainLengthOfPeer(self, peer):

        try:
            url = peer + "GetBlockChainLength"
        
            publicKeyString = keySerialization.serializePublicKeyToString(self.publicKey)
            signature = Signing.normalSigning(self.__privateKey, str(publicKeyString))
            data = {
                "sender": publicKeyString,
                "signature":signature
            }
            
            headers = {'Content-type': 'application/json',
                    'Accept': 'text/plain'}

            data = Serialization.serializeObjToJson(data)
            
            r = requests.post(url, data= data, headers=headers)

            if r.status_code == requests.codes.ok:

                data = Serialization.deserializeObjFromJsonR(r.text)

                length = data["chainLength"]

                print({"chainLengthdata":length})

                return length
            
            return 0

        except:
            return 0
    
    def signData(self, data):
        return Signing.normalSigning(self.__privateKey, data)


    def createBlock(self, TransactionSource):
        transactions = []

        transactionDict = PBFTNode.node.getPendingTransactions(TransactionSource)

        for key in transactionDict:
            transactions.append(transactionDict[key])

        newIndex = self.blockChain.length
        timestamp = time.time()

        previousHash = self.blockChain.last_block().getHash()
        proposerId = self.id
        newIndex = self.blockChain.length
        block = Block(newIndex, transactions, timestamp,
                    previousHash, proposerId)
        return block


    def requestMissingBlocksFromPeer(self, peer):
        import requests
        import json
        
        print("Missing Blocks Detected, requesting blocks from peers")
        url = peer + "MissingBlockRequeset"
        lastHash = self.blockChain.last_block().getHash()
        signature = Signing.normalSigning(self.__privateKey, lastHash)
        data = {
            "lastHash": lastHash,
            "sender": keySerialization.serializePublicKeyToString(self.publicKey),
            "signature": signature
        }
        data = Serialization.serializeObjToJson(data)
        headers = {'Content-type': 'application/json',
                'Accept': 'text/plain'}

        try:
            r = requests.post(url, data= data, headers=headers)

            if r.status_code == requests.codes.ok:

                print({"response from other server for missing block request": r.text})

                data = Serialization.deserializeObjFromJsonR(r.text)

                #print({"result from missing block request":data['response']})

                #print(data['response'] == "Blockchains shared no hashes, completely out of sync")

                print({"missingBlockData":data})

                if data['response'] == "Blockchains shared no hashes, completely out of sync":
                    self.requestEntireBlockChainFromPeer(peer)
                
                else:
                    
                    missingBlocks = data['response']['missingBlocks']

                    print({"# of missing Blocks Found":len(missingBlocks)})

                    if len(missingBlocks) > 0:
                        for i in range(len(missingBlocks)-1, -1, -1):
                            deserializedBlock = Block.deserializeJSON(missingBlocks[i])
                            if BlockVerification.VerifyBlock(deserializedBlock,self.node) == True:
                                PBFTNode.node.blockChain.add_block(deserializedBlock)
                            else: 
                                raise Exception("Resync of blockchain failed becuase of invalid block")
            else:
                return None

        except Exception as e :
            print(str(e))

    def requestEntireBlockChainFromPeer(self, peer):
        import requests
        import json

        print("Requesting blockchain from longest Peer")

        url = peer + "RequestEntireBlockchain"
        signature = Signing.normalSigning(self.__privateKey, keySerialization.serializePublicKeyToString(self.publicKey))
        data = {
            "sender": keySerialization.serializePublicKeyToString(self.publicKey),
            "signature": signature
        }

        headers = {'Content-type': 'application/json',
                'Accept': 'text/plain'}

        data = Serialization.serializeObjToJson(data)

        r = requests.post(url, data= data, headers=headers)

        if r.status_code == requests.codes.ok:

            #print({"response from entire blockchain request": r.text})

            jsn = Serialization.deserializeObjFromJsonR(r.text)

            recievedHash = jsn['blockChainHash']

            blockchainString = jsn['blockChain']
            print("Saved new blockchain")

            PBFTNode.node.blockChain = BlockChain.deserializeJSON(blockchainString)
        else:
            print({"failed status entire blkchn": r.status_code})
            print({"failed status entire blkchn": r.text})
        

    
    def SendBlockCreationSignalForSingularNode(self):
        import requests
        #try:
        url = "http://127.0.0.1:" + str(5000 + nodeId) + "/AddNewBlockForSingularNode"
        publicKeyString =  keySerialization.serializePublicKeyToString(self.publicKey)
        signature = Signing.normalSigning(self.__privateKey, publicKeyString)
        data = {
            "sender": publicKeyString,
            "signature": signature
        }
        data = Serialization.serializeObjToJson(data)
        headers = {'Content-type': 'application/json',
                'Accept': 'text/plain'}
        
        r = requests.post(url, data= data, headers=headers)
        if r.status_code == requests.codes.ok:

            data = Serialization.deserializeObjFromJsonR(r.text)

            return data
        else:
            return None
        #except:
            #print("Node not found: self")

                
        #print("Done Broadcasting new block")
        
    def reBroadcastMessage(self, data, route):
        from threading import Thread
        #print("rebroadcasting Message " + route)
        if route == "Transaction":
            for peer in self.peers:
                self.reBroadcastSingleMessage(peer,data, route)
        #else:
            #print("Rebroadcasting Disabled")
        #print("Done ReBroadcasting " + route)

    def reBroadcastSingleMessage(self, peer,data, route):
        from threading import Thread
        from requests import post
        import json
        try:
            url = peer + route
            headers = {'Content-type': 'application/json',
                    'Accept': 'text/plain'}
            Thread(target=post, args=(url,), kwargs={"json": json.loads(data), "headers": headers}).start()

        except:
            print("line 213: Node not found at: " + peer)


    def broadcastBlockToPeers(self, block, blockHash):
        
        for peer in self.peers:
            self.broadcastBlockToSinglePeer(peer, block, blockHash)
                
        #print("Done Broadcasting new block")

    def broadcastBlockToSinglePeer(self, peer, block, blockHash):
        try:
            #print("Broadcasting New Block to: " + peer)
            url = peer + "ProposeBlock"
            blockString = block.serializeJSON()
            signature = Signing.normalSigning(self.__privateKey, blockHash)
            data = {
                "blockData":blockString,
                "blockHash": blockHash,
                "sender": keySerialization.serializePublicKeyToString(self.publicKey),
                "signature": signature
            }
            data = Serialization.serializeObjToJson(data)
            headers = {'Content-type': 'application/json',
                    'Accept': 'text/plain'}
            
            r = requests.post(url, data= data, headers=headers)
            if r.status_code == requests.codes.ok:

                data = Serialization.deserializeObjFromJsonR(r.text)


                if peer in PBFTNode.node.delinquentPeers and PBFTNode.node.delinquentPeers[peer] > 5:
                    PBFTNode.node.delinquentPeers[peer] = 0
                    print({"welcome back! Id": peer})

                #print({"Broadcast Single Block":data})
            else:
                if peer in PBFTNode.node.delinquentPeers:

                    PBFTNode.node.delinquentPeers[peer] += 1
                else:
                    PBFTNode.node.delinquentPeers[peer] = 1
                    
                return None
        except:

            if peer in PBFTNode.node.delinquentPeers:

                PBFTNode.node.delinquentPeers[peer] += 1
            else:
                PBFTNode.node.delinquentPeers[peer] = 1
            print("line 248: Node not found at: " + peer)


    def broadcastBlockChainToNewNode(self, peer):
        import requests
        import hashlib
        try:
            url = peer + "SendNewBlockChain"
            blockChainString = self.blockChain.serializeJSON()
            hash = hashlib.sha256(blockChainString.encode()).hexdigest()
            signature = Signing.normalSigning(self.__privateKey, hash)
            data = {
                "blockChain":blockChainString,
                "blockChainHash": hash,
                "sender": keySerialization.serializePublicKeyToString(self.publicKey),
                "signature": signature
            }
            data = Serialization.serializeObjToJson(data)
            headers = {'Content-type': 'application/json',
                    'Accept': 'text/plain'}
            
            r = requests.post(url, data= data, headers=headers)
            if r.status_code == requests.codes.ok:

                data = Serialization.deserializeObjFromJsonR(r.text)

                #print({"Broadcast Blockchain to new node":data})
            else:
                return None
        except:
            
            print("line 279: Node not found at: " + peer)
                
        #print("Done Broadcasting new blockchain")

    def broadcastVerificationVotesToPeers(self, blockHash, blockString):
        for peer in self.peers:
            self.broadcastVerificationVoteToSinglePeer(peer, blockHash, blockString)
            

    def broadcastVerificationVoteToSinglePeer(self, peer,blockHash, blockString):
        try:
            #print("Broadcasting Verification Vote to: " + peer)
            url = peer + "VerificationVote"
            signature = Signing.normalSigning(self.__privateKey, blockHash)
            data = {
                "blockData":blockString,
                "sender": keySerialization.serializePublicKeyToString(self.publicKey),
                "signature": signature,
                "blockHash": blockHash
            }
            data = Serialization.serializeObjToJson(data)
            headers = {'Content-type': 'application/json',
                    'Accept': 'text/plain'}
            r = requests.post(url, data=data, headers=headers)
            if r.status_code == requests.codes.ok:

                data = Serialization.deserializeObjFromJsonR(r.text)

                if peer in PBFTNode.node.delinquentPeers and PBFTNode.node.delinquentPeers[peer] > 5:
                    PBFTNode.node.delinquentPeers[peer] = 0
                    print({"welcome back! Id": peer})

                #print({"Verifiaction vote resp":data})
            else:
                if peer in PBFTNode.node.delinquentPeers:

                    PBFTNode.node.delinquentPeers[peer] += 1
                else:
                    PBFTNode.node.delinquentPeers[peer] = 1
        except:
            if peer in PBFTNode.node.delinquentPeers:
                PBFTNode.node.delinquentPeers[peer] += 1
            else:
                PBFTNode.node.delinquentPeers[peer] = 1
            print("line 307: Node not found at: " + peer)
        
    def broadcastCommitVotesToPeers(self, blockHash, blockString):
        for peer in self.peers:
            self.broadcastCommitVoteToSinglePeer(peer, blockHash, blockString)
            
    def broadcastCommitVoteToSinglePeer(self, peer,blockHash, blockString):
        try:
            #print("Broadcasting Commit Vote to: " + peer)
            url = peer + "CommitVote"
            signature = Signing.normalSigning(self.__privateKey, blockHash)
            data = {
                "blockData":blockString,
                "sender": keySerialization.serializePublicKeyToString(self.publicKey),
                "signature": signature,
                "blockHash": blockHash
            }
            data = Serialization.serializeObjToJson(data)
            headers = {'Content-type': 'application/json',
                    'Accept': 'text/plain'}
            r = requests.post(url, data=data, headers=headers)
            if r.status_code == requests.codes.ok:

                data = Serialization.deserializeObjFromJsonR(r.text)
                #print({"Commit vote resp":data})
        except:
            print("line 333: Node not found at: " + peer)
        
    def broadcastNewRoundVotesToPeers(self, blockHash, blockString):
        import requests
        for peer in self.peers:
            self.broadcastNewRoundVoteToSinglePeer(peer, blockHash, blockString)
            

    def broadcastNewRoundVoteToSinglePeer(self,peer, blockHash, blockString):
        try:
            #print("Broadcasting New Round Vote to: " + peer)
            url = peer + "NewRound"
            signature = Signing.normalSigning(self.__privateKey, blockHash)
            data = {
                "blockData": blockString,
                "sender": keySerialization.serializePublicKeyToString(self.publicKey),
                "signature": signature,
                "blockHash": blockHash
            }
            data = Serialization.serializeObjToJson(data)
            headers = {'Content-type': 'application/json',
                    'Accept': 'text/plain'}
            r = requests.post(url, data=data, headers=headers)
            if r.status_code == requests.codes.ok:

                data = Serialization.deserializeObjFromJsonR(r.text)
                #print({"New Round vote resp":data})
        except:
            print("line 360: Node not found at: " + peer)
        

    def calculateProposerId(self):
        
        NumberOfPeers = len(self.peers)

        #print({"lenPeers":len(self.peers)})

        if len(self.peers) < 1 or self.blockChain.chain[-1].proposerId == -1:
            #print("Other things are happening, weird")
            return 0
        #print({"proposerOffset": self.proposerOffset})
        index = (self.blockChain.chain[-1].proposerId + 1 + self.proposerOffset) % (NumberOfPeers)
        return index 

    def signData(self, data):
        return Signing.normalSigning(self.__privateKey, data)


    @staticmethod
    def compressJson(input):
        return brotli.compress(input)

    @staticmethod
    def decompressJson(input):
        return brotli.decompress(input)

    @staticmethod
    def configureBlockChainForFirstUse():

        client1 = TinyWebClient.initializeClient("0")
        blockChain = BlockChain(creatorPublicKey=client1.publicKey)

        return blockChain
