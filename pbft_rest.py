from time import perf_counter
from flask import Flask, request, jsonify
from os import path

from Packages.Serialization.keySerialization import keySerialization
from Packages.Structures.BlockChain.Parsers.BlockchainParser import BlockchainParser

from Packages.Structures.BlockChain.Transaction import Transaction
from ..Serialization.Serialization import Serialization

from ..Structures.BlockChain.Block import Block

from ..Structures.BlockChain.BlockChain import BlockChain

from ..pBFT.node import PBFTNode

from ..Verification.Signing import Signing

from ..Verification.BlockVerification import BlockVerification

import json

import time

import asyncio

def createBlock():
    transactions = []
    for tr in MessageQueues.transactionQueue.values():
        transactions.append(tr)

    newIndex = PBFTNode.node.blockChain.length
    timestamp = time.time()
    # print(timestamp)
    previousHash = PBFTNode.node.blockChain.last_block().getHash()
    proposerId = PBFTNode.node.id
    newIndex = PBFTNode.node.blockChain.length
    block = Block(newIndex, transactions, timestamp,
                previousHash, proposerId)
    return block

class MessageQueues:
    PendingBlockDict = {}
    CommitedBlockDict = {}
    transactionQueue = {}
    validationVotes = {}
    commitMessages = {}
    newRoundMessages = {}
    missingProposerVotes = {}
    transactionQueueLimit = 3
    blockChainParent = ""
    

app = Flask(__name__)


@app.route("/")
def hello_world():
    return "<p>Hello, World!</p>"


@app.route("/Transaction", methods=['POST'])
def get_transaction():
    jsn = request.get_json()

    print(jsn)
    transaction = Transaction.loadJson(jsn)

    transactionHash = transaction.hash()
    
    if transactionHash in MessageQueues.transactionQueue:
        return json.dumps({"response": "Transaction Already Queued"})

    if not(transaction.sender.encode() in BlockchainParser.getAllUsers(PBFTNode.node.blockChain)):
        print({"userNot Verified publicKey": transaction.sender})
        return json.dumps({"response": "User Not Verified"})

    print("------------")
    print(transaction.sender.encode())
    print("------------")
    print(transaction.signatureStr)
    print("------------")
    print(transactionHash)
    print("------------")

    try:
        Signing.verifyStringSignatureData(transaction.sender, transaction.signatureStr)
    except:
        return json.dumps({"response": "KeyError"})

    if not BlockVerification.VerifyTransaction(transaction, PBFTNode.node, "Transactions"):
        return json.dumps({"response": "invalid Permissions"})

    MessageQueues.transactionQueue[transactionHash] = transaction

    PBFTNode.node.reBroadcastMessage(Serialization.serializeObjToJson(jsn), "Transaction")

    PBFTNode.node.ProposerId = PBFTNode.node.calculateProposerId()

    print({"Proposer Id":PBFTNode.node.ProposerId})


    """
    if len(MessageQueues.transactionQueue) > MessageQueues.transactionQueueLimit and PBFTNode.node.ProposerId == PBFTNode.node.id:
        print("about to propose a block!")

        #PBFTNode.node.requestMissingBlocks()

        currentBlock = createBlock()
        BlockVerification.VerifyBlock(currentBlock)

        blockHash = currentBlock.getHash()

        if currentBlock.previous_hash != PBFTNode.node.blockChain.last_block().getHash():
                raise Exception({"in Transaction, sync error detected":"Chains Out of sync while proposing block"})

        #print({"Proposed Block previous hash":currentBlock.previous_hash})

        #print({"Proposed Block blockchais Hashes":PBFTNode.node.blockChain.getListOfBlockHashes()})

        PBFTNode.node.broadcastBlockToPeers(currentBlock, blockHash)

        #PBFTNode.node.broadcastVerificationVotesToPeers(blockHash)
    """

    

    return json.dumps({"status":"ok"})

@app.route("/TransactionInternal", methods=['POST'])
def TransactionInternal():
    jsn = request.get_json()

    proposer = jsn['transaction']['sender']

    signature = jsn['signature']

    transaction = jsn['transaction']

    hash = Serialization.hashObject(transaction)

    try:
        Signing.verifyingTheSignature(keySerialization.deserializePublicKeyFromString(proposer), signature, hash)
        
    except:
        return json.dumps({"response": "KeyError"})

    MessageQueues.transactionQueue[hash] = transaction


    return json.dumps({"response": "ok"})

    
    


@app.route("/ProposeBlock", methods=['POST'])
def NewBlock():
    jsn = request.get_json()

    blockjsn = jsn['blockData']

    proposer = jsn['sender']

    signature = jsn['signature']

    recievedHash = jsn['blockHash']

    idIpInfo = {}

    try:
        #print({"Proposing Block Pub Key": proposer})
        #print(PBFTNode.node.fullPeerInfo)
        idIpInfo = PBFTNode.node.fullPeerInfo[proposer]
        Signing.verifyingTheSignature(keySerialization.deserializePublicKeyFromString(proposer), signature, recievedHash)
        
    except:
        return json.dumps({"response": "KeyError"})

    blockString = json.dumps(blockjsn, indent=4, sort_keys=True)

    myPublicKey = keySerialization.serializePublicKeyToString(PBFTNode.node.publicKey)
    

    if recievedHash in MessageQueues.PendingBlockDict or recievedHash in MessageQueues.CommitedBlockDict:
        return json.dumps({"response": "Block already Processed"})

    block = Block.deserializeJSON(blockString)
    blockHash = block.getHash()


    if not(proposer in PBFTNode.node.PKeyIdDict):
        PBFTNode.node.PKeyIdDict[proposer] = block.proposerId


    if recievedHash == blockHash and BlockVerification.VerifyBlock(block, PBFTNode.node):
        import random
        random.shuffle(PBFTNode.node.peers)

        if block.previous_hash != PBFTNode.node.blockChain.last_block().getHash():
                raise Exception({"in commit, sync error detected":"Chains Out of sync while recieving poposed block"})

        MessageQueues.PendingBlockDict[recievedHash]  = block

        PBFTNode.node.reBroadcastMessage(Serialization.serializeObjToJson(jsn), "ProposeBlock")
        #time.sleep(1)

        PBFTNode.node.broadcastVerificationVotesToPeers(recievedHash, blockString)

        return json.dumps({"response": "ok"})

    return json.dumps({"response": "hash/validation error"})
        

    



@app.route("/VerificationVote", methods=['POST'])
def VerificationVote():
    
    jsn = request.get_json()

    proposer = jsn['sender']

    signature = jsn['signature']

    recievedHash = jsn['blockHash']


    idIpInfo = {}

    try:
        idIpInfo = PBFTNode.node.fullPeerInfo[proposer]
        Signing.verifyingTheSignature(keySerialization.deserializePublicKeyFromString(proposer), signature, recievedHash)
        
    except:
        return json.dumps({"response": "KeyError"})

    blockjsn = jsn['blockData']

    blockString = json.dumps(blockjsn, indent=4, sort_keys=True)

    block = Block.deserializeJSON(blockString)
    blockHash = block.getHash()


    if recievedHash == blockHash:
        if recievedHash in MessageQueues.validationVotes:
            if proposer in MessageQueues.validationVotes[recievedHash]:
                return json.dumps({"response": "Vote Already Counted"})

        

        if not(recievedHash in MessageQueues.validationVotes):
            MessageQueues.validationVotes[recievedHash] = []

        MessageQueues.validationVotes[recievedHash].append(proposer)

        PBFTNode.node.reBroadcastMessage(Serialization.serializeObjToJson(jsn), "VerificationVote")
        #time.sleep(1)

        reachedThreshold = False

        #if len(PBFTNode.node.peers) == 1 or len(PBFTNode.node.peers) == 1:
            #if recievedHash in MessageQueues.validationVotes and len(MessageQueues.validationVotes[recievedHash]) == len(PBFTNode.node.peers)+1:
                #reachedThreshold = True
        
        #elif len(PBFTNode.node.peers) >= 2:

        activePeers = 0

        for peer in PBFTNode.node.peers:
            if not(peer in PBFTNode.node.delinquentPeers):
                activePeers += 1
            elif PBFTNode.node.delinquentPeers[peer] < 15:
                activePeers += 1
            

        minApprovals = int(2 * (activePeers / 3) + 1)

        #print({"active Peers":activePeers})

        #print({"min approvals": minApprovals})
        if recievedHash in MessageQueues.validationVotes:
            if len(MessageQueues.validationVotes[recievedHash]) >= minApprovals:
                reachedThreshold = True

        if reachedThreshold:
            #print("about to send commit")
            PBFTNode.node.broadcastCommitVotesToPeers(recievedHash, blockString)

            return jsonify({"response": "Broadcasted Commit"})
        
        return jsonify({"response": "Recieved verification but didnt hit threshold"})

    return json.dumps({"response": "hashes didnt match"})





@app.route("/CommitVote", methods=['POST'])
def CommitVote():
    jsn = request.get_json()

    proposer = jsn['sender']

    signature = jsn['signature']

    recievedHash = jsn['blockHash']

    idIpInfo = {}

    try:
        idIpInfo = PBFTNode.node.fullPeerInfo[proposer]
        Signing.verifyingTheSignature(keySerialization.deserializePublicKeyFromString(proposer), signature, recievedHash)
        
    except:
        return json.dumps({"response": "KeyError"})


    blockjsn = jsn['blockData']

    blockString = json.dumps(blockjsn, indent=4, sort_keys=True)

    block = Block.deserializeJSON(blockString)
    blockHash = block.getHash()

    if recievedHash == blockHash:
        if recievedHash in MessageQueues.commitMessages:
            if proposer in MessageQueues.commitMessages[recievedHash]:
                return json.dumps({"response": "Vote Already Counted"})

        

        if not(recievedHash in MessageQueues.commitMessages):
            MessageQueues.commitMessages[recievedHash] = []

        #print({"in commitVote, recievedHash": recievedHash})
        MessageQueues.commitMessages[recievedHash].append(proposer)

        #print({"InCommitVote, commitMessages":MessageQueues.commitMessages[recievedHash] })

        PBFTNode.node.reBroadcastMessage(Serialization.serializeObjToJson(jsn), "CommitVote")
        #time.sleep(1)

        reachedThreshold = False

        #if len(PBFTNode.node.peers) == 1 or len(PBFTNode.node.peers) == 1:

            #if recievedHash in MessageQueues.commitMessages and len(MessageQueues.commitMessages[recievedHash]) >= len(PBFTNode.node.peers) + 1:
                #reachedThreshold = True
            
        #elif len(PBFTNode.node.peers) >= 2:
        activePeers = 0

        for peer in PBFTNode.node.peers:
            if not(peer in PBFTNode.node.delinquentPeers):
                activePeers += 1
            elif PBFTNode.node.delinquentPeers[peer] < 15:
                activePeers += 1
            

        minApprovals = int(2 * (activePeers / 3) + 1)


        if recievedHash in MessageQueues.commitMessages:
            if len(MessageQueues.commitMessages[recievedHash]) >= minApprovals:
                reachedThreshold = True


        if reachedThreshold:

            #print({"Proposed Block":block.getHash()})

            #print({"Proposed Block previous hash":block.previous_hash})

            #print({"Proposed Block blockchais last Hashes":PBFTNode.node.blockChain.last_block().getHash()})

            #print("about to send newRound")

            if block.getHash() == PBFTNode.node.blockChain.last_block().getHash():
                print("Block Already Commited to chain")
                MessageQueues.CommitedBlockDict[blockHash] = blockHash
                PBFTNode.node.broadcastNewRoundVotesToPeers(recievedHash, blockString)
                return jsonify({"response": "Block Already Commited to chain"})

            
            if block.previous_hash != PBFTNode.node.blockChain.last_block().getHash():
                raise Exception({"in commit, sync error detected":"While Committing, chain out of sync"})

            if not(blockHash in MessageQueues.CommitedBlockDict):

                block.previous_hash = PBFTNode.node.blockChain.last_block().getHash()

                #PBFTNode.node.requestMissingBlocks()

                PBFTNode.node.proposerOffset = 0

                PBFTNode.node.blockChain.add_block(block)

                MessageQueues.CommitedBlockDict[blockHash] = blockHash

                PBFTNode.node.broadcastNewRoundVotesToPeers(recievedHash, blockString)

                print({"Block Committed, BlockChainLength": len(PBFTNode.node.blockChain.chain)})

            
        
        return jsonify({"response": "Recieved commit but didnt hit threshold"})

    return json.dumps({"response": "hashes dont match"})

  



@app.route("/NewRound", methods=['POST'])
def NewRound():
    jsn = request.get_json()

    proposer = jsn['sender']

    signature = jsn['signature']

    recievedHash = jsn['blockHash']


    idIpInfo = {}

    try:
        idIpInfo = PBFTNode.node.fullPeerInfo[proposer]
        Signing.verifyingTheSignature(keySerialization.deserializePublicKeyFromString(proposer), signature, recievedHash)
        
    except:
        return json.dumps({"response": "KeyError"})

    blockjsn = jsn['blockData']

    blockString = json.dumps(blockjsn, indent=4, sort_keys=True)

    block = Block.deserializeJSON(blockString)
    blockHash = block.getHash()

    if recievedHash == blockHash:
        if recievedHash in MessageQueues.newRoundMessages:
            if proposer in MessageQueues.newRoundMessages[recievedHash]:
                return json.dumps({"response": "Vote Already Counted"})

        if not(recievedHash in MessageQueues.newRoundMessages):
            MessageQueues.newRoundMessages[recievedHash] = []

        MessageQueues.newRoundMessages[recievedHash].append(proposer)

        PBFTNode.node.reBroadcastMessage(Serialization.serializeObjToJson(jsn), "NewRound")
        #time.sleep(1)

        reachedThreshold = False        

        #if len(PBFTNode.node.peers) == 1 or len(PBFTNode.node.peers) == 1:
            #if recievedHash in MessageQueues.newRoundMessages:
                #if len(MessageQueues.newRoundMessages[recievedHash]) == len(PBFTNode.node.peers) + 1:
                    #reachedThreshold = True
            
        #elif len(PBFTNode.node.peers) >= 2:
        activePeers = 0

        for peer in PBFTNode.node.peers:
            if not(peer in PBFTNode.node.delinquentPeers):
                activePeers += 1
            elif PBFTNode.node.delinquentPeers[peer] < 15:
                activePeers += 1
            

        minApprovals = int(2 * (activePeers / 3) + 1)


        print({"New Round Votes": len(MessageQueues.newRoundMessages[recievedHash])})
        print({"minApprovals":minApprovals})

        if recievedHash in MessageQueues.newRoundMessages:
            if len(MessageQueues.newRoundMessages[recievedHash]) >= minApprovals:
                reachedThreshold = True

        if reachedThreshold:
            if block.previous_hash == PBFTNode.node.blockChain.chain[-1].getHash():

                print("----------------------- \nNode was not needed in voting, catching up to make sure that it stays in the loop \n -----------------------")

            

                print({"Proposed Block blockchais last Hashes":PBFTNode.node.blockChain.last_block().getHash()})

                PBFTNode.node.blockChain.add_block(block)

                MessageQueues.CommitedBlockDict[blockHash] = blockHash

                print({"Block Committed, BlockChainLength": len(PBFTNode.node.blockChain.chain)})


            print("Clearing House")
            if recievedHash in MessageQueues.validationVotes:
                del MessageQueues.validationVotes[recievedHash]
            if recievedHash in MessageQueues.commitMessages:
                del MessageQueues.commitMessages[recievedHash]
            if recievedHash in MessageQueues.newRoundMessages:
                del MessageQueues.newRoundMessages[recievedHash]

            trnsDeletedCount = 0
            for trns in block.transactions:
                transactionHash = Serialization.hashObject(trns)
                if transactionHash in MessageQueues.transactionQueue:
                    del MessageQueues.transactionQueue[transactionHash]
                    trnsDeletedCount += 1
            print({"transactions Deleted From Queue": trnsDeletedCount}) 
            print({"transactions is block that was commited": len(block.transactions)}) 
            


            return jsonify({"response": "Cleared Queues"})
        
        return jsonify({"response": "Recieved new round but didnt hit threshold to clear"})

    return jsonify({"response": "voting on a non-existent block"})



@app.route("/BlockChainLastHash", methods=['POST'])
def BlockChainLastHash():
    jsn = request.get_json()

    proposer = jsn['sender']

    signature = jsn['signature']

    idIpInfo = {}
    try:

        Signing.verifyingTheSignature(keySerialization.deserializePublicKeyFromString(proposer), signature, proposer)
        
    except:
        return json.dumps({"response": "KeyError"})
    return json.dumps({"lastHash": PBFTNode.node.blockChain.chain[-1].getHash()})

@app.route("/GetPendingTransactions", methods=['POST'])
def GetPendingTransactions():
    jsn = request.get_json()

    proposer = jsn['sender']

    signature = jsn['signature']

    idIpInfo = {}
    try:
        Signing.verifyingTheSignature(keySerialization.deserializePublicKeyFromString(proposer), signature, proposer)
    except:
        return json.dumps({"response": "KeyError"})
    return json.dumps({"pendingTransactions": MessageQueues.transactionQueue})



@app.route("/GetBlockChainLength", methods=['POST'])
def GetBlockChainLength():
    jsn = request.get_json()

    proposer = jsn['sender']

    signature = jsn['signature']

    try:
        Signing.verifyingTheSignature(keySerialization.deserializePublicKeyFromString(proposer), signature, proposer)
        
    except:
        return json.dumps({"response": "KeyError"})

    return json.dumps({"chainLength": PBFTNode.node.blockChain.length})

    

@app.route("/MissingBlockRequeset", methods=['POST'])
def MissingBlockRequeset():

    jsn = request.get_json()

    proposer = jsn['sender']

    signature = jsn['signature']

    lastHash = jsn['lastHash']

    print({"Missing Block Requets: last Hash": lastHash})

    missingBlocks = []

    missingHashes = []



    try:
        Signing.verifyingTheSignature(keySerialization.deserializePublicKeyFromString(proposer), signature, lastHash)
        
    except:
        return json.dumps({"response": "KeyError"})

    for i in range(len(PBFTNode.node.blockChain.chain)-1 ,-1,-1):
        
        currentHash = PBFTNode.node.blockChain.chain[i].getHash()
        #print({"Missing Block Request current Hash Scanned":currentHash})
        if currentHash != lastHash:
            missingBlocks.append(PBFTNode.node.blockChain.chain[i].serializeJSON())
            missingHashes.append(PBFTNode.node.blockChain.chain[i].getHash())
        elif currentHash == lastHash:
            return json.dumps({"response":{"missingBlocks":missingBlocks}})

    #print({"Proposed Block blockchais Hashes":PBFTNode.node.blockChain.getListOfBlockHashes()})

    #print({"Missing Block Hashes":missingHashes})

    if len(missingHashes) != 0:
        return json.dumps({"response":"Blockchains shared no hashes, completely out of sync"})

    return json.dumps({"response":{"missingBlocks":[]}})




@app.route("/SendNewBlockChain", methods=['POST'])
def SendNewBlockChain():

    jsn = request.get_json()

    proposer = jsn['sender']

    signature = jsn['signature']

    recievedHash = jsn['blockChainHash']

    blockchainString = jsn['blockChain']


    idIpInfo = {}

    try:
        idIpInfo = PBFTNode.node.fullPeerInfo[proposer]
        Signing.verifyingTheSignature(keySerialization.deserializePublicKeyFromString(proposer), signature, recievedHash)
        
    except:
        return json.dumps({"response": "KeyError"})

    #print({"remoteIP": request.remote_addr})

    if request.remote_addr in PBFTNode.node.peers:
        return json.dumps({"response":"already synced BLKCHN with node"})
    

    MessageQueues.blockChainParent = proposer

    

    if keySerialization.serializePublicKeyToString(PBFTNode.node.publicKey) == proposer:
        return json.dumps({"response": "Will "})

    

    PBFTNode.node.blockChain = BlockChain.deserializeJSON(blockchainString)

    return json.dumps({"response":"thankyoufor the blockchain"})

@app.route("/RequestEntireBlockchain", methods=['POST'])
def RequestEntireBlockchain():

    jsn = request.get_json()

    proposer = jsn['sender']

    signature = jsn['signature']

    idIpInfo = {}

    try:
        Signing.verifyingTheSignature(keySerialization.deserializePublicKeyFromString(proposer), signature, proposer)
        
    except:
        return json.dumps({"response": "KeyError"})

    blockchainString = PBFTNode.node.blockChain.serializeJSON()

    blockChainHash = Serialization.hashString(blockchainString)

    signature = PBFTNode.node.signData(blockChainHash)

    output = {
        "signature": signature,
        "sender": keySerialization.serializePublicKeyToString(PBFTNode.node.publicKey),
        "blockChain": blockchainString,
        "blockChainHash": blockChainHash
    }

    return json.dumps(output)


@app.route("/AddNewBlockForSingularNode", methods=['POST'])
def AddNewBlockForSingularNode():
    jsn = request.get_json()

    proposer = jsn['sender']

    signature = jsn['signature']

    idIpInfo = {}

    try:
        Signing.verifyingTheSignature(keySerialization.deserializePublicKeyFromString(proposer), signature, proposer)
       
    except:
        return json.dumps({"response": "KeyError"})

    block = createBlock()

    PBFTNode.node.blockChain.add_block(block)

    MessageQueues.transactionQueue = {}

    print({"BlockChainLength": len(PBFTNode.node.blockChain.chain)})

    print({"transactionLength For Latest block": len(PBFTNode.node.blockChain.chain[-1].transactions)})

    return jsonify({"response": "Added block to chain"})
