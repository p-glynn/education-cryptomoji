'use strict';

const {
    createHash
} = require('crypto');
// accepts public key, message, signature
const { verify } = require('./signing');
const { Block } = require('./blockchain');

/**
 * A simple validation function for transactions. Accepts a transaction
 * and returns true or false. It should reject transactions that:
 *   - have negative amounts
 *   - were improperly signed
 *   - have been modified since signing
 */
const isValidTransaction = transaction => {
    const { source, recipient, amount, signature } = transaction
    if (amount < 0) return false
    
    const data = source + recipient + amount
    return verify(source, data, signature)

};

/**
 * Validation function for blocks. Accepts a block and returns true or false.
 * It should reject blocks if:
 *   - their hash or any other properties were altered
 *   - they contain any invalid transactions
 */
const isValidBlock = block => {
    const isTrue = (value) => value
    const { transactions, previousHash, nonce, hash } = block


    // make sure all transaction are valid
    // map makes an array of validity of each transaction i.e. [true, true, true, false]
    // every returns whether each item in array satisifies given function
    const validateTransactions = transactions.map(transaction => isValidTransaction(transaction))
    const allTransactionsAreValid = validateTransactions.every(isTrue)
    if (!allTransactionsAreValid) return false

    const testBlock = new Block(transactions, previousHash)
    if (testBlock.hash !== hash) return false
    if (testBlock.nonce !== nonce) return false

    return true

};

/**
 * One more validation function. Accepts a blockchain, and returns true
 * or false. It should reject any blockchain that:
 *   - is a missing genesis block
 *   - has any block besides genesis with a null hash
 *   - has any block besides genesis with a previousHash that does not match
 *     the previous hash
 *   - contains any invalid blocks
 *   - contains any invalid transactions
 */
const isValidChain = blockchain => {
    const { blocks } = blockchain
    if (blocks[0].transactions.length || blocks[0].previousHash != null) {
        return false
    }
    const isTrue = (value) => value

    const validateBlocks = blocks.map(block => isValidBlock(block))
    const allBlocksAreValid = validateBlocks.every(isTrue)
    if (!allBlocksAreValid) return false

    for (let i=0; i<blocks.length-1; i++) {
        if (blocks[i].hash !== blocks[i+1].previousHash) return false
    }

    return true

};

/**
 * This last one is just for fun. Become a hacker and tamper with the passed in
 * blockchain, mutating it for your own nefarious purposes. This should
 * (in theory) make the blockchain fail later validation checks;
 */
const breakChain = blockchain => {
    // Your code here

};

module.exports = {
    isValidTransaction,
    isValidBlock,
    isValidChain,
    breakChain
};
