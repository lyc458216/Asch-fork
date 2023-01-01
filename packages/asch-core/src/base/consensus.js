// 主要处理共识相关的机制。
// PBFT算法里的发起提案、投票确认等都是在这个模块完成的。
// 主要包含的方法为创建投票、验证票数、发起提案等。
const assert = require('assert')
const crypto = require('crypto')
const ByteBuffer = require('bytebuffer')
const ed = require('../utils/ed.js')
const slots = require('../utils/slots.js')
const featureSwitch = require('../utils/feature-switch.js')

let self
function Consensus(scope) {
  self = this
  this.scope = scope
  this.pendingBlock = null
  this.pendingVotes = null
  this.votesKeySet = {}
}

// 创建投票(createVotes)
Consensus.prototype.createVotes = (keypairs, block) => {
  const hash = self.getVoteHash(block.height, block.id)
  const votes = {
    height: block.height,
    id: block.id,
    signatures: [],
  }
  keypairs.forEach((el) => {
    votes.signatures.push({
      key: el.publicKey.toString('hex'),
      sig: ed.Sign(hash, el).toString('hex'),
    })
  })
  return votes
}

Consensus.prototype.verifyVote = (height, id, voteItem) => {
  try {
    const hash = self.getVoteHash(height, id)
    const signature = Buffer.from(voteItem.sig, 'hex')
    const publicKey = Buffer.from(voteItem.key, 'hex')
    return ed.Verify(hash, signature, publicKey)
  } catch (e) {
    return false
  }
}

Consensus.prototype.getVoteHash = (height, id) => {
  const bytes = new ByteBuffer()
  bytes.writeLong(height)
  if (featureSwitch.isEnabled('enableLongId')) {
    bytes.writeString(id)
  } else {
    const idBytes = app.util.bignumber(id).toBuffer({ size: 8 })
    for (let i = 0; i < 8; i++) {
      bytes.writeByte(idBytes[i])
    }
  }
  bytes.flip()
  return crypto.createHash('sha256').update(bytes.toBuffer()).digest()
}

// 验证要数(hasEnoughVotes)
// 检查Votes是否包含足够多的受托人签名用hasEnoughVotes
// 目前受托人人数是101，需要的签名至少101×2/3=68个受托人。
// 也就是说，如果当时在线的受托人人数不满68人，则无法让这个区块链正常产块。
Consensus.prototype.hasEnoughVotes = votes => votes && votes.signatures
  && votes.signatures.length > slots.delegates * 2 / 3

// Votes需要包含至少6个受托人签名才行。这个判断比上面那个hasEnoughVotes要求更轻一些。
Consensus.prototype.hasEnoughVotesRemote = votes => votes && votes.signatures
  && votes.signatures.length >= 6

Consensus.prototype.getPendingBlock = () =>
  ({ block: self.pendingBlock, failedTransactions: self.failedTransactions })

Consensus.prototype.hasPendingBlock = (timestamp) => {
  if (!self.pendingBlock) {
    return false
  }
  return slots.getSlotNumber(self.pendingBlock.timestamp) === slots.getSlotNumber(timestamp)
}

Consensus.prototype.setPendingBlock = (block, failedTransactions) => {
  self.pendingVotes = null
  self.votesKeySet = {}
  self.pendingBlock = block
  self.failedTransactions = failedTransactions
}

Consensus.prototype.clearState = () => {
  self.pendingVotes = null
  self.votesKeySet = {}
  self.pendingBlock = null
  self.failedTransactions = null
}

Consensus.prototype.addPendingVotes = (votes) => {
  if (!self.pendingBlock || self.pendingBlock.height !== votes.height
    || self.pendingBlock.id !== votes.id) {
    return self.pendingVotes
  }
  for (let i = 0; i < votes.signatures.length; ++i) {
    const item = votes.signatures[i]
    if (self.votesKeySet[item.key]) {
      continue
    }
    if (self.verifyVote(votes.height, votes.id, item)) {
      self.votesKeySet[item.key] = true
      if (!self.pendingVotes) {
        self.pendingVotes = {
          height: votes.height,
          id: votes.id,
          signatures: [],
        }
      }
      self.pendingVotes.signatures.push(item)
    }
  }
  return self.pendingVotes
}

// 发起提案(createPropose)
Consensus.prototype.createPropose = (keypair, block, peerId) => {
  assert(keypair.publicKey.toString('hex') === block.delegate)
  const propose = {
    height: block.height,
    id: block.id,
    timestamp: block.timestamp,
    generatorPublicKey: block.delegate,
    peerId,
  }
  const hash = self.getProposeHash(propose)
  propose.hash = hash.toString('hex')
  propose.signature = ed.Sign(hash, keypair).toString('hex')
  return propose
}

Consensus.prototype.getProposeHash = (propose) => {
  const bytes = new ByteBuffer()
  bytes.writeLong(propose.height)

  if (featureSwitch.isEnabled('enableLongId')) {
    bytes.writeString(propose.id)
  } else {
    const idBytes = app.util.bignumber(propose.id).toBuffer({ size: 8 })
    for (let i = 0; i < 8; i++) {
      bytes.writeByte(idBytes[i])
    }
  }

  const generatorPublicKeyBuffer = Buffer.from(propose.generatorPublicKey, 'hex')
  for (let i = 0; i < generatorPublicKeyBuffer.length; i++) {
    bytes.writeByte(generatorPublicKeyBuffer[i])
  }

  bytes.writeInt(propose.timestamp)

  bytes.writeString(propose.peerId)

  bytes.flip()
  return crypto.createHash('sha256').update(bytes.toBuffer()).digest()
}

Consensus.prototype.normalizeVotes = (votes) => {
  const report = self.scope.scheme.validate(votes, {
    type: 'object',
    properties: {
      height: {
        type: 'integer',
      },
      id: {
        type: 'string',
      },
      signatures: {
        type: 'array',
        minLength: 1,
        maxLength: slots.delegates,
      },
    },
    required: ['height', 'id', 'signatures'],
  })
  if (!report) {
    throw Error(self.scope.scheme.getLastError())
  }
  return votes
}

Consensus.prototype.acceptPropose = (propose, cb) => {
  const hash = self.getProposeHash(propose)
  if (propose.hash !== hash.toString('hex')) {
    return setImmediate(cb, 'Propose hash is not correct')
  }
  try {
    const signature = Buffer.from(propose.signature, 'hex')
    const publicKey = Buffer.from(propose.generatorPublicKey, 'hex')
    if (ed.Verify(hash, signature, publicKey)) {
      return setImmediate(cb)
    }
    return setImmediate(cb, 'Vefify signature failed')
  } catch (e) {
    return setImmediate(cb, `Verify signature exception: ${e.toString()}`)
  }
}

module.exports = Consensus
