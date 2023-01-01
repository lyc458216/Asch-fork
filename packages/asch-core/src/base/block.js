const crypto = require('crypto')
const ByteBuffer = require('bytebuffer')
const ed = require('../utils/ed.js')
const BlockStatus = require('../utils/block-status.js')
const constants = require('../utils/constants.js')
const featureSwitch = require('../utils/feature-switch.js')

// Private methods
const prv = {}
// 通过公钥计算地址，常用转换函数之一
prv.getAddressByPublicKey = (publicKey) => {
  const publicKeyHash = crypto.createHash('sha256').update(publicKey, 'hex').digest()
  const temp = Buffer.alloc(8)
  for (let i = 0; i < 8; i++) {
    temp[i] = publicKeyHash[7 - i]
  }

  const address = app.util.bignumber.fromBuffer(temp).toString()
  return address
}

prv.writeHexBytes = (buffer, hexString) => {
  if (!hexString) return

  const hexBuffer = Buffer.from(hexString, 'hex')
  for (let i = 0; i < hexBuffer.length; i++) {
    buffer.writeByte(hexBuffer[i])
  }
}

let self
// Constructor
function Block(scope) {
  self = this
  this.scope = scope
  prv.blockStatus = new BlockStatus()
}

// Public methods
// 排序待确认交易
// 每次产块的时候都会打包当前未确认的交易。
// 但是未确认的交易可能有很多，那如何确定交易的优先级呢?对交易的排序处理就是在这个方法里实现的。
// 具体规则如下:
Block.prototype.sortTransactions = data => data.transactions.sort((a, b) => {
  if (a.type === b.type) {
    // if (a.type === 1) {
    //   return 1
    // }
    // if (b.type === 1) {
    //   return -1
    // }
    return a.type - b.type
  }
  // if (a.amount !== b.amount) {
  //   return a.amount - b.amount
  // }
  return a.id.localeCompare(b.id)
})
// 创建区块的核心逻辑
Block.prototype.create = (data) => {
  // 使用 sortTransactions 对目前待确认交易列表进行排序
  const transactions = self.sortTransactions(data)
  // 计算区块高度:根据上一个区块的高度 + 1
  const nextHeight = (data.previousBlock) ? data.previousBlock.height + 1 : 1
  // 根据区块高度计算这个区块的奖励
  const reward = prv.blockStatus.calcReward(nextHeight)
  let totalFee = 0
  let totalAmount = 0
  let size = 0

  const blockTransactions = []
  const payloadHash = crypto.createHash('sha256')
  // 开始遍历待确认交易列表
  for (let i = 0; i < transactions.length; i++) {
    const transaction = transactions[i]
    // 获取本次交易的字节数(普通转账交易的字节数大概是 117)，累加这些字节数
    const bytes = self.scope.transaction.getBytes(transaction)
    // 如果累加的字节数大于阈值 (8M)，则结束遍历
    if (size + bytes.length > constants.maxPayloadLength) {
      break
    }

    size += bytes.length
    // 累加遍历到的交易的手续费，转账金额
    totalFee += transaction.fee
    totalAmount += transaction.amount

    blockTransactions.push(transaction)
    // 用每个交易的hash值算出本次区块的hash值
    payloadHash.update(bytes)
  }

  let block = {
    version: 0, // 目前是固定的0
    totalAmount,  // 累计打包交易的总金额
    totalFee, // 累加的打包交易的总手续费
    reward, // 本次产块给矿工的奖励
    payloadHash: payloadHash.digest().toString('hex'),  // 区块hash值，是通过之前打包的交易计算出来
    timestamp: data.timestamp,
    numberOfTransactions: blockTransactions.length,
    payloadLength: size,
    previousBlock: data.previousBlock.id, // 上一个区块的id
    generatorPublicKey: data.keypair.publicKey.toString('hex'), // 该区块生产者的公钥
    transactions: blockTransactions,  // 打包的交易列表
  }

  try {
    // 区块签名，签名需要用到当前矿工的私钥，并打包上该区块的主要信息中打出的签名
    block.blockSignature = self.sign(block, data.keypair)

    block = self.objectNormalize(block)
  } catch (e) {
    throw Error(e.toString())
  }

  return block
  // 区块数据结构举例（包含了一笔转账交易）：

  // {
  //   "version": 0,
  //     "totalAmount": 99,
  //       "totalFee": 10000000,
  //         "reward": 350000000,
  //           "payloadHash": "807b83f4b85c21a86449a94fce742844eca8144db177307d3828701826c16608",
  //   "timestamp": 53117160,
  //     "numberOfTransactions": 1,
  //       "payloadLength": 117,
  //         "previousBlock": "55399c10ee7cdb313d40c8f4c87a4253d4590c4fea27d29cefd60256617f9784",
  //   "generatorPublicKey": "9423778b5b792a9919b3813e756421ab30d13c4c1743f6a1d2aa94b60eae60bf",
  //   "transactions": [
  //   {
  //     "type": 0,
  //       "amount": 99,
  //         "fee": 10000000,
  //           "recipientId": "15748476572381496732",
  //             "timestamp": 53117146,
  //               "asset": { },
  //     "senderPublicKey": "8e5178db2bf10555cb57264c88833c48007100748d593570e013c9b15b17004e",
  //     "signature": "685fc7a43dc2ffb64e87ed5250d546f73e027a81faf1bd9d060c6333db37a49b47fbabf1d5f072b3320f59b0e87be6255808e270f096d2fd73a3e9d8433d3f0d",
  //     "id": "807b83f4b85c21a86449a94fce742844eca8144db177307d3828701826c16608",
  //     "senderId": "6518038767050467653"
  //   } ],
  //   "blockSignature": "ba14abf575a5edc77972299182cfe7340e87fe4677c23ceccf7b12e340684126f8b42432fd3a0e262b2cd92b5d0e793804c9cb2e03029ae3ddb1315b74889103"
  // }
}

// 区块签名，需要用到矿工的私钥
Block.prototype.sign = (block, keypair) => {
  const hash = self.getHash(block)

  return ed.Sign(hash, keypair).toString('hex')
}

// 区块的二进制序列函数
Block.prototype.getBytes = (block, skipSignature) => {
  const size = 4 + 4 + 8 + 4 + 8 + 8 + 64 + 64 + 32 +
    block.version > 0 ? (32 /* stateHash */ + 32 /* contractStateHash */) : 0 +
    64

  const bb = new ByteBuffer(size, true)
  bb.writeInt(block.version)
  bb.writeInt(block.timestamp)
  bb.writeLong(block.height)
  bb.writeInt(block.count)
  bb.writeLong(block.fees)
  bb.writeLong(block.reward)
  bb.writeString(block.delegate)

  // HARDCODE HOTFIX
  if (block.height > 6167000 && block.prevBlockId) {
    bb.writeString(block.prevBlockId)
  } else {
    bb.writeString('0')
  }

  prv.writeHexBytes(bb, block.payloadHash)

  if (block.version > 0) {
    prv.writeHexBytes(bb, block.stateHash)
    prv.writeHexBytes(bb, block.contractStateHash)
  }

  if (!skipSignature && block.signature) {
    prv.writeHexBytes(bb, block.signature)
  }

  bb.flip()
  const b = bb.toBuffer()

  return b
}

// 验证签名
Block.prototype.verifySignature = (block) => {
  const remove = 64

  try {
    const data = self.getBytes(block)
    const data2 = Buffer.alloc(data.length - remove)

    for (let i = 0; i < data2.length; i++) {
      data2[i] = data[i]
    }
    // 生成哈希值
    const hash = crypto.createHash('sha256').update(data2).digest()
    const blockSignatureBuffer = Buffer.from(block.signature, 'hex')
    const generatorPublicKeyBuffer = Buffer.from(block.delegate, 'hex')
    // 使用 ed25519 验证签名
    return ed.Verify(hash, blockSignatureBuffer || ' ', generatorPublicKeyBuffer || ' ')
  } catch (e) {
    throw Error(e.toString())
  }
}

Block.prototype.objectNormalize = (block) => {
  // eslint-disable-next-line guard-for-in
  for (const i in block) {
    if (block[i] == null || typeof block[i] === 'undefined') {
      delete block[i]
    }
    if (Buffer.isBuffer(block[i])) {
      block[i] = block[i].toString()
    }
  }

  const report = self.scope.scheme.validate(block, {
    type: 'object',
    properties: {
      id: {
        type: 'string',
      },
      height: {
        type: 'integer',
      },
      signature: {
        type: 'string',
        format: 'signature',
      },
      delegate: {
        type: 'string',
        format: 'publicKey',
      },
      payloadHash: {
        type: 'string',
        format: 'hex',
      },
      payloadLength: {
        type: 'integer',
      },
      stateHash: {
        type: 'string',
        format: 'hex_or_empty',
      },
      contractStateHash: {
        type: 'string',
        format: 'hex_or_empty',
      },
      prevBlockId: {
        type: 'string',
      },
      timestamp: {
        type: 'integer',
      },
      transactions: {
        type: 'array',
        uniqueItems: true,
      },
      version: {
        type: 'integer',
        minimum: 0,
      },
      reward: {
        type: 'integer',
        minimum: 0,
      },
    },
    required: ['signature', 'delegate', 'payloadHash', 'timestamp', 'transactions', 'version', 'reward'],
  })

  if (!report) {
    throw Error(self.scope.scheme.getLastError())
  }

  try {
    for (let i = 0; i < block.transactions.length; i++) {
      block.transactions[i] = self.scope.transaction.objectNormalize(block.transactions[i])
    }
  } catch (e) {
    throw Error(e.toString())
  }

  return block
}

// 用getHash进行哈希计算后取的十六进制字符串
Block.prototype.getId = block => self.getId2(block)

Block.prototype.getId_old = (block) => {
  if (featureSwitch.isEnabled('enableLongId')) {
    return self.getId2(block)
  }
  const hash = crypto.createHash('sha256').update(self.getBytes(block)).digest()
  const temp = Buffer.alloc(8)
  for (let i = 0; i < 8; i++) {
    temp[i] = hash[7 - i]
  }

  const id = app.util.bignumber.fromBuffer(temp).toString()
  return id
}

Block.prototype.getId2 = (block) => {
  const hash = crypto.createHash('sha256').update(self.getBytes(block)).digest()
  return hash.toString('hex')
}
// 根据区块的二进制序列后的字节数组做sha256哈希值
Block.prototype.getHash = block => crypto.createHash('sha256').update(self.getBytes(block)).digest()
// 计算手续费
Block.prototype.calculateFee = () => 10000000
// 数据库表区块的读写，转换
Block.prototype.dbRead = (raw) => {
  if (!raw.b_id) {
    return null
  }

  const block = {
    id: raw.b_id,
    version: parseInt(raw.b_version, 10),
    timestamp: parseInt(raw.b_timestamp, 10),
    height: parseInt(raw.b_height, 10),
    previousBlock: raw.b_previousBlock,
    numberOfTransactions: parseInt(raw.b_numberOfTransactions, 10),
    totalAmount: parseInt(raw.b_totalAmount, 10),
    totalFee: parseInt(raw.b_totalFee, 10),
    reward: parseInt(raw.b_reward, 10),
    payloadLength: parseInt(raw.b_payloadLength, 10),
    payloadHash: raw.b_payloadHash,
    generatorPublicKey: raw.b_generatorPublicKey,
    generatorId: prv.getAddressByPublicKey(raw.b_generatorPublicKey),
    blockSignature: raw.b_blockSignature,
    confirmations: raw.b_confirmations,
  }
  block.totalForged = (block.totalFee + block.reward)
  return block
}

// Export
module.exports = Block
