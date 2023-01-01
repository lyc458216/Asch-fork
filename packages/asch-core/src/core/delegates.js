// 主要负责受托人锻造区块的过程之一，这个过程是Asch的核心过程
// 主要涉及如何选出当前轮值锻造区块的受托人、一些功能函数以及一些和受托人有关的HTTP API查询
// 功能函 数按照启动顺序依次为:
// 等待区块链加载完成(onBlockchainReady)，加载本节点受托人(loadMyDelegates)，循环监听(loop)，确定受托人(getBlockSlotData)，获取受托人列表(generate Delegatelist)等
const crypto = require('crypto')
const util = require('util')
const ed = require('../utils/ed.js')
const Router = require('../utils/router.js')
const slots = require('../utils/slots.js')
const BlockStatus = require('../utils/block-status.js')
const sandboxHelper = require('../utils/sandbox.js')
const addressHelper = require('../utils/address.js')

let modules
let library
let self
const priv = {}
const shared = {}

const BOOK_KEEPER_NAME = 'round_bookkeeper'

priv.loaded = false
priv.blockStatus = new BlockStatus()
priv.keypairs = {}
priv.forgingEanbled = true

function Delegates(cb, scope) {
  library = scope
  self = this
  priv.attachApi()

  setImmediate(cb, null, self)
}

priv.attachApi = () => {
  const router = new Router()

  router.use((req, res, next) => {
    if (modules && priv.loaded) return next()
    return res.status(500).send({ success: false, error: 'Blockchain is loading' })
  })

  router.map(shared, {
    'get /count': 'count',
    'get /voters': 'getVoters',
    'get /get': 'getDelegate',
    'get /': 'getDelegates',
  })

  if (process.env.DEBUG) {
    router.get('/forging/disableAll', (req, res) => {
      self.disableForging()
      return res.json({ success: true })
    })

    router.get('/forging/enableAll', (req, res) => {
      self.enableForging()
      return res.json({ success: true })
    })
  }

  router.post('/forging/enable', (req, res) => {
    const body = req.body
    library.scheme.validate(body, {
      type: 'object',
      properties: {
        secret: {
          type: 'string',
          minLength: 1,
          maxLength: 100,
        },
        publicKey: {
          type: 'string',
          format: 'publicKey',
        },
      },
      required: ['secret'],
    }, (err) => {
      if (err) {
        return res.json({ success: false, error: err[0].message })
      }

      const ip = req.connection.remoteAddress

      if (library.config.forging.access.whiteList.length > 0
        && library.config.forging.access.whiteList.indexOf(ip) < 0) {
        return res.json({ success: false, error: 'Access denied' })
      }

      const keypair = ed.MakeKeypair(crypto.createHash('sha256').update(body.secret, 'utf8').digest())

      if (body.publicKey) {
        if (keypair.publicKey.toString('hex') !== body.publicKey) {
          return res.json({ success: false, error: 'Invalid passphrase' })
        }
      }

      if (priv.keypairs[keypair.publicKey.toString('hex')]) {
        return res.json({ success: false, error: 'Forging is already enabled' })
      }

      return modules.accounts.getAccount({ publicKey: keypair.publicKey.toString('hex') }, (err2, account) => {
        if (err2) {
          return res.json({ success: false, error: err2.toString() })
        }
        if (account && account.isDelegate) {
          priv.keypairs[keypair.publicKey.toString('hex')] = keypair
          library.logger.info(`Forging enabled on account: ${account.address}`)
          return res.json({ success: true, address: account.address })
        }
        return res.json({ success: false, error: 'Delegate not found' })
      })
    })
  })

  router.post('/forging/disable', (req, res) => {
    const body = req.body
    library.scheme.validate(body, {
      type: 'object',
      properties: {
        secret: {
          type: 'string',
          minLength: 1,
          maxLength: 100,
        },
        publicKey: {
          type: 'string',
          format: 'publicKey',
        },
      },
      required: ['secret'],
    }, (err) => {
      if (err) {
        return res.json({ success: false, error: err[0].message })
      }

      const ip = req.connection.remoteAddress

      if (library.config.forging.access.whiteList.length > 0
          && library.config.forging.access.whiteList.indexOf(ip) < 0) {
        return res.json({ success: false, error: 'Access denied' })
      }

      const keypair = ed.MakeKeypair(crypto.createHash('sha256').update(body.secret, 'utf8').digest())

      if (body.publicKey) {
        if (keypair.publicKey.toString('hex') !== body.publicKey) {
          return res.json({ success: false, error: 'Invalid passphrase' })
        }
      }

      if (!priv.keypairs[keypair.publicKey.toString('hex')]) {
        return res.json({ success: false, error: 'Delegate not found' })
      }

      return modules.accounts.getAccount({ publicKey: keypair.publicKey.toString('hex') }, (err2, account) => {
        if (err2) {
          return res.json({ success: false, error: err2.toString() })
        }
        if (account && account.isDelegate) {
          delete priv.keypairs[keypair.publicKey.toString('hex')]
          library.logger.info(`Forging disabled on account: ${account.address}`)
          return res.json({ success: true, address: account.address })
        }
        return res.json({ success: false, error: 'Delegate not found' })
      })
    })
  })

  router.get('/forging/status', (req, res) => {
    const query = req.query
    library.scheme.validate(query, {
      type: 'object',
      properties: {
        publicKey: {
          type: 'string',
          format: 'publicKey',
        },
      },
      required: ['publicKey'],
    }, (err) => {
      if (err) {
        return res.json({ success: false, error: err[0].message })
      }

      return res.json({ success: true, enabled: !!priv.keypairs[query.publicKey] })
    })
  })

  library.network.app.use('/api/delegates', router)
  library.network.app.use((err, req, res, next) => {
    if (!err) return next()
    library.logger.error(req.url, err.toString())
    return res.status(500).send({ success: false, error: err.toString() })
  })
}

priv.getBlockSlotData = (slot, height, cb) => {
  self.generateDelegateList(height, (err, activeDelegates) => {
    if (err) {
      return cb(err)
    }
    const lastSlot = slots.getLastSlot(slot)

    for (let currentSlot = slot; currentSlot < lastSlot; currentSlot += 1) {
      const delegatePos = currentSlot % slots.delegates

      const delegateKey = activeDelegates[delegatePos]

      if (delegateKey && priv.keypairs[delegateKey]) {
        return cb(null, {
          time: slots.getSlotTime(currentSlot),
          keypair: priv.keypairs[delegateKey],
        })
      }
    }
    return cb(null, null)
  })
}

// 循环监听对受托人来说是非常重要的一个方法。
// 受托人的服务器节点要不停地轮询，查看是否轮到自己产块，如果产块则进行下一步的处理
// 1) slots.getSlotNumber获取当前slot。
// 2) modules.blocks.getLastBlock获取最新区块。
// 3) 通过getBlockSlotData找出当前轮到哪个受托人锻造区块，并取出该受托人的密钥对。
// 4) 把第三步中取到的受托人密钥传入modules.blocks.generateBlock进行区块的锻造。
priv.loop = (cb) => {
  if (!priv.forgingEanbled) {
    library.logger.trace('Loop:', 'forging disabled')
    return setImmediate(cb)
  }
  if (!Object.keys(priv.keypairs).length) {
    library.logger.trace('Loop:', 'no delegates')
    return setImmediate(cb)
  }

  if (!priv.loaded || modules.loader.syncing()) {
    library.logger.trace('Loop:', 'node not ready')
    return setImmediate(cb)
  }

  const currentSlot = slots.getSlotNumber()
  const lastBlock = modules.blocks.getLastBlock()

  if (currentSlot === slots.getSlotNumber(lastBlock.timestamp)) {
    return setImmediate(cb)
  }

  if (Date.now() % (slots.interval * 1000) > 5000) {
    library.logger.trace('Loop:', 'maybe too late to collect votes')
    return setImmediate(cb)
  }

  // getBlockSlotData方法用于确定受托人
  // 1) 通过generateDelegateList从数据库中找出101个vote数量最多的账号公钥。
  // 2) 通过slots.getLastBlock获取下一个slot，下一个slot的计算方式就是当前slot + 101，101就是受托人的数量。
  // 3) 遍历currentSlot到lastSlot这101个slot，找到第1步中对应的受托人账号，如果这个受托人账号已经在我们的private.keypairs注册过，则返回对应的private.keypairs中的密钥对。
  // 所以这个函数就是先计算现在轮到哪个受托人锻造区块了，如果发现当前需要锻造的受托人密钥就在本节点，则取出该密钥，准备后续的锻造工作。
  return priv.getBlockSlotData(currentSlot, lastBlock.height + 1, (err, currentBlockData) => {
    if (err || currentBlockData === null) {
      library.logger.trace('Loop:', 'skipping slot')
      return setImmediate(cb)
    }

    return library.sequence.add(done => (async () => {
      try {
        if (slots.getSlotNumber(currentBlockData.time) === slots.getSlotNumber()
          && modules.blocks.getLastBlock().timestamp < currentBlockData.time) {
          await modules.blocks.generateBlock(currentBlockData.keypair, currentBlockData.time)
        }
        done()
      } catch (e) {
        done(e)
      }
    })(), (err2) => {
      if (err2) {
        library.logger.error('Failed generate block within slot:', err2)
      }
      cb()
    })
  })
}

// 加载本节点受托人列表
priv.loadMyDelegates = (cb) => {
  let secrets = []
  // secret就是Asch受托人的密码(12个单词组成)
  if (library.config.forging.secret) {
    secrets = util.isArray(library.config.forging.secret)
      ? library.config.forging.secret : [library.config.forging.secret]
  }

  return (async () => {
    try {
      const delegates = app.sdb.getAll('Delegate')
      if (!delegates || !delegates.length) {
        return cb('Delegates not found in db')
      }
      const delegateMap = new Map()
      for (const d of delegates) {
        delegateMap.set(d.publicKey, d)
      }
      for (const secret of secrets) {
        // 通过secret计算出密钥对，用密钥对中的公钥通过getAccount获取账号信息
        const keypair = ed.MakeKeypair(crypto.createHash('sha256').update(secret, 'utf8').digest())
        const publicKey = keypair.publicKey.toString('hex')
        if (delegateMap.has(publicKey)) {
          // 如果该账号是受托人，则把这个密钥对加入private.keypairs这个全局变量中，并且会成功打出“Forging enabled on account:”的日志，这个日志是受托人搭建服务器的时候，启动节点后需要 检查的重要日志之一，如果没有这个日志。则代表可能你的配置有错
          priv.keypairs[publicKey] = keypair
          library.logger.info(`Forging enabled on account: ${delegateMap.get(publicKey).address}`)
        } else {
          library.logger.info(`Delegate with this public key not found: ${keypair.publicKey.toString('hex')}`)
        }
      }
      return cb()
    } catch (e) {
      return cb(e)
    }
  })()
}

Delegates.prototype.getActiveDelegateKeypairs = (height, cb) => {
  self.generateDelegateList(height, (err, delegates) => {
    if (err) {
      return cb(err)
    }
    const results = []
    for (const key in priv.keypairs) {
      if (delegates.indexOf(key) !== -1) {
        results.push(priv.keypairs[key])
      }
    }
    return cb(null, results)
  })
}

Delegates.prototype.validateProposeSlot = (propose, cb) => {
  self.generateDelegateList(propose.height, (err, activeDelegates) => {
    if (err) {
      return cb(err)
    }
    const currentSlot = slots.getSlotNumber(propose.timestamp)
    const delegateKey = activeDelegates[currentSlot % slots.delegates]

    if (delegateKey && propose.generatorPublicKey === delegateKey) {
      return cb()
    }

    return cb('Failed to validate propose slot')
  })
}

// Public methods
Delegates.prototype.generateDelegateList = (height, cb) => (() => {
  try {
    const truncDelegateList = self.getBookkeeper()
    const seedSource = modules.round.calc(height).toString()

    let currentSeed = crypto.createHash('sha256').update(seedSource, 'utf8').digest()
    for (let i = 0, delCount = truncDelegateList.length; i < delCount; i++) {
      for (let x = 0; x < 4 && i < delCount; i++, x++) {
        const newIndex = currentSeed[x] % delCount
        const b = truncDelegateList[newIndex]
        truncDelegateList[newIndex] = truncDelegateList[i]
        truncDelegateList[i] = b
      }
      currentSeed = crypto.createHash('sha256').update(currentSeed).digest()
    }

    cb(null, truncDelegateList)
  } catch (e) {
    cb(`Failed to get bookkeeper: ${e}`)
  }
})()

Delegates.prototype.fork = (block, cause) => {
  library.logger.info('Fork', {
    delegate: block.delegate,
    block: {
      id: block.id,
      timestamp: block.timestamp,
      height: block.height,
      prevBlockId: block.prevBlockId,
    },
    cause,
  })
}

Delegates.prototype.validateBlockSlot = (block, cb) => {
  self.generateDelegateList(block.height, (err, activeDelegates) => {
    if (err) {
      return cb(err)
    }
    const currentSlot = slots.getSlotNumber(block.timestamp)
    const delegateKey = activeDelegates[currentSlot % slots.delegates]

    if (delegateKey && block.delegate === delegateKey) {
      return cb()
    }

    return cb(`Failed to verify slot, expected delegate: ${delegateKey}`)
  })
}

// fixme ?? : get method should not modify anything....
Delegates.prototype.getDelegates = (query, cb) => {
  let delegates = app.sdb.getAll('Delegate').map(d => Object.assign({}, d))
  if (!delegates || !delegates.length) return cb('No delegates')

  delegates = delegates.sort(self.compare)

  const lastBlock = modules.blocks.getLastBlock()
  const totalSupply = priv.blockStatus.calcSupply(lastBlock.height)
  for (let i = 0; i < delegates.length; ++i) {
    // fixme? d === delegates[i] ???
    const d = delegates[i]
    d.rate = i + 1
    delegates[i].approval = ((d.votes / totalSupply) * 100)

    let percent = 100 - (d.missedBlocks / (d.producedBlocks + d.missedBlocks) / 100)
    percent = percent || 0
    delegates[i].productivity = parseFloat(Math.floor(percent * 100) / 100).toFixed(2)

    delegates[i].vote = delegates[i].votes
    delegates[i].missedblocks = delegates[i].missedBlocks
    delegates[i].producedblocks = delegates[i].producedBlocks
    // app.sdb.update('Delegate', delegates[i], { address: delegates[i].address })
  }
  return cb(null, delegates)
}

Delegates.prototype.sandboxApi = (call, args, cb) => {
  sandboxHelper.callMethod(shared, call, args, cb)
}

Delegates.prototype.enableForging = () => {
  priv.forgingEanbled = true
}

Delegates.prototype.disableForging = () => {
  priv.forgingEanbled = false
}

// Events
Delegates.prototype.onBind = (scope) => {
  modules = scope
}

Delegates.prototype.onBlockchainReady = () => {
  priv.loaded = true

  priv.loadMyDelegates(function nextLoop(err) {
    if (err) {
      library.logger.error('Failed to load delegates', err)
    }

    priv.loop(() => {
      setTimeout(nextLoop, 100)
    })
  })
}

Delegates.prototype.compare = (l, r) => {
  if (l.votes !== r.votes) {
    return r.votes - l.votes
  }
  return l.publicKey < r.publicKey ? 1 : -1
}

Delegates.prototype.cleanup = (cb) => {
  priv.loaded = false
  cb()
}

Delegates.prototype.getTopDelegates = () => {
  const allDelegates = app.sdb.getAll('Delegate')
  return allDelegates.sort(self.compare).map(d => d.publicKey).slice(0, slots.delegates)
}

Delegates.prototype.getBookkeeperAddresses = () => {
  const bookkeeper = self.getBookkeeper()
  const addresses = new Set()
  for (const i of bookkeeper) {
    const address = addressHelper.generateNormalAddress(i)
    addresses.add(address)
  }
  return addresses
}

Delegates.prototype.getBookkeeper = () => {
  const item = app.sdb.get('Variable', BOOK_KEEPER_NAME)
  if (!item) throw new Error('Bookkeeper variable not found')

  // TODO: ?? make field type as JSON
  return JSON.parse(item.value)
}

Delegates.prototype.updateBookkeeper = (delegates) => {
  const value = JSON.stringify(delegates || self.getTopDelegates())
  const { create } = app.sdb.createOrLoad('Variable', { key: BOOK_KEEPER_NAME, value })
  if (!create) {
    app.sdb.update('Variable', { value }, { key: BOOK_KEEPER_NAME })
  }
}

shared.getDelegate = (req, cb) => {
  const query = req.body
  library.scheme.validate(query, {
    type: 'object',
    properties: {
      publicKey: {
        type: 'string',
      },
      name: {
        type: 'string',
      },
      address: {
        type: 'string',
      },
    },
  }, (err) => {
    if (err) {
      return cb(err[0].message)
    }

    return modules.delegates.getDelegates(query, (err2, delegates) => {
      if (err2) {
        return cb(err2)
      }

      const delegate = delegates.find((d) => {
        if (query.publicKey) {
          return d.publicKey === query.publicKey
        }
        if (query.address) {
          return d.address === query.address
        }
        if (query.name) {
          return d.name === query.name
        }

        return false
      })

      if (delegate) {
        return cb(null, { delegate })
      }
      return cb('Delegate not found')
    })
  })
}

shared.count = (req, cb) => (async () => {
  try {
    const count = app.sdb.getAll('Delegate').length
    return cb(null, { count })
  } catch (e) {
    library.logger.error('get delegate count error', e)
    return cb('Failed to count delegates')
  }
})()

shared.getVoters = (req, cb) => {
  const query = req.body
  library.scheme.validate(query, {
    type: 'object',
    properties: {
      name: {
        type: 'string',
        maxLength: 50,
      },
      limit: {
        type: 'integer',
        minimum: 0,
        maximum: 100,
      },
      offset: {
        type: 'integer',
        minimum: 0,
      },
    },
    required: ['name'],
  }, (err) => {
    if (err) {
      return cb(err[0].message)
    }

    return (async () => {
      try {
        const { limit: rawLimit, offset: rawOffset, name } = query
        const limit = Number.parseInt(rawLimit, 10) || 20
        const offset = Number.parseInt(rawOffset, 10) || 0
        const condition = { delegate: name }
        const count = await app.sdb.count('Vote', condition)
        if (count <= 0) return cb(null, { count, accounts: [] })

        const votes = await app.sdb.find('Vote', condition, { limit, offset })
        const addresses = votes.map(v => v.address)
        const accounts = await app.sdb.findAll('Account', { condition: { address: { $in: addresses } } })
        const lastBlock = modules.blocks.getLastBlock()
        const totalSupply = priv.blockStatus.calcSupply(lastBlock.height)
        for (const a of accounts) {
          a.balance = a.xas
          a.weightRatio = (a.weight * 100) / totalSupply
        }
        return cb(null, { count, accounts })
      } catch (e) {
        library.logger.error('Failed to find voters', e)
        return cb('Server error')
      }
    })()
  })
}

shared.getDelegates = (req, cb) => {
  const query = req.body
  const offset = Number(query.offset || 0)
  const limit = Number(query.limit || 10)
  if (Number.isNaN(limit) || Number.isNaN(offset)) {
    return cb('Invalid params')
  }

  return self.getDelegates({}, (err, delegates) => {
    if (err) return cb(err)
    return cb(null, {
      totalCount: delegates.length,
      delegates: delegates.slice(offset, offset + limit),
    })
  })
}

module.exports = Delegates
