const sodium = require('sodium').api

module.exports = {
  // 生成密钥对
  MakeKeypair(hash) {
    const keypair = sodium.crypto_sign_seed_keypair(hash)
    return {
      publicKey: keypair.publicKey,
      privateKey: keypair.secretKey,
    };
  },
  // 签名
  Sign(hash, keypair) {
    return sodium.crypto_sign_detached(hash, Buffer.from(keypair.privateKey, 'hex'))
  },
  // 签名验证
  Verify(hash, signatureBuffer, publicKeyBuffer) {
    return sodium.crypto_sign_verify_detached(signatureBuffer, hash, publicKeyBuffer)
  },
}
