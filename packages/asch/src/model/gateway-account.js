// 跨链网关用户表，资产在不同区块链之间的流通都是由跨链网关用户来维护
module.exports = {
  table: 'gateway_accounts',
  tableFields: [
    { name: 'address', type: 'String', length: 50, index: true },
    { name: 'seq', type: 'Number' , unique: true },
    { name: 'gateway', type: 'String', length: 20, index: true },
    { name: 'outAddress', type: 'String', length: 50, primary_key: true },
    { name: 'attachment', type: 'Text' },
    { name: 'version', type: 'Number' },
    { name: 'createTime', type: 'Number' },
  ]
}
