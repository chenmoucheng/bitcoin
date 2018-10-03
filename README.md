# bitcoin

Format: block height, TX, URL

110300, 16, https://www.blockchain.com/btc/tx/c99c49da4c38af669dea436d3e73780dfdb6c1ecf9958baa52960e8baee30e73
  Hashtype is 0.

135106, 89, https://www.blockchain.com/btc/tx/a618dc10b8a1f9d9a1469b3bb84fc17da86df2d51c27e2aa16fa130953840735
  Signature has an extra 00 at the end.

136201, 53, https://www.blockchain.com/btc/tx/bf4a7d685be994bc27ddd82cfd75fe27a8945544ef95e58b62a98c6dc6e99ad4
  Signature has an extra 0000 at the end.

139758,  8, https://www.blockchain.com/btc/tx/23befff6eea3dded0e34574af65c266c9398e7d7d9d07022bf1cd526c5cdbc94
  Signature has some extra 2a2a... at the end.

142433, 15, https://www.blockchain.com/btc/tx/6a04bd8e7ec80f8142261e2496e3f90a89a71b2c3ab13fb66265a520d882c081
  Input 0 is coinbase without valid script:
  https://www.blockchain.com/btc/tx/50cfd3361f7162b3c0c00dacd3d0e4ddf61e8ec0c51bfa54c4ca0e61876810a9

207733, 323, https://www.blockchain.com/btc/tx/51bf528ecf3c161e7c021224197dbe84f9a8564212f6207baa014c01a1668e1e
  Hashtype is 0x81.

211804, 244, https://www.blockchain.com/btc/tx/70c4e749f2b8b907875d1483ae43e8a6790b0c8397bbb33682e3602617f9a77a
  Invalid input public key(s):
  https://www.blockchain.com/btc/tx/274f8be3b7b9b1a220285f5f71f61e2691dd04df9d69bb02a8b3b85f91fb1857
  https://www.blockchain.com/btc/tx/70c15eb4cc3890960dbe1ae0cf13eedaeaef04d8e4820398fb4e991b23528f03

218695,  26, https://www.blockchain.com/btc/tx/bde69c82fa0870bb156edb334da4a8013d5d385e93608110313a8695184d6365
  Hashtype is 0x83.

238797, 316, https://www.blockchain.com/btc/tx/afd9c17f8913577ec3509520bd6e5d63e9c0fd2a5f70c787993b097ba6ca9fae
  Multiple SIGHASH_SINGLE inputs.

247939,  64, https://www.blockchain.com/btc/tx/315ac7d4c26d69668129cc352851d9389b4a6868f1509c6c8b66bead11e2619f
  # SIGHASH_SINGLE inputs > # outputs.

249976,  10, https://www.blockchain.com/btc/tx/da47bd83967d81f3cf6520f4ff81b3b6c4797bfe7ac2b5969aedbf01a840cda6
  OP_IF stuff.

251527,  52, https://www.blockchain.com/btc/tx/8a68c461a2473653fe0add786f0ca6ebb99b257286166dfb00707be24716af3a
  OP_INVALIDEOPCODE.

251684,   9, https://www.blockchain.com/btc/tx/61a078472543e9de9247446076320499c108b52307d8d0fafbe53b5c4e32acc4
  HASH256 some numerical value.

251898,  90, https://www.blockchain.com/btc/tx/f2d72a7bf22e29e3f2dc721afbf0a922860f81db9fc7eb397937f9d7e87cc438
  OP_DEPTH.

251898,  99, https://www.blockchain.com/btc/tx/cd874fa8cb0e2ec2d385735d5e1fd482c4fe648533efb4c50ee53bda58e15ae2
  OP_SWAP.

256961,   1, https://www.blockchain.com/btc/tx/54fabd73f1d20c980a0686bf0035078e07f69c58437e4d586fb29aa0bee9814f
  OP_TOALTSTACK and OP_FROMALTSTACK.

268561, 1652, https://www.blockchain.com/btc/tx/9fb65b7304aaa77ac9580823c2c06b259cc42591e5cce66d76a81b6f51cc5c28
  OP_PICK and OP_NIP.

269614, 458, https://www.blockchain.com/btc/tx/aef4cf7abcd4344ae612d5f27735010a26e5102af20a97a5f43802583d72eb78
  OP_TUCK, OP_ROT, and OP_ROLL.

269628, 698, https://www.blockchain.com/btc/tx/fd9d8d6156233ffc84c4c6c76b265ab1fd947bb4e99475a19d9d54da6d226556
  Short-circuited BOOLAND does not work.

297775,  47, https://www.blockchain.com/btc/tx/7afdcb9067f6549a569116a79cb1256920a0c566ff36cf4dce88718d57402f4f
  OP_2DUP.

306609,  18, https://www.blockchain.com/btc/tx/2c1462024303955581e74ff750a019ed817f682191eb1ef7e3162d91a17cb633
  Comparing different representations of zero.

