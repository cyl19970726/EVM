## Why need Evm?

在以太坊光坊文档(https://ethereum.org/en/developers/docs/evm/)中这样介绍对EVM介绍的:

> “分布式账本”的类比通常用于描述像比特币这样的区块链，它使用基本的密码学工具实现了一种去中心化的货币。加密货币的行为类似于“正常”货币，因为规则规定了可以做什么和不能做什么来修改分类帐。例如，一个比特币地址不能花费比它之前收到的更多的比特币。这些规则支持比特币和许多其他区块链上的所有交易。
>
> 虽然以太坊拥有自己的原生加密货币 (Ether)，它遵循几乎完全相同的直观规则，但它还支持更强大的功能：[智能合约](https://ethereum.org/en/developers/docs/smart-contracts/)。对于这个更复杂的功能，需要一个更复杂的类比。
>
> **以太坊不是分布式账本，而是分布式[状态机](https://en.wikipedia.org/wiki/Finite-state_machine)。**
>
> **以太坊的状态是一个大数据结构，它不仅包含所有账户和余额，而且是一个*机器状态*，它可以根据一组预定义的规则从一个块到另一个块变化，并且可以执行任意机器代码。**
>
> **EVM 定义了从块到块改变状态的具体规则。**

简单的说，不同节点执行一个相同交易后，可以得出一组完全相同的输出（结果）

## 以太坊状态转换函数

EVM 的行为就像一个数学函数：给定一个输入，它产生一个确定性的输出。因此，更正式地将以太坊描述为具有**状态转换功能**是非常有帮助的：

> Y(S, T)= S'

给定一个旧的有效状态`(S)`和一组新的有效交易`(T)`，以太坊状态转换函数`Y(S, T)`产生一个新的有效输出状态`S'`





## EVM 说明

EVM 作为具有1024 个深度的[堆栈机器](https://en.wikipedia.org/wiki/Stack_machine)执行。每个项目都是一个 256 位字（32字节），选择它是为了便于使用 256 位密码术（例如 Keccak-256 哈希或 secp256k1 签名）。

在执行期间，EVM 维护一个瞬态*内存*（作为字寻址的字节数组），它不会在事务之间持续存在。

然而，合约确实包含一个 Merkle Patricia*存储*树（作为一个字可寻址的字数组），与相关帐户和全局状态的一部分相关联。

编译智能合同字节码执行作为数字EVM的[操作码](https://ethereum.org/en/developers/docs/evm/opcodes)，其执行诸如标准栈操作`XOR`，`AND`，`ADD`，`SUB`，等。该EVM还实现了许多特定blockchain-栈操作的，如`ADDRESS`，`BALANCE`，`BLOCKHASH`等。

[![显示 EVM 操作需要 gas 的位置的图表](https://ethereum.org/static/9628ab90bfd02f64cf873446cbdc6c70/302a4/gas.png)](https://ethereum.org/static/9628ab90bfd02f64cf873446cbdc6c70/302a4/gas.png)*从[以太坊 EVM](https://takenobu-hs.github.io/downloads/ethereum_evm_illustrated.pdf)改编的图表[说明](https://takenobu-hs.github.io/downloads/ethereum_evm_illustrated.pdf)*



# EVM设计

1.32 Bytes的word

2.1024深度的stack

3.memory采用动态内存

4.分为读操作和写操作，写操作会涉及改变state trie

5.PC指针指向当前的执行opCode,并且pc++的单位是byte



![EVM执行流程](/Users/chenyanlong/Desktop/EVM虚拟机/image/EVM执行流程.jpg)

图像来源《以太坊深入浅出》