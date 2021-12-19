// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package core

import (
	"errors"
	"math"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/params"
)

var (
	errInsufficientBalanceForGas = errors.New("insufficient balance to pay for gas")
)

/*
The State Transitioning Model

A state transition is a change made when a transaction is applied to the current world state
The state transitioning model does all the necessary work to work out a valid new state root.

1) Nonce handling
2) Pre pay gas
3) Create a new state object if the recipient is \0*32
4) Value transfer
== If contract creation ==
  4a) Attempt to run transaction data
  4b) If valid, use result as code for the new state object
== end ==
5) Run Script section
6) Derive new state root
*/
type StateTransition struct {
	gp         *GasPool
	msg        Message
	gas        uint64
	gasPrice   *big.Int
	initialGas uint64
	value      *big.Int
	data       []byte
	state      vm.StateDB
	evm        *vm.EVM
}

// Message represents a message sent to a contract.
type Message interface {
	From() common.Address
	//FromFrontier() (common.Address, error)
	To() *common.Address

	GasPrice() *big.Int
	Gas() uint64
	Value() *big.Int

	Nonce() uint64
	CheckNonce() bool
	Data() []byte
}

/*
交易的固有成本必须小于该交易设置的 gas 上限
在前一篇博文中，我们说明了为什么使用以太坊需要付费，以及 gas 的概念。总的来说，每一笔交易都有与之关联的 gas ——发送一笔交易的成本包含两部分：固有成本和执行成本。

执行成本根据该交易需要使用多少以太坊虚拟机（EVM）的资源来运算而定，执行一笔交易所需的操作越多，则它的执行成本就越高。

固有成本由交易的负载（ payload ）决定，交易负载分为以下三种负载：

	>如果该交易是为了创建智能合约，则负载就是创建智能合约的 EVM 代码
	>如果该交易是为了调用智能合约的函数，则负载就是执行消息的输入数据
	>如果该交易只是单纯在两个账户间转账，则负载为空

设 Nzeros 代表交易负载中，字节为 0 的字节总数；Nnonzeros 代表交易负载中，字节不为 0 的字节总数。
可以通过下列公式计算出该交易的固有成本（黄皮书 6.2 章，方程式 54、55 和 56）：

固有成本 = Gtransaction + Gtxdatazero * Nzeros + Gtxdatanonzero * Nnonzeros + Gtxcreate

在黄皮书的附录 G 中，可以看到一份创建和执行交易的相关成本的费用表。与固有成本相关的内容如下：

Gtransaction = 21,000 Wei
Gtxcreate = 32,000 Wei
Gtxdatazero = 4 Wei
Gtxdatanonzero = 68 Wei (在伊斯坦布尔升级时会改为 16 wei)

*/
//计算进行该笔交易的固有成本
// IntrinsicGas computes the 'intrinsic gas' for a message with the given data.
func IntrinsicGas(data []byte, contractCreation, isHomestead bool, isEIP2028 bool) (uint64, error) {
	// Set the starting gas for the raw transaction
	/*1.首先如果是创建合约的交易起步价为53000gas, 如果是普通合约调用交易则为21000gas.*/
	var gas uint64
	if contractCreation && isHomestead {
		gas = params.TxGasContractCreation
	} else {
		gas = params.TxGas
	}
	// Bump the required gas by the amount of transactional data
	if len(data) > 0 {
		// Zero and non-zero bytes are priced differently
		var nz uint64
		/*2.其次计算输入的合约数据中的非零字节和零自己的数量*/
		for _, byt := range data {
			if byt != 0 {
				nz++
			}
		}
		// Make sure we don't exceed uint64 for all data combinations
		nonZeroGas := params.TxDataNonZeroGasFrontier  // 64gas/byte
		if isEIP2028 {
			nonZeroGas = params.TxDataNonZeroGasEIP2028  //16gas/byte
		}

		// 1<<64-1 [大于] 不是0的字节数 x 68
		if (math.MaxUint64-gas)/nonZeroGas < nz {
			return 0, vm.ErrOutOfGas
		}
		/*
		3.
		分别计算其gas消耗。 零字节每字节4gas， 非零字节每字节68(16)gas。
	    零字节较为便宜是因为RLP编码协议可以压缩0字节。
		在向Trie 存储这些数据时，零字节占用空间很少。
		*/
		gas += nz * nonZeroGas

		// 0的数量
		z := uint64(len(data)) - nz
		if (math.MaxUint64-gas)/params.TxDataZeroGas < z {
			return 0, vm.ErrOutOfGas
		}
		/*4 检查是否整数溢出，同时把所消耗的gas加总。*/
		gas += z * params.TxDataZeroGas  //
	}
	return gas, nil
}

// NewStateTransition initialises and returns a new state transition object.
func NewStateTransition(evm *vm.EVM, msg Message, gp *GasPool) *StateTransition {
	return &StateTransition{
		gp:       gp,
		evm:      evm,
		msg:      msg,
		gasPrice: msg.GasPrice(),
		value:    msg.Value(),
		data:     msg.Data(),
		state:    evm.StateDB,
	}
}

// ApplyMessage computes the new state by applying the given message
// against the old state within the environment.
//
// ApplyMessage returns the bytes returned by any EVM execution (if it took place),
// the gas used (which includes gas refunds) and an error if it failed. An error always
// indicates a core error meaning that the message would always fail for that particular
// state and would never be accepted within a block.
func  ApplyMessage(evm *vm.EVM, msg Message, gp *GasPool) ([]byte, uint64, bool, error) {
	return NewStateTransition(evm, msg, gp).TransitionDb()
}

// to returns the recipient of the message.
func (st *StateTransition) to() common.Address {
	if st.msg == nil || st.msg.To() == nil /* contract creation */ {
		return common.Address{}
	}
	return *st.msg.To()
}

func (st *StateTransition) useGas(amount uint64) error {
	if st.gas < amount {
		return vm.ErrOutOfGas
	}
	st.gas -= amount

	return nil
}

func (st *StateTransition) buyGas() error {
	/*1.第一步是计算这个交易消耗的eth数量， 通过交易发起者提供的gas数量和gas价格。*/
	mgval := new(big.Int).Mul(new(big.Int).SetUint64(st.msg.Gas()), st.gasPrice)
	/*2.判断当前账户的余额是否足够支付这笔eth*/
	if st.state.GetBalance(st.msg.From()).Cmp(mgval) < 0 {
		return errInsufficientBalanceForGas
	}
	/*3. 从整个区块的Gas.pool中扣除这个交易预计消耗的Gas数量*/
	if err := st.gp.SubGas(st.msg.Gas()); err != nil {
		return err
	}
	/*4.这部分Gas数量转移到了st.gas 中， 这里会在后续的evm执行中被不停的扣除。 */
	st.gas += st.msg.Gas()
	/*5.在st.initialGas中记录最初分配的gas数量。 */
	st.initialGas = st.msg.Gas()
	/*6.这里最为关键， 从发起者账户中扣除对应的eth数量。 （当然如果中途出错，一切都有可能回滚）*/
	st.state.SubBalance(st.msg.From(), mgval)
	return nil
}

/*随机数检查*/
func (st *StateTransition) preCheck() error {
	// Make sure this transaction's nonce is correct.
	if st.msg.CheckNonce() {
		nonce := st.state.GetNonce(st.msg.From())
		if nonce < st.msg.Nonce() {
			return ErrNonceTooHigh
		} else if nonce > st.msg.Nonce() {
			return ErrNonceTooLow
		}
	}
	return st.buyGas()
}

// TransitionDb will transition the state by applying the current message and
// returning the result including the used gas. It returns an error if failed.
// An error indicates a consensus issue.
func (st *StateTransition) TransitionDb() (ret []byte, usedGas uint64, failed bool, err error) {
	/*1.检查nonce是否符合要求
	    检查账户是否足够支付gas fee*/
	if err = st.preCheck(); err != nil {
		return
	}
	msg := st.msg
	//记录发起这笔交易的发起人地址
	sender := vm.AccountRef(msg.From())
	homestead := st.evm.ChainConfig().IsHomestead(st.evm.BlockNumber)
	istanbul := st.evm.ChainConfig().IsIstanbul(st.evm.BlockNumber) // 是不是伊斯坦布尔升级后的版本

	/*如果 msg.To()==nil 代表创建合约*/
	contractCreation := msg.To() == nil

	/* Pay intrinsic gas  计算固有成本的gas */
	gas, err := IntrinsicGas(st.data, contractCreation, homestead, istanbul)
	if err != nil {
		return nil, 0, false, err
	}
	/*st.gas 减去IntrinsicGas*/
	if err = st.useGas(gas); err != nil {
		return nil, 0, false, err
	}

	var (
		evm = st.evm
		// vm errors do not effect consensus and are therefor
		// not assigned to err, except for insufficient balance
		// error.
		vmerr error
	)

	/*判断合约类型
		---接下来就是调用虚拟机的操作了
	*/
	if contractCreation {
		/* 进行创建合约操作*/
		/*st.data = message.data() = tx.txdata.payload*/
		ret, _, st.gas, vmerr = evm.Create(sender, st.data, st.gas, st.value)
	} else {
		// Increment the nonce for the next transaction

		st.state.SetNonce(msg.From(), st.state.GetNonce(sender.Address())+1)
		ret, st.gas, vmerr = evm.Call(sender, st.to(), st.data, st.gas, st.value)
	}

	/*如果虚拟机执行发生错误，判断错误类型，如果是账户余额不足则直接停止该进程，其他错误继续执行*/
	if vmerr != nil {
		log.Debug("VM returned with error", "err", vmerr)
		// The only possible consensus-error would be if there wasn't
		// sufficient balance to make the transfer happen. The first
		// balance transfer may never fail.
		if vmerr == vm.ErrInsufficientBalance {
			return nil, 0, false, vmerr
		}
	}

	/*退回多余的gas*/
	st.refundGas()
	/*向打包该交易的矿工账户添加手续费*/
	st.state.AddBalance(st.evm.Coinbase, new(big.Int).Mul(new(big.Int).SetUint64(st.gasUsed()), st.gasPrice))

	return ret, st.gasUsed(), vmerr != nil, err
}

func (st *StateTransition) refundGas() {
	// Apply refund counter, capped to half of the used gas.
	/*退款上限为已用气体的一半。*/
	refund := st.gasUsed() / 2
	if refund > st.state.GetRefund() {
		refund = st.state.GetRefund()
	}
	st.gas += refund

	// Return ETH for remaining gas, exchanged at the original rate.
	remaining := new(big.Int).Mul(new(big.Int).SetUint64(st.gas), st.gasPrice)
	st.state.AddBalance(st.msg.From(), remaining)

	// Also return remaining gas to the block gas counter so it is
	// available for the next transaction.
	/* 将剩余的该交易执行完成后剩余的gas加回gasPool*/
	st.gp.AddGas(st.gas)
}

// gasUsed returns the amount of gas used up by the state transition.
func (st *StateTransition) gasUsed() uint64 {
	return st.initialGas - st.gas
}
