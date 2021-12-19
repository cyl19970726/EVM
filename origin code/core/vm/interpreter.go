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

package vm

import (
	"fmt"
	"hash"
	"sync/atomic"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/log"
)

// Config are the configuration options for the Interpreter
type Config struct {
	Debug                   bool   // Enables debugging
	Tracer                  Tracer // Opcode logger
	NoRecursion             bool   // Disables call, callcode, delegate call and create
	EnablePreimageRecording bool   // Enables recording of SHA3/keccak preimages

	JumpTable [256]operation // EVM instruction table, automatically populated if unset

	EWASMInterpreter string // External EWASM interpreter options
	EVMInterpreter   string // External EVM interpreter options

	ExtraEips []int // Additional EIPS that are to be enabled
}

// Interpreter is used to run Ethereum based contracts and will utilise the
// passed environment to query external sources for state information.
// The Interpreter will run the byte code VM based on the passed
// configuration.
type Interpreter interface {
	// Run loops and evaluates the contract's code with the given input data and returns
	// the return byte-slice and an error if one occurred.
	Run(contract *Contract, input []byte, static bool) ([]byte, error)
	// CanRun tells if the contract, passed as an argument, can be
	// run by the current interpreter. This is meant so that the
	// caller can do something like:
	//
	// ```golang
	// for _, interpreter := range interpreters {
	//   if interpreter.CanRun(contract.code) {
	//     interpreter.Run(contract.code, input)
	//   }
	// }
	// ```
	CanRun([]byte) bool
}

// callCtx contains the things that are per-call, such as stack and memory,
// but not transients like pc and gas
type callCtx struct {
	memory   *Memory
	stack    *Stack
	contract *Contract
}

// keccakState wraps sha3.state. In addition to the usual hash methods, it also supports
// Read to get a variable amount of data from the hash state. Read is faster than Sum
// because it doesn't copy the internal state, but also modifies the internal state.
type keccakState interface {
	hash.Hash
	Read([]byte) (int, error)
}

// EVMInterpreter represents an EVM interpreter
type EVMInterpreter struct {
	evm *EVM
	cfg Config

	intPool *intPool

	hasher    keccakState // Keccak256 hasher instance shared across opcodes
	hasherBuf common.Hash // Keccak256 hasher result array shared aross opcodes

	readOnly   bool   // Whether to throw on stateful modifications
	returnData []byte // Last CALL's return data for subsequent reuse
}

// NewEVMInterpreter returns a new instance of the Interpreter.
func NewEVMInterpreter(evm *EVM, cfg Config) *EVMInterpreter {
	// We use the STOP instruction whether to see
	// the jump table was initialised. If it was not
	// we'll set the default jump table.
	/*
	这里主要是根据区块所属的世代分配对应版本的jumptable， 与gastable。
	主要是不同世代之间指令有变更，以及对应的gas值设置有变更。
	最后还是用这些信息来初始化evm.config 中定义的解释器
	*/

	/* 如果evm的JumpTrable 还没初始化，根据当前链的版本确定使用哪一个jumpTable*/
	if !cfg.JumpTable[STOP].valid {
		var jt JumpTable
		switch {
		case evm.chainRules.IsIstanbul:
			jt = istanbulInstructionSet
		case evm.chainRules.IsConstantinople:
			jt = constantinopleInstructionSet
		case evm.chainRules.IsByzantium:
			jt = byzantiumInstructionSet
		case evm.chainRules.IsEIP158:
			jt = spuriousDragonInstructionSet
		case evm.chainRules.IsEIP150:
			jt = tangerineWhistleInstructionSet
		case evm.chainRules.IsHomestead:
			jt = homesteadInstructionSet
		default:
			jt = frontierInstructionSet
		}
		for i, eip := range cfg.ExtraEips {
			if err := EnableEIP(eip, &jt); err != nil {
				// Disable it, so caller can check if it's activated or not
				cfg.ExtraEips = append(cfg.ExtraEips[:i], cfg.ExtraEips[i+1:]...)
				log.Error("EIP activation failed", "eip", eip, "error", err)
			}
		}
		cfg.JumpTable = jt
	}

	return &EVMInterpreter{
		evm: evm,
		cfg: cfg,
	}
}

// Run loops and evaluates the contract's code with the given input data and returns
// the return byte-slice and an error if one occurred.
//
// It's important to note that any errors returned by the interpreter should be
// considered a revert-and-consume-all-gas operation except for
// errExecutionReverted which means revert-and-keep-gas-left.
func (in *EVMInterpreter) Run(contract *Contract, input []byte, readOnly bool) (ret []byte, err error) {
	/*1.从intPoolPool中调用一个intpool;并且设置defer，在程序结束之后还回去*/
	/* 用来放数的 */
	if in.intPool == nil {
		in.intPool = poolOfIntPools.get()
		defer func() {
			poolOfIntPools.put(in.intPool)
			in.intPool = nil
		}()
	}

	// Increment the call depth which is restricted to 1024
	/*2.计算调用深度  ; 同时设置defer-1*/
	in.evm.depth++
	defer func() { in.evm.depth-- }()

	// Make sure the readOnly is only set if we aren't in readOnly yet.
	// This makes also sure that the readOnly flag isn't removed for child calls.
	/*确保readOnly的标志只在我们不只readOnly时为false，其他时间一定为true*/
	if readOnly && !in.readOnly {
		in.readOnly = true
		defer func() { in.readOnly = false }()
	}

	// Reset the previous call's return data. It's unimportant to preserve the old buffer
	// as every returning call will return new data anyway.
	in.returnData = nil

	// Don't bother with the execution if there's no code.
	/*如果没有代码就不执行*/
	if len(contract.Code) == 0 {
		return nil,
		nil
	}

	var (
		op          OpCode        // current opcode
		mem         = NewMemory() // bound memory
		stack       = newstack()  // local stack  size：1024

		callContext = &callCtx{
			memory:   mem,
			stack:    stack,
			contract: contract,
		}
		// For optimisation reason we're using uint64 as the program counter.
		// It's theoretically possible to go above 2^64. The YP defines the PC
		// to be uint256. Practically much less so feasible.
		pc   = uint64(0) // program counter

		cost uint64
		// copies used by tracer
		pcCopy  uint64 // needed for the deferred Tracer
		gasCopy uint64 // for Tracer to log gas remaining before execution
		logged  bool   // deferred Tracer should ignore already logged steps
		res     []byte // result of the opcode execution function
	)
	contract.Input = input

	// Reclaim the stack as an int pool when the execution stops
	/*当执行停止时，将stack当前状态会收到intpool中*/
	defer func() { in.intPool.put(stack.data...) }()

	if in.cfg.Debug {
		defer func() {
			if err != nil {
				if !logged {
					in.cfg.Tracer.CaptureState(in.evm, pcCopy, op, gasCopy, cost, mem, stack, contract, in.evm.depth, err)
				} else {
					in.cfg.Tracer.CaptureFault(in.evm, pcCopy, op, gasCopy, cost, mem, stack, contract, in.evm.depth, err)
				}
			}
		}()
	}
	// The Interpreter main run loop (contextual). This loop runs until either an
	// explicit STOP, RETURN or SELFDESTRUCT is executed, an error occurred during
	// the execution of one of the operations or until the done flag is set by the
	// parent context.
	/*
	当interpreter 开始run loop,让其停止的情况：
	1. 遇到明显的 STOP ,RETURN ,SELFDESTRUCT
	2. 执行中遇到错误
	3. 父上下文设置完成标志位。（父上下文要求被调用的EVM上下文终止执行，退出）
	*/
	steps := 0
	for {
		steps++
		if steps%1000 == 0 && atomic.LoadInt32(&in.evm.abort) != 0 {
			break
		}
		if in.cfg.Debug {
			// Capture pre-execution values for tracing.
			logged, pcCopy, gasCopy = false, pc, contract.Gas
		}

		// Get the operation from the jump table and validate the stack to ensure there are
		// enough stack items available to perform the operation.
		/* 从jumptable 获取一个operation,同时验证stack能否确保有足够的堆栈项来有效完成这个operation*/
		op = contract.GetOp(pc)  /*返回c.Code[pc] 也即返回了一个字节   pc初始化值为0*/ //获取第一个操作数在Junptable中的位置
		operation := in.cfg.JumpTable[op]
		if !operation.valid {
			return nil, fmt.Errorf("invalid opcode 0x%x", int(op))
		}
		// Validate stack
		/*验证堆栈：
		1. 以太坊的命令执行也规定了最大和最小堆栈数量
		*/
		if sLen := stack.len(); sLen < operation.minStack {
			return nil, fmt.Errorf("stack underflow (%d <=> %d)", sLen, operation.minStack)
		} else if sLen > operation.maxStack {
			return nil, fmt.Errorf("stack limit reached %d (%d)", sLen, operation.maxStack)
		}


		// If the operation is valid, enforce（强制执行） and write restrictions（限制、约束）
		/*如果operation是有效的，强制执行和写入限制*/
		if in.readOnly && in.evm.chainRules.IsByzantium {

			// If the interpreter is operating in readonly mode, make sure no
			// state-modifying operation is performed. The 3rd stack item
			// for a call operation is the value. Transferring value from one
			// account to the others means the state is modified and should also
			// return with an error.
			/*
			如果解释器以只读模式进行执行，确保没有任何更改状态的操作被执行
			更改状态的操作：
			对于一个call operation来说，其第三个栈项是value.
			从一个账户转账到其他账户意味着state 被修改 应该停止执行并且返回err
			*/
			if operation.writes || (op == CALL && stack.Back(2).Sign() != 0) {
				return nil, errWriteProtection
			}
		}
		// Static portion of gas
		/* constantGas */
		cost = operation.constantGas // For tracing
		if !contract.UseGas(operation.constantGas) {
			return nil, ErrOutOfGas
		}

		/*计算需要在内存中新开的大小 和 运行操作花费内存*/
		var memorySize uint64
		// calculate the new memory size and expand the memory to fit
		// the operation
		/*在计算动态气体部分之前应该进行内存检测去发现计算溢出*/
		// Memory check needs to be done prior to（在前）） evaluating the dynamic gas portion,
		// to detect calculation overflows
		if operation.memorySize != nil {
			memSize, overflow := operation.memorySize(stack) /* 计算当前操作所需耗费的内存空间 */
			if overflow {
				return nil, errGasUintOverflow
			}
			// memory is expanded in words of 32 bytes. Gas
			// is also calculated in words.
			if memorySize, overflow = math.SafeMul(toWordSize(memSize), 32); overflow {
				return nil, errGasUintOverflow
			}
		}
		// Dynamic portion of gas
		// consume the gas and return an error if not enough gas is available.
		// cost is explicitly set so that the capture state defer method can get the proper cost
		/*计算该指令的动态gas消耗数量， 这里引用该指令对应的operation对象的callback函数来完成。*/
		if operation.dynamicGas != nil {
			var dynamicCost uint64
			dynamicCost, err = operation.dynamicGas(in.evm, contract, stack, mem, memorySize)
			cost += dynamicCost // total cost, for debug tracing
			if err != nil || !contract.UseGas(dynamicCost) {
				return nil, ErrOutOfGas
			}
		}
		/*如果Gas 数量足够， 则分配更多的memory。*/
		if memorySize > 0 {
			mem.Resize(memorySize) // 实际上是在原来的mem中加上当前operation所需要的size，
		}

		if in.cfg.Debug {
			in.cfg.Tracer.CaptureState(in.evm, pc, op, gasCopy, cost, mem, stack, contract, in.evm.depth, err)
			logged = true
		}

		// execute the operation
		/*执行该指令了。 这里要跳转到该指令对应的operation对象定义的execute函数*/
		/*  pc 栈指针    */
		res, err = operation.execute(&pc, in, callContext)
		// verifyPool is a build flag. Pool verification makes sure the integrity
		// of the integer pool by comparing values to a default value.
		if verifyPool {
			verifyIntegerPool(in.intPool)
		}
		// if the operation clears the return data (e.g. it has returning data)
		// set the last return to the result of the operation.
		if operation.returns {
			in.returnData = res
		}

		switch {
		case err != nil:
			return nil, err
		case operation.reverts:
			return res, errExecutionReverted
		case operation.halts:
			return res, nil
		case !operation.jumps:
			pc++
		}
	}
	return nil, nil
}

// CanRun tells if the contract, passed as an argument, can be
// run by the current interpreter.
func (in *EVMInterpreter) CanRun(code []byte) bool {
	return true
}
