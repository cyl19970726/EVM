// Copyright 2015 The go-ethereum Authors
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

package state

import (
	"bytes"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
)
//OpenTrie: 打开指定状态版本(root)的含世界状态的顶层树。
//OpenStorageTrie: 打开账户(addrHash)下指定状态版本(root)的账户数据存储树。
//CopyTrie: 深度拷贝树。
//ContractCode：获取账户（addrHash）的合约，必须和合约哈希(codeHash)匹配。
//ContractCodeSize 获取指定合约大小
//TrieDB：获得 Trie 底层的数据驱动 DB，如: levedDB 、内存数据库、远程数据库


//世界树 迭代器
// NodeIterator is an iterator to traverse the entire state trie post-order,
// including all of the contract code and contract state tries.
type NodeIterator struct {
	state *StateDB // State being iterated

	stateIt trie.NodeIterator // Primary iterator for the global state trie
	dataIt  trie.NodeIterator // Secondary iterator for the data trie of a contract

	accountHash common.Hash // Hash of the node containing the account
	codeHash    common.Hash // Hash of the contract source code
	code        []byte      // Source code associated with a contract

	Hash   common.Hash // Hash of the current entry being iterated (nil if not standalone)
	Parent common.Hash // Hash of the first full ancestor node (nil if current is the root)

	Error error // Failure set in case of an internal error in the iterator
}

// NewNodeIterator creates an post-order state node iterator.
func NewNodeIterator(state *StateDB) *NodeIterator {
	return &NodeIterator{
		state: state,
	}
}

// Next moves the iterator to the next node, returning whether there are any
// further nodes. In case of an internal error this method returns false and
// sets the Error field to the encountered failure.
func (it *NodeIterator) Next() bool {
	// If the iterator failed previously, don't do anything
	if it.Error != nil {
		return false
	}
	// Otherwise step forward with the iterator and report any errors
	if err := it.step(); err != nil {
		it.Error = err
		return false
	}
	return it.retrieve()
}

// step moves the iterator to the next entry of the state trie.
func (it *NodeIterator) step() error {
	// Abort if we reached the end of the iteration
	if it.state == nil {
		return nil
	}
	// Initialize the iterator if we've just started
	if it.stateIt == nil {
		it.stateIt = it.state.trie.NodeIterator(nil)
	}
	// If we had data nodes previously, we surely have at least state nodes
	if it.dataIt != nil {
		if cont := it.dataIt.Next(true); !cont {
			if it.dataIt.Error() != nil {
				return it.dataIt.Error()
			}
			it.dataIt = nil
		}
		return nil
	}
	// If we had source code previously, discard that
	if it.code != nil {
		it.code = nil
		return nil
	}
	// Step to the next state trie node, terminating if we're out of nodes
	if cont := it.stateIt.Next(true); !cont {
		if it.stateIt.Error() != nil {
			return it.stateIt.Error()
		}
		it.state, it.stateIt = nil, nil
		return nil
	}
	// If the state trie node is an internal entry, leave as is
	if !it.stateIt.Leaf() {
		return nil
	}
	// Otherwise we've reached an account node, initiate data iteration
	var account Account
	if err := rlp.Decode(bytes.NewReader(it.stateIt.LeafBlob()), &account); err != nil {
		return err
	}
	dataTrie, err := it.state.db.OpenStorageTrie(common.BytesToHash(it.stateIt.LeafKey()), account.Root)
	if err != nil {
		return err
	}
	it.dataIt = dataTrie.NodeIterator(nil)
	if !it.dataIt.Next(true) {
		it.dataIt = nil
	}
	if !bytes.Equal(account.CodeHash, emptyCodeHash) {
		it.codeHash = common.BytesToHash(account.CodeHash)
		addrHash := common.BytesToHash(it.stateIt.LeafKey())
		it.code, err = it.state.db.ContractCode(addrHash, common.BytesToHash(account.CodeHash))
		if err != nil {
			return fmt.Errorf("code %x: %v", account.CodeHash, err)
		}
	}
	it.accountHash = it.stateIt.Parent()
	return nil
}

// retrieve pulls and caches the current state entry the iterator is traversing.
// The method returns whether there are any more data left for inspection.
func (it *NodeIterator) retrieve() bool {
	// Clear out any previously set values
	it.Hash = common.Hash{}

	// If the iteration's done, return no available data
	if it.state == nil {
		return false
	}
	// Otherwise retrieve the current entry
	switch {
	case it.dataIt != nil:
		it.Hash, it.Parent = it.dataIt.Hash(), it.dataIt.Parent()
		if it.Parent == (common.Hash{}) {
			it.Parent = it.accountHash
		}
	case it.code != nil:
		it.Hash, it.Parent = it.codeHash, it.accountHash
	case it.stateIt != nil:
		it.Hash, it.Parent = it.stateIt.Hash(), it.stateIt.Parent()
	}
	return true
}
