# MIT License
#
# Copyright (c) 2018 Evgeny Medvedev, evge.medvedev@gmail.com
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
from eth_utils import function_signature_to_4byte_selector

from ethereum_dasm.evmdasm import EvmCode, Contract


class EthContractService:

    def get_function_sighashes(self, bytecode):
        bytecode = clean_bytecode(bytecode)
        if bytecode is not None:
            evm_code = EvmCode(contract=Contract(bytecode=bytecode), static_analysis=False, dynamic_analysis=False)
            evm_code.disassemble(bytecode)
            basic_blocks = evm_code.basicblocks
            if basic_blocks and len(basic_blocks) > 0:
                push4_instructions = set()
                for block in basic_blocks:
                    instructions = block.instructions
                    block_push4_instructions = [inst for inst in instructions if inst.name == 'PUSH4']
                    push4_instructions.update(block_push4_instructions)

                return sorted(list({'0x' + inst.operand for inst in push4_instructions}))
            else:
                return []
        else:
            return []

    # https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20.md
    # https://github.com/OpenZeppelin/openzeppelin-solidity/blob/master/contracts/token/ERC20/ERC20.sol
    def is_erc20_contract(self, function_sighashes):
        c = ContractWrapper(function_sighashes)
        return all([
            c.implements('totalSupply()'),
            c.implements('balanceOf(address)'),
            c.implements('transfer(address,uint256)'),
            c.implements('transferFrom(address,address,uint256)'),
            c.implements('approve(address,uint256)'),
            c.implements('allowance(address,address)')
        ])

    # https://github.com/ethereum/EIPs/blob/master/EIPS/eip-721.md
    # https://github.com/OpenZeppelin/openzeppelin-solidity/blob/master/contracts/token/ERC721/ERC721Basic.sol
    # so we have to check for it's sighashes explicitly
    def is_erc721_contract(self, function_sighashes):
        c = ContractWrapper(function_sighashes)
        return all([
            c.implements('balanceOf(address)'),
            c.implements('ownerOf(uint256)'),
            c.implements_any_of('transfer(address,uint256)', 'transferFrom(address,address,uint256)'),
            c.implements('approve(address,uint256)'),
            c.implements('getApproved(uint256)'),
            c.implements('setApprovalForAll(address,bool)'),
            c.implements('isApprovedForAll(address,address)'),
            c.implements('transferFrom(address,address,uint256)'),
            c.implements('safeTransferFrom(address,address,uint256)'),
            c.implements('safeTransferFrom(address,address,uint256,bytes)'),
        ])

def clean_bytecode(bytecode):
    if bytecode is None or bytecode == '0x':
        return None
    elif bytecode.startswith('0x'):
        return bytecode[2:]
    else:
        return bytecode


def get_function_sighash(signature):
    return '0x' + function_signature_to_4byte_selector(signature).hex()


class ContractWrapper:
    def __init__(self, sighashes):
        self.sighashes = sighashes

    def implements(self, function_signature):
        sighash = get_function_sighash(function_signature)
        return sighash in self.sighashes

    def implements_any_of(self, *function_signatures):
        return any(self.implements(function_signature) for function_signature in function_signatures)
