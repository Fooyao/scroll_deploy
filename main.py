import asyncio
import random
import string
import sys
import rlp
from solcx import compile_source, install_solc, get_solc_version
from loguru import logger
import httpx
from web3 import AsyncWeb3

g_success, g_fail = 0, 0

logger.remove()
logger.add(sys.stdout, colorize=True, format="<g>{time:HH:mm:ss:SSS}</g> | <r>{extra[fail]}</r>-<g>{extra[success]}</g> | <level>{message}</level>")
logger = logger.patch(lambda record: record["extra"].update(fail=g_fail, success=g_success))


class Scroll:
    def __init__(self, privateKey):
        try:
            self.chainid = 534352
            RPCLIST = ['https://rpc.ankr.com/scroll', 'https://rpc.ankr.com/scroll', 'https://scroll.blockpi.network/v1/rpc/public']
            self.w3 = AsyncWeb3(AsyncWeb3.AsyncHTTPProvider(random.choice(RPCLIST)))
            self.privateKey = privateKey
            self.account = self.w3.eth.account.from_key(self.privateKey)
            self.http = httpx.AsyncClient(http2=True, verify=False)
            self.contract_interface = None
            self.state = True
        except Exception as e:
            self.state = False
            logger.error(f"初始化失败{e}")

    async def check_deploy(self):
        try:
            maxnonce = await self.w3.eth.get_transaction_count(self.account.address)
            for i in range(maxnonce):
                address_bytes = bytes.fromhex(self.account.address[2:])
                rlp_encoded_nonce = rlp.encode([address_bytes, i])
                hash_output = AsyncWeb3.keccak(rlp_encoded_nonce)
                contract_address = AsyncWeb3.to_checksum_address(hash_output[-20:].hex())
                bytecode = await self.w3.eth.get_code(contract_address)
                if bytecode.hex() != '0x':
                    logger.success(f'[{self.account.address}]  已部署合约:{contract_address}')
                    return False
            logger.info(f'[{self.account.address}] 未部署合约，将部署')
            return True
        except Exception as e:
            logger.error(f"[{self.account.address}] 检查部署失败{e}")
            return False

    async def compile_source(self):
        try:
            erc20 = '''// SPDX-License-Identifier: MIT
                pragma solidity ^0.8.4;
                contract ERC20 {
                    string private constant _name = "TTTT";
                    function name() external pure returns (string memory){ return _name;}
                    function symbol() external pure returns (string memory){ return _name;}
                    function decimals() external pure returns (uint8) { return 18;}
                    function totalSupply() external pure returns (uint256) {return 999999 ether;}
                }'''
            name = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(4))
            erc20 = erc20.replace('TTTT', name)
            compiled_sol = compile_source(erc20, output_values=['abi', 'bin'])
            contract_id, contract_interface = compiled_sol.popitem()
            self.contract_interface = contract_interface
        except Exception as e:
            logger.error(f"编译失败{e}")
            return False

    async def Created(self):
        try:
            nonce = await self.w3.eth.get_transaction_count(self.account.address)
            gasPrice = await self.w3.eth.gas_price
            tx = {
                "from": self.account.address,
                "gas": 2000000,
                "chainId": self.chainid,
                "gasPrice": gasPrice,
                "nonce": nonce,
                "data": self.contract_interface['bin']
            }
            tx['gas'] = await self.w3.eth.estimate_gas(tx)
            signed_tx = self.w3.eth.account.sign_transaction(tx, private_key=self.privateKey)
            try:
                tx_hash = await self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
                logger.success(f'[{self.account.address}] 部署合约已发送 哈希{self.w3.to_hex(tx_hash)}')
                freceipt = await self.w3.eth.wait_for_transaction_receipt(tx_hash, 3000, 2)
                if freceipt['status'] == 1:
                    logger.success(f'[{self.account.address}] 部署合约成功')
                    return True
                else:
                    logger.error(f'[{self.account.address}] 部署合约失败')
                    return False
            except Exception as e:
                logger.error(f'[{self.account.address}] 部署合约发送失败{e}')
                return False
        except Exception as e:
            logger.error(f'[{self.account.address}] 部署合约失败{e}')
            return False


async def main(f_path):
    global g_success, g_fail
    with open(f_path, 'r') as f:
        file_list = f.readlines()
    logger.info(f'共{len(file_list)}个账号')
    for line in file_list:
        private_key = line.strip().split('----')[-1]
        scroll = Scroll(private_key)
        try:
            if scroll.state:
                if await scroll.check_deploy():
                    await scroll.compile_source()
                    if await scroll.Created():
                        g_success += 1
                    else:
                        g_fail += 1
            else:
                g_fail += 1
        except Exception as e:
            logger.error(f'[{scroll.account.address}] 失败{e}')
            g_fail += 1


if __name__ == '__main__':
    try:
        get_solc_version()
    except Exception as e:
        install_solc(version='0.8.18')
    file_path = input('请输入文件路径：')
    asyncio.run(main(file_path))
