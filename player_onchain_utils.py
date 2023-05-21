import asyncio
import json
import os
from collections import defaultdict
from typing import Any, Dict, Iterable, List, NamedTuple, Optional

from eth_account.signers.base import BaseAccount
from eth_typing import ChecksumAddress
from eth_typing.encoding import HexStr
from player_data import ASSET_IDS_TO_ERC20_ADDRESSES, MAIN_CONTRACT_ADDRESS, TOKEN_PATRON
from web3 import Account, HTTPProvider, Web3
from web3.contract import ContractFunction
from web3.datastructures import AttributeDict
from web3.types import Nonce, RPCEndpoint, TxParams, Wei

from starkware.python.utils import from_bytes

DEFAULT_WEI_PER_DEPOSIT = 5 * 10**15  # 0.005 ETH.
DEFAULT_GAS_PRICE = 5 * 10**9
CWD = os.path.dirname(__file__)
ERC20_ABI_PATH = os.path.join(CWD, "abis/partial_erc20_abi.json")
STARKEX_ABI_PATH = os.path.join(CWD, "abis/partial_starkex_abi.json")

VaultInfo = NamedTuple(
    "VaultInfo", [("stark_public_key", str), ("asset_id", int), ("vault_id", int)]
)


class TransactionFailed(Exception):
    pass


class OnchainUtils:
    def __init__(
        self, node_url: str, funder_private_key: str, gas_price: Optional[int] = None
    ) -> None:
        """
        This class is used to run all on-chain transactions required before sending StarkEx
        transactions to the gateway.

        :param node_url: URL of node processing Goerli transactions.
        :type node_url: str
        :param gas_price: Optional gas price to pay.
        :type gas_price: Optional[int]
        :param funder_private_key: Private ETH key of an account with enough ETH balance to perform
           the onchain transactions.
        :type funder_private_key: str
        """
        # Maps user ETH accounts to transaction nonces.
        self.user_nonces: Dict[ChecksumAddress, Nonce] = {}

        # Init web3.
        self.gas_price = gas_price or DEFAULT_GAS_PRICE
        self.w3 = self._init_web3(node_url=node_url)

        # Set the token patron (the user performing the actual deposits).
        self.patron = Account.from_key(TOKEN_PATRON["eth_private_key"])

        # Set the funded account (fund the token patron).
        self.funded = Account.from_key(funder_private_key)

        # Map token IDs to ERC20 contracts.
        erc20_abi = json.load(open(ERC20_ABI_PATH))
        self.erc20_contracts = {
            asset_id: self.w3.eth.contract(
                abi=erc20_abi, address=Web3.toChecksumAddress(token_address)
            )
            for asset_id, token_address in ASSET_IDS_TO_ERC20_ADDRESSES.items()
        }

        # Keep a reference to the StarkEx main contract.
        starkex_abi = json.load(open(STARKEX_ABI_PATH))
        self.main_contract = self.w3.eth.contract(abi=starkex_abi, address=MAIN_CONTRACT_ADDRESS)

    def _init_web3(self, node_url: str) -> Web3:
        w3 = Web3(HTTPProvider(endpoint_uri=node_url))
        gas_price_strategy = lambda w3, tx_params: Wei(self.gas_price)
        w3.eth.setGasPriceStrategy(gas_price_strategy)
        return w3

    async def _fund_the_patron(self, n_deposits: int):
        """
        Transfer ETH to the patron user, so that user can perform deposits.
        """
        tx_dict = {
            "to": self.patron.address,
            "from": self.funded.address,
            "nonce": self._allocate_nonce(eth_address=self.funded.address),
            "value": n_deposits * DEFAULT_WEI_PER_DEPOSIT,
            "gasPrice": self.w3.eth.gas_price,
        }
        tx_dict["gas"] = self.w3.eth.estimateGas(tx_dict)
        signed_tx = self.funded.signTransaction(tx_dict)
        tx_hash = self.w3.eth.sendRawTransaction(signed_tx.rawTransaction).hex()
        print(f'Funding the patron with {tx_dict["value"]} wei, transaction hash: {tx_hash}')
        await self._wait_for_tx_receipt(tx_hash=tx_hash)  # type: ignore
        print("Patron funded")

    def _aggregate_deposit_amounts_by_vault(
        self, deposit_requests: List[Dict[str, Any]]
    ) -> Dict[VaultInfo, int]:
        """
        Constructs and returns a dictionary mapping (stark_public_key, asset_id, vault_id) tuples to
        the total desired deposit of the respective token to the respective vault.

        This function is used to deposit the correct amount onchain, per vault.
        """
        total_amounts: Dict[VaultInfo, int] = defaultdict(int)
        for deposit_request in deposit_requests:
            stark_public_key = deposit_request["stark_key"]
            asset_id = int(deposit_request["token_id"], 16)
            vault_id = int(deposit_request["vault_id"])
            vault = VaultInfo(
                stark_public_key=stark_public_key, asset_id=asset_id, vault_id=vault_id
            )
            total_amounts[vault] += int(deposit_request["amount"])
        return total_amounts

    def _allocate_nonce(self, eth_address: ChecksumAddress) -> Nonce:
        """
        Returns sequential nonces for given ETH address.

        Assumes all transactions performed by the given address are done in this script.
        """
        nonce = self.user_nonces.get(eth_address, self.w3.eth.getTransactionCount(eth_address))
        self.user_nonces[eth_address] = Nonce(nonce + 1)
        return nonce

    def _get_revert_reason(self, tx_hash: HexStr) -> str:
        """
        Returns the revert message of a reverted transaction.
        """
        client_version = self.w3.clientVersion
        if client_version.startswith("Geth"):
            trace = self.w3.manager.request_blocking(
                RPCEndpoint("debug_traceTransaction"),
                [tx_hash, {"disableMemory": True, "disableStack": True, "disableStorage": True}],
            )
            assert trace["failed"], "Transaction was not reverted"
            revert_payload = trace["returnValue"]
            if len(revert_payload) == 0:
                gas = self.w3.eth.getTransaction(tx_hash)["gas"]
                gasUsed = self.w3.eth.getTransactionReceipt(tx_hash)["gasUsed"]
                if gas == gasUsed:
                    return f"Out of gas. gasUsed: {gasUsed}."
        else:
            assert False, f"Unknown client: {client_version}"

        if len(revert_payload) == 0:
            return "N/A (Low level solidity error)"
        revert_payload = bytes.fromhex(revert_payload)

        # Solidity generates reverts with an error in the following structure:
        # 1. 4 bytes function selector, (the constant 0x08c379a0 == Keccak256(b'Error(string)')[:4])
        # 2. 32bytes offset of string return value (always 0x20 in this case).
        # 3. 32bytes with the length of the revert reason.
        # 4. Revert reason string.
        assert from_bytes(revert_payload[:0x4]) == 0x08C379A0
        assert from_bytes(revert_payload[0x4:0x24]) == 0x20
        msg_length = from_bytes(revert_payload[0x24:0x44])

        return str(revert_payload[0x44 : 0x44 + msg_length].decode("ascii"))

    def _transmit_tx(
        self, tx: ContractFunction, sender: BaseAccount, tx_args: Optional[TxParams] = None
    ) -> HexStr:
        """
        Builds, signs and sends ETH transaction. Returns the transaction hash.
        """
        tx_args = TxParams() if tx_args is None else tx_args
        tx_args.update(
            {"from": sender.address, "nonce": self._allocate_nonce(eth_address=sender.address)}
        )
        tx_dict = tx.buildTransaction(tx_args)
        signed_tx = sender.signTransaction(tx_dict)
        return self.w3.eth.sendRawTransaction(signed_tx.rawTransaction).hex()  # type: ignore

    async def _wait_for_tx_receipt(self, tx_hash: HexStr) -> Dict[HexStr, AttributeDict]:
        """
        Blocks and waits for transaction receipt. Returns a dictionary mapping the transaction hash
        to the receipt.
        """
        return {tx_hash: self.w3.eth.waitForTransactionReceipt(tx_hash)}  # type: ignore

    async def _wait_for_tx_receipts(self, tx_hashes: List[HexStr]) -> Dict[HexStr, AttributeDict]:
        """
        Blocks until all transactions are included onchain (or until a revert occurs).

        Returns a dictionary mapping transaction hashes to their receipts.
        """
        gathered_receipts: List[Dict[HexStr, AttributeDict]] = await asyncio.gather(
            *(self._wait_for_tx_receipt(tx_hash=tx_hash) for tx_hash in tx_hashes)
        )
        return dict((tx_hash, d[tx_hash]) for d in gathered_receipts for tx_hash in d)

    def _get_deposit_balances(
        self, users_tokens_vaults: Iterable[VaultInfo]
    ) -> Dict[VaultInfo, int]:
        """
        Returns a list of the current pending deposit balances for every user-token-vault tuple.
        """
        return {
            vault: self.main_contract.functions.getQuantizedDepositBalance(
                int(vault.stark_public_key, 16), vault.asset_id, vault.vault_id
            ).call()
            for vault in users_tokens_vaults
        }

    async def _onchain_deposits(self, aggregated_user_token_vault: Dict[VaultInfo, int]):
        """
        Each user makes onchain deposits into the StarkEx contract.
        """
        # Store previous balances for later comparison.
        prev_balances = self._get_deposit_balances(
            users_tokens_vaults=aggregated_user_token_vault.keys()
        )

        # Call deposit() once per user-token-vault triple.
        tx_hashes: List[HexStr] = []
        for (stark_public_key, asset_id, vault_id), amount in aggregated_user_token_vault.items():
            deposit_tx = self.main_contract.functions.deposit(
                int(stark_public_key, 16), asset_id, vault_id, amount
            )
            print(
                f"Depositing {amount} of token 0x...{hex(asset_id)[-6:]} into vault {vault_id} "
                f"belonging to stark key 0x...{stark_public_key[-6:]}"
            )
            deposit_tx_hash = self._transmit_tx(tx=deposit_tx, sender=self.patron)
            print(f"https://goerli.etherscan.io/tx/{deposit_tx_hash}")
            tx_hashes += [deposit_tx_hash]

        # Wait for transactions to complete.
        print("Waiting for deposits to be accepted onchain...")
        receipts_dict = await self._wait_for_tx_receipts(tx_hashes=tx_hashes)
        if not all(
            receipt is not None and receipt["status"] == 1 for receipt in receipts_dict.values()
        ):
            failed = {
                tx_hash: receipt
                for tx_hash, receipt in receipts_dict.items()
                if receipt is None or receipt["status"] != 1
            }
            raise TransactionFailed(f"Deposit(s) failed. Failed transaction receipts:\n{failed}")

        # Verify deposited amounts are as requested.
        current_balances = self._get_deposit_balances(
            users_tokens_vaults=aggregated_user_token_vault.keys()
        )
        assert all(
            current_balances[vault] - prev_balances[vault] == amount
            for vault, amount in aggregated_user_token_vault.items()
        ), f"Failed to deposit to all vaults. Receipts:\n{receipts_dict}"

    async def make_onchain_deposits(self, deposit_requests: List[Dict[str, Any]]):
        """
        Performs all on-chain actions required before deposit requests are sent to gateway.
        """
        aggregated_user_token_vault = self._aggregate_deposit_amounts_by_vault(
            deposit_requests=deposit_requests
        )
        n_deposits = len(aggregated_user_token_vault)
        if n_deposits == 0:
            print("No deposits to perform")
            return
        # The patron user needs ETH to perform deposits.
        await self._fund_the_patron(n_deposits=n_deposits)
        await self._onchain_deposits(aggregated_user_token_vault=aggregated_user_token_vault)
