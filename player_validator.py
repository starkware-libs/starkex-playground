from typing import Any, Dict, List, Set

from player_data import VAULT_RANGE


class InvalidTransaction(Exception):
    pass


class Validator:
    def __init__(self):
        """
        Class used to verify transactions are valid before processing.

        :param vault_range: Lower bound (inclusive) and upper bound (exclusive) of valid vault IDs.
        :type vault_range: Tuple[int, int]
        """
        self.vault_lower_bound, self.vault_upper_bound = VAULT_RANGE
        self.valid_tx_types = [
            "DepositRequest",
            "WithdrawalRequest",
            "SettlementRequest",
            "TransferRequest",
            "MintRequest",
        ]

    def _get_vault_ids(self, tx_dicts: List[Dict[str, Any]]) -> Set[int]:
        """
        Collects all vault IDs that appear in any of the transactions.
        """
        vault_ids: Set[int] = set()
        for tx in tx_dicts:
            if tx["type"] in ["DepositRequest", "WithdrawalRequest"]:
                vault_ids.add(tx["vault_id"])
            elif tx["type"] == "SettlementRequest":
                vault_ids.update(
                    tx[party][vault]
                    for party in ("party_a_order", "party_b_order")
                    for vault in ("vault_id_buy", "vault_id_sell")
                )
            elif tx["type"] == "TransferRequest":
                vault_ids.update((tx["receiver_vault_id"], tx["sender_vault_id"]))

        return vault_ids

    def _verify_tx_types(self, tx_dicts: List[Dict[str, Any]]):
        """
        Verifies that all transactions have supported types.
        """
        if not all(tx["type"] in self.valid_tx_types for tx in tx_dicts):
            raise InvalidTransaction("Invalid transaction type found.")

    def _verify_txs_vault_range(self, vault_ids: Set[int]):
        """
        Verifies that the vault IDs are in the acceptable range.
        """
        vault_lower, vault_upper = self.vault_lower_bound, self.vault_upper_bound
        if not all(vault_lower <= vault_id < vault_upper for vault_id in vault_ids):
            raise InvalidTransaction(
                "Found transaction with vault ID out-of-range. Vault IDs must be at least "
                f"{vault_lower} and less than {vault_upper}."
            )

    def verify_txs(self, tx_dicts: List[Dict[str, Any]]):
        """
        Verifies that the transactions are valid.

        Valid transactions must be of a specific type, in a specific vault range, use valid tokens
        and valid users only.
        """
        self._verify_tx_types(tx_dicts=tx_dicts)
        vault_ids = self._get_vault_ids(tx_dicts=tx_dicts)
        self._verify_txs_vault_range(vault_ids=vault_ids)
