#!/usr/bin/env python3.9

import argparse
import asyncio
import json
import logging
from typing import Any, Dict, List

from player_gateway_utils import DEFAULT_GATEWAY_URL, BadRequest, PlaygroundGatewayClient
from player_onchain_utils import OnchainUtils
from player_validator import Validator

INVALID_TX_ID_ERROR_TEXT = "StarkErrorCode.INVALID_TRANSACTION_ID"
TRANSACTION_PENDING = "TRANSACTION_PENDING"
DEPOSIT_REQUEST_TX_TYPE = "DepositRequest"


logger = logging.getLogger("starkex_playground")


class PlayerError(Exception):
    pass


# Transaction processing utils.
async def tx_dicts_to_add_tx_dicts(
    tx_dicts: List[Dict[str, Any]], gateway_client: PlaygroundGatewayClient
) -> List[Dict[str, Any]]:
    """
    Converts a dictionary conforming to TransactionRequest structure into a dictionary conforming to
    AddTransactionRequest structure; i.e., tx_dict becomes {'tx': tx_dict, 'tx_id': ID}.

    The 'tx_id' values start from the next available transaction ID.
    """
    first_tx_id = await gateway_client.get_first_unused_tx_id()
    return [{"tx": tx, "tx_id": tx_id} for tx_id, tx in enumerate(tx_dicts, start=first_tx_id)]


async def send_tx(gateway_client: PlaygroundGatewayClient, tx_dict: Dict[str, Any]):
    """
    Send a transaction to the gateway with the first unused tx_id.
    If the tx_id was already taken, send the same transaction again with another tx_id
    """
    while True:
        tx_id = await gateway_client.get_first_unused_tx_id()
        logger.debug(f'Sending transaction to gatway. type: {tx_dict["type"]}, tx_id: {tx_id}')
        tx_request = {"tx": tx_dict, "tx_id": tx_id}
        try:
            response_json = await gateway_client.send_add_tx_request(tx_request)
            response = json.loads(response_json)
            if response["code"] != TRANSACTION_PENDING:
                raise PlayerError(
                    f"Transaction tx_id: {tx_id} failed! Please DO NOT attempt to re-play failed "
                    f"transactions; you may run this script on a transaction file that has not yet "
                    f"been played."
                )
            return
        except BadRequest as bad_request:
            bad_request_text = json.loads(bad_request.text)["code"]
            if bad_request_text == INVALID_TX_ID_ERROR_TEXT:
                logger.debug(f"tx_id {tx_id} is already used, allocating a new tx_id")


async def play_offchain_txs(
    gateway_client: PlaygroundGatewayClient, tx_dicts: List[Dict[str, Any]]
):
    """
    Sends all transactions to the gateway.
    """
    logger.info(f"Sending {len(tx_dicts)} transactions to StarkEx gateway.")
    for tx_dict in tx_dicts:
        await send_tx(gateway_client=gateway_client, tx_dict=tx_dict)


async def play_onchain_txs(onchain_player: OnchainUtils, tx_dicts: List[Dict[str, Any]]):
    """
    Handles onchain deposits.
    """
    deposit_requests = [tx for tx in tx_dicts if tx["type"] == DEPOSIT_REQUEST_TX_TYPE]
    await onchain_player.make_onchain_deposits(deposit_requests=deposit_requests)


def config_logger(verbose: bool):
    """
    Configures the logger verbosity level
    """
    ch = logging.StreamHandler()
    logger.addHandler(ch)
    if verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)


# Main logic.
async def main(
    txs_path: str, gateway_url: str, node_url: str, funder_private_key: str, verbose: bool
):
    """
    Reads the configuration and the transactions JSON files, verifies that the transactions satisfy
    the configuration constraints, and plays the transactions.
    """
    config_logger(verbose=verbose)

    # Read transactions JSON.
    with open(txs_path, "r") as txs_file:
        tx_dicts = json.load(txs_file)

    # Validate the transactions against the configuration file.
    validator = Validator()
    validator.verify_txs(tx_dicts=tx_dicts)

    # Run the transactions. This requires onchain actions before the transactions are sent to the
    # StarkEx system.
    gateway_client = PlaygroundGatewayClient(gateway_url=gateway_url)
    onchain_player = OnchainUtils(node_url=node_url, funder_private_key=funder_private_key)

    # Process transactions.
    await play_onchain_txs(onchain_player=onchain_player, tx_dicts=tx_dicts)
    await play_offchain_txs(gateway_client=gateway_client, tx_dicts=tx_dicts)


def run_main():
    """
    Parses arguments and calls the main logic.
    """
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="Generate transactions for StarkEx Playground.",
    )
    parser.add_argument(
        "--txs", type=str, required=True, help="Path to JSON file containing transactions to run."
    )
    parser.add_argument(
        "--gateway_url", type=str, default=DEFAULT_GATEWAY_URL, help="URL of the StarkEx gateway."
    )
    parser.add_argument(
        "--node_url",
        type=str,
        required=True,
        help="URL of the node processing the Ropsten transactions (required for deposits).",
    )
    parser.add_argument(
        "--funder_private_key",
        type=str,
        required=True,
        help="The private ETH key of a funded account (for on-chain transactions).",
    )
    parser.add_argument(
        "--verbose", action="store_true", default=False, help="Verbosity turned on."
    )
    args = parser.parse_args()

    asyncio.run(
        main(
            txs_path=args.txs,
            gateway_url=args.gateway_url,
            node_url=args.node_url,
            funder_private_key=args.funder_private_key,
            verbose=args.verbose,
        )
    )


if __name__ == "__main__":
    run_main()
