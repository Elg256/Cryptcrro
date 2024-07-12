from cryptcrro.asymetric import crro
import os


class CrroCoin:

    @staticmethod
    def get_info_block(num_trs=False):
        with open("block", "r") as file:
            block = file.read()

            block = block.split("-TrBegin-")
            block_head = block[0]

            lines = block_head.split("\n")

            for line in lines:
                if line.startswith("By:"):
                    pubkey_miner = line.replace("By:", "")
                if line.startswith("Phash:"):
                    previous_hash = line.replace("Phash:", "")

            numbers_trs = len(block) - 1

            all_transaction = block[1:]

            print("numbers_trs", numbers_trs)

            if num_trs == True:
                return pubkey_miner, previous_hash, all_transaction, numbers_trs
            else:
                return pubkey_miner, previous_hash, all_transaction

    @staticmethod
    def get_info_transaction(transaction: str):

        lines = transaction.split("\n")

        amount = "Not found"
        id_coins = "Not found"
        sender = "Not found"
        recipient = "Not found"

        for line in lines:
            if line.startswith("Amount:"):
                amount = line.replace("Amount:", "")
            if line.startswith("IdCoin:"):
                id_coins = line.replace("IdCoin:", "").split(",")
            if line.startswith("From:"):
                sender = line.replace("From:", "")
            if line.startswith("To:"):
                recipient = line.replace("To:", "")

        return amount, id_coins, sender, recipient

    pubkey_miner, previous_hash, all_transaction = get_info_block()

    amount, id_coins, sender, recipient = get_info_transaction("".join(all_transaction))

    @staticmethod
    def make_transaction(privkey, pubkey, pubkey_recipient, id_coins):

        id_coins = ",".join(id_coins)

        pubkey = str(pubkey).replace("(", "").replace(")", "")

        pubkey_recipient = str(pubkey_recipient).replace("(", "").replace(")", "")

        transaction = f"-TrBegin-\nAmount:{len(id_coins)}\nIdCoin:{id_coin}\nFrom:{pubkey}\nTo{pubkey_recipient}-TrEnd-"

        signed_transaction = crro.sign(privkey, transaction)

        lines = signed_transaction.split("\n")

        signed_transaction = [line for line in lines if not line.startswith("---")]

        signed_transaction = "".join(signed_transaction)

        return signed_transaction

    @staticmethod
    def show_balance(pubkey):
        pubkey = str(pubkey)
        initial_count = 0
        amount = 0
        dir = "./blockchain"
        for path in os.listdir(dir):
            if os.path.isfile(os.path.join(dir, path)):
                initial_count += 1

        for i in range(0, initial_count):
            with open(f"blockchain/block{i}", "r") as file:
                data = file.read()
                lines = data.split("\n")

                for line in lines:
                    if line.startswith(f"From:{pubkey}"):
                        for amount_line in lines:
                            if amount_line.startswith("Amount:"):
                                amount_line = int(amount_line.replace("Amount:", ""))
                                amount -= amount_line
                                break
                    if line.startswith(f"To:{pubkey}"):
                        for amount_line in lines:
                            if amount_line.startswith("Amount:"):
                                amount_line = int(amount_line.replace("Amount:", ""))
                                amount += amount_line
                                break
        return amount




