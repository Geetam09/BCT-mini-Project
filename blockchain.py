# blockchain.py
import hashlib
import json
import time
from typing import List, Dict, Optional

class Block:
    def __init__(
        self,
        index: int,
        timestamp: float,
        votes: List[Dict],
        previous_hash: str,
        nonce: int = 0,
        hash: Optional[str] = None
    ):
        """
        Accept nonce and hash optionally so we can reconstruct blocks loaded from JSON.
        """
        self.index = index
        self.timestamp = timestamp
        self.votes = votes or []
        self.previous_hash = previous_hash
        self.nonce = nonce
        # if a stored hash exists, use it; otherwise compute
        self.hash = hash if hash is not None else self.compute_hash()

    def compute_hash(self) -> str:
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "votes": self.votes,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

class SimpleBlockchain:
    def __init__(self, chain_data: Optional[List[Dict]] = None, difficulty: int = 2):
        self.difficulty = difficulty
        if chain_data:
            # reconstruct Block objects from stored dicts (which include nonce and hash)
            self.chain = [
                Block(
                    index=b.get("index", 0),
                    timestamp=b.get("timestamp", time.time()),
                    votes=b.get("votes", []),
                    previous_hash=b.get("previous_hash", "0"),
                    nonce=b.get("nonce", 0),
                    hash=b.get("hash")
                )
                for b in chain_data
            ]
            if len(self.chain) == 0:
                self.create_genesis_block()
        else:
            self.chain = []
            self.create_genesis_block()

    def create_genesis_block(self):
        genesis = Block(0, time.time(), [], "0", nonce=0)
        self.proof_of_work(genesis)
        self.chain.append(genesis)

    @property
    def last_block(self) -> Block:
        return self.chain[-1]

    def proof_of_work(self, block: Block) -> str:
        block.nonce = block.nonce or 0
        computed_hash = block.compute_hash()
        target = "0" * self.difficulty
        while not computed_hash.startswith(target):
            block.nonce += 1
            computed_hash = block.compute_hash()
        block.hash = computed_hash
        return computed_hash

    def new_votes_block(self, votes: List[Dict]) -> Block:
        index = self.last_block.index + 1
        timestamp = time.time()
        previous_hash = self.last_block.hash
        block = Block(index, timestamp, votes, previous_hash, nonce=0)
        self.proof_of_work(block)
        self.chain.append(block)
        return block

    def add_block(self, block: Block):
        if block.previous_hash != self.last_block.hash:
            raise ValueError("Previous hash mismatch")
        if not self.is_valid_proof(block, block.hash):
            raise ValueError("Invalid proof of work")
        self.chain.append(block)

    def to_dict(self) -> List[Dict]:
        return [{
            "index": b.index,
            "timestamp": b.timestamp,
            "votes": b.votes,
            "previous_hash": b.previous_hash,
            "nonce": b.nonce,
            "hash": b.hash
        } for b in self.chain]

    def is_chain_valid(self) -> bool:
        for i in range(1, len(self.chain)):
            curr = self.chain[i]
            prev = self.chain[i-1]
            if curr.previous_hash != prev.hash:
                return False
            if curr.compute_hash() != curr.hash:
                return False
            if not curr.hash.startswith("0" * self.difficulty):
                return False
        return True
