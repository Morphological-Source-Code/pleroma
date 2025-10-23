#!/usr/bin/env -S uv run
# /* script
# requires-python = ">=3.14"
# dependencies = [
#     "uv==*.*",
# ]
# -*- coding: utf-8 -*-
# ------------------------------
# 3.14 std libs **ONLY**      |
# Platform(s):                |
# Win11 (production)          |
# Ubuntu-22.04 (dev, staging) |
# ------------------------------
import os
import time
import ast
import secrets
import hmac
import sys
import re
import platform
import ctypes
from enum import IntEnum, IntFlag, auto
from dataclasses import dataclass
import logging
import concurrent.interpreters as interpreters
import mmap, hashlib
import threading 

logging.basicConfig(
    level=logging.INFO, format="[%(asctime)s][%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)
# --- Constants ---
BUF_SIZE = 8192
REGION_A = (0, BUF_SIZE // 2)
REGION_B = (BUF_SIZE // 2, BUF_SIZE)

# Simplified DH parameters (for demonstration, use a robust crypto library in production)
P = 0xE95E4A5F737059DC60DF5991D45029409E60FC09
G = 2


# --- Worker Function (for sub-interpreters) ---
# This function will be executed in a sub-interpreter.
# It receives communication queues and shared memory details.
def sub_interpreter_worker(
    worker_id: str,
    region_start: int,
    region_len: int,
    peer_start: int,
    peer_len: int,
    buf_addr: int,
    to_main_queue,
    from_main_queue,
):
    import ctypes
    import secrets
    import hashlib
    import hmac
    import logging  # Sub-interpreters need their own logging setup

    logging.basicConfig(
        level=logging.INFO,
        format=f"[%(asctime)s][%(levelname)s][Worker-{worker_id}] %(message)s",
    )
    worker_logger = logging.getLogger(__name__)

    worker_logger.info(f"Worker {worker_id} started.")

    try:
        shm = (ctypes.c_char * region_len).from_address(buf_addr + region_start)
        peer_shm = (ctypes.c_char * peer_len).from_address(buf_addr + peer_start)

        # --- Perform 'quantized' work first, as-if DH-verified ---
        msg = f"Hello from subinterp {worker_id}".encode("utf-8")
        code_hash = hashlib.sha256(b"sub_interpreter_worker").digest()

        # Send the work over the queue (assuming verification will pass later)
        to_main_queue.put({"type": "WORK", "msg": msg, "code_hash": code_hash})
        worker_logger.info(
            f"Worker {worker_id}: Sent work (msg and code_hash) over queue."
        )

        # --- Now perform lazy DH key exchange ---
        priv = secrets.randbelow(P - 2) + 1
        pub = pow(G, priv, P)
        pub_bytes = pub.to_bytes(32, "big")

        # Send public key over queue instead of writing to shared memory
        to_main_queue.put({"type": "PUBKEY", "pub": pub_bytes})
        worker_logger.info(
            f"Worker {worker_id}: Sent public key over queue. Waiting for peer's public key..."
        )

        # Wait for peer's public key from main
        peer_pub_msg = from_main_queue.get(timeout=5)
        if not isinstance(peer_pub_msg, bytes):
            worker_logger.error(
                f"Worker {worker_id}: Did not receive expected peer public key bytes."
            )
            return
        their_pub = int.from_bytes(peer_pub_msg, "big")
        shared = pow(their_pub, priv, P)
        key = hashlib.sha256(
            shared.to_bytes((shared.bit_length() + 7) // 8, "big")
        ).digest()
        worker_logger.info(f"Worker {worker_id}: Shared secret derived.")

        # --- Compute HMAC on the previously sent work (msg) ---
        mac = hmac.new(key, msg, hashlib.sha256).digest()

        # Send the lazy DH package (mac and key for demo verification by main)
        to_main_queue.put({"type": "DH_PACKAGE", "mac": mac, "key": key})
        worker_logger.info(
            f"Worker {worker_id}: Sent lazy DH package (mac and key) over queue."
        )

        # Signal completion to main interpreter
        to_main_queue.put("WORK_DONE")
        worker_logger.info(
            f"Worker {worker_id}: Work completed and signaled main interpreter."
        )

    except Exception as e:
        worker_logger.exception(
            f"Worker {worker_id}: An error occurred during execution."
        )
        to_main_queue.put(f"ERROR: {str(e)}")  # Send error back to main interpreter


# --- Main Interpreter Logic ---
class SubInterpreterManager:
    def __init__(self, buf_size: int = BUF_SIZE):
        self.buf_size = buf_size
        self.buf = mmap.mmap(-1, self.buf_size)
        self.buf_addr = ctypes.addressof(ctypes.c_char.from_buffer(self.buf))
        self.interpreters = {}
        self.channels = {}
        logger.info(f"Shared memory buffer initialized at address: {self.buf_addr}")

    def create_managed_interpreter(
        self, name: str, region_config: tuple, peer_region_config: tuple
    ):
        if name in self.interpreters:
            raise ValueError(f"Interpreter with name '{name}' already exists.")

        interp = interpreters.create()

        # Create two queues for bidirectional communication
        to_worker_queue = interpreters.create_queue()  # Main puts to send to worker
        from_worker_queue = (
            interpreters.create_queue()
        )  # Main gets to receive from worker

        self.channels[name] = {
            "to_worker_queue": to_worker_queue,
            "from_worker_queue": from_worker_queue,
        }

        self.interpreters[name] = {
            "interp_obj": interp,
            "region": region_config,
            "peer_region": peer_region_config,
            "to_main_queue": from_worker_queue,  # Worker puts to this (send to main)
            "from_main_queue": to_worker_queue,  # Worker gets from this (recv from main)
            "thread": None,  # To hold the thread object
        }
        logger.info(f"Interpreter '{name}' created with ID: {interp.id}")
        return interp

    def start_worker(self, name: str, peer_name: str):
        if name not in self.interpreters:
            raise ValueError(f"Interpreter '{name}' not found.")
        if peer_name not in self.interpreters:
            raise ValueError(f"Peer interpreter '{peer_name}' not found.")

        interp_data = self.interpreters[name]
        peer_interp_data = self.interpreters[peer_name]

        region_start, region_end = interp_data["region"]
        region_len = region_end - region_start
        peer_start, peer_end = peer_interp_data["region"]
        peer_len = peer_end - peer_start

        to_main_queue = interp_data["to_main_queue"]
        from_main_queue = interp_data["from_main_queue"]

        # Assuming call_in_thread is available; otherwise, use exec in a thread
        thread = interp_data["interp_obj"].call_in_thread(
            sub_interpreter_worker,
            name,  # worker_id
            region_start,
            region_len,
            peer_start,
            peer_len,
            self.buf_addr,
            to_main_queue,
            from_main_queue,
        )
        interp_data["thread"] = thread
        logger.info(
            f"Worker '{name}' started in a new thread for interpreter ID: {interp_data['interp_obj'].id}"
        )
        return thread

    def wait_for_completion(self, timeout: float = 10.0):
        # Wait for all worker threads to complete
        for name, data in self.interpreters.items():
            if data["thread"]:
                logger.info(f"Waiting for worker '{name}' to complete...")
                data["thread"].join(timeout=timeout)
                if data["thread"].is_alive():
                    logger.warning(
                        f"Worker '{name}' did not complete within {timeout} seconds."
                    )
                else:
                    logger.info(f"Worker '{name}' thread finished.")

    def close_all(self):
        for name, data in self.interpreters.items():
            interp = data["interp_obj"]
            if interp.is_running():
                logger.warning(f"Interpreter '{name}' is still running. Cannot close.")
            else:
                interp.close()
                logger.info(f"Interpreter '{name}' (ID: {interp.id}) closed.")
        self.buf.close()
        logger.info("Shared memory buffer closed.")

    def get_region_data(self, name: str):
        if name not in self.interpreters:
            raise ValueError(f"Interpreter '{name}' not found.")
        region_start, region_end = self.interpreters[name]["region"]
        region_len = region_end - region_start
        return (ctypes.c_char * region_len).from_buffer(self.buf, region_start)


if __name__ == "__main__":
    logger.info("Starting main application.")

    # Example of using AST to inspect code of any Universe-object
    tree = ast.parse(open(__file__).read())
    logger.info(
        f"Defined functions in main script: {[n.name for n in tree.body if isinstance(n, ast.FunctionDef)]}"
    )

    manager = SubInterpreterManager()
    manager.create_managed_interpreter("A", REGION_A, REGION_B)
    manager.create_managed_interpreter("B", REGION_B, REGION_A)
    # Start workers in their respective interpreters
    thread_a = manager.start_worker("A", "B")
    thread_b = manager.start_worker("B", "A")
    # --- Orchestrate communication between workers via main interpreter ---
    # First, receive the work (sent assuming DH verification)
    work_a = manager.channels["A"]["from_worker_queue"].get(timeout=5)
    if isinstance(work_a, dict) and work_a.get("type") == "WORK":
        logger.info(
            f"Main: Received work from A: msg={work_a['msg'].decode('utf-8', errors='ignore')}, code_hash={work_a['code_hash'].hex()}"
        )
    else:
        logger.error(f"Main: Unexpected message from A: {work_a}")

    work_b = manager.channels["B"]["from_worker_queue"].get(timeout=5)
    if isinstance(work_b, dict) and work_b.get("type") == "WORK":
        logger.info(
            f"Main: Received work from B: msg={work_b['msg'].decode('utf-8', errors='ignore')}, code_hash={work_b['code_hash'].hex()}"
        )
    else:
        logger.error(f"Main: Unexpected message from B: {work_b}")

    # Now, receive public keys
    pub_a_msg = manager.channels["A"]["from_worker_queue"].get(timeout=5)
    if isinstance(pub_a_msg, dict) and pub_a_msg.get("type") == "PUBKEY":
        pub_a = pub_a_msg["pub"]
        logger.info("Main: Received public key from A.")
    else:
        logger.error(f"Main: Unexpected pub message from A: {pub_a_msg}")

    pub_b_msg = manager.channels["B"]["from_worker_queue"].get(timeout=5)
    if isinstance(pub_b_msg, dict) and pub_b_msg.get("type") == "PUBKEY":
        pub_b = pub_b_msg["pub"]
        logger.info("Main: Received public key from B.")
    else:
        logger.error(f"Main: Unexpected pub message from B: {pub_b_msg}")

    # Forward public keys
    if "pub_a" in locals() and "pub_b" in locals():
        manager.channels["A"]["to_worker_queue"].put(pub_b)
        logger.info("Main: Forwarded B's public key to A.")
        manager.channels["B"]["to_worker_queue"].put(pub_a)
        logger.info("Main: Forwarded A's public key to B.")

    # Receive lazy DH packages
    dh_a = manager.channels["A"]["from_worker_queue"].get(timeout=5)
    if isinstance(dh_a, dict) and dh_a.get("type") == "DH_PACKAGE":
        mac_a = dh_a["mac"]
        key_a = dh_a["key"]
        logger.info(
            f"Main: Received DH package from A: mac={mac_a.hex()}, key={key_a.hex()}"
        )
    else:
        logger.error(f"Main: Unexpected DH package from A: {dh_a}")

    dh_b = manager.channels["B"]["from_worker_queue"].get(timeout=5)
    if isinstance(dh_b, dict) and dh_b.get("type") == "DH_PACKAGE":
        mac_b = dh_b["mac"]
        key_b = dh_b["key"]
        logger.info(
            f"Main: Received DH package from B: mac={mac_b.hex()}, key={key_b.hex()}"
        )
    else:
        logger.error(f"Main: Unexpected DH package from B: {dh_b}")

    # Perform lazy verification
    if "key_a" in locals() and "key_b" in locals():
        if key_a == key_b:
            logger.info("Main: Keys from A and B match.")
            # Verify A's work
            computed_mac_a = hmac.new(key_a, work_a["msg"], hashlib.sha256).digest()
            if computed_mac_a == mac_a:
                logger.info("Main: Lazy verification of A's work passed.")
            else:
                logger.error("Main: Lazy verification of A's work failed.")
            # Verify B's work
            computed_mac_b = hmac.new(key_b, work_b["msg"], hashlib.sha256).digest()
            if computed_mac_b == mac_b:
                logger.info("Main: Lazy verification of B's work passed.")
            else:
                logger.error("Main: Lazy verification of B's work failed.")
        else:
            logger.error("Main: Keys from A and B do not match.")

    # Wait for both workers to signal completion
    logger.info("Main: Waiting for workers to signal WORK_DONE...")
    worker_a_status = manager.channels["A"]["from_worker_queue"].get(timeout=10)
    worker_b_status = manager.channels["B"]["from_worker_queue"].get(timeout=10)

    if worker_a_status == "WORK_DONE":
        logger.info("Main: Worker A reported WORK_DONE.")
    else:
        logger.error(f"Main: Worker A reported: {worker_a_status}")

    if worker_b_status == "WORK_DONE":
        logger.info("Main: Worker B reported WORK_DONE.")
    else:
        logger.error(f"Main: Worker B reported: {worker_b_status}")

    # Cleanup (workers will be garbage collected after close)
    manager.wait_for_completion()
    manager.close_all()
    logger.info("Application finished.")

# =(no-affiliation):======================================= (SmallTalk ©Xerox)=|
# ==========================================================(Squeak ©SqueakJS)=|
# ======================================================(Pharo ©Pharo Project)=|
#   ███████╗███╗   ███╗ █████╗ ██╗     ██╗  ████████╗ █████╗ ██╗     ██╗  ██╗  |
#   ██╔════╝████╗ ████║██╔══██╗██║     ██║  ╚══██╔══╝██╔══██╗██║     ██║ ██╔╝  |
#   ███████╗██╔████╔██║███████║██║     ██║     ██║   ███████║██║     █████╔╝   |
#   ╚════██║██║╚██╔╝██║██╔══██║██║     ██║     ██║   ██╔══██║██║     ██╔═██╗   |
#   ███████║██║ ╚═╝ ██║██║  ██║███████╗███████╗██║   ██║  ██║███████╗██║  ██╗  |
#   ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝  |
#                            BOUNDARY CROSSED:                                 |
#  Below this line: LIVING OBJECTS, VISUAL WORKSPACE, SELF-MODIFYING GUI;      |
# ==============('TOU(s) and LICENSE(s) are distributed alongside this 'file')=|
#  Assuming you have read and understood the TOU(s) and LICENSE(s), included:  |
#                                                                              |
#  Your IDE, LSP, debugger, REPL, Server and runtime are all the same thing!   |
#                                                                              |
#  The code above can introspect and modify everything below.                  |
#  The code below can render and manipulate everything above.                  |
#                                                                              |
#  This is not a "file", not logic; it is Morphological Source Code©™;         |
#  You are engaged in the programming of a morphism, and with respect to       |
#  groups; your 'sets' are emergent, topological, and quantized.               |
#                                                                              |
#  **DISCLAIMER**                                                              |
#  All runtimes, 'Quines' (derivatives), and distributions are subject to      |
#  "Morphological Source Code"©™ (patent pending) 'TOU' &'LICENSE' (CCBY ND)   |
#                                                                              |
# ===============================================================(pre-release)=|

# /* EndApp
# Morphism = [
# None
# ]
