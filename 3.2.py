import hashlib

def H(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

# ============================================================
# TODO 1: Merkle Root
# ============================================================

def merkle_root(leaves: list[bytes]) -> bytes:
    level = leaves[:]

    while len(level) > 1:

        # Nếu số node là số lẻ,
        # duplicate node cuối cùng
        if len(level) % 2 == 1:
            level.append(level[-1])

        next_level = []

        # Ghép từng cặp node
        for i in range(0, len(level), 2):
            parent = H(level[i] + level[i + 1])
            next_level.append(parent)

        level = next_level

    return level[0]


# ============================================================
# TODO 2: Merkle Proof
# ============================================================

def merkle_proof(
    leaves: list[bytes],
    index: int
) -> list[tuple[bytes, bool]]:

    proof = []
    level = leaves[:]

    while len(level) > 1:

        # Nếu số node là số lẻ,
        # duplicate node cuối cùng
        if len(level) % 2 == 1:
            level.append(level[-1])

        # Tìm sibling
        sibling_index = index ^ 1

        sibling = level[sibling_index]

        # True nếu sibling nằm bên trái
        sibling_is_left = sibling_index < index

        proof.append(
            (sibling, sibling_is_left)
        )

        # Tạo level tiếp theo
        next_level = []

        for i in range(0, len(level), 2):
            parent = H(level[i] + level[i + 1])
            next_level.append(parent)

        # Chuyển index lên node cha
        index //= 2

        level = next_level

    return proof


# ============================================================
# TODO 3: Verify Merkle Proof
# ============================================================

def verify_proof(
    leaf_hash: bytes,
    proof: list[tuple[bytes, bool]],
    root: bytes
) -> bool:

    current = leaf_hash

    for sibling, sibling_is_left in proof:

        if sibling_is_left:
            # Sibling nằm bên trái
            current = H(sibling + current)

        else:
            # Sibling nằm bên phải
            current = H(current + sibling)

    # So sánh root tính được với root ban đầu
    return current == root


# ============================================================
# CHECKS
# ============================================================

if __name__ == "__main__":

    txs = [
        f"tx{i}: A->B {i} coin".encode()
        for i in range(8)
    ]

    leaves = [
        H(t)
        for t in txs
    ]

    root = merkle_root(leaves)

    print("root:", root.hex())


    # CHECK 1
    ok = all(
        verify_proof(
            leaves[i],
            merkle_proof(leaves, i),
            root
        )
        for i in range(8)
    )

    print(
        "CHECK 1 (all 8 proofs valid):",
        "OK" if ok else "FAIL"
    )


    # CHECK 2
    print(
        "CHECK 2 (proof length == 3):",
        "OK"
        if len(merkle_proof(leaves, 4)) == 3
        else "FAIL"
    )


    # CHECK 3
    fake = H(
        b"tx4: A->B 999999 coin"
    )

    print(
        "CHECK 3 (tampered leaf fails):",
        "OK"
        if not verify_proof(
            fake,
            merkle_proof(leaves, 4),
            root
        )
        else "FAIL"
    )


    # CHECK 4
    l7 = leaves[:7]

    r7 = merkle_root(l7)

    print(
        "CHECK 4 (odd count works):",
        "OK"
        if all(
            verify_proof(
                l7[i],
                merkle_proof(l7, i),
                r7
            )
            for i in range(7)
        )
        else "FAIL"
    )