import subprocess
from enum import Enum, auto


# ------------ Utils ------------

def big_power_modulo(number: int, power: int, modulo: int) -> int:
    """Calculates modulo of a number raised to a certain power"""
    result = 1

    number %= modulo

    while power > 0:
        result = (result * number) % modulo if power % 2 == 1 else result

        number = (number * number) % modulo

        power //= 2

    return result


def discover_tailscale_addresses() -> dict[str, str]:
    """
    Discovers all active devices in the Tailscale VPN using the Tailscale CLI.

    Returns:
        dict[str, str]: A dictionary containing hostname and IP addresses.
    """

    result = subprocess.run(
        ["tailscale", "status"],
        capture_output=True,
        text=True,
        check=True
    )

    data = str(result.stdout)
    users = data.split('\n')[:-1]   # remove the last \n

    user_data = {}

    for user in users:
        ip_address, hostname = user.split()[0:2]
        user_data[hostname] = ip_address

    return user_data


# TODO: - create file fragmenting-reconstruct method


def pack_text_message(payload: bytearray):
    return bytearray("TEXT_MSG\n\r".encode()) + payload


def pack_key_gen_message(public_key: int) -> bytearray:
    return bytearray(f"KEY_GEN\n\r{public_key}".encode())


def pack_file_block_message(payload: bytearray, block_number: int, file_size: int) -> bytearray:
    return bytearray(f"FILE_BLOCK\n\r{block_number}\n\r{file_size}\n\r".encode()) + payload


def unpack_message(message: bytearray) -> dict | None:

    parts = message.split(b"\n\r")

    match parts[0]:
        case b'TEXT_MSG':
            return {'type': 'TEXT_MSG', 'payload': parts[1]}
        case b'KEY_GEN':
            return {'type': 'KEY_GEN', 'public_key': int(parts[1])}
        case b'FILE_BLOCK':
            return {'type': 'FILE_BLOCK', 'block_number': int(parts[1]), 'file_size': int(parts[2]), 'payload': parts[3]}
        case _:
            return None


if __name__ == "__main__":
    # print(big_power_modulo(512345000000000000000000000000000000000000000000000000000000, 1000000000000001, 23))
    # print(big_power_modulo(289, 11, 1363))
    # print(big_power_modulo(2, 1, 11))

    # print(discover_tailscale_addresses())
    # for device in devices:
    #     print(f"Host: {device['hostname']}, IPs: {', '.join(device['addresses'])}, Online: {device['online']}")

    def test_message_packing():
        # Test TEXT_MSG
        payload = bytearray("Hello, World!".encode())
        packed_text = pack_text_message(payload)
        print("Packed TEXT_MSG:", packed_text)

        unpacked_text = unpack_message(packed_text)
        print("Unpacked TEXT_MSG:", unpacked_text)

        # Test KEY_GEN
        public_key = 123456789
        packed_key = pack_key_gen_message(public_key)
        print("\nPacked KEY_GEN:", packed_key)

        unpacked_key = unpack_message(packed_key)
        print("Unpacked KEY_GEN:", unpacked_key)

        # Test FILE_BLOCK
        file_payload = bytearray(b"Test file data block")
        block_number = 1
        file_size = len(file_payload)
        packed_block = pack_file_block_message(file_payload, block_number, file_size)
        print("\nPacked FILE_BLOCK:", packed_block)

        unpacked_block = unpack_message(packed_block)
        print("Unpacked FILE_BLOCK:", unpacked_block)


    # Run the test
    test_message_packing()



