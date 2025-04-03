import subprocess


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
        list[dict]: A list of dictionaries containing hostname and IP addresses.
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


if __name__ == "__main__":
    # print(big_power_modulo(512345000000000000000000000000000000000000000000000000000000, 1000000000000001, 23))
    # print(big_power_modulo(289, 11, 1363))
    # print(big_power_modulo(2, 1, 11))

    print(discover_tailscale_addresses())
    # for device in devices:
    #     print(f"Host: {device['hostname']}, IPs: {', '.join(device['addresses'])}, Online: {device['online']}")


