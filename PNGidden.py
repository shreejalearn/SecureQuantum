from time import strftime
from rich import print
import numpy as np
import PIL.Image
import sys
import os
import cirq
from random import choices

STOP_INDICATOR = "$###STOP###$"

def is_file_exists(file_path: str) -> bool:
    return os.path.isfile(file_path)


def is_file_png(file_path: str) -> bool:
    return file_path.endswith('.png')


def timestamp() -> str:
    return strftime("%H-%M-%S")


def get_png_path_from_user() -> str:
    is_file = False
    is_png = False
    while not is_file or not is_png:
        image_path = input("Enter image path -> ")
        is_file = is_file_exists(image_path)
        if not is_file:
            print("[bold red]Image path is invalid.")
        is_png = is_file_png(image_path)
        if not is_png:
            print("[bold red]The image is not a PNG file.")
    return image_path


def get_secret_message_from_user() -> str:
    secret_message = input("Enter your secret message -> ")
    while len(secret_message) == 0:
        secret_message = input("Message can not be empty... Try again -> ")

    return secret_message

def hide_message_in_image(image_path: str, message_to_hide: str, key) -> None:
    image = PIL.Image.open(image_path, 'r')
    width, height = image.size
    img_arr = np.array(list(image.getdata()))

    if image.mode == 'P':
        print("[bold red]Image not supported.")
        return
        
    channels = 4 if image.mode == 'RGBA' else 3
    pixels = img_arr.size // channels
    message_to_hide += STOP_INDICATOR
    encrypted_message = ''.join(chr(ord(message_char) ^ key_bit) for message_char, key_bit in zip(message_to_hide, key))

    byte_message = ''.join(f"{ord(c):08b}" for c in encrypted_message)
    print(f"Message to hide (in bits) :\n{byte_message}")
    bits = len(byte_message)

    if bits > pixels:
        print("[bold red]Not enough space to encode the message")
        return
    else:
        index = 0
        for i in range(pixels):
            for j in range(0, 3):
                if index < bits:
                    img_arr[i][j] = int(bin(img_arr[i][j])[2:-1] + byte_message[index], 2)
                    index += 1
    img_arr = img_arr.reshape((height, width, channels))
    result = PIL.Image.fromarray(img_arr.astype('uint8'), image.mode)
    encoded_image_path = f"encoded-{timestamp()}.png"
    result.save(encoded_image_path)
    print(
        f"[bold green]Successfully hidden the message inside the image!\n"
        f"New png file is -> {encoded_image_path}"
    )


def extract_message_from_image(image_path: str, key) -> None:    
    image = PIL.Image.open(image_path, 'r')
    img_arr = np.array(list(image.getdata()))
    channels = 4 if image.mode == 'RGBA' else 3
    pixels = img_arr.size // channels

    secret_bits = [bin(img_arr[i][j])[-1] for i in range(pixels) for j in range(0, 3)]
    secret_bits = ''.join(secret_bits)
    secret_bits = [secret_bits[i:i+8] for i in range(0, len(secret_bits), 8)]

    secret_message = ''.join(chr(int(secret_bits[i], 2)) for i in range(len(secret_bits)))

    # XOR each character of the secret message with the corresponding bit of the key again
    decrypted_message = ''.join(chr(ord(message_char) ^ key_bit) for message_char, key_bit in zip(secret_message, key))

    if STOP_INDICATOR in decrypted_message:
        print(
            f"\n[bold green]Decrypted Message ->\n"
            f"{decrypted_message[:decrypted_message.index(STOP_INDICATOR)]}\n"
        )
    else:
        print("[bold yellow]Could not find secret message")


def print_title() -> None:
    print(
        "[bold green]"
        " ____  _   _  ____ _     _     _\n\n"
        "Super Secret Messages"
        "\n  [italic green]____  _   _  ____ _     _     _\n"
    )


def run_TUI(alice_key, bob_key) -> None:
    options = ["Exit (or Ctrl+C anytime)", "Hide message in image", "Extract message from image"]
    print_options = ''
    for index in range(len(options)):
        print_options += f"[bold green][{index}] [cyan]{options[index]}\n"
    print((f"[bold magenta]Enter your choice:\n\n{print_options}"))

    user_choice = str(input().strip())

    if user_choice == '0':
        print("[bold cyan]Aborting Mission.")
        sys.exit()
    elif user_choice == '1':
        hide_message_in_image(get_png_path_from_user(), get_secret_message_from_user(), alice_key)
    elif user_choice == '2':
        extract_message_from_image(get_png_path_from_user(), bob_key)
    else:
        print("[bold red]Invalid option. Abort.")
        sys.exit()


def run_pngidden():
    try:
        print_title()

        # Generate QKD keys once
        num_bits = 64
        alice_key, bob_key = QKD(num_bits)

        while True:
            run_TUI(alice_key, bob_key)
    except KeyboardInterrupt:
        print("[bold red]\nStopped.")
    except ModuleNotFoundError:
        print("[bold red]\nMissing one of the pip packages.\nPlease run setup.py")
    except Exception:
        print("[bold red]\nError occurred.")


# Quantum Key Distribution (QKD) functions
def QKD(num_bits):
    # Setup
    encode_gates = {0: cirq.I, 1: cirq.X}
    basis_gates = {'Z': cirq.I, 'X': cirq.H}

    qubits = cirq.NamedQubit.range(num_bits, prefix='q')

    # Alice Chooses Bits and Bases
    alice_key = choices([0, 1], k=num_bits)
    alice_bases = choices(['Z', 'X'], k=num_bits)

    # Alice Creates Qubits
    alice_circuit = cirq.Circuit()

    for bit in range(num_bits):

        encode_value = alice_key[bit]
        encode_gate = encode_gates[encode_value]

        basis_value = alice_bases[bit]
        basis_gate = basis_gates[basis_value]

        qubit = qubits[bit]
        alice_circuit.append(encode_gate(qubit))
        alice_circuit.append(basis_gate(qubit))

    # Bob chooses a Bases
    bob_bases = choices(['Z', 'X'], k=num_bits)

    bob_circuit = cirq.Circuit()

    for bit in range(num_bits):

        basis_value = bob_bases[bit]
        basis_gate = basis_gates[basis_value]

        qubit = qubits[bit]
        bob_circuit.append(basis_gate(qubit))

    # Bob Measures Qubits
    bob_circuit.append(cirq.measure(qubits, key='bob key'))

    # Bob Creates a Key
    bb84_circuit = alice_circuit + bob_circuit

    sim = cirq.Simulator()
    results = sim.run(bb84_circuit)
    bob_key = results.measurements['bob key'][0]

    final_alice_key = []
    final_bob_key = []

    # Compare Bases
    for bit in range(num_bits):

        if alice_bases[bit] == bob_bases[bit]:
            final_alice_key.append(alice_key[bit])
            final_bob_key.append(bob_key[bit])

    # Compare Half their Bits
    num_bits_to_compare = int(len(final_alice_key) * .5)
    if final_alice_key[0:num_bits_to_compare] == final_bob_key[0:num_bits_to_compare]:
        final_alice_key = final_alice_key[num_bits_to_compare:]
        final_bob_key = final_bob_key[num_bits_to_compare:]

        return final_alice_key, final_bob_key

    else:
        return None, None


if __name__ == '__main__':
    run_pngidden()
