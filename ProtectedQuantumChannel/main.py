import cirq
from random import choices

def QKD_with_decoy_and_superposition(num_bits, num_decoy_bits):
    """
    Quantum Key Distribution (QKD) protocol with decoy states and superposition.

    Args:
    - num_bits (int): Number of regular qubits.
    - num_decoy_bits (int): Number of decoy states.

    Returns:
    - Tuple or None: Tuple containing Alice's and Bob's final keys if successful, otherwise None.
    """
    # Setup
    encode_gates = {0: cirq.I, 1: cirq.X}
    basis_gates = {'Z': cirq.I, 'X': cirq.H}

    qubits = cirq.NamedQubit.range(num_bits + num_decoy_bits, prefix='q')

    # Alice Chooses Bits and Bases
    alice_key = choices([0, 1], k=num_bits)
    alice_bases = choices(['Z', 'X'], k=num_bits)

    # Alice Creates Qubits including decoy states
    alice_circuit = cirq.Circuit()

    for bit in range(num_bits + num_decoy_bits):
        if bit < num_bits:  # Regular qubits
            encode_value = alice_key[bit]
            encode_gate = encode_gates[encode_value]

            basis_value = alice_bases[bit]
            basis_gate = basis_gates[basis_value]

            qubit = qubits[bit]
            alice_circuit.append(encode_gate(qubit))
            alice_circuit.append(basis_gate(qubit))
        else:  # Decoy states
            encode_value = choices([0, 1], k=1)[0]
            encode_gate = encode_gates[encode_value]

            basis_value = choices(['Z', 'X'], k=1)[0]
            basis_gate = basis_gates[basis_value]

            qubit = qubits[bit]
            alice_circuit.append(encode_gate(qubit))
            alice_circuit.append(basis_gate(qubit))

    # Apply superposition to decoy qubits
    for bit in range(num_bits, num_bits + num_decoy_bits):
        alice_circuit.append(cirq.H(qubits[bit]))  # Apply Hadamard gate for superposition

    # Bob chooses Bases
    bob_bases = choices(['Z', 'X'], k=num_bits + num_decoy_bits)

    bob_circuit = cirq.Circuit()

    for bit in range(num_bits + num_decoy_bits):
        basis_value = bob_bases[bit]
        basis_gate = basis_gates[basis_value]

        qubit = qubits[bit]
        bob_circuit.append(basis_gate(qubit))

    # Bob Measures Qubits
    bob_circuit.append(cirq.measure(qubits, key='bob_key'))

    # Bob Creates a Key
    bb84_circuit = alice_circuit + bob_circuit

    sim = cirq.Simulator()
    results = sim.run(bb84_circuit)
    bob_key = results.measurements['bob_key'][0]

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

        return final_alice_key, final_bob_key  # Return the keys if successful

    else:
        return None, None  # Return None if keys cannot be established

def encrypt(message, key):
    """
    Encrypts a message using XOR encryption with a given key.

    Args:
    - message (str): The message to be encrypted.
    - key (list): The key for encryption.

    Returns:
    - str: The encrypted message.
    """
    # Convert message to binary
    binary_message = ''.join(format(ord(char), '08b') for char in message)
    
    # XOR encryption with key
    encrypted_message = ''.join(str(int(binary_message[i]) ^ key[i % len(key)]) for i in range(len(binary_message)))
    
    return encrypted_message

def decrypt(encrypted_message, key):
    """
    Decrypts a message using XOR decryption with a given key.

    Args:
    - encrypted_message (str): The encrypted message.
    - key (list): The key for decryption.

    Returns:
    - str: The decrypted message.
    """
    # XOR decryption with key
    decrypted_message = ''.join(str(int(encrypted_message[i]) ^ key[i % len(key)]) for i in range(len(encrypted_message)))
    
    # Convert binary to ASCII
    decrypted_text = ''.join(chr(int(decrypted_message[i:i+8], 2)) for i in range(0, len(decrypted_message), 8))
    
    return decrypted_text

def error_rate(alice_key, bob_key):
    """
    Calculates the error rate between Alice's and Bob's keys.

    Args:
    - alice_key (list): Alice's key.
    - bob_key (list): Bob's key.

    Returns:
    - float: The error rate between Alice's and Bob's keys.
    """
    # Calculate the error rate between Alice and Bob's keys
    num_errors = sum(1 for alice_bit, bob_bit in zip(alice_key, bob_key) if alice_bit != bob_bit)
    return num_errors / len(alice_key)

def test_with_and_without_eavesdropper(num_bits, num_decoy_bits, error_threshold=0.1):
    """
    Tests the QKD protocol with and without an eavesdropper.

    Args:
    - num_bits (int): Number of regular qubits.
    - num_decoy_bits (int): Number of decoy states.
    - error_threshold (float): Maximum allowable error rate.

    Returns:
    - None
    """
    # Test without eavesdropper
    print("Testing without eavesdropper:")
    alice_key, bob_key = QKD_with_decoy_and_superposition(num_bits, num_decoy_bits)
    if alice_key and bob_key:
        print("Key exchange successful. Alice and Bob established a secure key.")

        # Calculate error rate
        err_rate = error_rate(alice_key, bob_key)
        print("Error rate between Alice and Bob's keys:", err_rate)

        if err_rate <= error_threshold:
            print("No eavesdropper detected. Error rate is within threshold.")

            # Encrypt and Decrypt
            message = "Hello, world!"
            print("Original Message:", message)

            encrypted_message = encrypt(message, alice_key)
            print("Encrypted Message:", encrypted_message)

            decrypted_message = decrypt(encrypted_message, bob_key)
            print("Decrypted Message:", decrypted_message)
        else:
            print("Eavesdropper detected. Error rate exceeds threshold.")

    else:
        print("Key exchange failed. Unable to establish a secure key.")

    print("\nTesting with eavesdropper:")
    alice_key, eavesdropper_key = QKD_with_decoy_and_superposition(num_bits, num_decoy_bits)
    if alice_key and eavesdropper_key:
        print("Eavesdropper detected. They have different keys.")
    else:
        print("Unable to detect the eavesdropper. Alice and the eavesdropper may have the same key.")

# Parameters
num_bits = 10  # Number of regular qubits
num_decoy_bits = 5  # Number of decoy states

# Test the QKD protocol with and without an eavesdropper
test_with_and_without_eavesdropper(num_bits, num_decoy_bits)
