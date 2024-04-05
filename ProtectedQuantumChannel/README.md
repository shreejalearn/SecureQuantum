A more complex QDK and detection algorithm. This is taking advantage of the quantum principle of superposition.

Encoding the Message: The sender begins by encoding the message into qubits using quantum gates. One common technique is to use the BB84 protocol. In BB84, the sender randomly selects a basis (either the rectilinear or diagonal basis) for each qubit and applies the appropriate encoding. For example, a qubit might be encoded as |0⟩ or |1⟩ in the rectilinear basis, or as |+⟩ or |−⟩ in the diagonal basis. The sender keeps track of the basis used for each qubit but does not reveal this information to the receiver.

Transmission: The encoded qubits are then sent over a communication channel to the receiver. It's important to note that this channel could be susceptible to eavesdropping, where an unauthorized party might intercept the qubits to gain information about the encoded message.

Eavesdropping Detection: To detect any potential eavesdropping, the sender and receiver engage in a process known as "key reconciliation" through a public channel. In this process, they compare a subset of the qubits they both received. If no eavesdropping occurred, these qubits should be in the same basis. If discrepancies are found, it indicates potential eavesdropping. In such cases, the sender and receiver discard the affected qubits and abort the communication.

Decryption: Once the sender and receiver are confident that no eavesdropping has occurred, the receiver proceeds with decryption. The receiver randomly chooses a basis (rectilinear or diagonal) for each qubit and measures it accordingly. The receiver then shares the basis information publicly with the sender.

Applying Scrambling for Decryption: Here's where the receiver knows what scrambling to apply for decryption. The receiver compares the basis information shared by the sender with the basis they initially used for encoding. If the sender and receiver used the same basis for a particular qubit, the receiver does not need to apply any additional scrambling. However, if they used different bases, the receiver applies the appropriate quantum gates to transform the qubit back to its original state.

Extracting the Message: After applying the necessary operations, the receiver obtains the qubits in their original state. By measuring these qubits, the receiver can extract the original message sent by the sender.

- Another key note as to why this works is because once a qubit is measured, it can't be returned to superposition again, making it useless for the hacker to actually do anything with the public communication channel sharing bitwise operations and their corresponding results.
