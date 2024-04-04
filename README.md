# Steganography + QDK - PNGidden

Hide text messages in PNG files using the LSB – least significant bit. Additionally, implementing Quantum Key Distribution for encryption.

In this way, we change the lowest bits in the image to be our message – and we’ll have an almost imperceptible change on the actual way the image looks. Through steganography, embedding secret messages within images alongside Quantum encryption, we allow for secure and inconspicuous channel for sending information. This is a simple POC, but hopefully exciting due to possible future implementations (ie: further implementation of the BB84 QDK algorithm, etc.). This helped me understand cryptography and quantum communication principles through a practical example.

# Future Use Cases

Data Concealment: LSB steganography can be used to conceal sensitive data within digital images. This can be useful in situations where data needs to be stored or transmitted inconspicuously, such as in espionage or confidential data transfer.

Digital Watermarking: This technique can be employed for digital watermarking, where information such as copyright notices or ownership details are embedded within images. This can help in tracking unauthorized use or distribution of digital assets.

- - - - - - - -

Secure Communication in Military: Military organizations often require secure communication methods to transmit sensitive information. This could be utilized to hide messages within images, providing an additional layer of security. Companies like Lockheed Martin or BAE Systems, which specialize in defense technology, might implement such systems.

Healthcare: Healthcare institutions deal with highly confidential patient data. This could be employed to hide patient information within medical images for secure transmission between hospitals or healthcare providers.

Finance: Financial institutions need secure methods to communicate sensitive financial data and trade secrets. This could be used to hide messages within images, ensuring confidentiality during regular communication like a logo footer in an email. 

Journalism and Whistleblower Protection: Journalists and whistleblowers often need to securely communicate sensitive information without revealing their identities. This could provide a means to hide information within images, allowing for secure transmission to journalists or whistleblowing platforms. 

## PNG file structure

First 8 bytes:
```
89 50 4E 47 0D 0A 1A 0A               |   PNG File Signature
```
Last 12 bytes:
```
00 00 00 00 49 45 4e 44 ae 42 60 82   |   ....IEND.B`.|
```

### File Chunks

IHDR = Header

PLTE = Palette Table

IDAT = Image Data (Pixels)

IEND = End of file

## Setup & Requirements

* Install python 3.10.0 or upper from [here](https://www.python.org/)

* Make sure your version is 3.10.0 or upper
```
python --version
```

* Install pip prerequisites
```
pip install -r requirements.txt
```

* You can also run my setup file to verify everything works:
```
python setup.py
```

## Usage
* Windows 10/11:
```
python PNGidden.py
```

* Linux or Mac OS:
```
python3 PNGidden.py
``'
