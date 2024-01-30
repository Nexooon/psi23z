#Nazwa projektu: CyBORgi
#Autorzy pliku: Filip Browarny, Krzysztof Kluczyński, Hubert Brzóskniewicz, Kamil Kułak

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

class AuthenticationManager:
    def __init__(self) -> None:
        self.private_key = None
        self.public_key = None
        self.generete_key_pair()
    
    def get_public_key(self):
        return self.public_key

    def generete_key_pair(self):
        private_key = ec.generate_private_key(
            ec.SECP256R1(), default_backend()
        )
        public_key = private_key.public_key()

        self.private_key = private_key
        self.public_key = public_key
    
    def get_public_key_pem(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def sign_message(self, message):
        if isinstance(message, int):
            message = str(message)
        signature = self.private_key.sign(
            message.encode('utf-8'),
            ec.ECDSA(hashes.SHA256())
        )
        return signature
    
    def verify_signature(self, message, signature, public_key_bytes):
        public_key = serialization.load_pem_public_key(
            public_key_bytes, backend=default_backend()
        )
        try:
            if isinstance(message, int):
                message = str(message)
            public_key.verify(
                signature,
                message.encode('utf-8'),
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except Exception as e:
            print(f"Verification failed: {e}")
            return False
    