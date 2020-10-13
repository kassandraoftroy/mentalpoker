from ecdsa import curves, keys
from .utils import *
import binascii

# Default crypto parameters for elliptic are the curve SECP256k1
# Any other curves from the ecdsa package should work out of the box
DEFAULT_CURVE = curves.SECP256k1

class ECPrivateKey:
	def __init__(self, alpha=None, curve=DEFAULT_CURVE):
		if alpha is None:
			self.alpha = randrange(2, curve.order)
		else:
			self.alpha = alpha
		self.curve = curve

	def unmask(self, point):
		return mod_inv(self.alpha, self.curve.order)*point

	def mask(self, point):
		return self.alpha*point

def point2hex(point, curve=DEFAULT_CURVE):
	vk = keys.VerifyingKey.from_public_point(point, curve=curve)
	return binascii.hexlify(vk.to_string()).decode()

def hex2point(hex_, curve=DEFAULT_CURVE):
	return keys.VerifyingKey.from_string(binascii.unhexlify(hex_), curve=curve).pubkey.point
