from .elgamal import *
from .elliptic import *
from .utils import *

CARDS = ['Ac', '2c', '3c', '4c', '5c', '6c', '7c', '8c', '9c', 'Tc', 'Jc', 'Qc', 'Kc', 'Ad', '2d', '3d', '4d', '5d', '6d', '7d', '8d', '9d', 'Td', 'Jd', 'Qd', 'Kd', 'Ah', '2h', '3h', '4h', '5h', '6h', '7h', '8h', '9h', 'Th', 'Jh', 'Qh', 'Kh', 'As', '2s', '3s', '4s', '5s', '6s', '7s', '8s', '9s', 'Ts', 'Js', 'Qs', 'Ks']

class DealerEC:
	def __init__(self, cards=CARDS, shuffle_key=None, curve=DEFAULT_CURVE):
		points = generate_points_from_curve(curve, len(cards))
		self.point_to_card = {points[i].x():cards[i] for i in range(len(cards))}
		self.new_deck = points
		self.curve = curve
		self.shuffle_key = shuffle_key
		if self.shuffle_key is None:
			self.shuffle_key = ECPrivateKey(curve=self.curve)
		self.decks = {}

	def shuffle(self, deck, refresh_key=True):
		if refresh_key:
			self.shuffle_key = ECPrivateKey(curve=self.curve)
		encrypted = [self.shuffle_key.mask(card) for card in deck]
		shuffle(encrypted)
		return encrypted

	def deal(self, deck, shuffle_locked=True, deck_id="temp"):
		if shuffle_locked:
			deck = [self.shuffle_key.unmask(card) for card in deck]
		keys = [ECPrivateKey(curve=self.curve) for _ in range(len(deck))]
		self.decks[deck_id] = keys
		return [keys[i].mask(deck[i]) for i in range(len(deck))]

	def reveal_card(self, card, keys):
		for key in keys:
			card = key.unmask(card)
		return self.point_to_card[card.x()]

	def get_card_key(self, index, deck_id="temp"):
		return self.get_deck_keys(deck_id)[index]

	def get_deck_keys(self, deck_id="temp"):
		return self.decks[deck_id]

RESIDUES = [2, 4, 5, 8, 9, 10, 11, 16, 17, 18, 20, 21, 22, 25, 29, 31, 32, 34, 36, 37, 39, 40, 41, 42, 44, 45, 49, 50, 53, 55, 57, 58, 61, 62, 64, 67, 68, 69, 71, 72, 73, 74, 78, 79, 80, 81, 82, 83, 84, 85, 88, 90]

class DealerEG:
	def __init__(self, cards=CARDS, shuffle_key=None, crypto_params=PUBLIC_PARAMS):
		if crypto_params == PUBLIC_PARAMS and len(cards)<=len(CARDS):
			residues = RESIDUES[:len(cards)]
		else:
			residues = generate_residues_from_params(crypto_params, len(cards))
		self.int_to_card={residues[i]:cards[i] for i in range(len(cards))}
		self.new_deck = residues
		self.crypto_params = crypto_params
		self.shuffle_key = shuffle_key
		if self.shuffle_key is None:
			self.shuffle_key = EGPrivateKey(public_params=self.crypto_params)
		self.decks = {}

	def shuffle(self, deck, refresh_key=False):
		if refresh_key:
			self.shuffle_key = EGPrivateKey(public_params=self.crypto_params)
		encrypted = [self.shuffle_key.commutative_encrypt(card) for card in deck]
		shuffle(encrypted)
		return encrypted

	def deal(self, deck, shuffle_locked=True, deck_id="temp"):
		if shuffle_locked:
			deck = self.remove_shuffle_lock(deck)
		keys = [EGPrivateKey(public_params=self.crypto_params) for _ in range(len(deck))]
		self.decks[deck_id] = keys
		return [keys[i].commutative_encrypt(deck[i]) for i in range(len(deck))]

	def reveal_card(self, card, keys):
		value = [*card]
		for key in keys:
			value = key.commutative_decrypt(value)
		if type(value) is not int:
			raise ValueError("Provided keys not able to fully decrypt card")
		return self.int_to_card[value]

	def remove_shuffle_lock(self, deck):
		return [self.shuffle_key.commutative_decrypt(card) for card in deck]

	def get_card_key(self, index, deck_id="temp"):
		return self.get_deck_keys(deck_id)[index]

	def get_deck_keys(self, deck_id="temp"):
		return self.decks[deck_id]

def generate_points_from_curve(curve, n):
	return [i*curve.generator for i in range(1,n+1)]

def generate_residues_from_params(crypto_params, n):
	sk = EGPrivateKey(public_params=crypto_params)
	i = 2
	residues = []
	p = crypto_params[0]
	exp = (p - 1)//2
	while len(residues) < n:
		c = sk.encrypt(i)
		if pow(c[0], exp, p) == 1:
			residues.append(i)
		i += 1
	return residues
