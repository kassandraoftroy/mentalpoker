from .utils import *

'''
	Extended Elgamal Encryption Suite
	Original Implementation By: superarius
	
	Universally re-encryptable, commutative ElGamal based cryptosystem. For scheme details see:
	http://groups.csail.mit.edu/cis/theses/weis-phd-thesis.pdf (p 71)

    Also includes:
	- Basic ElGamal Encryption
	- ElGamal variant of Shamir's Three-pass protocol (No Key Protocol)

	SECURITY NOTES: 
	1. Be sure to enforce matching quadratic residuostiy to all message encodings (for semantic security).
	2. The default parameter set P,G,Q are secure (as of 2019). Verify security of custom parameters.
'''

# Default 2048-bit safe prime P (from rfc 5114)
P = 0xAD107E1E9123A9D0D660FAA79559C51FA20D64E5683B9FD1B54B1597B61D0A75E6FA141DF95A56DBAF9A3C407BA1DF15EB3D688A309C180E1DE6B85A1274A0A66D3F8152AD6AC2129037C9EDEFDA4DF8D91E8FEF55B7394B7AD5B7D0B6C12207C9F98D11ED34DBF6C6BA0B2C8BBC27BE6A00E0A0B9C49708B3BF8A317091883681286130BC8985DB1602E714415D9330278273C7DE31EFDC7310F7121FD5A07415987D9ADC0A486DCDF93ACC44328387315D75E198C641A480CD86A1B9E587E8BE60E69CC928B2B9C52172E413042E9B23F10B0E16E79763C9B53DCF4BA80A29E3FB73C16B8E75B97EF363E2FFA31F71CF9DE5384E71B81C0AC4DFFE0C10E64F
G = 0xAC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF74866A08CFE4FFE3A6824A4E10B9A6F0DD921F01A70C4AFAAB739D7700C29F52C57DB17C620A8652BE5E9001A8D66AD7C17669101999024AF4D027275AC1348BB8A762D0521BC98AE247150422EA1ED409939D54DA7460CDB5F6C6B250717CBEF180EB34118E98D119529A45D6F834566E3025E316A330EFBB77A86F0C1AB15B051AE3D428C8F8ACB70A8137150B8EEB10E183EDD19963DDD9E263E4770589EF6AA21E7F5F2FF381B539CCE3409D13CD566AFBB48D6C019181E1BCFE94B30269EDFE72FE9B6AA4BD7B5A0F1C71CFFF4C19C418E1F6EC017981BC087F2A7065B384B890D3191F2BFA
Q = 0x801C0D34C58D93FE997177101F80535A4738CEBCBF389A99B36371EB
PUBLIC_PARAMS = [P,G,Q]

# ElGamal Public Key
class EGPublicKey:
	def __init__(self, beta, public_params=PUBLIC_PARAMS):
		self.beta = beta
		self.p, self.g, self.q = public_params

	def encrypt(self, message):
		k = randrange(1,self.q)
		if type(message) is not int:
			raise ValueError("Message must be encoded as an integer")
		c1 = pow(self.g, k, self.p) 
		c2 = pow(self.beta, k, self.p)*message%self.p
		return c1, c2

	def commutative_encrypt(self, message):
		if type(message) is int:
			c2, c1 = self.encrypt(message)
			c4, c3 = self.encrypt(1)
			return [((c1, c2), (c3, c4))]
		else:
			rs = [randrange(1,self.q) for _ in range(len(message))]
			r_last = mod_inv(prod(rs)%self.p, self.p)
			cs = self.commutative_encrypt(r_last)
			for i in range(len(rs)):
				cs.append(self.universal_reencrypt(((rs[i]*message[i][0][0], message[i][0][1]), message[i][1])))
			shuffle(cs)
			return cs

	def universal_reencrypt(self, ciphertext):
		t = randrange(1,self.q)
		u = randrange(1,self.q)
		c1 = (ciphertext[0][0]*pow(ciphertext[1][0], t, self.p)%self.p, ciphertext[0][1]*pow(ciphertext[1][1], t, self.p)%self.p)
		c2 = (pow(ciphertext[1][0], u, self.p), pow(ciphertext[1][1], u, self.p))
		return (c1, c2)


# ElGamal Private Key
class EGPrivateKey:
	def __init__(self, alpha=None, public_params=PUBLIC_PARAMS):
		p,g,q = public_params
		if alpha is None:
			self.alpha = randrange(1,q)
		elif type(alpha) is not int or alpha>=q:
			raise ValueError("Cannot restore private key, not an integer in valid range")
		else:
			self.alpha = alpha
		beta = pow(g, self.alpha, p)
		self.pub = EGPublicKey(beta, public_params)

	def encrypt(self, message):
		return self.pub.encrypt(message)

	def decrypt(self, ciphertext):
		c1,c2 = ciphertext
		return mod_inv(pow(c1, self.alpha, self.pub.p), self.pub.p)*c2%self.pub.p

	def commutative_encrypt(self, message):
		return self.pub.commutative_encrypt(message)

	def commutative_decrypt(self, ciphertext):
		if len(ciphertext) > 1:
			result_cipher = []
			for j in range(len(ciphertext)):
				if mod_inv(pow(ciphertext[j][1][1], self.alpha, self.pub.p), self.pub.p)*ciphertext[j][1][0]%self.pub.p == 1:
					val = mod_inv(pow(ciphertext[j][0][1], self.alpha, self.pub.p), self.pub.p)*ciphertext[j][0][0]%self.pub.p
					if len(ciphertext) > 2:
						rs = [randrange(1, self.pub.q) for _ in range(len(ciphertext)-2)]
						rs.append(mod_inv(prod(rs)%self.pub.p, self.pub.p)*val%self.pub.p)
					else:
						rs = [val,]
					rs.insert(j, None)
					for i in range(len(ciphertext)):
						if i != j:
							result_cipher.append(self.pub.universal_reencrypt(((ciphertext[i][0][0]*rs[i]%self.pub.p, ciphertext[i][0][1]), ciphertext[i][1])))
			if len(result_cipher) == 0:
				raise ValueError("Private Key does not correlate to this ciphertext")
			shuffle(result_cipher)
			return result_cipher
		elif len(ciphertext) == 1 and mod_inv(pow(ciphertext[0][1][1], self.alpha, self.pub.p), self.pub.p)*ciphertext[0][1][0]%self.pub.p == 1:
			return mod_inv(pow(ciphertext[0][0][1], self.alpha, self.pub.p), self.pub.p)*ciphertext[0][0][0]%self.pub.p
		else:
			raise ValueError("Private Key does not correlate to this ciphertext")

	def three_pass_reencrypt(self, ciphertext, neighbor_beta):
		c1,c2=ciphertext
		k = randrange(1,self.pub.q)
		z1=c1*pow(self.pub.g, k, self.pub.p)%self.pub.p
		z2=pow(z1, self.alpha, self.pub.p)*pow(neighbor_beta, k, self.pub.p)*c2%self.pub.p
		return z1, z2

	def three_pass_redecrypt(self, ciphertext, neighbor_beta):
		c1,c2=ciphertext
		k = randrange(1, self.pub.q)
		z1=c1*pow(self.pub.g, k, self.pub.p)%self.pub.p
		z2=mod_inv(pow(c1, self.alpha, self.pub.p), self.pub.p)*pow(neighbor_beta, k, self.pub.p)*c2%self.pub.p
		return z1,z2

	def public_key(self):
		return self.pub
