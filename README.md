# Mental Poker

### NOTE: This repo is intended for research purposes only and has not been audited. In fact, the implementation based on elliptic curve cryptography is NOT SECURE as implemented here. The ElGamal variant remains potentially sound however is not very practical in terms of computational overhead and more State of the Art, scalable approaches now exist, see: https://geometry.xyz/notebook/mental-poker-in-the-age-of-snarks-part-1


Mental Poker is the common name for a set of cryptographic problems that concerns playing a fair game over distance without the need for a trusted third party ([read more](https://en.wikipedia.org/wiki/Mental_poker))

This repository is a cryptographic toolbox written in python, for the basic operations of mental card games:

1. shuffling (randomizing the order of cards)
2. dealing (locking a shared order of unknown cards)
3. reavealing (opening unknown cards to one or all parties)

Using a universally re-encryptable commutative variant of ElGamal a set of parties at a distance can compute these "deck of cards" operations in a provably fair way.

*(how the parties communicate with each other, and the logic of any specific card game are outside the scope of this package)*

## Install

`pip install mentalpoker`

python >=3.6

## Usage

`from mentalpoker import DealerEG`

For the standard mental poker cryptographic operations use the `DealerEG` class.

Participating parties in a p2p card game should all implement a matching `Dealer` (same crypto parameters), since everyone participates in the dealing operations (in every single hand) to assure fairness. The basic scheme for preparing a deck for card game play without a trusted dealer involves passing the deck in a ring two times: starting with a new deck the first participant does a shuffle(), then passes the shuffled deck to the next player who also does a shuffle(), when the first participant receives the deck again they run deal(), and pass the output deck to the next player who also runs deal() etc. Once every party has run shuffle() and deal(), the final output deck is ready for play.

Here is a two party example:

```
>>> from mentalpoker import DealerEG
>>> dealerA = DealerEG()
>>> dealerB = DealerEG()
>>> deck = dealerA.new_deck // A takes a fresh deck of cards
>>> deck = dealerA.shuffle(deck) // A shuffles and encrypts the deck
>>> deck = dealerB.shuffle(deck) // B shuffles and encrypts the deck received from A
>>> deck = dealerA.deal(deck) // A "deals" the deck received from B, encrypting each individual card
>>> deck = dealerB.deal(deck) // B "re-deals" the deck received from A, also encrypting each individual card
>>> keys = [i.get_card_key(0) for i in (dealerA, dealerB)] // A and B share decryption keys for card 1
>>> dealerA.reveal_card(deck[0], keys) // either player can now view the first card
'Ah'
```

To reveal cards, everyone passes their decryption key for the card with that index in the deck. To make a card part of someones "hand", everyone reveals their decryption key only to one party who can then secretly see the card. If everyone broadcasts their decrpytion keys, then everyon can view the card at that index.

There is no limit on the number of players, though performance deteriorates worse with ElGamal cryptosystem as the number of players increases.

