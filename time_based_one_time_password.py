#!/usr/bin/python3

from datetime import datetime
from time import time, sleep
from hashlib import sha512
from pyblake2 import blake2b
from sys import exit, argv, stderr
from functools import reduce


def argv_or_default(index, default=None):
	try:
		return argv[index]

	except IndexError:
		return default


def date_to_seconds(dt):
	return (dt - epoch).total_seconds()


#config
change_key_every = 30 #seconds
_hash_len = 128
_pin_len = 6
default_rounds = 10
#/config

def time_for_key():
	if input_date is None:
		_time = time()

	else:
		_time = seconds_input_date

	str_date = datetime\
			.strftime(datetime.utcfromtimestamp(_time), date_format)

	return str(int(_time / change_key_every)), str_date


def hmac_hex(key, message):
	_hmac = b''
	counter = 1

	def _make_hmac(key, message, _hmac):
		return sha512(
			key + _hmac + blake2b(key + _hmac + message).digest()
		)

	while counter < rounds:
		_hmac = _make_hmac(key, message, _hmac).digest()
		counter += 1

	return _make_hmac(key, message, _hmac).hexdigest()


def secure_time_based_key(key, l=_hash_len):
	tfk, str_date = time_for_key()
	_hash = hmac_hex(key.encode(), tfk.encode())

	if l == _hash_len:
		return str_date, _hash

	if l > _hash_len:
		while len(_hash) < l:
			_hash += hmac_hex(key.encode(), _hash.encode())

	return str_date, _hash[:l]


def secure_time_based_pin(key, l=_pin_len):
	pin = ''

	str_date, key = secure_time_based_key(key)
	mult_divisor = 2000 / l

	def _reduce_hash(a, b):
		o_b = ord(b)
		multiplier = 1 + o_b / mult_divisor

		try:
			if int(a) > 1:
				return a * multiplier

		except (ValueError, TypeError):
			o_a = ord(a)
			if o_a > 10:
				return o_a * multiplier

		return ord(a) * multiplier

	pin = str(int(reduce(_reduce_hash, key)))[::-1]

	return str_date, pin[:l]


date_format = '%Y-%m-%dT%H:%M:%S'

if __name__ == '__main__':
	key = argv_or_default(1)

	if key is None:
		print('Key is required', file=stderr)
		exit(1)

	rounds = int(argv_or_default(2, default_rounds))

	input_date = argv_or_default(3)

	if input_date:
		epoch = datetime.utcfromtimestamp(0)
		input_date = datetime.strptime(input_date, date_format)
		seconds_input_date = date_to_seconds(input_date)

	print(secure_time_based_pin(key))
	print(secure_time_based_key(key))

else:
	rounds = default_rounds
	input_date = None