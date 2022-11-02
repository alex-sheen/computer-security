from pymd5 import md5, padding
msg1 = b"Nobody inspects"
msg2 = b" the spammish repetition"

# We will compute the hash of msg3 below, without knowing msg1. Note the
# padding, which is unnatural but necessary for the attack.
msg3 = msg1 + padding(len(msg1)*8) + msg2
h = md5()
h.update(msg3)
print(h.hexdigest())

# Here we compute the digest of the first string only; padding is applied
# internally.
h = md5()
h.update(msg1)
s1 = h.hexdigest()

# This is the length extension attack. It only needs the first digest and msg2,
# but msg1. It should compute the digest of msg3 and match the above. Note that
# count is set to 512, to "trick" the hash into thinking that 512 bits have been
# processed so far.
h = md5(state=bytes.fromhex(s1), count=512)
h.update(msg2)
print(h.hexdigest())
