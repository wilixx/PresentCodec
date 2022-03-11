#!/usr/bin/python
# -*- coding: utf-8 -*-
# @Time    : 2022/03/10 09:30
# @Author  : Allen Guo
# @Email   : 13468897661@163.com
# @Profile : https://wilixx.github.io
# @File    : Present_codec_guo_implementation.py
# @Function: Encoding and decoding using present algorithm.

__author__ = 'Allen Guo'

import codecs

""" PRESENT block cipher implementation by Allen Guo.
Reference: https://blog.csdn.net/ftx456789/article/details/113613764, at CSDN. 
"""

s_box = [0xc, 0x5, 0x6, 0xb, 0x9, 0x0, 0xa, 0xd, 0x3, 0xe, 0xf, 0x8, 0x4, 0x7, 0x1, 0x2]
inv_s_box = [0x5, 0xE, 0xF, 0x8, 0xC, 0x1, 0x2, 0xD, 0xB, 0x4, 0x6, 0x3, 0x0, 0x7, 0x9, 0xA]

p_box = [0, 16, 32, 48, 1, 17, 33, 49, 2, 18, 34, 50, 3, 19, 35, 51,
         4, 20, 36, 52, 5, 21, 37, 53, 6, 22, 38, 54, 7, 23, 39, 55,
         8, 24, 40, 56, 9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59,
         12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63]
inv_p_box = [p_box.index(x) for x in range(64)]


class PresentCodec(object):
    def __init__(self, key, rounds=32):
        self.rounds = rounds
        key = codecs.decode(key[2:], 'hex')
        round_key = int(codecs.encode(key, 'hex'), 16)
        if len(key) * 8 == 80:
            self.roundkeys = generateRoundkeys(round_key, self.rounds)
        else:
            print("The key is invalid, which should be 80 bits. ")
            raise

    def encrypt(self, block):
        block = codecs.decode(block[2:], 'hex')
        state = int(codecs.encode(block, 'hex'), 16)
        for i in range(self.rounds - 1):
            state = addRoundKey(state, self.roundkeys[i])
            state = SubByte(state)
            state = PSub(state)
        cipher = addRoundKey(state, self.roundkeys[-1])
        encrypted = '0x' + '%0*x' % (8 * 2, cipher)
        return encrypted  # number2string_N(cipher, 8)

    def decrypt(self, block):
        block = codecs.decode(block[2:], 'hex')
        state = int(codecs.encode(block, 'hex'), 16)
        for i in range(self.rounds - 1):
            state = addRoundKey(state, self.roundkeys[-i - 1])
            state = InvPSub(state)
            state = InvSubByte(state)
        decipher = addRoundKey(state, self.roundkeys[0])
        decrypted = '0x' + '%0*x' % (8 * 2, decipher)
        return decrypted


def generateRoundkeys(key, rounds):
    roundkeys = []
    for i in range(1, rounds + 1):
        roundkeys.append(key >> 16)
        key = ((key & (2 ** 19 - 1)) << 61) + (key >> 19)
        key = (s_box[key >> 76] << 76) + (key & (2 ** 76 - 1))
        key ^= i << 15
    return roundkeys


def addRoundKey(state, key):
    return state ^ key


def SubByte(state):
    output = 0
    for i in range(16):
        output += s_box[(state >> (i * 4)) & 0xF] << (i * 4)
    return output


def InvSubByte(state):
    output = 0
    for i in range(16):
        output += inv_s_box[(state >> (i * 4)) & 0xF] << (i * 4)
    return output


def PSub(state):
    output = 0
    for i in range(64):
        output += ((state >> i) & 0x01) << p_box[i]
    return output


def InvPSub(state):
    output = 0
    for i in range(64):
        output += ((state >> i) & 0x01) << inv_p_box[i]
    return output


if __name__ == "__main__":
    # Note that you shall specify an 80-bit key.
    key = '0x00000000000000000000'
    plain = '0x00000000000000000000'
    # plain = '0x55555555555555555555'

    print(">>> key:", key)
    print(">>> plain:", plain)

    Model = PresentCodec(key)
    cipher = Model.encrypt(plain)
    print(">>> cipher: ", cipher)

    # pain = '0x00000000000000000000',  cipher = '0x5579c1387b228445.
    decrypted = Model.decrypt(cipher)
    print(">>> decrypted: ", decrypted)
