import math
import mmh3


class BloomFilter(object):
    def __init__(self, items_count, fp_prob):
        # False possible probability in decimal
        self.fp_prob = fp_prob
 
        # Size of bit array to use
        self.size = self.get_size(items_count, fp_prob)
        print(self.size)

        # number of hash functions to use
        self.hash_count = self.get_hash_count(self.size, items_count)
        print(self.hash_count)
 
        # array of given size containing hash_count hash function results
        self.array = [0 for i in range(self.size)]
 
    def add(self, item):
        for i in range(self.hash_count):
            array_pos = mmh3.hash(item, i) % self.size
            self.array[array_pos] = 1
 
    def check(self, item):
        for i in range(self.hash_count):
            array_pos = mmh3.hash(item, i) % self.size
            # if at least one position is not set, the element is not in hte filter
            if self.array[array_pos] == 0:
                return False
        return True
 
    def get_size(self, n, p):
        '''
        Return the size of bit array(m) to used using
        following formula
        m = -(n * lg(p)) / (lg(2)^2)
        n : int
            number of items expected to be stored in filter
        p : float
            False Positive probability in decimal
        '''
        m = -(n * math.log(p))/(math.log(2)**2)
        return int(m)
 
    def get_hash_count(self, m, n):
        '''
        Return the hash function(k) to be used using
        following formula
        k = (m/n) * lg(2)
 
        m : int
            size of bit array
        n : int
            number of items expected to be stored in filter
        '''
        k = (m/n) * math.log(2)
        return int(k)
