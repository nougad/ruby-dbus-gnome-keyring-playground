# stealing from http://snippets.dzone.com/posts/show/4600
class Integer
    # Compute self ^ e mod m
    def mod_exp e, m
        result = 1
        b = self
        while e > 0
            result = (result * b) % m if e[0] == 1
            e = e >> 1
            b = (b * b) % m
        end
        return result
    end

    # A roundabout, slow but fun way of counting bits.
    def bits_set
        ("%b" % self).count('1')
        #to_s(2).count('1')   # alternative
        #count = 0         # alternative
        #byte = self.abs
        #count += byte & 1 and byte >>= 1 until byte == 0     # cf. http://snippets.dzone.com/posts/show/4233
        #count
    end
end


class DH
    attr_reader :p, :g, :q, :x, :e

    # p is the prime, g the generator and q order of the subgroup
    def initialize g, p, q
        @p = p
        @g = g
        @q = q
    end

    # generate the [secret] random value and the public key
    def generate tries=16
        return @e unless @e.nil?
        tries.times do
            @x = rand(@q)
            @e = self.g.mod_exp(@x, self.p)
            return @e if self.valid?
        end
        raise ArgumentError, "can't generate valid e"
    end

    # validate a public key
    def valid? _e = self.e
        _e and _e.between?(2, self.p-2) and _e.bits_set > 1
    end

    # compute the shared secret, given the public key
    def secret f
        f.mod_exp(self.x, self.p)
    end
    alias my_public_key generate
end

=begin
alice = DH.new(53, 5, 23)
bob   = DH.new(53, 5, 15)
alice.generate
bob.generate

puts alice.valid? bob.e
alice_s = alice.secret(bob.e)
bob_s   = bob.secret(alice.e)
puts alice_s
puts bob_s
=end

