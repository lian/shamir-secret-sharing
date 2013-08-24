require 'openssl'
require 'digest/sha1'

class ShamirSecretSharing
  VERSION = '0.0.1'

  def self.pack(shares); shares; end
  def self.unpack(shares); shares; end
  def self.encode(string); string; end
  def self.decode(string); string; end

  def self.smallest_prime_of_bytelength(bytelength)
    n = OpenSSL::BN.new((2**(bytelength*8)+1).to_s)
    loop{ break if n.prime_fasttest?(20); n += 2 }
    n
  end

  def self.split(secret, available, needed, do_data_checksum=true)
    raise ArgumentError, "needed must be <= available" unless needed <= available
    raise ArgumentError, "needed must be >= 2"         unless needed >= 2
    raise ArgumentError, "available must be <= 250"    unless available <= 250

    if do_data_checksum
      checksum = Digest::SHA512.digest(secret)[0]
      secret = OpenSSL::BN.new((checksum + secret).unpack("H*")[0], 16) rescue OpenSSL::BN.new("0")
      raise ArgumentError, "bytelength of secret must be >= 1"   if secret.num_bytes < 2
      raise ArgumentError, "bytelength of secret must be <= 512" if secret.num_bytes > 513
    else
      secret = OpenSSL::BN.new(secret.unpack("H*")[0], 16) rescue OpenSSL::BN.new("0") # without checksum
      raise ArgumentError, "bytelength of secret must be >= 1"   if secret.num_bytes < 1
      raise ArgumentError, "bytelength of secret must be <= 512" if secret.num_bytes > 512
    end

    prime  = smallest_prime_of_bytelength(secret.num_bytes)
    coef = [ secret ] + Array.new(needed-1){ OpenSSL::BN.rand(secret.num_bytes * 8) }

    shares = (1..available).map{|x|
      x = OpenSSL::BN.new(x.to_s)
      y = coef.each_with_index.inject(OpenSSL::BN.new("0")){|acc, (c, idx)|
        acc + c * x.mod_exp(idx, prime)
      } % prime
      [x, secret.num_bytes, y]
    }
    pack(shares)
  end

  def self.combine(shares, do_raise=false, do_data_checksum=true)
    return false if shares.size < 2
    shares = unpack(shares)
    prime = smallest_prime_of_bytelength(shares[0][1])

    secret = shares.inject(OpenSSL::BN.new("0")){|secret,(x,num_bytes,y)|
      l_x = l(x, shares, prime)
      summand = OpenSSL::BN.new(y.to_s).mod_mul(l_x, prime)
      secret = (secret + summand) % prime
    }
    if do_data_checksum
      checksum, secret = [ secret.to_s(16) ].pack("H*").unpack("aa*")
      checksum == Digest::SHA512.digest(secret)[0] ? secret : false
    else
      secret = [ secret.to_s(16) ].pack("H*")
    end
  rescue ShareChecksumError, ShareDecodeError => ex
    raise if do_raise
    false
  end

  # Part of the Lagrange interpolation.
  # This is l_j(0), i.e.  # \prod_{x_j \neq x_i} \frac{-x_i}{x_j - x_i}
  # for more information compare Wikipedia: # http://en.wikipedia.org/wiki/Lagrange_form
  def self.l(current_x, shares, prime)
    shares.select{|x,num_bytes,y| x != current_x }.map{|x,num_bytes,y|
      minus_xi = OpenSSL::BN.new((-x).to_s)
      one_over_xj_minus_xi = OpenSSL::BN.new((current_x - x).to_s).mod_inverse(prime)
      minus_xi.mod_mul(one_over_xj_minus_xi, prime)
    }.inject{|p,f| p.mod_mul(f, prime) }
  end

  def self.encrypt(data, available, needed, key_bit_length=128)
    key = key_bit_length.is_a?(String) ? key_bit_length : [ OpenSSL::BN.rand(key_bit_length).to_s(16) ].pack("H*")
    c = OpenSSL::Cipher.new('aes-256-cbc').encrypt
    c.key, c.iv = Digest::SHA512.digest(key).unpack("a32a16")
    encrypted = c.update(data) << c.final
    [ split(key, available, needed), encode(encrypted) ]
  end

  def self.decrypt(shares, encrypted, do_raise=false)
    key = combine(shares, do_raise)
    return false unless key

    encrypted_decoded = decode(encrypted) rescue nil
    raise ShareDecodeError, "encrypted_data: #{encrypted}" unless encrypted_decoded

    return false unless encrypted and key
    c = OpenSSL::Cipher.new('aes-256-cbc').decrypt
    c.key, c.iv = Digest::SHA512.digest(key).unpack("a32a16")
    data = c.update(encrypted_decoded) << c.final
    data
  rescue OpenSSL::Cipher::CipherError, ShareDecodeError
    raise if do_raise
    false
  end


  class Number < ShamirSecretSharing
    def self.split(secret, available, needed)
      num = OpenSSL::BN.new(secret.to_s)
      raise ArgumentError, "available must be <= 9"    unless available <= 9
      raise ArgumentError, "num too large. bytelength must be <= 9" unless num.num_bytes <= 9
      shares = ShamirSecretSharing.split([num.to_s(16)].pack("H*"), available, needed, do_data_checksum=nil)
      shares.map{|i| i.join.to_i }
    end

    def self.combine(shares)
      shares = shares.map{|i| i.to_s.match(/(\d)(\d)(\d+)/); [$1.to_i, $2.to_i, $3.to_i] }
      ShamirSecretSharing.combine(shares, do_raise=false, do_data_checksum=nil).unpack("H*")[0].to_i(16)
    end
  end

  class ShareChecksumError < ::StandardError; end
  class ShareDecodeError < ::StandardError; end

  class Packed < ShamirSecretSharing # packing format and checkum
    def self.pack(shares)
      shares.map{|x,num_bytes,y|
        buf = [ x, num_bytes, y.to_s(16) ].pack("CnH*")
        checksum = Digest::SHA512.digest(buf)[0...2]
        encode(checksum << buf)
      }
    end
    def self.unpack(shares)
      shares.map{|i|
        buf = decode(i) rescue nil
        raise ShareDecodeError, "share: #{i}" unless buf
        checksum, buf = buf.unpack("a2a*")
        raise ShareChecksumError, "share: #{i}" unless checksum == Digest::SHA512.digest(buf)[0...2]
        i = buf.unpack("CnH*"); [ i[0], i[1], i[2].to_i(16) ]
      }
    end
  end

  class Base58 < Packed
    def self.encode(string); int_to_base58( string.unpack("H*")[0].to_i(16) ); end
    def self.decode(string); [ OpenSSL::BN.new(base58_to_int(string).to_s).to_s(16) ].pack("H*"); end
    def self.int_to_base58(int_val, leading_zero_bytes=0)
      alpha, base58_val, base = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz", "", 58
      while int_val > 0
        int_val, remainder = int_val.divmod(base)
        base58_val = alpha[remainder] + base58_val
      end; base58_val
    end

    def self.base58_to_int(base58_val)
      alpha, base = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz", 58
      base58_val.reverse.each_char.with_index.inject(0) do |int_val, (char,index)|
        raise ArgumentError, 'Value not a valid Base58 String.' unless char_index = alpha.index(char)
        int_val + char_index*(base**index)
      end
    end
  end

  class Base64 < Packed
    def self.encode(string); [string].pack("m0"); end
    def self.decode(string); string.unpack("m0")[0]; end
  end

  class Hex < Packed
    def self.encode(string); string.unpack("H*")[0]; end
    def self.decode(string); [string].pack("H*"); end
  end
end




if $0 == __FILE__
  require "minitest/autorun"

  class MiniTest::Unit::TestCase
    def assert_raises_and_message(klass, msg, &blk)
      err = assert_raises(klass, &blk); assert_equal msg, err.message
    end
  end


  class TestShamirSecretSharing < MiniTest::Unit::TestCase

    def helper(&b)
      [ [6,3], [10, 2], [3,2], [100, 30] ].each{|available,needed| b.call(available, needed) }
    end


    def test_shamir_base58
      secret = "hello"
      helper{|available,needed|
        shares = ShamirSecretSharing::Base58.split(secret, available, needed)
        assert_equal secret, ShamirSecretSharing::Base58.combine(shares.shuffle[0...needed])
      }
    end

    def test_shamir_base64
      secret = "hello"
      helper{|available,needed|
        shares = ShamirSecretSharing::Base64.split(secret, available, needed)
        assert_equal secret, ShamirSecretSharing::Base64.combine(shares.shuffle[0...needed])
      }
    end

    def test_shamir_hex
      secret = "hello"
      helper{|available,needed|
        shares = ShamirSecretSharing::Hex.split(secret, available, needed)
        assert_equal secret, ShamirSecretSharing::Hex.combine(shares.shuffle[0...needed])
      }
    end

    def test_shamir_number
      secret = 123
      shares = ShamirSecretSharing::Number.split(secret, 6, 3)
      assert_equal secret, ShamirSecretSharing::Number.combine(shares.shuffle[0...3])
    end

    def test_shamir_base58_encrypt
      text = "A"*32
      helper{|available,needed|
        shares, encrypted = ShamirSecretSharing::Base58.encrypt(text, available, needed, 96)
        assert_equal text, ShamirSecretSharing::Base58.decrypt(shares.shuffle[0...needed], encrypted)
      }
    end

    def test_shamir_base64_encrypt
      text = "A"*32
      helper{|available,needed|
        shares, encrypted = ShamirSecretSharing::Base64.encrypt(text, available, needed, 96)
        assert_equal text, ShamirSecretSharing::Base64.decrypt(shares.shuffle[0...needed], encrypted)
      }
    end

    def test_shamir_hex_encrypt
      text = "A"*32
      helper{|available,needed|
        shares, encrypted = ShamirSecretSharing::Hex.encrypt(text, available, needed, 96)
        assert_equal text, ShamirSecretSharing::Hex.decrypt(shares.shuffle[0...needed], encrypted)
      }
    end

    def test_shamir_with_broken_share_checksum
      secret = "hello"
      share_with_broken_checksum = ShamirSecretSharing::Base58.encode("foobar")
      share_with_broken_encoding = "1Il"
      shares = ShamirSecretSharing::Base58.split(secret, 3, 2)
      assert_equal false, ShamirSecretSharing::Base58.combine( [shares.shuffle.first, share_with_broken_checksum])
      assert_equal false, ShamirSecretSharing::Base58.combine( [shares.shuffle.first, share_with_broken_encoding])

      do_raise = true
      err = assert_raises(ShamirSecretSharing::ShareChecksumError){ ShamirSecretSharing::Base58.combine( [shares.shuffle.first, share_with_broken_checksum], do_raise) }
      assert_match /share: /, err.message
      assert_raises(ShamirSecretSharing::ShareDecodeError){ ShamirSecretSharing::Base58.combine( [shares.shuffle.first, share_with_broken_encoding], do_raise) }
      assert_match /share: /, err.message
    end

    def test_shamir_encrypt_with_broken_encypted_data
      text = "A"*32
      broken_encrypted_data = ShamirSecretSharing::Base58.encode("foobar")
      broken_encrypted_data_encoding = "1Il"
      share_with_broken_encoding = "1Il"
      shares, encrypted = ShamirSecretSharing::Base58.encrypt(text, 3, 2, 96)
      assert_equal false, ShamirSecretSharing::Base58.decrypt(shares.shuffle[0...2], broken_encrypted_data)
      assert_equal false, ShamirSecretSharing::Base58.decrypt(shares.shuffle[0...2], broken_encrypted_data_encoding)

      do_raise = true
      assert_raises(OpenSSL::Cipher::CipherError) { ShamirSecretSharing::Base58.decrypt(shares.shuffle[0...2], broken_encrypted_data, do_raise) }
      err = assert_raises(ShamirSecretSharing::ShareDecodeError){ ShamirSecretSharing::Base58.decrypt( [shares.shuffle.first, share_with_broken_encoding], encrypted, do_raise) }
      assert_match /share: /, err.message
      err = assert_raises(ShamirSecretSharing::ShareDecodeError){ ShamirSecretSharing::Base58.decrypt(shares.shuffle[0...2], broken_encrypted_data_encoding, do_raise) }
      assert_match /encrypted_data: /, err.message
    end

    def test_shamir_split_argument_errors
      assert_raises_and_message(ArgumentError, "needed must be <= available")            { ShamirSecretSharing::Base58.split("foobar", 2, 3)   }
      assert_raises_and_message(ArgumentError, "needed must be >= 2")                    { ShamirSecretSharing::Base58.split("foobar", 3, 1)   }
      assert_raises_and_message(ArgumentError, "available must be <= 250")               { ShamirSecretSharing::Base58.split("foobar", 251, 2) }
      assert_raises_and_message(ArgumentError, "bytelength of secret must be >= 1")      { ShamirSecretSharing::Base58.split("", 3, 2)         }
      assert_raises_and_message(ArgumentError, "bytelength of secret must be <= 512")    { ShamirSecretSharing::Base58.split("A"*513, 3, 2)    }
    end

  end

=begin
  require 'pp'

  pp shares = ShamirSecretSharing::Base58.split("hello", 6, 3)
  pp ShamirSecretSharing::Base58.combine(shares[0...3])

  pp shares = ShamirSecretSharing::Base64.split("hello", 6, 3)
  pp ShamirSecretSharing::Base64.combine(shares[0...3])

  pp shares = ShamirSecretSharing::Hex.split("hello", 6, 3)
  pp ShamirSecretSharing::Hex.combine(shares[0...3])

  pp shares = ShamirSecretSharing::Number.split(123, 6, 3)
  pp ShamirSecretSharing::Number.combine(shares[0...3])


  shares, encrypted = ShamirSecretSharing::Base58.encrypt("A"*32, 6, 3, 96)
  pp [shares, encrypted]
  p ShamirSecretSharing::Base58.decrypt(shares.shuffle[0...3], encrypted)

  shares, encrypted = ShamirSecretSharing::Base64.encrypt("A"*32, 6, 3, 96)
  pp [shares, encrypted]
  p ShamirSecretSharing::Base64.decrypt(shares.shuffle[0...3], encrypted)

  shares, encrypted = ShamirSecretSharing::Hex.encrypt("A"*32, 6, 3, 96)
  pp [shares, encrypted]
  p ShamirSecretSharing::Hex.decrypt(shares.shuffle[0...3], encrypted)
=end

end
