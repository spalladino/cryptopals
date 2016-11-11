struct Slice(T)

  def xor(other : Slice(T)) : Slice(T)
    raise "Length must match for XOR (expected #{self.size} but was #{other.size})" unless self.size == other.size
    result = Slice(T).new(self.size)
    self.size.times do |i|
      result[i] = (self[i] ^ other[i]).to_u8
    end
    result
  end

  def xor(other : Char) : Slice(T)
    xor(other.ord.to_u8)
  end

  def xor(other : T) : Slice(T)
    result = Slice(T).new(self.size)
    self.size.times do |i|
      result[i] = (self[i] ^ other).to_u8
    end
    result
  end

  def ^(other)
    xor(other)
  end

end
